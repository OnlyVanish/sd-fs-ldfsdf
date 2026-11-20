package main

import (
	"archive/zip"
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxAPKBytes       = int64(1024 * 1024 * 1024)
	maxSeasonZipBytes = int64(160 * 1024 * 1024)
	maxSeasonExpanded = uint64(256 * 1024 * 1024)
	maxSeasonEntries  = 3000
	maxManifestBytes  = int64(1024 * 1024)
	pbkdf2Iterations  = 310000
)

var seasonIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,47}$`)
var adminPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Config struct {
	Addr          string
	DataDir       string
	AdminUsername string
	AdminHash     string
	AdminPath     string
}

type AppRelease struct {
	VersionCode  int       `json:"version_code"`
	VersionName  string    `json:"version_name"`
	SHA256       string    `json:"sha256"`
	SizeBytes    int64     `json:"size_bytes"`
	DownloadURL  string    `json:"download_url"`
	ReleaseNotes string    `json:"release_notes"`
	ForceUpdate  bool      `json:"force_update"`
	PublishedAt  time.Time `json:"published_at"`
	FileName     string    `json:"file_name,omitempty"`
}

type SeasonRelease struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Version     int       `json:"version"`
	Order       int       `json:"order"`
	LevelCount  int       `json:"level_count"`
	Entry       string    `json:"entry"`
	SHA256      string    `json:"sha256"`
	SizeBytes   int64     `json:"size_bytes"`
	DownloadURL string    `json:"download_url"`
	PublishedAt time.Time `json:"published_at"`
	FileName    string    `json:"file_name,omitempty"`
}

type SeasonManifest struct {
	Format         string `json:"format"`
	SchemaVersion  int    `json:"schemaVersion"`
	ID             string `json:"id"`
	Title          string `json:"title"`
	Version        int    `json:"version"`
	Order          int    `json:"order"`
	LevelCount     int    `json:"levelCount"`
	Entry          string `json:"entry"`
	MinGameVersion string `json:"minGameVersion"`
}

type Session struct {
	CSRF      string
	ExpiresAt time.Time
}

type Attempt struct {
	Count   int
	Blocked time.Time
}

type Server struct {
	cfg      Config
	mu       sync.RWMutex
	sessions map[string]Session
	attempts map[string]Attempt
	app      *AppRelease
	seasons  map[string]SeasonRelease
	page     *template.Template
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		fmt.Fprintln(os.Stderr, "Read the new admin password from stdin (use a hidden shell prompt to prevent echo).")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		password := strings.TrimSpace(line)
		if len(password) < 14 || len(password) > 128 {
			fmt.Fprintln(os.Stderr, "Password must contain at least 14 characters")
			os.Exit(2)
		}
		hash, err := makePasswordHash(password)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)
		return
	}

	cfg := Config{
		Addr:          env("CROW_ADDR", "127.0.0.1:8090"),
		DataDir:       env("CROW_DATA_DIR", "./data"),
		AdminUsername: env("ADMIN_USERNAME", "Admin"),
		AdminHash:     strings.TrimSpace(os.Getenv("ADMIN_PASSWORD_HASH")),
		AdminPath:     normalizeAdminPath(env("ADMIN_PATH", "/jsjxjdkdl/jskdksld")),
	}
	if cfg.AdminHash == "" {
		log.Fatal("ADMIN_PASSWORD_HASH is required. Generate it with: crow-server hash-password")
	}
	if !validPasswordHash(cfg.AdminHash) {
		log.Fatal("ADMIN_PASSWORD_HASH format is invalid")
	}
	if !adminPathPattern.MatchString(cfg.AdminPath) || strings.Contains(cfg.AdminPath, "..") {
		log.Fatal("ADMIN_PATH is invalid; use slash-separated letters, numbers, underscore or dash")
	}

	for _, dir := range []string{
		filepath.Join(cfg.DataDir, "releases"),
		filepath.Join(cfg.DataDir, "seasons"),
		filepath.Join(cfg.DataDir, "tmp"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatal(err)
		}
	}

	s := &Server{cfg: cfg, sessions: map[string]Session{}, attempts: map[string]Attempt{}, seasons: map[string]SeasonRelease{}}
	if err := s.loadState(); err != nil {
		log.Fatal(err)
	}
	s.page = template.Must(template.New("admin").Funcs(template.FuncMap{"divMB": func(n int64) float64 { return float64(n) / (1024 * 1024) }}).Parse(adminHTML))

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/api/v1/app", s.appManifest)
	mux.HandleFunc("/api/v1/app/download", s.appDownload)
	mux.HandleFunc("/api/v1/seasons", s.seasonManifest)
	mux.HandleFunc("/api/v1/seasons/", s.seasonDownload)
	s.registerAdminRoutes(mux)

	h := s.securityHeaders(s.recoverer(mux))
	server := &http.Server{
		Addr: cfg.Addr, Handler: h,
		ReadHeaderTimeout: 8 * time.Second,
		ReadTimeout:       15 * time.Minute,
		WriteTimeout:      0, // APK upload/downloads are streamed; proxy enforces its own timeout.
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	log.Printf("Crow update server listening on %s; admin path %s", cfg.Addr, cfg.AdminPath)
	log.Fatal(server.ListenAndServe())
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
func normalizeAdminPath(v string) string {
	v = "/" + strings.Trim(v, "/")
	if v == "/" {
		return "/admin-console"
	}
	return v
}

func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	base := s.cfg.AdminPath
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+"/", http.StatusPermanentRedirect)
	})
	mux.HandleFunc(base+"/", s.adminRoot)
	mux.HandleFunc(base+"/login", s.adminLogin)
	mux.HandleFunc(base+"/logout", s.requireAdmin(s.adminLogout))
	mux.HandleFunc(base+"/upload-apk", s.requireAdmin(s.uploadAPK))
	mux.HandleFunc(base+"/upload-season", s.requireAdmin(s.uploadSeason))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Printf("panic: %v", v)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	jsonResponse(w, 200, map[string]any{"ok": true, "service": "crow-update"})
}

func (s *Server) appManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	s.mu.RLock()
	rel := s.app
	if rel != nil {
		copy := *rel
		rel = &copy
	}
	s.mu.RUnlock()
	if rel == nil {
		jsonResponse(w, 200, map[string]any{"version_code": 0, "version_name": "", "download_url": "", "sha256": "", "size_bytes": 0, "release_notes": "", "force_update": false})
		return
	}
	rel.DownloadURL = "/api/v1/app/download"
	jsonResponse(w, 200, rel)
}

func (s *Server) appDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	s.mu.RLock()
	rel := s.app
	s.mu.RUnlock()
	if rel == nil {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.cfg.DataDir, "releases", rel.FileName)
	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	w.Header().Set("Content-Length", strconv.FormatInt(rel.SizeBytes, 10))
	w.Header().Set("Content-Disposition", `attachment; filename="Crow-update.apk"`)
	http.ServeFile(w, r, path)
}

func (s *Server) seasonManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	s.mu.RLock()
	list := make([]SeasonRelease, 0, len(s.seasons))
	for _, v := range s.seasons {
		list = append(list, v)
	}
	s.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool {
		if list[i].Order == list[j].Order {
			return list[i].ID < list[j].ID
		}
		return list[i].Order < list[j].Order
	})
	for i := range list {
		list[i].DownloadURL = "/api/v1/seasons/" + list[i].ID + "/download"
	}
	jsonResponse(w, 200, map[string]any{"seasons": list})
}

func (s *Server) seasonDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "seasons" || parts[4] != "download" || !seasonIDPattern.MatchString(parts[3]) {
		http.NotFound(w, r)
		return
	}
	s.mu.RLock()
	rel, ok := s.seasons[parts[3]]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.cfg.DataDir, "seasons", rel.FileName)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.FormatInt(rel.SizeBytes, 10))
	w.Header().Set("Content-Disposition", `attachment; filename="`+rel.ID+`.zip"`)
	http.ServeFile(w, r, path)
}

func (s *Server) adminRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if strings.TrimSuffix(r.URL.Path, "/") != s.cfg.AdminPath {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.sessionFromRequest(r); !ok {
		loginCSRF, err := randomToken(24)
		if err != nil {
			http.Error(w, "internal server error", 500)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "crow_login_csrf", Value: loginCSRF, Path: s.cfg.AdminPath + "/", Expires: time.Now().Add(15 * time.Minute), MaxAge: 900, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		s.render(w, map[string]any{"LoggedIn": false, "CSRF": "", "LoginCSRF": loginCSRF, "AdminPath": s.cfg.AdminPath, "Message": ""})
		return
	}
	s.renderDashboard(w, r, "")
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !s.allowLogin(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	loginCookie, cookieErr := r.Cookie("crow_login_csrf")
	if cookieErr != nil || subtle.ConstantTimeCompare([]byte(r.FormValue("login_csrf")), []byte(loginCookie.Value)) != 1 {
		http.Error(w, "invalid login request", http.StatusForbidden)
		return
	}
	username, password := r.FormValue("username"), r.FormValue("password")
	validUser := subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.AdminUsername)) == 1
	validPass := len(password) <= 128 && verifyPasswordHash(password, s.cfg.AdminHash)
	if !validUser || !validPass {
		log.Printf("failed admin login from %s", clientIP(r))
		s.mu.Lock()
		attempt := s.attempts[clientIP(r)]
		attempt.Count++
		if attempt.Count >= 10 {
			attempt.Blocked = time.Now().Add(15 * time.Minute)
		}
		s.attempts[clientIP(r)] = attempt
		s.mu.Unlock()
		w.Header().Set("Retry-After", "3")
		s.render(w, map[string]any{"LoggedIn": false, "CSRF": "", "LoginCSRF": loginCookie.Value, "AdminPath": s.cfg.AdminPath, "Message": "نام کاربری یا رمز عبور نادرست است."})
		return
	}
	clearAttempt := clientIP(r)
	s.mu.Lock()
	delete(s.attempts, clearAttempt)
	s.mu.Unlock()
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal server error", 500)
		return
	}
	csrf, err := randomToken(24)
	if err != nil {
		http.Error(w, "internal server error", 500)
		return
	}
	s.mu.Lock()
	s.sessions[token] = Session{CSRF: csrf, ExpiresAt: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "crow_admin", Value: token, Path: s.cfg.AdminPath + "/", Expires: time.Now().Add(12 * time.Hour), MaxAge: 43200, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	log.Printf("admin login succeeded from %s", clientIP(r))
	http.Redirect(w, r, s.cfg.AdminPath+"/", http.StatusSeeOther)
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	if c, err := r.Cookie("crow_admin"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "crow_admin", Value: "", Path: s.cfg.AdminPath + "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, s.cfg.AdminPath+"/", http.StatusSeeOther)
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sessionFromRequest(r); !ok {
			http.Redirect(w, r, s.cfg.AdminPath+"/", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) sessionFromRequest(r *http.Request) (Session, bool) {
	c, err := r.Cookie("crow_admin")
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	s.mu.RLock()
	session, ok := s.sessions[c.Value]
	s.mu.RUnlock()
	if !ok || time.Now().After(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
		return Session{}, false
	}
	return session, true
}

func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return false
	}
	session, ok := s.sessionFromRequest(r)
	if !ok || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(session.CSRF)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) uploadAPK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPKBytes+2*1024*1024)
	if err := r.ParseMultipartForm(32 * 1024 * 1024); err != nil {
		http.Error(w, "upload too large or invalid", 400)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !s.checkCSRF(w, r) {
		return
	}
	versionCode, _ := strconv.Atoi(r.FormValue("version_code"))
	versionName := strings.TrimSpace(r.FormValue("version_name"))
	notes := strings.TrimSpace(r.FormValue("release_notes"))
	force := r.FormValue("force_update") == "on"
	if versionCode < 1 || versionName == "" || len(versionName) > 32 || len(notes) > 4000 {
		http.Error(w, "version fields invalid", 400)
		return
	}
	s.mu.RLock()
	current := s.app
	s.mu.RUnlock()
	if current != nil && versionCode <= current.VersionCode {
		http.Error(w, "version_code must be greater than the currently published release", 400)
		return
	}
	file, header, err := r.FormFile("apk")
	if err != nil {
		http.Error(w, "APK file is required", 400)
		return
	}
	defer file.Close()
	if header.Size <= 0 || header.Size > maxAPKBytes {
		http.Error(w, "APK size is invalid", 400)
		return
	}
	if !strings.EqualFold(filepath.Ext(header.Filename), ".apk") {
		http.Error(w, "only .apk files are accepted", 400)
		return
	}
	tmp, err := os.CreateTemp(filepath.Join(s.cfg.DataDir, "tmp"), "crow-apk-*.part")
	if err != nil {
		http.Error(w, "storage error", 500)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(file, maxAPKBytes+1))
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil || written != header.Size || written > maxAPKBytes {
		http.Error(w, "APK upload could not be saved", 400)
		return
	}
	if !isAPKZip(tmpName) {
		http.Error(w, "uploaded file is not a valid APK archive", 400)
		return
	}
	name := fmt.Sprintf("crow-v%d-%s.apk", versionCode, time.Now().UTC().Format("20060102T150405Z"))
	destination := filepath.Join(s.cfg.DataDir, "releases", name)
	if err := os.Rename(tmpName, destination); err != nil {
		http.Error(w, "could not publish APK", 500)
		return
	}
	release := &AppRelease{VersionCode: versionCode, VersionName: versionName, SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: written, DownloadURL: "/api/v1/app/download", ReleaseNotes: notes, ForceUpdate: force, PublishedAt: time.Now().UTC(), FileName: name}
	s.mu.Lock()
	previous := s.app
	s.app = release
	err = s.saveAppLocked()
	if err != nil {
		s.app = previous
	}
	s.mu.Unlock()
	if err != nil {
		_ = os.Remove(destination)
		http.Error(w, "could not save release metadata", 500)
		return
	}
	log.Printf("published Crow APK version=%d sha256=%s", versionCode, release.SHA256)
	s.renderDashboard(w, r, "APK با موفقیت منتشر شد.")
}

func (s *Server) uploadSeason(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSeasonZipBytes+2*1024*1024)
	if err := r.ParseMultipartForm(16 * 1024 * 1024); err != nil {
		http.Error(w, "upload too large or invalid", 400)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !s.checkCSRF(w, r) {
		return
	}
	file, header, err := r.FormFile("season_zip")
	if err != nil {
		http.Error(w, "season ZIP is required", 400)
		return
	}
	defer file.Close()
	if header.Size <= 0 || header.Size > maxSeasonZipBytes || !strings.EqualFold(filepath.Ext(header.Filename), ".zip") {
		http.Error(w, "season ZIP size or extension is invalid", 400)
		return
	}
	tmp, err := os.CreateTemp(filepath.Join(s.cfg.DataDir, "tmp"), "crow-season-*.part")
	if err != nil {
		http.Error(w, "storage error", 500)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(file, maxSeasonZipBytes+1))
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil || written != header.Size || written > maxSeasonZipBytes {
		http.Error(w, "season upload could not be saved", 400)
		return
	}
	manifest, err := inspectSeasonZip(tmpName)
	if err != nil {
		http.Error(w, "season ZIP rejected: "+err.Error(), 400)
		return
	}
	season := SeasonRelease{ID: manifest.ID, Title: manifest.Title, Version: manifest.Version, Order: manifest.Order, LevelCount: manifest.LevelCount, Entry: manifest.Entry, SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: written, PublishedAt: time.Now().UTC()}
	name := fmt.Sprintf("%s-v%d-%s.zip", season.ID, season.Version, time.Now().UTC().Format("20060102T150405Z"))
	season.FileName = name
	destination := filepath.Join(s.cfg.DataDir, "seasons", name)
	if err := os.Rename(tmpName, destination); err != nil {
		http.Error(w, "could not publish season", 500)
		return
	}
	s.mu.Lock()
	old, existed := s.seasons[season.ID]
	if existed && season.Version <= old.Version {
		s.mu.Unlock()
		_ = os.Remove(destination)
		http.Error(w, "season version must be greater than the currently published version", 400)
		return
	}
	if existed && (season.Order != old.Order || season.LevelCount != old.LevelCount) {
		s.mu.Unlock()
		_ = os.Remove(destination)
		http.Error(w, "season order and level count must remain unchanged; publish new levels as a new season", 400)
		return
	}
	if !existed {
		maxOrder := 0
		for _, current := range s.seasons {
			if current.Order > maxOrder {
				maxOrder = current.Order
			}
		}
		if season.Order <= maxOrder {
			s.mu.Unlock()
			_ = os.Remove(destination)
			http.Error(w, "new season order must be greater than every published season", 400)
			return
		}
	}
	s.seasons[season.ID] = season
	err = s.saveSeasonsLocked()
	if err != nil {
		if existed {
			s.seasons[season.ID] = old
		} else {
			delete(s.seasons, season.ID)
		}
	}
	s.mu.Unlock()
	if err != nil {
		_ = os.Remove(destination)
		http.Error(w, "could not save season metadata", 500)
		return
	}
	log.Printf("published Crow season id=%s version=%d sha256=%s", season.ID, season.Version, season.SHA256)
	s.renderDashboard(w, r, "فصل با موفقیت منتشر شد.")
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, message string) {
	session, ok := s.sessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, s.cfg.AdminPath+"/", http.StatusSeeOther)
		return
	}
	s.mu.RLock()
	app := s.app
	seasons := make([]SeasonRelease, 0, len(s.seasons))
	for _, v := range s.seasons {
		seasons = append(seasons, v)
	}
	s.mu.RUnlock()
	sort.Slice(seasons, func(i, j int) bool { return seasons[i].Order < seasons[j].Order })
	data := map[string]any{"LoggedIn": true, "CSRF": session.CSRF, "AdminPath": s.cfg.AdminPath, "Message": message, "App": app, "Seasons": seasons}
	s.render(w, data)
}

func (s *Server) render(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.page.Execute(w, data); err != nil {
		log.Printf("render admin page: %v", err)
	}
}

func (s *Server) allowLogin(w http.ResponseWriter, r *http.Request) bool {
	ip := clientIP(r)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.attempts[ip]
	if now.Before(a.Blocked) {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(time.Until(a.Blocked).Seconds()))))
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return false
	}
	if !a.Blocked.IsZero() && !now.Before(a.Blocked) {
		a = Attempt{}
		s.attempts[ip] = a
	}
	if a.Count >= 10 {
		a.Blocked = now.Add(15 * time.Minute)
		s.attempts[ip] = a
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	// Go listens only on loopback behind Caddy. Caddy overwrites X-Real-IP with
	// its actual peer address; never expose this listener directly to the Internet.
	if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwarded != nil {
		return forwarded.String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) loadState() error {
	if err := readJSON(filepath.Join(s.cfg.DataDir, "app.json"), &s.app); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if s.app != nil {
		if s.app.VersionCode < 1 || s.app.VersionName == "" || s.app.SizeBytes < 1 || !sha256Pattern.MatchString(s.app.SHA256) || !validStoredFileName(s.app.FileName, ".apk") || !strings.HasPrefix(s.app.FileName, fmt.Sprintf("crow-v%d-", s.app.VersionCode)) {
			return errors.New("stored APK release metadata is invalid")
		}
		if err := verifyStoredFile(filepath.Join(s.cfg.DataDir, "releases", s.app.FileName), s.app.SizeBytes); err != nil {
			return fmt.Errorf("stored APK release file: %w", err)
		}
		s.app.DownloadURL = "/api/v1/app/download"
	}
	var list []SeasonRelease
	if err := readJSON(filepath.Join(s.cfg.DataDir, "seasons.json"), &list); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, v := range list {
		if !seasonIDPattern.MatchString(v.ID) || v.Version < 1 || v.Order < 1 || v.LevelCount < 1 || v.SizeBytes < 1 || !sha256Pattern.MatchString(v.SHA256) || !validStoredFileName(v.FileName, ".zip") || !strings.HasPrefix(v.FileName, fmt.Sprintf("%s-v%d-", v.ID, v.Version)) {
			return fmt.Errorf("stored season metadata is invalid for %q", v.ID)
		}
		if err := verifyStoredFile(filepath.Join(s.cfg.DataDir, "seasons", v.FileName), v.SizeBytes); err != nil {
			return fmt.Errorf("stored season %q: %w", v.ID, err)
		}
		s.seasons[v.ID] = v
	}
	return nil
}

func validStoredFileName(name, extension string) bool {
	return name != "" && name == filepath.Base(name) && !strings.ContainsAny(name, `/\`) && !strings.Contains(name, "..") && strings.EqualFold(filepath.Ext(name), extension)
}

func verifyStoredFile(path string, expectedSize int64) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() != expectedSize {
		return errors.New("file type or size does not match metadata")
	}
	return nil
}
func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
func writeJSONAtomic(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func (s *Server) saveAppLocked() error {
	return writeJSONAtomic(filepath.Join(s.cfg.DataDir, "app.json"), s.app)
}
func (s *Server) saveSeasonsLocked() error {
	list := make([]SeasonRelease, 0, len(s.seasons))
	for _, v := range s.seasons {
		list = append(list, v)
	}
	return writeJSONAtomic(filepath.Join(s.cfg.DataDir, "seasons.json"), list)
}

func jsonResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
func makePasswordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := pbkdf2([]byte(password), salt, pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}
func validPasswordHash(value string) bool {
	p := strings.Split(value, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	it, err := strconv.Atoi(p[1])
	if err != nil || it < 100000 || it > 1000000 {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(p[2])
	hash, e2 := base64.RawStdEncoding.DecodeString(p[3])
	return e1 == nil && e2 == nil && len(salt) >= 16 && len(hash) == 32
}
func verifyPasswordHash(password, encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 4 {
		return false
	}
	iterations, _ := strconv.Atoi(p[1])
	salt, _ := base64.RawStdEncoding.DecodeString(p[2])
	expected, _ := base64.RawStdEncoding.DecodeString(p[3])
	actual := pbkdf2([]byte(password), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func isAPKZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = zip.NewReader(f, func() int64 {
		st, _ := f.Stat()
		if st == nil {
			return 0
		}
		return st.Size()
	}())
	return err == nil
}

func inspectSeasonZip(path string) (SeasonManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return SeasonManifest{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return SeasonManifest{}, err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return SeasonManifest{}, errors.New("فایل ZIP معتبر نیست")
	}
	if len(zr.File) == 0 || len(zr.File) > maxSeasonEntries {
		return SeasonManifest{}, errors.New("تعداد فایل‌های ZIP نامعتبر است")
	}
	var manifestBytes []byte
	var total uint64
	for _, z := range zr.File {
		name := strings.ReplaceAll(z.Name, "\\", "/")
		if strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
			return SeasonManifest{}, errors.New("مسیر ناامن داخل ZIP")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." || part == "." {
				return SeasonManifest{}, errors.New("مسیر ناامن داخل ZIP")
			}
		}
		total += z.UncompressedSize64
		if total > maxSeasonExpanded || z.UncompressedSize64 > 64*1024*1024 {
			return SeasonManifest{}, errors.New("حجم بازشده بیش از حد است")
		}
		if name == "pack.json" {
			if z.UncompressedSize64 > uint64(maxManifestBytes) {
				return SeasonManifest{}, errors.New("pack.json بیش از حد بزرگ است")
			}
			rc, e := z.Open()
			if e != nil {
				return SeasonManifest{}, e
			}
			manifestBytes, e = io.ReadAll(io.LimitReader(rc, maxManifestBytes+1))
			rc.Close()
			if e != nil {
				return SeasonManifest{}, e
			}
		}
	}
	if len(manifestBytes) == 0 {
		return SeasonManifest{}, errors.New("pack.json در ریشه‌ی ZIP پیدا نشد")
	}
	var m SeasonManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return m, errors.New("pack.json معتبر نیست")
	}
	if m.Format != "crow-season-pack" || m.SchemaVersion != 1 {
		return m, errors.New("فرمت بسته پشتیبانی نمی‌شود")
	}
	if !seasonIDPattern.MatchString(m.ID) || strings.TrimSpace(m.Title) == "" || len(m.Title) > 160 || m.Version < 1 || m.Order < 1 || m.LevelCount < 1 || m.LevelCount > 1000 {
		return m, errors.New("مشخصات فصل نامعتبر است")
	}
	if !safeRelative(m.Entry) || !strings.HasSuffix(strings.ToLower(m.Entry), ".js") {
		return m, errors.New("entry نامعتبر است")
	}
	found := false
	for _, z := range zr.File {
		if z.Name == m.Entry && !z.FileInfo().IsDir() {
			found = true
			break
		}
	}
	if !found {
		return m, errors.New("فایل entry در بسته وجود ندارد")
	}
	return m, nil
}
func safeRelative(s string) bool {
	if s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, "\\") || strings.Contains(s, ":") {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

const adminHTML = `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل مدیریت Crow</title><style>
:root{color-scheme:dark;--bg:#080a10;--panel:#111722;--line:#293346;--gold:#d6ad65;--muted:#9ba8bd;--text:#eef2f8;--green:#71d6a4}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#1a2233,#080a10 65%);color:var(--text);font-family:Tahoma,Arial,sans-serif;min-height:100vh}.wrap{width:min(100% - 32px,1000px);margin:48px auto}.head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:24px}.brand{font-size:26px;font-weight:800;color:#fff}.brand span{color:var(--gold)}.sub{color:var(--muted);font-size:13px;margin-top:7px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.card{background:linear-gradient(145deg,#151e2b,#0e141e);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 18px 50px #0005}.card h2{margin:0 0 18px;font-size:18px}.muted{color:var(--muted);font-size:13px;line-height:1.9}.field{display:block;margin:13px 0}.field span{display:block;font-size:13px;color:#bdc7d8;margin-bottom:8px}input,textarea{width:100%;border-radius:10px;border:1px solid #344156;background:#090e17;color:#fff;padding:13px;font:inherit;outline:none}input:focus,textarea:focus{border-color:var(--gold)}input[type=file]{padding:10px}textarea{min-height:88px;resize:vertical}.btn{border:0;border-radius:10px;background:linear-gradient(110deg,#e4bd78,#b77c3e);color:#17120c;font-weight:800;padding:13px 18px;cursor:pointer;font:inherit}.btn:disabled{opacity:.5}.msg{padding:13px 15px;border:1px solid #2b7555;background:#123222;color:#a5efc8;border-radius:12px;margin:0 0 18px}.error{border-color:#81474b;background:#351b21;color:#ffc4c9}.row{display:flex;align-items:center;justify-content:space-between;gap:12px}.pill{border:1px solid #344156;color:#c7d1e2;border-radius:100px;padding:6px 10px;font-size:11px}.stat{font-size:22px;color:var(--gold);font-weight:bold;margin:10px 0}.progress{height:9px;background:#080d15;border-radius:20px;overflow:hidden;margin-top:12px;display:none}.progress i{display:block;height:100%;width:0;background:linear-gradient(90deg,#e4bd78,#71d6a4)}.list{display:grid;gap:10px}.item{padding:13px;border:1px solid #2b3546;border-radius:12px;background:#0b111b}.item b{display:block;margin-bottom:7px}.item small{color:var(--muted);line-height:2}.check{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}.check input{width:auto}.login{max-width:420px;margin:8vh auto}.full{grid-column:1/-1}.logout{background:transparent;border:1px solid #485369;color:#cbd5e5;border-radius:10px;padding:9px 13px;cursor:pointer}@media(max-width:700px){.grid{grid-template-columns:1fr}.wrap{margin:24px auto}.head{align-items:flex-start}.full{grid-column:auto}}
</style></head><body><main class="wrap">{{if .LoggedIn}}
<div class="head"><div><div class="brand">CROW <span>CONTROL</span></div><div class="sub">مدیریت انتشار بازی، APK و فصل‌ها</div></div><form method="post" action="{{.AdminPath}}/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="logout">خروج امن</button></form></div>
{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
<div class="grid"><section class="card"><h2>نسخه‌ی منتشرشده‌ی بازی</h2>{{if .App}}<div class="stat">نسخه {{.App.VersionName}}</div><div class="muted">Version Code: {{.App.VersionCode}}<br>حجم: {{printf "%.2f" (divMB .App.SizeBytes)}} MB<br>SHA-256: {{.App.SHA256}}<br>تاریخ انتشار: {{.App.PublishedAt}}</div>{{else}}<p class="muted">هنوز APK منتشر نشده است.</p>{{end}}</section>
<section class="card"><h2>آپلود APK جدید</h2><p class="muted">نسخه‌کد باید از نسخه‌ی فعلی بالاتر باشد. APK باید با همان package name و کلید امضای نسخه‌ی نصب‌شده ساخته شده باشد.</p><form id="apkForm" method="post" enctype="multipart/form-data" action="{{.AdminPath}}/upload-apk"><input type="hidden" name="csrf" value="{{.CSRF}}"><label class="field"><span>Version Code</span><input type="number" name="version_code" min="1" required></label><label class="field"><span>Version Name</span><input name="version_name" maxlength="32" placeholder="1.4" required></label><label class="field"><span>توضیحات انتشار</span><textarea name="release_notes" maxlength="4000" placeholder="رفع اشکال‌ها و تغییرات نسخه..."></textarea></label><label class="field"><span>فایل APK</span><input type="file" name="apk" accept=".apk,application/vnd.android.package-archive" required></label><label class="check"><input type="checkbox" name="force_update"> این نسخه اجباری است (در صورت انتشار، بازی تا دریافت آن متوقف می‌شود)</label><button class="btn" style="margin-top:16px" type="submit">آپلود و انتشار APK</button><div class="progress" id="apkProgress"><i></i></div><p class="muted" id="apkStatus"></p></form></section>
<section class="card"><h2>انتشار فصل جدید</h2><p class="muted">ZIP باید شامل pack.json و فایل JavaScript ورودی باشد. شناسه ثابت باشد و برای انتشار همان فصل، شماره نسخه را افزایش بده.</p><form id="seasonForm" method="post" enctype="multipart/form-data" action="{{.AdminPath}}/upload-season"><input type="hidden" name="csrf" value="{{.CSRF}}"><label class="field"><span>بسته‌ی فصل (ZIP)</span><input type="file" name="season_zip" accept=".zip,application/zip" required></label><button class="btn" type="submit">اعتبارسنجی و انتشار فصل</button><div class="progress" id="seasonProgress"><i></i></div><p class="muted" id="seasonStatus"></p></form></section>
<section class="card"><h2>فصل‌های منتشرشده</h2>{{if .Seasons}}<div class="list">{{range .Seasons}}<div class="item"><b>{{.Title}}</b><small>شناسه: {{.ID}} · نسخه: {{.Version}} · مرحله: {{.LevelCount}} · ترتیب: {{.Order}}<br>SHA-256: {{.SHA256}}</small></div>{{end}}</div>{{else}}<p class="muted">هنوز بسته‌ی فصلی منتشر نشده است.</p>{{end}}</section>
<section class="card full"><h2>نکات انتشار امن</h2><p class="muted">APK فقط وقتی نصب می‌شود که package name، شماره نسخه، SHA-256 و امضای آن با اپ نصب‌شده تطبیق داشته باشد. فصل‌ها هم با SHA-256 کنترل و سپس در حافظه‌ی خصوصی برنامه نصب می‌شوند. APK و فصل را فقط از مسیر HTTPS عمومی منتشر کن.</p></section></div>
<script>
function bindUpload(id,progressId,statusId){const f=document.getElementById(id);f.addEventListener('submit',e=>{e.preventDefault();const b=f.querySelector('button[type=submit]'),p=document.getElementById(progressId),bar=p.querySelector('i'),s=document.getElementById(statusId);b.disabled=true;p.style.display='block';s.textContent='در حال ارسال امن فایل...';const x=new XMLHttpRequest();x.open('POST',f.action);x.upload.onprogress=e=>{if(e.lengthComputable){const n=Math.round(e.loaded/e.total*100);bar.style.width=n+'%';s.textContent='ارسال فایل: '+n+'٪';}};x.onload=()=>{b.disabled=false;if(x.status>=200&&x.status<400){document.open();document.write(x.responseText);document.close();}else{s.textContent='خطا در انتشار: '+x.responseText;}};x.onerror=()=>{b.disabled=false;s.textContent='ارتباط با سرور قطع شد.'};x.send(new FormData(f));});}
bindUpload('apkForm','apkProgress','apkStatus');bindUpload('seasonForm','seasonProgress','seasonStatus');
</script>{{else}}
<div class="login card"><div class="brand">CROW <span>CONTROL</span></div><div class="sub">ورود مدیر سیستم انتشار</div>{{if .Message}}<div class="msg error" style="margin-top:18px">{{.Message}}</div>{{end}}<form method="post" action="{{.AdminPath}}/login"><input type="hidden" name="login_csrf" value="{{.LoginCSRF}}"><label class="field"><span>نام کاربری</span><input name="username" autocomplete="username" required maxlength="64"></label><label class="field"><span>رمز عبور</span><input type="password" name="password" autocomplete="current-password" required maxlength="256"></label><button class="btn" style="width:100%;margin-top:8px">ورود امن</button></form><p class="muted">نشست ورود محدود به ۱۲ ساعت است. مسیر پنل را با دیگران به اشتراک نگذار.</p></div>
{{end}}</main></body></html>`
