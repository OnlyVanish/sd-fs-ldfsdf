package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	password := "test-only-password-12345"
	encoded, err := makePasswordHash(password)
	if err != nil {
		t.Fatal(err)
	}
	if !validPasswordHash(encoded) {
		t.Fatal("generated hash did not validate")
	}
	if !verifyPasswordHash(password, encoded) {
		t.Fatal("generated hash did not verify")
	}
	if verifyPasswordHash(password+"x", encoded) {
		t.Fatal("wrong password verified")
	}
}

func TestAdminPathValidation(t *testing.T) {
	good := []string{"/jsjxjdkdl/jskdksld", "/admin-123/hidden_path"}
	for _, value := range good {
		if !adminPathPattern.MatchString(value) {
			t.Errorf("expected valid admin path: %q", value)
		}
	}
	bad := []string{"/", "//admin", "/a/../b", "/admin?x=1", "/admin/#fragment", "/admin\\x"}
	for _, value := range bad {
		if adminPathPattern.MatchString(value) {
			t.Errorf("expected invalid admin path: %q", value)
		}
	}
}

func writeTestSeasonZip(t *testing.T, archivePath, entryName string) {
	t.Helper()
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	manifest := SeasonManifest{
		Format: "crow-season-pack", SchemaVersion: 1,
		ID: "season-test", Title: "Test Season", Version: 1,
		Order: 20, LevelCount: 1, Entry: entryName,
	}
	data, _ := json.Marshal(manifest)
	w, err := zw.Create("pack.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(data); err != nil {
		t.Fatal(err)
	}
	w, err = zw.Create(entryName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("CrowContent.registerSeason({});")); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectSeasonZipAcceptsValidPack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "season.zip")
	writeTestSeasonZip(t, path, "season.js")
	manifest, err := inspectSeasonZip(path)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ID != "season-test" || manifest.Entry != "season.js" || manifest.LevelCount != 1 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestInspectSeasonZipRejectsTraversal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "season-bad.zip")
	writeTestSeasonZip(t, path, "../escape.js")
	if _, err := inspectSeasonZip(path); err == nil {
		t.Fatal("zip traversal entry should be rejected")
	}
}

func TestProjectSeasonTemplateIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "..", "Crow_Season_Template.zip")
	manifest, err := inspectSeasonZip(path)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ID != "season-03" || manifest.LevelCount != 1 || manifest.Order <= 16 {
		t.Fatalf("unexpected template manifest: %+v", manifest)
	}
}
