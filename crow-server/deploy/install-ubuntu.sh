#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then echo "Run as root: sudo bash deploy/install-ubuntu.sh"; exit 1; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v go >/dev/null 2>&1 || { echo "Go 1.22+ is required. Install Go first."; exit 1; }
GO_VERSION="$(go version | awk '{print $3}' | sed 's/^go//')"
if [[ "$(printf '%s\n' "1.22.0" "$GO_VERSION" | sort -V | head -n1)" != "1.22.0" ]]; then echo "Go 1.22+ is required (found $GO_VERSION)."; exit 1; fi
command -v caddy >/dev/null 2>&1 || { echo "Caddy 2.11+ is required. Install the official Caddy package first."; exit 1; }
CADDY_VERSION="$(caddy version | sed -nE 's/^v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1)"
if [[ -z "$CADDY_VERSION" || "$(printf '%s\n' "2.11.0" "$CADDY_VERSION" | sort -V | head -n1)" != "2.11.0" ]]; then echo "Caddy 2.11+ is required (found ${CADDY_VERSION:-unknown})."; exit 1; fi

id crow >/dev/null 2>&1 || useradd --system --home /opt/crow-server --shell /usr/sbin/nologin crow
install -d -o crow -g crow -m 0750 /opt/crow-server /opt/crow-server/data /opt/crow-server/data/releases /opt/crow-server/data/seasons /opt/crow-server/data/tmp
install -d -o root -g crow -m 0750 /opt/crow-server/cmd
cp -a "$ROOT/cmd" "$ROOT/go.mod" /opt/crow-server/
chown -R root:crow /opt/crow-server/cmd /opt/crow-server/go.mod
(cd /opt/crow-server && runuser -u crow -- go build -trimpath -ldflags="-s -w" -o /opt/crow-server/crow-server ./cmd/crow-server)
chmod 0750 /opt/crow-server/crow-server
if [[ ! -f /opt/crow-server/.env ]]; then install -o root -g crow -m 0640 "$ROOT/.env.example" /opt/crow-server/.env; echo "Created /opt/crow-server/.env. Set ADMIN_PASSWORD_HASH before starting."; fi
install -o root -g root -m 0644 "$ROOT/deploy/crow.service" /etc/systemd/system/crow.service
systemctl daemon-reload
systemctl enable crow

if [[ -f "$ROOT/deploy/Caddyfile" ]]; then install -o root -g root -m 0644 "$ROOT/deploy/Caddyfile" /etc/caddy/Caddyfile; fi
systemctl enable caddy
systemctl restart caddy || true
systemctl restart crow || true

echo "Installation files are in place. Edit /opt/crow-server/.env, then run: systemctl restart crow"
echo "Check logs: journalctl -u crow -f"
