#!/bin/sh
# Put security.agent into service on dev2 (or any systemd box), as root. Idempotent.
#
#   sudo sh deploy/install-dev2.sh [<sha>]      # default: origin/main
#
# The service runs as the unprivileged system user `securityagent`, sandboxed the way
# pay.agent and pit.world are: code /opt/security.agent root:securityagent read-only,
# data /var/lib/security-agent (0700), the desktops' tunnel keys in
# /var/lib/security-agent-tunnel (read by sshd as nobody), secrets in a root-only
# app.env that systemd reads and the app cannot.
set -eu
REPO=https://github.com/moshcoder/security.agent.git
APP_DIR=/opt/security.agent
APP_USER=securityagent
UNIT=security-agent
PORT=8799
ENV_DIR=/root/.local/share/security-agent
ENV_FILE=$ENV_DIR/app.env
BUN_SRC=${BUN_SRC:-/root/.bun/bin/bun}
[ -x "$BUN_SRC" ] || BUN_SRC=$(command -v bun || true)

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -n "$BUN_SRC" ] && [ -x "$BUN_SRC" ] || { echo "bun not found (set BUN_SRC)" >&2; exit 1; }

id "$APP_USER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/security-agent --shell /usr/sbin/nologin "$APP_USER"

# Code: a detached checkout of the commit asked for, owned by root.
[ -d "$APP_DIR/.git" ] || git clone -q "$REPO" "$APP_DIR"
git -C "$APP_DIR" fetch -q origin main
SHA=${1:-$(git -C "$APP_DIR" rev-parse origin/main)}
git -C "$APP_DIR" merge-base --is-ancestor "$SHA" origin/main || { echo "$SHA is not on origin/main" >&2; exit 1; }
git -C "$APP_DIR" checkout -q --detach "$SHA"
install -d -m 755 /usr/local/lib/security-agent
install -m 755 "$BUN_SRC" /usr/local/lib/security-agent/bun
(cd "$APP_DIR" && /usr/local/lib/security-agent/bun install --production --frozen-lockfile --ignore-scripts >/dev/null)
chown -R root:"$APP_USER" "$APP_DIR"
chmod -R g-w,o-rwx "$APP_DIR"
chmod 750 "$APP_DIR"

# Secrets: made once, kept across deploys. The c0mpute account key is the fleet's.
install -d -m 700 "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
  c0=$(sed -n 's/^C0MPUTE_API_KEY=//p' /home/anthony/.c0mpute-fleet.env 2>/dev/null || true)
  umask 077
  cat > "$ENV_FILE" <<EOF
SECAGENT_KEY=$(openssl rand -hex 32)
SECAGENT_ADMIN_KEY=$(openssl rand -hex 24)
SECAGENT_DB=/var/lib/security-agent/security-agent.db
SECAGENT_TUNNEL_HOST=dev2.profullstack.com
SECAGENT_TUNNEL_USER=secagent-tunnel
SECAGENT_TUNNEL_KEYS=/var/lib/security-agent-tunnel/tunnel_authorized_keys
C0MPUTE_API_KEY=$c0
EOF
  echo "wrote $ENV_FILE (push it to the logicsrc vault profullstack/security-agent--prod)"
fi

install -d -o "$APP_USER" -g "$APP_USER" -m 755 /var/lib/security-agent-tunnel

cat > /etc/systemd/system/$UNIT.service <<EOF
# security.agent: github.com/moshcoder/security.agent. Written by deploy/install-dev2.sh.
[Unit]
Description=security.agent (a security team for your AI agent)
After=network-online.target
Wants=network-online.target

[Service]
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
Environment=HOME=/var/lib/security-agent PORT=$PORT HOST=127.0.0.1 BUN_INSTALL_CACHE_DIR=/var/cache/security-agent
ExecStart=/usr/local/lib/security-agent/bun src/server.ts
Restart=always
RestartSec=3
StateDirectory=security-agent
StateDirectoryMode=0700
CacheDirectory=security-agent
ReadWritePaths=/var/lib/security-agent-tunnel
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$UNIT" >/dev/null 2>&1
systemctl restart "$UNIT"

for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "ok: $UNIT $(git -C "$APP_DIR" rev-parse --short HEAD) $(curl -fsS http://127.0.0.1:$PORT/health)"
    exit 0
  fi
  sleep 1
done
echo "$UNIT did not answer /health" >&2
journalctl -u "$UNIT" -n 30 --no-pager >&2
exit 3
