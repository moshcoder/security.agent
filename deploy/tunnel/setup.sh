#!/bin/sh
# One-time host setup for security.agent desktop tunnels. Run as root on the box
# that runs security.agent. Idempotent. Validates sshd's config before reloading
# and puts the old one back if the new one does not parse.
#
#   sudo sh deploy/tunnel/setup.sh
#
# Makes: user secagent-tunnel (no password, no shell, no home files), the
# AuthorizedKeysCommand script, the sshd Match block, and the keys file the app
# writes (/var/lib/security-agent/tunnel_authorized_keys, owned by the app user).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
APP_USER=${APP_USER:-securityagent}
KEYS=/var/lib/security-agent/tunnel_authorized_keys
CONF=/etc/ssh/sshd_config.d/60-security-agent-tunnel.conf

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

if ! id secagent-tunnel >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin secagent-tunnel
fi
passwd -l secagent-tunnel >/dev/null 2>&1 || true

install -d -o root -g root -m 755 /usr/local/lib/security-agent
install -o root -g root -m 755 "$HERE/authorized-keys" /usr/local/lib/security-agent/authorized-keys

install -d -m 755 /var/lib/security-agent
if id "$APP_USER" >/dev/null 2>&1; then
  [ -f "$KEYS" ] || install -o "$APP_USER" -g "$APP_USER" -m 644 /dev/null "$KEYS"
  chown "$APP_USER:$APP_USER" "$KEYS"
else
  [ -f "$KEYS" ] || install -m 644 /dev/null "$KEYS"
fi

backup=""
if [ -f "$CONF" ] && ! cmp -s "$HERE/sshd-security-agent.conf" "$CONF"; then
  backup="$CONF.bak-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$CONF" "$backup"
fi
install -o root -g root -m 644 "$HERE/sshd-security-agent.conf" "$CONF"

if ! sshd -t; then
  echo "sshd -t failed: putting the old config back" >&2
  if [ -n "$backup" ]; then mv "$backup" "$CONF"; else rm -f "$CONF"; fi
  exit 1
fi
systemctl reload ssh 2>/dev/null || systemctl reload sshd
echo "ok: secagent-tunnel ready; keys from $KEYS"
