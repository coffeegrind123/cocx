#!/usr/bin/env bash
# cocx CLI: configuration validation, and the generated Caddy vhost fed to a REAL Caddy
# (`caddy adapt`) in every mode combination — a vhost that only looks right is how mail
# TLS goes stale. Run: make test
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
pass=0
fail=0
check() { # name, expected exit ("0" or "nonzero"), command...
  local name="$1" want="$2" rc
  shift 2
  "$@" >"$TMP/out" 2>&1
  rc=$?
  if { [ "$want" = 0 ] && [ "$rc" = 0 ]; } || { [ "$want" = nonzero ] && [ "$rc" != 0 ]; }; then
    pass=$((pass + 1)); echo "  ok    $name"
  else
    fail=$((fail + 1)); echo "  FAIL  $name (exit $rc)"; sed 's/^/        /' "$TMP/out" | tail -8
  fi
}

conf() { # extra lines...
  {
    echo 'MAIL_DOMAIN=example.com'
    echo 'MAIL_HOSTNAME=mail.example.com'
    echo 'MAIL_ACCOUNT=admin@example.com'
    echo 'HOST=192.0.2.10'
    printf '%s\n' "$@"
  } > "$TMP/c.conf"
  echo "$TMP/c.conf"
}

# A real Caddy for `caddy adapt`, cached per version (tests/.cache is gitignored).
CADDY_VERSION=2.11.7
CADDY="${CADDY:-$ROOT/tests/.cache/caddy-$CADDY_VERSION}"
if [ ! -x "$CADDY" ]; then
  mkdir -p "$(dirname "$CADDY")"
  if ! curl -fsSL --max-time 120 "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION/caddy_${CADDY_VERSION}_linux_amd64.tar.gz" \
       | tar -xz -C "$(dirname "$CADDY")" caddy; then
    echo "could not fetch caddy $CADDY_VERSION; set CADDY=/path/to/caddy"
    exit 1
  fi
  mv "$(dirname "$CADDY")/caddy" "$CADDY"
fi

echo "configuration validation"
check "missing config file is refused"        nonzero "$ROOT/cocx" -c "$TMP/nope.conf" check
check "unknown WEBSERVER is refused"          nonzero "$ROOT/cocx" -c "$(conf WEBSERVER=nginx)" vhost
check "account outside MAIL_DOMAIN refused"   nonzero "$ROOT/cocx" -c "$(conf MAIL_ACCOUNT=admin@other.example)" vhost
check "caddy-external without cert dir"       nonzero "$ROOT/cocx" -c "$(conf WEBSERVER=caddy-external)" vhost
check "relative ROOT_REDIRECT refused"        nonzero "$ROOT/cocx" -c "$(conf ROOT_REDIRECT=example.com)" vhost
check "unknown command is refused"            nonzero "$ROOT/cocx" -c "$(conf)" frobnicate
check "help works without a config"           0       "$ROOT/cocx" help

echo "generated vhost is valid Caddyfile"
for issuer in letsencrypt letsencrypt-staging internal; do
  for pw in yes no; do
    for redir in "" "https://www.example.com/"; do
      for logo in "" "/tmp/logo.svg"; do
        c="$(conf "CADDY_ISSUER=$issuer" "PUBLIC_WEBMAIL=$pw" "ROOT_REDIRECT=$redir" "BIMI_LOGO=$logo")"
        "$ROOT/cocx" -c "$c" vhost > "$TMP/vhost.caddy" 2>/dev/null
        check "issuer=$issuer webmail=$pw redirect=${redir:+yes} bimi=${logo:+yes}" 0 \
          "$CADDY" adapt --config "$TMP/vhost.caddy" --adapter caddyfile
      done
    done
  done
done

echo "vhost semantics (from the adapted JSON, not the text)"
c="$(conf CADDY_ISSUER=letsencrypt PUBLIC_WEBMAIL=yes)"
"$ROOT/cocx" -c "$c" vhost > "$TMP/v.caddy"
"$CADDY" adapt --config "$TMP/v.caddy" --adapter caddyfile 2>/dev/null > "$TMP/v.json"
check "key reuse on (DANE needs a stable key)"   0 grep -q '"reuse_private_keys":true' "$TMP/v.json"
check "issuer pinned to Let's Encrypt"           0 grep -q 'acme-v02.api.letsencrypt.org/directory' "$TMP/v.json"
check "admin UI is refused publicly"             0 python3 - "$TMP/v.json" <<'PY'
import json, sys
s = json.dumps(json.load(open(sys.argv[1])))
assert '"/admin*"' in s and '"status_code": 404' in s, "no 404 for /admin*"
PY
check "webmail proxied to :1080"                 0 grep -q '127.0.0.1:1080' "$TMP/v.json"
check "mta-sts proxied to :81"                   0 grep -q '127.0.0.1:81' "$TMP/v.json"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
