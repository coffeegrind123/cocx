# shellcheck shell=bash
# The web side: Caddy (in the caddy modes), the BIMI logo, and waiting for certificates.
#
# In the caddy modes mox runs `quickstart -existing-webserver`: it binds neither 80 nor
# 443 and does NO ACME. Caddy obtains the certificates through the vhost below and mox
# reads the files straight out of Caddy's storage. Consequence worth stating plainly:
# remove the vhost and mail keeps listening on 25/465/993 with a certificate that quietly
# expires. Every cocx run rewrites it, so drift is repaired rather than discovered.

CADDY_MIN=2.8
CADDY_SNIPPET=/etc/caddy/cocx-mail.caddy
CADDY_EXTERNAL_SNIPPET=/etc/cocx/caddy-mail.caddy
BIMI_DIR_CADDY=/var/lib/cocx/bimi
BIMI_DIR_MOX=/home/mox/web/bimi

# reuse_private_keys needs Caddy >= 2.8. The guard is a VERSION check, never "is caddy
# installed": distro repos ship 2.6 (Debian 12), which accepts every other directive and
# then rejects this one — or, worse, a guard on presence never upgrades it at all.
install_caddy() {
  [ "$WEBSERVER" = "caddy" ] || return 0
  msg "Ensuring Caddy >= $CADDY_MIN (official repository)..."
  rsh "MIN=$CADDY_MIN bash -s" <<'EOS'
set -e
ver() { caddy version 2>/dev/null | grep -oE '^v[0-9]+\.[0-9]+' | tr -d v; }
ok() { [ -n "$(ver)" ] && [ "$(printf '%s\n%s\n' "$MIN" "$(ver)" | sort -V | head -1)" = "$MIN" ]; }
if ok; then echo "    caddy $(ver) — ok"; exit 0; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https gnupg >/dev/null
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
  | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
  > /etc/apt/sources.list.d/caddy-stable.list
chmod 644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
apt-get update -qq
apt-get install -y -qq caddy >/dev/null
hash -r
ok || { echo "    caddy is still $(ver) after install — need >= $MIN for reuse_private_keys"; exit 1; }
echo "    caddy $(ver) installed"
EOS
}

# The vhost text. Generated here, on the operator side, from config — one definition used
# both for the managed Caddy and for the snippet handed to an external one.
caddy_vhost() {
  local email="${ACME_EMAIL:-$MAIL_ACCOUNT}" issuer
  case "$CADDY_ISSUER" in
    letsencrypt)
      issuer="		issuer acme {
			dir https://acme-v02.api.letsencrypt.org/directory
			email $email
		}" ;;
    letsencrypt-staging)
      issuer="		issuer acme {
			dir https://acme-staging-v02.api.letsencrypt.org/directory
			email $email
		}" ;;
    internal)
      issuer="		issuer internal" ;;
  esac

  # One TLS block shared by every mail host.
  #
  # reuse_private_keys is REQUIRED for DANE, not an optimisation: the published TLSA pins
  # this key, and without reuse Caddy mints a new one at every renewal (~60 days), the
  # TLSA stops matching, and DANE-enforcing senders refuse mail — silently, two months on.
  #
  # The issuer is PINNED, not left to Caddy's default (Let's Encrypt with ZeroSSL as
  # fallback): mox reads the certificate from a path that contains the issuer's
  # directory name, so a silent fallback would leave mox serving the old certificate
  # until it expired. A pinned issuer that fails, fails loudly in Caddy's log instead.
  local tls="	tls {
		reuse_private_keys
$issuer
	}"

  # "/" exactly — never a prefix. Thunderbird autoconfig lives at /mail/config-v1.1.xml,
  # outside /.well-known/, and a broader redirect would silently stop clients
  # auto-detecting the account. Not paired with a robots.txt Disallow either: that
  # blocks the fetch, so a crawler would never see the redirect and the 404 would stay
  # indexed. The redirect alone is the fix.
  local rootredir=""
  [ -n "${ROOT_REDIRECT:-}" ] && rootredir="	redir / $ROOT_REDIRECT 301"

  local bimi=""
  [ -n "${BIMI_LOGO:-}" ] && bimi="	handle /bimi/* {
		root * $BIMI_DIR_CADDY
		uri strip_prefix /bimi
		header Content-Type image/svg+xml
		header Cache-Control \"public, max-age=86400\"
		file_server
	}"

  cat <<VHOST
# Managed by cocx — rewritten on every run; edit cocx.conf instead.

mta-sts.$MAIL_DOMAIN, autoconfig.$MAIL_DOMAIN {
$tls
	encode zstd gzip
$rootredir
	reverse_proxy 127.0.0.1:81
}

$MAIL_HOSTNAME {
$tls
	encode zstd gzip
$bimi
VHOST

  if [ "$PUBLIC_WEBMAIL" = "yes" ]; then
    # Webmail, account and webapi via mox's internal :1080 listener, which quickstart
    # configures with Forwarded: true so mox takes the client IP (rate limiting) and
    # https-ness (secure cookies) from Caddy's X-Forwarded-* headers. The admin UI is
    # refused here and reachable only through `cocx tunnel`.
    cat <<VHOST
	handle /admin* {
		respond 404
	}
	redir / /webmail/ 302
	handle {
		reverse_proxy 127.0.0.1:1080
	}
}
VHOST
  else
    cat <<VHOST
$rootredir
	reverse_proxy 127.0.0.1:81
}
VHOST
  fi
}

# Write the vhost and make Caddy load it. In caddy mode the snippet is imported from the
# main Caddyfile; the stock Debian Caddyfile (a :80 placeholder site serving
# /usr/share/caddy) is replaced by a minimal one because its catch-all :80 block is not
# something anyone configured. Any other Caddyfile is kept and only gains the import line.
configure_caddy() {
  case "$WEBSERVER" in
    caddy) ;;
    caddy-external)
      msg "Writing the Caddy vhost snippet for your external Caddy..."
      caddy_vhost | rsh "install -d -m 755 /etc/cocx && cat > $CADDY_EXTERNAL_SNIPPET"
      info "snippet: $HOST:$CADDY_EXTERNAL_SNIPPET — import it from your Caddyfile and reload."
      info "mox reads certificates from CADDY_CERT_DIR=$CADDY_CERT_DIR"
      return 0 ;;
    *) return 0 ;;
  esac

  msg "Writing Caddy mail vhost ($CADDY_SNIPPET)..."
  caddy_vhost | rsh "cat > $CADDY_SNIPPET.new"
  rsh "SNIP='$CADDY_SNIPPET' bash -s" <<'EOS'
set -e
CF=/etc/caddy/Caddyfile
if [ ! -f "$CF" ] || grep -q 'The Caddyfile is an easy way to configure your Caddy web server' "$CF"; then
  [ -f "$CF" ] && cp -a "$CF" "$CF.dist-$(date +%Y%m%d-%H%M%S)"
  printf '# Caddyfile — add your own sites below or in further imports.\n\nimport %s\n' "$SNIP" > "$CF"
  echo "    replaced the stock Caddyfile with a minimal one"
elif ! grep -qE "^[[:space:]]*import[[:space:]]+$SNIP[[:space:]]*$" "$CF"; then
  cp -a "$CF" "$CF.bak-$(date +%Y%m%d-%H%M%S)"
  printf '\nimport %s\n' "$SNIP" >> "$CF"
  echo "    added: import $SNIP"
fi
if [ -f "$SNIP" ] && cmp -s "$SNIP" "$SNIP.new"; then
  rm -f "$SNIP.new"
  echo "    vhost unchanged"
else
  [ -f "$SNIP" ] && cp -a "$SNIP" "$SNIP.prev"
  mv -f "$SNIP.new" "$SNIP"
  if ! caddy validate --config "$CF" --adapter caddyfile >/tmp/cocx-caddy-validate.log 2>&1; then
    echo "    !! caddy rejected the new config — restoring the previous vhost:"
    sed 's/^/       /' /tmp/cocx-caddy-validate.log | tail -15
    if [ -f "$SNIP.prev" ]; then mv -f "$SNIP.prev" "$SNIP"; else rm -f "$SNIP"; fi
    exit 1
  fi
  echo "    vhost updated"
fi
systemctl enable caddy >/dev/null 2>&1
if systemctl is-active --quiet caddy; then systemctl reload caddy; else systemctl start caddy; fi
EOS
}

# Ship the BIMI logo to where the web side serves it. Validated LOCALLY first: a logo that
# is not SVG Tiny PS is silently ignored by every receiver, so it must never ship.
ship_bimi_logo() {
  [ -n "${BIMI_LOGO:-}" ] || return 0
  [ -f "$BIMI_LOGO" ] || die "BIMI_LOGO=$BIMI_LOGO does not exist"
  python3 "$COCX_DIR/tools/bimi-logo.py" check "$BIMI_LOGO" >/dev/null \
    || die "BIMI_LOGO is not valid SVG Tiny PS — run: tools/bimi-logo.py check $BIMI_LOGO"
  local dir owner
  if [ "$WEBSERVER" = "mox" ]; then dir=$BIMI_DIR_MOX; owner=mox:mox; else dir=$BIMI_DIR_CADDY; owner=root:root; fi
  msg "Shipping BIMI logo -> $dir/logo.svg..."
  rsh "install -d -m 755 '$dir' && cat > '$dir/logo.svg.new' && mv -f '$dir/logo.svg.new' '$dir/logo.svg' && chmod 644 '$dir/logo.svg' && chown $owner '$dir' '$dir/logo.svg'" < "$BIMI_LOGO"
}

# The URL the BIMI record points at, or nothing if BIMI is off.
bimi_url() {
  if [ -n "${BIMI_LOGO_URL:-}" ]; then
    printf '%s' "$BIMI_LOGO_URL"
  elif [ -n "${BIMI_LOGO:-}" ]; then
    printf 'https://%s/bimi/logo.svg' "$MAIL_HOSTNAME"
  fi
}

# On a fresh box the certificates do not exist until the web side has issued them, and
# `mox config test` fails on missing KeyCerts paths. Wait rather than fail confusingly.
wait_for_certs() {
  [ "$WEBSERVER" = "mox" ] && return 0
  local certd i
  certd="$(caddy_cert_dir)"
  msg "Waiting for certificates for the mail hostnames ($certd)..."
  for i in $(seq 1 36); do
    if rsh "for h in '$MAIL_HOSTNAME' 'mta-sts.$MAIL_DOMAIN' 'autoconfig.$MAIL_DOMAIN'; do test -s '$certd'/\$h/\$h.crt || exit 1; done" 2>/dev/null; then
      info "certificates present"
      return 0
    fi
    # Touch the hosts over HTTPS so an idle Caddy starts issuance on demand.
    [ $((i % 6)) -eq 1 ] && rsh "for h in '$MAIL_HOSTNAME' 'mta-sts.$MAIL_DOMAIN' 'autoconfig.$MAIL_DOMAIN'; do curl -sk --max-time 5 -o /dev/null --resolve \$h:443:127.0.0.1 https://\$h/ || true; done" 2>/dev/null
    sleep 10
  done
  warn "no certificates after 6 minutes in $certd"
  warn "  the hostnames must resolve to this box and port 80/443 must be reachable for ACME;"
  warn "  journalctl -u caddy on $HOST names the actual ACME error."
  return 1
}
