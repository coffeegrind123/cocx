# shellcheck shell=bash
# mox itself: build, first-time config, per-mode TLS wiring, DANE, units, policy.
#
# Layout on the host (mox's own convention — its config paths are relative to it):
#   /home/mox/mox              the binary          /home/mox/mox.prev   rollback copy
#   /home/mox/config/          mox.conf, domains.conf, DKIM keys, host keys
#   /home/mox/data/            accounts, queue, report databases
#   /home/mox/.mox-buildstamp  "<upstream-commit> <series-hash>"
#   /root/cocx-quickstart.out  quickstart output incl. generated passwords (0600)

MOX_HOME=/home/mox
QUICKSTART_OUT=/root/cocx-quickstart.out

mox_installed() {
  rsh "test -f $MOX_HOME/config/mox.conf && test -x $MOX_HOME/mox" 2>/dev/null
}

# ------------------------------------------------------------------------- build
#
# mox's CheckUpdates is disabled on purpose: its updater watches tagged RELEASES and this
# tracks `main`, which runs ahead of them. Running cocx IS the update mechanism, so the
# check has to be cheap or people stop running it: compare upstream main and our series
# hash against the stamp, and skip the ~2 minute build when both match.
#
# `mox version` cannot answer this. Built from a source tree it reports
# "(devel)-go1.x.y" with no commit, and it could never see a change to OUR patches.
mox_series_hash() { bash "$COCX_DIR/mox/build.sh" --series-hash; }

upstream_main() {
  curl -fsSL --max-time 20 https://api.github.com/repos/mjl-/mox/commits/main 2>/dev/null \
    | sed -nE 's/^  "sha": "([0-9a-f]{40})",?$/\1/p' | head -1
}

mox_needs_build() {
  if [ "${FORCE_BUILD:-0}" = "1" ]; then
    msg "FORCE_BUILD=1 — rebuilding regardless"
    return 0
  fi
  local upstream series stamp
  upstream="$(upstream_main)"
  series="$(mox_series_hash)"
  stamp="$(rsh_q "cat $MOX_HOME/.mox-buildstamp" | head -1)"
  if [ -z "$upstream" ]; then
    msg "could not reach GitHub for the upstream commit — building to be safe"
    return 0
  fi
  if [ "${stamp%% *}" = "$upstream" ] && [ "${stamp##* }" = "$series" ]; then
    msg "mox already current (upstream ${upstream:0:12}, series $series) — skipping rebuild"
    return 1
  fi
  msg "mox rebuild needed: upstream ${stamp:0:12}->${upstream:0:12}, series ${stamp##* }->$series"
  return 0
}

# Builds as the mox user into /home/mox/patchsrc/out/mox, then installs as mox.new. A
# failed build (an upstream rebase conflict, a control failure) therefore never leaves a
# broken binary where a working mail server was; the caller swaps mox.new in only after
# `mox config test` passes.
build_mox() {
  msg "Building patched mox (upstream main + OpenPGP series) on the host..."
  ship "$COCX_DIR/mox" "$MOX_HOME/patchsrc" build.sh tools src patches
  rsh "chown -R mox:mox $MOX_HOME/patchsrc"

  rsh 'bash -s' <<'EOS'
set -e
export PATH=/usr/local/go/bin:/usr/local/bin:$PATH GOPATH=/home/mox/go GOCACHE=/home/mox/.cache/go-build CGO_ENABLED=0
install -d -o mox -g mox /home/mox "$GOPATH" "$GOCACHE"
# cd somewhere the mox user can stat: runuser keeps root's cwd (/root, mode 700) and the
# Go toolchain calls getcwd() first, failing with "cannot determine current directory:
# permission denied" — which reads like a Go or network problem.
cd /home/mox/patchsrc
runuser -u mox -- env PATH="$PATH" GOPATH="$GOPATH" GOCACHE="$GOCACHE" CGO_ENABLED=0 \
  HOME=/home/mox npm_config_cache=/home/mox/.npm MOX_BUILD_DIR=/home/mox/.build \
  bash /home/mox/patchsrc/build.sh
[ -x /home/mox/patchsrc/out/mox ] || { echo "build produced no binary"; exit 1; }
install -o mox -g mox -m 750 /home/mox/patchsrc/out/mox /home/mox/mox.new
EOS

  # Written only after a binary exists, so an interrupted build cannot make the next run
  # believe it is current.
  local stamp
  stamp="$(rsh_q "cat $MOX_HOME/patchsrc/out/mox.buildstamp" | head -1)"
  [ -n "$stamp" ] || die "patched mox build produced no build stamp"
  rsh "printf '%s\n' '$stamp' > $MOX_HOME/.mox-buildstamp.new"
  msg "built patched mox — stamp: $stamp"
}

# Swap mox.new into place, keeping the previous binary as mox.prev for rollback. The stamp
# moves with the binary: a failed swap must not record a build that is not running.
swap_mox_binary() {
  msg "Swapping in the new binary..."
  rsh "bash -s" <<'EOS'
set -e
cd /home/mox
if [ ! -f mox.new ]; then echo "    no mox.new produced — keeping the running binary"; exit 0; fi
[ -f mox ] && cp -a mox mox.prev
mv -f mox.new mox
if [ -f config/mox.conf ] && ! ./mox config test >/dev/null; then
  echo "    !! new binary rejects the current config — restoring the previous binary"
  [ -f mox.prev ] && mv -f mox.prev mox
  rm -f .mox-buildstamp.new
  exit 1
fi
[ -f .mox-buildstamp.new ] && mv -f .mox-buildstamp.new .mox-buildstamp
echo "    swapped (previous binary kept as mox.prev)"
EOS
}

rollback_mox() {
  msg "Rolling back to mox.prev..."
  rsh 'bash -s' <<'EOS'
set -e
cd /home/mox
[ -f mox.prev ] || { echo "no mox.prev to roll back to"; exit 1; }
mv -f mox mox.bad && mv -f mox.prev mox
./mox config test >/dev/null
# The stamp described the build we just removed; clear it so the next run rebuilds.
rm -f .mox-buildstamp
systemctl restart mox
echo "    rolled back; the failed binary is kept as mox.bad"
EOS
}

# ------------------------------------------------------------- first-time config
quickstart() {
  msg "Running mox quickstart for $MAIL_ACCOUNT ($WEBSERVER mode)..."
  local ew=""
  [ "$WEBSERVER" != "mox" ] && ew="-existing-webserver"
  rsh "MAIL_HOSTNAME='$MAIL_HOSTNAME' MAIL_ACCOUNT='$MAIL_ACCOUNT' EW='$ew' OUT='$QUICKSTART_OUT' bash -s" <<'EOS'
set -e
cd /home/mox
[ -f mox.new ] && mv -f mox.new mox && { [ -f .mox-buildstamp.new ] && mv -f .mox-buildstamp.new .mox-buildstamp || true; }
if [ -f config/mox.conf ]; then echo "    config exists — skipping quickstart"; exit 0; fi
umask 077
# -skipdial: on a fresh box outbound :25 is often still blocked by the provider, and the
# connectivity probe would hang rather than fail.
# shellcheck disable=SC2086
./mox quickstart $EW -skipdial -hostname "$MAIL_HOSTNAME" "$MAIL_ACCOUNT" mox > "$OUT" 2>&1 \
  || { echo "    quickstart FAILED:"; tail -20 "$OUT" | sed 's/^/      /'; exit 1; }
chmod 600 "$OUT"
echo "    quickstart output (contains generated passwords) -> $OUT"
EOS
}

# Where mox reads TLS material from in the Caddy modes.
caddy_cert_dir() {
  if [ "$WEBSERVER" = "caddy-external" ]; then
    printf '%s' "$CADDY_CERT_DIR"
    return
  fi
  local base=/var/lib/caddy/.local/share/caddy/certificates
  case "$CADDY_ISSUER" in
    letsencrypt)         printf '%s' "$base/acme-v02.api.letsencrypt.org-directory" ;;
    letsencrypt-staging) printf '%s' "$base/acme-staging-v02.api.letsencrypt.org-directory" ;;
    internal)            printf '%s' "$base/local" ;;
  esac
}

# Rewrite the parts of mox.conf quickstart cannot know. Every edit is idempotent and
# config-tested; the previous file is kept as mox.conf.bak-<time>.
configure_mox() {
  msg "Configuring mox.conf ($WEBSERVER mode)..."
  rsh "MODE='$WEBSERVER' CERTD='$(caddy_cert_dir)' H='$MAIL_HOSTNAME' D='$MAIL_DOMAIN' \
       PUBLIC_WEBMAIL='$PUBLIC_WEBMAIL' bash -s" <<'EOS'
set -e
cd /home/mox/config
[ -f mox.conf ] || { echo "    no mox.conf — run the install first"; exit 1; }
cp -a mox.conf mox.conf.new
python3 - "$MODE" "$CERTD" "$H" "$D" "$PUBLIC_WEBMAIL" <<'PY'
import re, sys
mode, certd, host, dom, public_webmail = sys.argv[1:6]
p = '/home/mox/config/mox.conf.new'
s = open(p).read()

if mode != 'mox':
    # quickstart writes "path/to/<host>-chain.crt.pem" placeholders. Point them at the
    # certificates Caddy manages for these same hostnames. Caddy's .crt holds the chain.
    for h in (host, f'mta-sts.{dom}', f'autoconfig.{dom}', f'mail.{dom}'):
        s = s.replace(f'path/to/{h}-chain.crt.pem', f'{certd}/{h}/{h}.crt')
        s = s.replace(f'path/to/{h}.key.pem',       f'{certd}/{h}/{h}.key')

# KEEP quickstart's IPv6 listen address. Removing it does not stop mox sending over v6
# (with one family configured, mox still uses BOTH outbound); it only stops the v6 address
# being DECLARED — and then mail leaves from an address in neither SPF nor rDNS. That
# fails spf on every v6-sent message, visible only in DMARC aggregate reports, while DKIM
# alignment keeps DMARC passing so nothing bounces. Measured, not theorised.

# debug logs every internet scanner that touches the HTTP listeners.
s = s.replace('\nLogLevel: debug\n', '\nLogLevel: info\n')

# Public webmail/account/webapi in mox mode: enabled on the PUBLIC listener so they are
# served over mox's own ACME TLS. In the Caddy modes Caddy proxies the internal :1080
# listener instead, so nothing changes here. Admin is never made public.
def public_block(s):
    m = re.search(r'^\tpublic:\n((?:\t\t.*\n|\n)*)', s, re.M)
    return m
if mode == 'mox':
    m = public_block(s)
    if not m:
        sys.exit('mox.conf has no public listener')
    body = m.group(1)
    wanted = {'AccountHTTPS': '/account/', 'WebmailHTTPS': '/webmail/', 'WebAPIHTTPS': '/webapi/'}
    for key, path in wanted.items():
        has = re.search(rf'^\t\t{key}:\n', body, re.M)
        if public_webmail == 'yes' and not has:
            body += f'\t\t{key}:\n\t\t\tEnabled: true\n\t\t\tPath: {path}\n'
        elif public_webmail != 'yes' and has:
            body = re.sub(rf'^\t\t{key}:\n(?:\t\t\t.*\n)*', '', body, flags=re.M)
    s = s[:m.start(1)] + body + s[m.end(1):]
open(p, 'w').write(s)
PY
chown mox:mox mox.conf.new; chmod 600 mox.conf.new
if cmp -s mox.conf mox.conf.new; then rm -f mox.conf.new; echo "    unchanged"; exit 0; fi
cp -a mox.conf "mox.conf.bak-$(date +%Y%m%d-%H%M%S)"
mv -f mox.conf.new mox.conf
cd /home/mox && ./mox config test >/dev/null && echo "    updated; config test OK"
EOS
}

# ------------------------------------------------------------------------ DANE
#
# DANE pins the SHA-256 of the TLS public key in DNS, so the key MUST be stable — once a
# TLSA is published and the zone is signed, a mismatch does not degrade, DANE-enforcing
# senders simply refuse the mail.
#
#   mox mode    mox's own host keys (config/hostkeys/, RSA + ECDSA) are used for ACME
#               certificates and never rotate. Nothing to do here.
#   caddy modes Caddy owns the key. The vhost sets `reuse_private_keys` (Caddy >= 2.8) so
#               renewal keeps it. mox opens HostPrivateKeyFiles as the UNPRIVILEGED mox
#               user (unlike KeyCerts, which root opens), and Caddy's key is 0600 to the
#               caddy user — so mox would get EPERM and refuse to START. Hence a mox-owned
#               copy, re-synced by the cert-watch unit whenever the certificate changes.
#               An ACL would be wiped the moment Caddy rewrites the file.
setup_dane() {
  [ "$WEBSERVER" = "mox" ] && return 0
  msg "Configuring DANE host key (mox-readable copy of Caddy's stable key)..."
  rsh "CERTD='$(caddy_cert_dir)' MH='$MAIL_HOSTNAME' bash -s" <<'DANEEOF'
set -e
cat > /usr/local/sbin/cocx-sync-hostkey <<SYNC
#!/usr/bin/env bash
# Copy the web server's mail TLS private key where mox (unprivileged) can read it, for
# DANE, then restart mox so it serves the renewed certificate. Correct only because the
# key is reused across renewals (Caddy reuse_private_keys). Installed by cocx.
set -euo pipefail
SRC="${CERTD}/${MH}/${MH}.key"
DST=/home/mox/config/dane-mail.key
[ -s "\$SRC" ] || { echo "cocx-sync-hostkey: source key missing: \$SRC" >&2; exit 1; }
if ! { [ -f "\$DST" ] && cmp -s "\$SRC" "\$DST"; }; then
  install -o mox -g mox -m 600 "\$SRC" "\$DST"
  echo "cocx-sync-hostkey: refreshed \$DST"
fi
systemctl restart mox
SYNC
chmod 755 /usr/local/sbin/cocx-sync-hostkey
SRC="${CERTD}/${MH}/${MH}.key"
if [ -s "$SRC" ]; then
  install -o mox -g mox -m 600 "$SRC" /home/mox/config/dane-mail.key
else
  echo "    (certificate not present yet — the key syncs on first issuance)"
fi

# Comment-aware: mox.conf documents every option in comments, so a plain substring test
# always reports "already configured".
python3 - <<'PYEOF'
import re
p = '/home/mox/config/mox.conf'
s = open(p).read()
active = [l for l in s.splitlines() if 'HostPrivateKeyFiles' in l and not l.lstrip().startswith('#')]
if active:
    print("    HostPrivateKeyFiles already configured")
else:
    m = re.search(r'^\t\tSMTP:$', s, re.M)
    if not m:
        raise SystemExit("no public SMTP listener in mox.conf")
    # HostPrivateKeyFiles is a CHILD of TLS (3 tabs), a sibling of KeyCerts — NOT of the
    # listener. At 2 tabs mox rejects it: unknown key "HostPrivateKeyFiles". TLS is the
    # block immediately before SMTP in quickstart's output.
    s = s[:m.start()] + "\t\t\tHostPrivateKeyFiles:\n\t\t\t\t- /home/mox/config/dane-mail.key\n" + s[m.start():]
    open(p, 'w').write(s)
    print("    HostPrivateKeyFiles configured")
PYEOF
chown mox:mox /home/mox/config/mox.conf; chmod 600 /home/mox/config/mox.conf
if [ -s /home/mox/config/dane-mail.key ]; then
  cd /home/mox && ./mox config test >/dev/null && echo "    mox config OK"
fi
DANEEOF
}

# --------------------------------------------------------------------- systemd
install_units() {
  msg "Installing systemd units..."
  rsh "MODE='$WEBSERVER' CERTD='$(caddy_cert_dir)' H='$MAIL_HOSTNAME' bash -s" <<'EOS'
set -e
# quickstart writes mox.service next to the binary; it is the upstream-maintained unit,
# with its sandboxing, so it is used as-is rather than re-authored.
[ -f /home/mox/mox.service ] && install -m644 /home/mox/mox.service /etc/systemd/system/mox.service

if [ "$MODE" != "mox" ]; then
  # Caddy renews certificates in place; mox reads them only at startup. Without this,
  # mail TLS silently serves an expired certificate ~60 days after the last restart.
  # The key is re-synced BEFORE the restart (DANE copy; see setup_dane).
  cat > /etc/systemd/system/mox-certwatch.service <<UNIT
[Unit]
Description=Re-sync the DANE key and restart mox when the web server renews its certificate
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cocx-sync-hostkey
UNIT
  cat > /etc/systemd/system/mox-certwatch.path <<UNIT
[Unit]
Description=Watch the mox TLS certificate for renewal
[Path]
PathChanged=${CERTD}/${H}/${H}.crt
[Install]
WantedBy=multi-user.target
UNIT
else
  systemctl disable --now mox-certwatch.path 2>/dev/null || true
  rm -f /etc/systemd/system/mox-certwatch.path /etc/systemd/system/mox-certwatch.service
fi
systemctl daemon-reload
systemctl enable mox >/dev/null 2>&1
if [ "$MODE" != "mox" ]; then systemctl enable --now mox-certwatch.path >/dev/null 2>&1; fi
EOS
}

restart_mox() {
  rsh 'cd /home/mox && ./mox config test >/dev/null && systemctl restart mox && sleep 2 && systemctl is-active --quiet mox' \
    || die "mox failed to (re)start — journalctl -u mox -n 50 on $HOST"
}

# ------------------------------------------------------------------ addresses
#
# postmaster@ needs nothing: mox routes it natively via mox.conf `Postmaster: Account:`.
# abuse@ has no such special case and is the address blocklist operators and feedback
# loops actually write to; when it bounces, a complaint that could have been a
# conversation becomes a listing instead.
#
# Testing these: mox answers `250` to RCPT for EVERY address and rejects unknown ones at
# DATA, so an RCPT-only probe proves nothing. Carry a known-bogus control through DATA.
ensure_role_addresses() {
  [ -n "${ROLE_ADDRESSES:-}" ] || return 0
  msg "Ensuring role addresses: $ROLE_ADDRESSES..."
  # `mox config address add` goes through the RUNNING server's control socket; with mox
  # stopped it fails ("connect: no such file") — so mox must be up, and a failure is fatal.
  rsh "DOM='$MAIL_DOMAIN' ACCT='${MAIL_ACCOUNT%%@*}' ROLES='$ROLE_ADDRESSES' bash -s" <<'EOS'
set -e
cd /home/mox
systemctl is-active --quiet mox || { echo "    mox is not running — cannot add addresses"; exit 1; }
for lp in $ROLES; do
  addr="$lp@$DOM"
  # Match as a Destinations key, so a substring elsewhere (a comment, another domain)
  # cannot read as "already configured".
  if grep -qE "^[[:space:]]*${addr//./\\.}:" config/domains.conf; then
    echo "    exists  $addr"
  else
    ./mox config address add "$addr" "$ACCT" >/dev/null
    echo "    created $addr -> $ACCT"
  fi
done
./mox config test >/dev/null
EOS
}

# MTA-STS MaxAge. quickstart writes 24h — right while a setup is moving, too short after.
#
# ⚠ ORDER IS LOAD-BEARING (mox's docs are explicit): change the POLICY first (config +
# restart, so /.well-known/mta-sts.txt serves it), then the DNS record. Every policy change
# needs a NEW PolicyID — the version string senders compare to decide whether to refetch.
# The DNS sync runs after this, so the ordering holds.
ensure_mtasts_maxage() {
  msg "Ensuring MTA-STS MaxAge = $MTASTS_MAXAGE..."
  rsh "WANT='$MTASTS_MAXAGE' bash -s" <<'EOS'
set -e
cd /home/mox/config
cur=$(grep -vE '^\s*#' domains.conf | grep -oP '(?<=MaxAge: )\S+' | head -1)
if [ "$cur" = "$WANT" ]; then echo "    already $WANT"; exit 0; fi
cp -a domains.conf "domains.conf.bak-$(date +%Y%m%d-%H%M%S)"
NEWID=$(date -u +%Y%m%dT%H%M%S)
python3 - "$WANT" "$NEWID" <<'PY'
import re, sys
want, newid = sys.argv[1], sys.argv[2]
p = '/home/mox/config/domains.conf'
s = open(p).read()
s, n1 = re.subn(r'(\n\t+MaxAge: )\S+', r'\g<1>' + want, s, count=1)
s, n2 = re.subn(r'(\n\t+PolicyID: )\S+', r'\g<1>' + newid, s, count=1)
if not (n1 and n2):
    raise SystemExit("no MTASTS MaxAge/PolicyID in domains.conf")
open(p, 'w').write(s)
print(f"    MaxAge {want}, PolicyID {newid}")
PY
chown mox:mox domains.conf; chmod 600 domains.conf
cd /home/mox && ./mox config test >/dev/null
EOS
}

# mox-mode web handlers, all named cocx-* and fully reconciled on every run: handlers
# cocx owns are removed and the wanted set re-added, so changing BIMI_LOGO or
# ROOT_REDIRECT never stacks duplicates. Handlers the operator added are left alone.
#   cocx-bimi   https://MAIL_HOSTNAME/bimi/*  static, from /home/mox/web/bimi
#   cocx-rootN  exactly "/" on each mail hostname -> ROOT_REDIRECT, or -> /webmail/ on
#               the mail hostname itself when PUBLIC_WEBMAIL=yes
# The Caddy modes do the same in the Caddy vhost instead.
ensure_mox_web_handlers() {
  [ "$WEBSERVER" = "mox" ] || return 0
  msg "Reconciling mox web handlers (BIMI logo, root redirect)..."
  local roots="$MAIL_HOSTNAME mta-sts.$MAIL_DOMAIN autoconfig.$MAIL_DOMAIN"
  rsh "H='$MAIL_HOSTNAME' BIMI='${BIMI_LOGO:+yes}' ROOT='${ROOT_REDIRECT:-}' ROOTS='$roots' PW='$PUBLIC_WEBMAIL' bash -s" <<'EOS'
set -e
cd /home/mox/config
python3 - "$H" "$BIMI" "$ROOT" "$ROOTS" "$PW" <<'PY'
import re, sys
host, bimi, root, roots, public_webmail = sys.argv[1:6]
p = '/home/mox/config/domains.conf'
s = open(p).read()

def handler(lines):
    return "\t-\n" + "".join(f"\t\t{l}\n" for l in lines)

want = []
if bimi:
    want.append(handler([
        "LogName: cocx-bimi", f"Domain: {host}", "PathRegexp: ^/bimi/",
        "WebStatic:", "\tStripPrefix: /bimi/", "\tRoot: /home/mox/web/bimi",
        # Map keys in mox's canonical (sorted) order: mox re-serializes domains.conf on
        # any config command, and any other order makes every run see a "change".
        "\tResponseHeaders:", "\t\tCache-Control: public, max-age=86400",
        "\t\tContent-Type: image/svg+xml"]))
for i, h in enumerate(roots.split()):
    target = "/webmail/" if (public_webmail == "yes" and h == host) else root
    if not target:
        continue
    if target.startswith("http"):
        redirect = ["WebRedirect:", f"\tBaseURL: {target}", "\tStatusCode: 301"]
    else:
        redirect = ["WebRedirect:", "\tOrigPathRegexp: ^/$", f"\tReplacePath: {target}", "\tStatusCode: 302"]
    want.append(handler([f"LogName: cocx-root{i}", f"Domain: {h}", "PathRegexp: ^/$"] + redirect))

m = re.search(r'^WebHandlers:\n((?:\t.*\n|\n)*)', s, re.M)
items = re.findall(r'\t-\n(?:\t\t.*\n)*', m.group(1)) if m else []
keep = [it for it in items if not re.search(r'^\t\tLogName: cocx-', it, re.M)]
section = "".join(keep + want)
block = ("WebHandlers:\n" + section) if section else ""
if m:
    new = s[:m.start()] + block + s[m.end():]
else:
    new = s.rstrip("\n") + "\n" + block
if new != s:
    open(p + ".new", "w").write(new)
    print("    changed")
else:
    print("    unchanged")
PY
if [ -f domains.conf.new ]; then
  cp -a domains.conf "domains.conf.bak-$(date +%Y%m%d-%H%M%S)"
  mv -f domains.conf.new domains.conf
  chown mox:mox domains.conf; chmod 600 domains.conf
fi
cd /home/mox && ./mox config test >/dev/null
EOS
}

# The account password quickstart generated, for the junk filter's IMAP login. Read on
# the host; never printed, never copied off the box.
seed_filter_credentials() {
  msg "Seeding junk-filter credentials (/etc/cocx/mail-filter.env)..."
  rsh "ACCT='$MAIL_ACCOUNT' H='$MAIL_HOSTNAME' Q='$QUICKSTART_OUT' bash -s" <<'EOS'
set -e
E=/etc/cocx/mail-filter.env
install -d -m 700 /etc/cocx
if [ -s "$E" ] && grep -q '^MOX_ACCOUNT_PASSWORD=.' "$E"; then
  sed -i "s|^MOX_IMAP_HOST=.*|MOX_IMAP_HOST=$H|; s|^MOX_ACCOUNT=.*|MOX_ACCOUNT=$ACCT|" "$E"
  echo "    already seeded"; exit 0
fi
[ -f "$Q" ] || { echo "    !! no $Q — set MOX_ACCOUNT_PASSWORD in $E by hand"; exit 0; }
CP=$(grep -oP '(?<=account password for )[^:]+: \K.*' "$Q" | head -1)
[ -n "$CP" ] || { echo "    !! account password not found in $Q"; exit 0; }
umask 077
# systemd EnvironmentFile syntax, written for systemd only: NEVER `source` this file in a
# shell — generated passwords can contain '#', which a shell truncates as a comment and
# which then fails as an IMAP auth error with nothing pointing at quoting.
{
  echo "MOX_ACCOUNT=$ACCT"
  echo "MOX_ACCOUNT_PASSWORD=$CP"
  echo "MOX_IMAP_HOST=$H"
  echo "MOX_IMAP_PORT=993"
} > "$E"
chmod 600 "$E"
echo "    seeded"
EOS
}
