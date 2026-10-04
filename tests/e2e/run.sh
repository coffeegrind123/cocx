#!/usr/bin/env bash
# shellcheck disable=SC2016  # check commands are single-quoted on purpose: they expand IN the container
# End-to-end: install cocx for real inside a systemd Debian container (HOST=local), then
# assert on the RUNNING system — units, TLS on the wire, DANE key identity, web routing,
# backups, the filter — and re-run to prove the update path is idempotent.
#
#   tests/e2e/run.sh caddy     # WEBSERVER=caddy, Caddy internal CA
#   tests/e2e/run.sh mox       # WEBSERVER=mox (ACME cannot succeed offline; TLS checks skip)
#
# Public DNS cannot point at a container, so DNS_PROVIDER=none and the hostnames resolve
# through /etc/hosts. Everything else is the production code path.
set -uo pipefail

MODE="${1:-caddy}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAME="cocx-e2e-$MODE"
IMAGE=cocx-e2e
pass=0
fail=0

ok_()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad_() { fail=$((fail + 1)); echo "  FAIL  $1"; }
say() { printf '\n\033[36m== %s\033[0m\n' "$*"; }
cx() { docker exec "$NAME" bash -c "$*" </dev/null; }
cxi() { docker exec -i "$NAME" bash -c "$*"; }  # with stdin, for heredoc writes
check() { # name, command (run in the container)
  local name="$1"
  shift
  if out="$(cx "$*" 2>&1)"; then
    pass=$((pass + 1)); echo "  ok    $name"
  else
    fail=$((fail + 1)); echo "  FAIL  $name"; printf '%s\n' "$out" | tail -6 | sed 's/^/        /'
  fi
}

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -q -t "$IMAGE" - < "$ROOT/tests/e2e/Dockerfile"
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock --dns 1.1.1.1 "$IMAGE" >/dev/null
for _ in $(seq 1 30); do cx 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"' && break; sleep 1; done

say "staging cocx ($MODE mode)"
tar -C "$ROOT" --exclude=./tests/.cache --exclude=./.git -cz . | docker exec -i "$NAME" bash -c 'mkdir -p /opt/cocx-src && tar -C /opt/cocx-src -xz'
cx 'ip=$(ip -4 route get 1.1.1.1 | grep -oP "(?<=src )\S+"); echo "$ip mail.example.com mta-sts.example.com autoconfig.example.com" >> /etc/hosts'
cxi "cat > /opt/cocx-src/tests/e2e/logo.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>Example</title><rect x="0" y="0" width="100" height="100" fill="#fff"/><circle cx="50" cy="50" r="30" fill="#c00"/></svg>
EOF
cxi "cat > /opt/cocx-src/cocx.conf" <<EOF
MAIL_DOMAIN=example.com
MAIL_HOSTNAME=mail.example.com
MAIL_ACCOUNT=admin@example.com
HOST=local
WEBSERVER=$MODE
CADDY_ISSUER=internal
PUBLIC_WEBMAIL=yes
ROOT_REDIRECT=https://www.example.com/
DNS_PROVIDER=none
BIMI_LOGO=/opt/cocx-src/tests/e2e/logo.svg
EOF

say "install"
docker exec "$NAME" bash -c 'cd /opt/cocx-src && ./cocx install' 2>&1 | tee "/tmp/$NAME-install.log" | grep -E '^(==>|!!|ERROR)'
# The health check fails on DNS/PTR/outbound facts no container can satisfy; the install
# itself must still have completed.
if grep -q 'Install complete' "/tmp/$NAME-install.log"; then
  ok_ "install completed"
else
  bad_ "install did not complete (/tmp/$NAME-install.log)"
fi

say "assertions"
check "mox active"                  'systemctl is-active --quiet mox'
check "mox config test"             'cd /home/mox && ./mox config test'
check "build stamp recorded"        'grep -qE "^[0-9a-f]{40} [0-9a-f]{12}$" /home/mox/.mox-buildstamp'
check "quickstart output is 0600"   '[ "$(stat -c %a /root/cocx-quickstart.out)" = 600 ]'
check "abuse@ routed"               'grep -qE "^\s*abuse@example\.com:" /home/mox/config/domains.conf'
check "MTA-STS MaxAge one week"     'grep -vE "^\s*#" /home/mox/config/domains.conf | grep -q "MaxAge: 168h0m0s"'
check "LogLevel info"               'grep -q "^LogLevel: info" /home/mox/config/mox.conf'
check "unbound active"              'systemctl is-active --quiet unbound'
check "listening :25 :465 :993"     'for p in 25 465 993; do ss -Hlnt | grep -q ":$p "; done'
check "filter timer active"         'systemctl is-active --quiet cocx-mail-filter.timer'
check "filter credentials 0600"     '[ "$(stat -c %a /etc/cocx/mail-filter.env)" = 600 ] && grep -q "^MOX_ACCOUNT_PASSWORD=." /etc/cocx/mail-filter.env'
check "backup timer active"         'systemctl is-active --quiet cocx-backup.timer'
check "backup runs + verifies"      '/usr/local/sbin/cocx-backup >/dev/null && ls /var/backups/mox/daily/*.tar.gz'
check "backup is 0600, dir 0700"    'f=$(ls -t /var/backups/mox/daily/*.tar.gz | head -1); [ "$(stat -c %a "$f")" = 600 ] && [ "$(stat -c %a /var/backups/mox)" = 700 ]'

ip='$(ip -4 route get 1.1.1.1 | grep -oP "(?<=src )\S+")'
if [ "$MODE" = "caddy" ]; then
  CERTD=/var/lib/caddy/.local/share/caddy/certificates/local
  check "caddy active"              'systemctl is-active --quiet caddy'
  check "cert-watch path active"    'systemctl is-active --quiet mox-certwatch.path'
  check "mox.conf points at Caddy"  "grep -q '$CERTD/mail.example.com/mail.example.com.crt' /home/mox/config/mox.conf"
  # mox normalises its config dir to mox:root 0640 at startup; private either way.
  check "DANE key copy mox-owned, private" '[ "$(stat -c %U /home/mox/config/dane-mail.key)" = mox ] && [ $(( 0$(stat -c %a /home/mox/config/dane-mail.key) & 7 )) = 0 ]'
  check "DANE key == Caddy key"     "cmp -s $CERTD/mail.example.com/mail.example.com.key /home/mox/config/dane-mail.key"
  check "SMTP STARTTLS serves Caddy's key (TLSA would match)" \
    "a=\$(echo QUIT | timeout 10 openssl s_client -connect $ip:25 -starttls smtp -servername mail.example.com 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -c1-64); \
     b=\$(openssl pkey -in $CERTD/mail.example.com/mail.example.com.key -pubout -outform DER | sha256sum | cut -c1-64); e=\$(printf \"\" | sha256sum | cut -c1-64); [ \"\$a\" != \"\$e\" ] && [ \"\$a\" = \"\$b\" ]"
  check "TLSA emitted for that key" \
    "b=\$(openssl pkey -in $CERTD/mail.example.com/mail.example.com.key -pubout -outform DER | sha256sum | cut -c1-64); cd /home/mox && ./mox config dnsrecords example.com 2>/dev/null | grep -i \"TLSA 3 1 1 \$b\""
  check "webmail served publicly"   'curl -sk --resolve mail.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code}" https://mail.example.com/webmail/ | grep -q 200'
  check "admin refused publicly"    'curl -sk --resolve mail.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code}" https://mail.example.com/admin/ | grep -q 404'
  check "/ -> /webmail/"            'curl -sk --resolve mail.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code} %{redirect_url}" https://mail.example.com/ | grep -q "302 https://mail.example.com/webmail/"'
  check "MTA-STS policy via Caddy"  'curl -sk --resolve mta-sts.example.com:443:127.0.0.1 https://mta-sts.example.com/.well-known/mta-sts.txt | grep -q "mode: enforce"'
  check "mta-sts / redirects away"  'curl -sk --resolve mta-sts.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code} %{redirect_url}" https://mta-sts.example.com/ | grep -q "301 https://www.example.com/"'
  check "autoconfig XML served"     'curl -sk --resolve autoconfig.example.com:443:127.0.0.1 "https://autoconfig.example.com/mail/config-v1.1.xml?emailaddress=admin@example.com" | grep -q "<incomingServer"'
  check "BIMI logo is image/svg+xml" 'curl -sk --resolve mail.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code} %{content_type}" https://mail.example.com/bimi/logo.svg | grep -q "^200 image/svg+xml"'
  check "OpenPGP lib served by webmail" 'curl -sk --resolve mail.example.com:443:127.0.0.1 -o /dev/null -w "%{http_code}" https://mail.example.com/webmail/openpgp.js | grep -q 200'
  # The filter verifies TLS; trust Caddy's internal root for this run only.
  cx 'cp /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt /usr/local/share/ca-certificates/caddy-local.crt && update-ca-certificates >/dev/null 2>&1; grep -q NODE_EXTRA_CA_CERTS /etc/cocx/mail-filter.env || echo NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt >> /etc/cocx/mail-filter.env'
  check "junk filter sweeps over IMAP" 'systemctl start cocx-mail-filter.service && journalctl -u cocx-mail-filter --no-pager | grep -q "mail-filter\] applied"'
else
  check "no cert-watch in mox mode" '! systemctl is-enabled mox-certwatch.path 2>/dev/null'
  check "host keys generated"       'ls /home/mox/config/hostkeys/*ecdsap256* /home/mox/config/hostkeys/*rsa2048*'
  check "public webmail on listener" 'grep -P -A2 "^\t\tWebmailHTTPS:" /home/mox/config/mox.conf | grep -q "Enabled: true"'
  check "cocx web handlers present" 'grep -c "LogName: cocx-" /home/mox/config/domains.conf | grep -qE "^[4-9]"'
  check "BIMI file served by mox path" 'test -s /home/mox/web/bimi/logo.svg && [ "$(stat -c %U /home/mox/web/bimi/logo.svg)" = mox ]'
  # Offline there is no ACME certificate, so prove ROUTING over plain HTTP instead: a
  # matched handler answers 308 (upgrade to https); an unmatched path is the 404 control.
  check "BIMI handler routes (308 vs 404 control)" \
    "[ \"\$(curl -s -o /dev/null -w %{http_code} --resolve mail.example.com:80:$ip http://mail.example.com/bimi/logo.svg)\" = 308 ] && \
     [ \"\$(curl -s -o /dev/null -w %{http_code} --resolve mail.example.com:80:$ip http://mail.example.com/nope-control)\" = 404 ]"
  check "mox binds :80 and :443"    'ss -Hlntp | grep -E ":(80|443) " | grep -q mox'
  check "two TLSA (RSA + ECDSA)"    'cd /home/mox && [ "$(./mox config dnsrecords example.com 2>/dev/null | grep -c "TLSA 3 1 1")" = 2 ]'
fi

say "idempotent update (second run must not restart mox or rewrite config)"
cx 'systemctl show -p MainPID --value mox' > "/tmp/$NAME-pid1"
cx 'md5sum /home/mox/config/mox.conf /home/mox/config/domains.conf /etc/caddy/cocx-mail.caddy 2>/dev/null' > "/tmp/$NAME-sum1"
docker exec "$NAME" bash -c 'cd /opt/cocx-src && ./cocx update' > "/tmp/$NAME-update.log" 2>&1
if grep -q 'mox already current' "/tmp/$NAME-update.log"; then
  ok_ "rebuild skipped (stamp current)"
else
  bad_ "update rebuilt despite a current stamp"
fi
cx 'systemctl show -p MainPID --value mox' > "/tmp/$NAME-pid2"
cx 'md5sum /home/mox/config/mox.conf /home/mox/config/domains.conf /etc/caddy/cocx-mail.caddy 2>/dev/null' > "/tmp/$NAME-sum2"
if cmp -s "/tmp/$NAME-pid1" "/tmp/$NAME-pid2"; then
  ok_ "mox not restarted"
else
  bad_ "mox restarted on a no-op update"
fi
if cmp -s "/tmp/$NAME-sum1" "/tmp/$NAME-sum2"; then
  ok_ "config files unchanged"
else
  bad_ "a no-op update changed config"
  diff "/tmp/$NAME-sum1" "/tmp/$NAME-sum2"
fi

say "restore round-trip"
check "restore dry run changes nothing" 'cd /opt/cocx-src && a=$(ls -t /var/backups/mox/daily/*.tar.gz | head -1) && ./cocx restore "$a" | grep -q "dry run" && ! ls -d /home/mox/restore-aside-* 2>/dev/null'
check "restore --yes restores + keeps old state" 'cd /opt/cocx-src && a=$(ls -t /var/backups/mox/daily/*.tar.gz | head -1) && ./cocx restore "$a" --yes && systemctl is-active --quiet mox && ls -d /home/mox/restore-aside-*/config'
check "rollback to mox.prev" 'cd /opt/cocx-src && cp -a /home/mox/mox /home/mox/mox.prev && ./cocx rollback && systemctl is-active --quiet mox && test -f /home/mox/mox.bad'

echo
echo "$MODE: $pass passed, $fail failed  (logs: /tmp/$NAME-install.log /tmp/$NAME-update.log; container $NAME left running)"
[ "$fail" = 0 ]
