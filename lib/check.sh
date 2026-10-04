# shellcheck shell=bash
# `cocx check` — every fact that can silently break mail, checked from OUTSIDE where it
# matters (DoH for DNS, a live handshake for TLS), with a specific fix on every failure.
#
# Rules this file follows, each paid for:
#   * Every remote probe that answers through its exit code goes through rsh_q. Under
#     `set -e` + `pipefail` a bare `systemctl is-failed` (exit 1 on a HEALTHY unit)
#     aborted the check mid-way and silently swallowed every line after it.
#   * Zero is not a pass. A timer that is active but has completed zero runs means the
#     job never succeeds — that printed ✓ for weeks once, while the unit failed every run.
#   * Public DNS facts come over DoH: a local resolver caches negative answers for the
#     SOA minimum and turns "just published" into a false alarm.

CHECK_FAIL=0
ok()   { printf '  %-18s %s ✓\n' "$1" "$2"; }
bad()  { printf '  %-18s %s\n' "$1" "$2" >&2; CHECK_FAIL=1; }
note() { printf '  %-18s %s\n' "$1" "$2"; }

health_check() {
  CHECK_FAIL=0
  msg "Health check ($HOST, $WEBSERVER mode)..."

  # --- services ---------------------------------------------------------------
  local st
  st="$(rsh_q 'systemctl is-active mox')"
  if [ "$st" = "active" ]; then
    ok "mox unit" "active"
  else
    bad "mox unit" "$st — journalctl -u mox -n 50"
  fi
  note "version" "$(rsh_q "cat $MOX_HOME/.mox-buildstamp" | awk '{print "upstream " substr($1,1,12) ", series " $2}')"
  if [ "$WEBSERVER" != "mox" ]; then
    st="$(rsh_q 'systemctl is-active mox-certwatch.path')"
    if [ "$st" = "active" ]; then
      ok "cert-watch" "active"
    else
      bad "cert-watch" "$st — mail TLS will expire ~60 days after the last restart (cocx update)"
    fi
  fi
  if [ "$WEBSERVER" = "caddy" ]; then
    st="$(rsh_q 'systemctl is-active caddy')"
    if [ "$st" = "active" ]; then
      ok "caddy" "active"
    else
      bad "caddy" "$st — journalctl -u caddy"
    fi
  fi
  local listening
  listening="$(rsh_q "ss -Hlnt | awk '{print \$4}' | grep -oE ':(25|465|993)\$' | sort -u | tr '\n' ' '")"
  for p in 25 465 993; do
    printf '%s' "$listening" | grep -q ":$p " || bad "listen :$p" "nothing listening — mox config or startup problem"
  done

  # --- addresses, PTR, IPv6 parity -------------------------------------------------
  local ip4 ip6 ptr aaaa
  ip4="$(host_ip4)"
  ip6="$(host_ip6)"
  ptr="$(doh "$(ptr_name "$ip4")" PTR | head -1)"
  if [ "${ptr%.}" = "$MAIL_HOSTNAME" ]; then
    ok "rDNS v4" "$ip4 -> ${ptr%.}"
  else
    bad "rDNS v4" "$ip4 -> '${ptr:-<none>}', want $MAIL_HOSTNAME — major receivers reject this (cocx set-rdns)"
  fi
  if doh "$MAIL_HOSTNAME" A | grep -qxF "$ip4"; then
    ok "A" "$MAIL_HOSTNAME -> $ip4"
  else
    bad "A" "$MAIL_HOSTNAME does not resolve to $ip4 (cocx dns)"
  fi

  # The v6 half fails SILENTLY: v4 keeps working and every other line stays green, while
  # each message sent over v6 fails SPF inside DMARC reports. All five parts or none.
  if [ -z "$ip6" ]; then
    if [ "${IPV6:-auto}" = "off" ] && rsh_q "ip -6 addr show scope global" | grep -q inet6; then
      bad "IPv6" "IPV6=off but the box HAS global v6 — mox will still send over it, undeclared"
    else
      note "IPv6" "none on host"
    fi
  else
    if rsh_q "ss -Hlnt | awk '{print \$4}'" | grep -qF "[$ip6]:25"; then
      ok "v6 listen :25" "yes"
    else
      bad "v6 listen :25" "no — mox sends from v6 but cannot receive on it"
    fi
    if doh_txt "$MAIL_DOMAIN" | grep -q "ip6:$ip6"; then
      ok "SPF ip6" "present"
    else
      bad "SPF ip6" "SPF lacks ip6:$ip6 — every v6-sent message fails SPF (cocx dns)"
    fi
    aaaa="$(doh "$MAIL_HOSTNAME" AAAA | head -1)"
    if [ "$aaaa" = "$ip6" ]; then
      ok "AAAA" "$aaaa"
    else
      bad "AAAA" "'${aaaa:-<none>}', want $ip6 — v6 rDNS is not forward-confirmed (cocx dns)"
    fi
    ptr="$(doh "$(ptr_name "$ip6")" PTR | head -1)"
    if [ "${ptr%.}" = "$MAIL_HOSTNAME" ]; then
      ok "rDNS v6" "${ptr%.}"
    else
      bad "rDNS v6" "'${ptr:-<none>}', want $MAIL_HOSTNAME — Google 550-5.7.25 (cocx set-rdns)"
    fi
  fi
  rsh_q 'getent hosts '"$ip4" | grep -qw "$MAIL_HOSTNAME" \
    || { rsh_q "grep -E '^${ip4//./\\.}[[:space:]]' /etc/hosts" | grep -q . \
         && bad "/etc/hosts" "a line for $ip4 overrides the PTR mox sees (cocx update fixes it)"; }

  # --- outbound :25 ---------------------------------------------------------------
  # A real banner, not an open socket: some hosts accept the TCP connect and drop data.
  if rsh_q "timeout 10 bash -c 'exec 3<>/dev/tcp/gmail-smtp-in.l.google.com/25 && head -c 3 <&3'" | grep -q '^220'; then
    ok "outbound :25" "open (220 from Google MX)"
  else
    bad "outbound :25" "BLOCKED — mail is received but never delivered; usually a provider default (cocx open-smtp)"
  fi

  # --- TLS: certificate + DANE -----------------------------------------------------
  local spki days
  spki="$(rsh_q "echo QUIT | timeout 15 openssl s_client -connect $ip4:25 -starttls smtp -servername $MAIL_HOSTNAME 2>/dev/null \
               | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl sha256 | awk '{print \$NF}'" | tr -d '\n')"
  days="$(rsh_q "echo QUIT | timeout 15 openssl s_client -connect $ip4:25 -starttls smtp -servername $MAIL_HOSTNAME 2>/dev/null \
               | openssl x509 -noout -enddate | cut -d= -f2" | tr -d '\n')"
  if [ -n "$days" ]; then
    days=$(( ( $(date -d "$days" +%s) - $(date +%s) ) / 86400 ))
    if [ "$days" -ge 14 ]; then
      ok "SMTP cert" "valid $days more days"
    else
      bad "SMTP cert" "expires in $days days — is renewal (and cert-watch) working?"
    fi
  else
    bad "SMTP cert" "no STARTTLS certificate on :25"
  fi

  local ad tlsa
  ad="$(rsh_q "dig $MAIL_DOMAIN. soa +dnssec | grep -c 'flags:.* ad'")"
  note "resolver" "unbound $(rsh_q 'systemctl is-active unbound')"
  if [ "${ad:-0}" = "1" ]; then
    ok "DNSSEC" "validated"
    # Once signed, the published TLSA MUST match the live key or DANE-enforcing senders
    # refuse mail. Any one published record matching is enough (mox mode publishes two).
    tlsa="$(doh "_25._tcp.$MAIL_HOSTNAME" TLSA | awk '{print tolower($NF)}')"
    if [ -z "$tlsa" ]; then
      bad "DANE TLSA" "zone is signed but no TLSA published (cocx dns)"
    elif printf '%s\n' "$tlsa" | grep -qxF "$spki"; then
      ok "DANE TLSA" "matches the live key"
    else
      bad "DANE TLSA" "MISMATCH — live key $spki is not published. DANE senders are REFUSING mail now (cocx dns)"
    fi
  else
    note "DNSSEC" "not validated — DANE inactive (publish the DS at the registrar: cocx ds)"
  fi

  # --- mail DNS ---------------------------------------------------------------------
  local mx dmarc mtasts
  mx="$(doh "$MAIL_DOMAIN" MX | tr '\n' ' ')"
  if printf '%s' "$mx" | grep -q "$MAIL_HOSTNAME\."; then
    ok "MX" "$mx"
  else
    bad "MX" "'${mx:-<none>}' does not point at $MAIL_HOSTNAME"
  fi
  dmarc="$(doh_txt "_dmarc.$MAIL_DOMAIN" | head -1)"
  if printf '%s' "$dmarc" | grep -qE 'p=(quarantine|reject)'; then
    ok "DMARC" "$dmarc"
  else
    bad "DMARC" "'${dmarc:-<none>}' — not enforcing (and BIMI is ignored under p=none)"
  fi
  mtasts="$(curl -s --max-time 15 "https://mta-sts.$MAIL_DOMAIN/.well-known/mta-sts.txt" | tr '\r\n' '  ')"
  if printf '%s' "$mtasts" | grep -q 'mode: enforce'; then
    ok "MTA-STS policy" "served (enforce)"
  else
    bad "MTA-STS policy" "https://mta-sts.$MAIL_DOMAIN/.well-known/mta-sts.txt not serving an enforce policy"
  fi

  local url bimi_ct
  url="$(bimi_url)"
  if [ -n "$url" ]; then
    if doh_txt "default._bimi.$MAIL_DOMAIN" | grep -qF "l=$url"; then
      ok "BIMI record" "present"
    else
      bad "BIMI record" "missing or points elsewhere (cocx dns)"
    fi
    bimi_ct="$(curl -s -o /dev/null -w '%{http_code} %{content_type}' --max-time 15 "$url")"
    case "$bimi_ct" in
      "200 image/svg+xml"*) ok "BIMI logo" "$url" ;;
      *) bad "BIMI logo" "$url answers '$bimi_ct', want '200 image/svg+xml' — receivers drop the logo" ;;
    esac
  fi

  # --- junk filter: three facts that fail independently --------------------------
  if [ "${JUNK_FILTER:-yes}" = "yes" ]; then
    local ft runs failed err
    ft="$(rsh_q 'systemctl is-active cocx-mail-filter.timer')"
    if [ "$ft" != "active" ]; then
      bad "junk filter" "timer $ft (cocx update)"
    elif ! rsh_q 'test -s /etc/cocx/mail-filter.env && echo y' | grep -q y; then
      bad "junk filter" "no /etc/cocx/mail-filter.env — the unit is being skipped"
    else
      failed="$(rsh_q 'systemctl is-failed cocx-mail-filter.service')"
      runs="$(rsh_q "journalctl -u cocx-mail-filter --since '-14 days' | grep -c 'mail-filter] applied'")"
      if [ "$failed" = "failed" ]; then
        err="$(rsh_q "journalctl -u cocx-mail-filter -n 40 --no-pager | grep -m1 'mail-filter\\]'")"
        bad "junk filter" "FAILING: ${err:-journalctl -u cocx-mail-filter}"
      elif [ "${runs:-0}" -eq 0 ] 2>/dev/null; then
        # The sweep logs "applied:" at the end of EVERY successful run, even when it
        # moved nothing — so zero runs always means it never completes.
        # A just-installed timer legitimately has none yet; past an hour it cannot.
        local since
        since="$(rsh_q 'systemctl show -p ActiveEnterTimestamp --value cocx-mail-filter.timer')"
        if [ -n "$since" ] && [ $(( $(date +%s) - $(date -d "$since" +%s 2>/dev/null || date +%s) )) -gt 3600 ]; then
          bad "junk filter" "timer active for over an hour but ZERO completed sweeps"
        else
          note "junk filter" "timer just started — no sweep yet"
        fi
      else
        ok "junk filter" "$runs sweep(s) in 14 days"
      fi
    fi
  fi

  # --- backups -------------------------------------------------------------------
  if [ "${BACKUP:-yes}" = "yes" ]; then
    local bt last age
    bt="$(rsh_q 'systemctl is-active cocx-backup.timer')"
    last="$(rsh_q "ls -1t $BACKUP_DIR/daily/*.tar.gz | head -1")"
    if [ "$bt" != "active" ]; then
      bad "backup" "timer $bt (cocx update)"
    elif [ -z "$last" ]; then
      note "backup" "timer active, no archive yet (first run tonight; or: cocx backup)"
    else
      age=$(( ( $(date +%s) - $(rsh_q "stat -c %Y '$last'") ) / 3600 ))
      if [ "$age" -le 30 ]; then
        ok "backup" "latest ${age}h old"
      else
        bad "backup" "latest archive is ${age}h old — journalctl -u cocx-backup"
      fi
    fi
  fi

  if [ "$CHECK_FAIL" = 0 ]; then
    msg "all checks passed"
  else
    warn "some checks FAILED (see above)"
  fi
  return "$CHECK_FAIL"
}

# `cocx blocklists` — the host's IPs and the mail domain against the major DNSBLs.
#
# Queried FROM THE HOST, through its own validating resolver. Spamhaus refuses queries
# that arrive via public resolvers and answers 127.255.255.252/.254/.255 — an ERROR code
# that parses as "listed" and reads as a catastrophe. So three outcomes, not two:
# empty = clean, 127.255.255.x = query refused, anything else = listed.
#
# And a clean sweep is worthless without a POSITIVE CONTROL: the standard test entries
# (127.0.0.2, dbltest.com) MUST come back listed, or the queries are failing and every
# "clean" line is meaningless. The control runs first and a failed control fails the run.
blocklist_check() {
  local ip4 ip6
  ip4="$(host_ip4)"
  ip6="$(host_ip6)"
  msg "DNS blocklists for $ip4${ip6:+, $ip6} and $MAIL_DOMAIN (queried from $HOST)..."
  rsh "IP4='$ip4' IP6='$ip6' DOM='$MAIL_DOMAIN' MH='$MAIL_HOSTNAME' bash -s" <<'EOS'
IPLISTS="zen.spamhaus.org bl.spamcop.net b.barracudacentral.org dnsbl-1.uceprotect.net
psbl.surriel.com bl.mailspike.net dnsbl.dronebl.org all.spamrats.com ix.dnsbl.manitu.net"
V6LISTS="zen.spamhaus.org"
DOMLISTS="dbl.spamhaus.org multi.uribl.com multi.surbl.org"
rev4() { echo "$1" | awk -F. '{print $4"."$3"."$2"."$1}'; }
rev6() { python3 -c 'import ipaddress,sys; print(".".join(reversed(ipaddress.ip_address(sys.argv[1]).exploded.replace(":",""))))' "$1"; }
q() { dig +short +time=3 +tries=2 "$1" A 2>/dev/null | grep -E '^[0-9.]+$' | tr '\n' ' '; }
verdict() { # list answer
  case "$2" in
    "") printf '    %-28s clean\n' "$1" ;;
    # Spamhaus 127.255.255.x and DBL 127.0.1.255, URIBL/SURBL 127.0.0.1: query refused.
    127.255.255.*|127.0.1.255*|"127.0.0.1 ") printf '    %-28s QUERY REFUSED (%s) — resolver not accepted by this list\n' "$1" "$2"; bad=1 ;;
    *) printf '    %-28s LISTED (%s)\n' "$1" "$2"; listed=1 ;;
  esac
}
bad=0; listed=0
echo "  controls (must be listed, or nothing below means anything):"
for c in 2.0.0.127.zen.spamhaus.org 2.0.0.127.bl.spamcop.net dbltest.com.dbl.spamhaus.org; do
  a=$(q "$c")
  case "$a" in
    127.255.255.*|"") printf '    %-34s FAILED (%s)\n' "$c" "${a:-no answer}"; bad=1 ;;
    *) printf '    %-34s ok (%s)\n' "$c" "$a" ;;
  esac
done
[ "$bad" = 1 ] && { echo "  !! controls failed — the results below cannot be trusted"; }
echo "  $IP4:"
for l in $IPLISTS; do verdict "$l" "$(q "$(rev4 "$IP4").$l")"; done
if [ -n "$IP6" ]; then
  echo "  $IP6:"
  for l in $V6LISTS; do verdict "$l" "$(q "$(rev6 "$IP6").$l")"; done
fi
for d in "$DOM" "$MH"; do
  echo "  $d:"
  for l in $DOMLISTS; do verdict "$l" "$(q "$d.$l")"; done
done
[ "$bad" = 0 ] && [ "$listed" = 0 ]
EOS
}
