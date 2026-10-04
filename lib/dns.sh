# shellcheck shell=bash
# DNS: the mail record set, zone-level hardening (DNSSEC, CAA), and the DS hand-off.
#
#   DNS_PROVIDER=cloudflare  everything is written through the API, DNS-only (never proxied)
#   DNS_PROVIDER=manual      the same desired state is printed as zone lines and VERIFIED
#                            over DoH; publishing is yours.
#   DNS_PROVIDER=none        print the zone lines only; never query or touch DNS (labs, or
#                            DNS owned by another system).
#
# The record set's source of truth is always `mox config dnsrecords` on the mail host.

CF_API="${COCX_CF_API:-https://api.cloudflare.com/client/v4}"

cf_token() {
  [ -f "$CF_TOKEN_FILE" ] || die "DNS_PROVIDER=cloudflare but no token at $CF_TOKEN_FILE"
  tr -d ' \r\n' < "$CF_TOKEN_FILE"
}

# Zone id, looked up once by name when not configured.
cf_zone_id() {
  if [ -z "${CF_ZONE_ID:-}" ]; then
    CF_ZONE_ID="$(curl -s --max-time 25 "$CF_API/zones?name=${CF_ZONE_NAME:-$MAIL_DOMAIN}" \
      -H "Authorization: Bearer $(cf_token)" \
      | python3 -c 'import json,sys; r=json.load(sys.stdin).get("result") or []; print(r[0]["id"] if r else "")' 2>/dev/null)"
    [ -n "$CF_ZONE_ID" ] || die "no Cloudflare zone named ${CF_ZONE_NAME:-$MAIL_DOMAIN} visible to this token"
  fi
  printf '%s' "$CF_ZONE_ID"
}

# cf_ensure <type> <name> <content> — create if absent, PATCH in place if different.
# Never delete-and-recreate: a gap is cached by resolvers for the TTL.
cf_ensure() {
  local type="$1" name="$2" content="$3" tok api existing id cur
  tok="$(cf_token)"
  api="$CF_API/zones/$(cf_zone_id)/dns_records"
  existing="$(curl -s --max-time 25 "$api?type=$type&name=$name" -H "Authorization: Bearer $tok" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin).get("result") or []; print((r[0]["id"]+"|"+r[0]["content"]) if r else "|")' 2>/dev/null)"
  id="${existing%%|*}"
  cur="${existing#*|}"
  if [ "${cur%.}" = "${content%.}" ]; then
    printf '    exists  %-6s %s\n' "$type" "$name"
  elif [ -n "$id" ]; then
    curl -s --max-time 25 -X PATCH "$api/$id" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
      -d "{\"content\":\"$content\",\"proxied\":false}" \
      | python3 -c "import json,sys;print('    updated' if json.load(sys.stdin).get('success') else '    FAILED ', '$type $name')"
  else
    curl -s --max-time 25 -X POST "$api" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
      -d "{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\",\"ttl\":300,\"proxied\":false}" \
      | python3 -c "import json,sys;print('    created' if json.load(sys.stdin).get('success') else '    FAILED ', '$type $name')"
  fi
}

# The hostnames must resolve BEFORE anything asks for a certificate: neither Caddy nor
# mox can complete ACME for a name that does not point here. A only at this stage — the
# AAAA is published by the final sync, after the v6 firewall and PTR are in place, so v6
# is never advertised while still closed.
dns_bootstrap_hostname() {
  [ "$DNS_PROVIDER" = "none" ] && return 0
  local ip4
  ip4="$(host_ip4)"
  [ -n "$ip4" ] || die "could not determine the host's IPv4 address (set PUBLIC_IP4)"
  if [ "$DNS_PROVIDER" = "cloudflare" ]; then
    msg "Ensuring mail hostname DNS (A + mta-sts/autoconfig CNAMEs)..."
    cf_ensure A     "$MAIL_HOSTNAME"            "$ip4"
    cf_ensure CNAME "mta-sts.$MAIL_DOMAIN"      "$MAIL_HOSTNAME"
    cf_ensure CNAME "autoconfig.$MAIL_DOMAIN"   "$MAIL_HOSTNAME"
    return 0
  fi
  msg "Checking the mail hostnames resolve here (DNS_PROVIDER=manual)..."
  local missing=0
  doh "$MAIL_HOSTNAME" A | grep -qxF "$ip4" || { warn "publish: $MAIL_HOSTNAME A $ip4"; missing=1; }
  for h in "mta-sts.$MAIL_DOMAIN" "autoconfig.$MAIL_DOMAIN"; do
    doh "$h" CNAME | grep -qxF "$MAIL_HOSTNAME." || { warn "publish: $h CNAME $MAIL_HOSTNAME."; missing=1; }
  done
  if [ "$missing" = 1 ]; then
    warn "certificates cannot be issued until these resolve; publish them and re-run."
    return 1
  fi
  info "all resolve"
}

# DNSSEC signing (Cloudflare). Idempotent: "pending" until the DS is anchored at the
# registrar, "active" after. Signing alone is inert — the DS must be published at the
# REGISTRAR, which no DNS API credential can do; `cocx ds` prints it.
ensure_dnssec() {
  [ "$DNS_PROVIDER" = "cloudflare" ] || return 0
  local status
  status="$(curl -s --max-time 25 "$CF_API/zones/$(cf_zone_id)/dnssec" -H "Authorization: Bearer $(cf_token)" \
    | python3 -c 'import json,sys; print((json.load(sys.stdin).get("result") or {}).get("status",""))' 2>/dev/null)"
  case "$status" in
    active)  msg "DNSSEC: active" ;;
    pending) msg "DNSSEC: signed, awaiting the DS record at the registrar (cocx ds)" ;;
    *)
      msg "Enabling DNSSEC signing on the zone..."
      curl -s --max-time 30 -X PATCH "$CF_API/zones/$(cf_zone_id)/dnssec" \
        -H "Authorization: Bearer $(cf_token)" -H 'Content-Type: application/json' -d '{"status":"active"}' \
        | python3 -c '
import json, sys
d = json.load(sys.stdin)
r = d.get("result") or {}
print("    status:", r.get("status") if d.get("success") else d.get("errors"))' ;;
  esac
}

# CAA: which CAs may issue for the domain (validators walk UP the tree, so the apex
# record covers every host). ADDITIVE ONLY — never delete:
#   * keep every issuer the web side can use. Caddy's default fallback is ZeroSSL
#     (sectigo.com); a CAA listing only letsencrypt.org works until the day it is needed.
#   * Cloudflare INJECTS its own CAA (incl. issuewild) the moment any CAA exists on a zone
#     with Universal SSL. Those are load-bearing; an `issuewild ";"` contradicts them.
ensure_caa() {
  [ "$DNS_PROVIDER" = "none" ] && return 0
  local iodef="mailto:$MAIL_ACCOUNT" issuer
  if [ "$DNS_PROVIDER" = "manual" ]; then
    msg "Checking CAA (DNS_PROVIDER=manual)..."
    local have
    have="$(doh "$MAIL_DOMAIN" CAA)"
    for issuer in $CAA_ISSUERS; do
      printf '%s\n' "$have" | grep -q "issue \"$issuer\"" \
        || warn "publish: $MAIL_DOMAIN CAA 0 issue \"$issuer\""
    done
    printf '%s\n' "$have" | grep -q "iodef \"$iodef\"" || warn "publish: $MAIL_DOMAIN CAA 0 iodef \"$iodef\""
    return 0
  fi
  msg "Ensuring CAA records ($CAA_ISSUERS + iodef)..."
  local tok api existing
  tok="$(cf_token)"
  api="$CF_API/zones/$(cf_zone_id)/dns_records"
  existing="$(curl -s --max-time 25 "$api?type=CAA&per_page=100" -H "Authorization: Bearer $tok" \
    | python3 -c '
import json, sys
for r in (json.load(sys.stdin).get("result") or []):
    d = r.get("data") or {}
    print("%s=%s" % (d.get("tag"), d.get("value")))' 2>/dev/null)"
  _caa() {
    if printf '%s\n' "$existing" | grep -qxF "$1=$2"; then
      printf '    exists  %-6s %s\n' "$1" "$2"; return 0
    fi
    curl -s --max-time 25 -X POST "$api" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
      -d "{\"type\":\"CAA\",\"name\":\"$MAIL_DOMAIN\",\"ttl\":300,\"data\":{\"flags\":0,\"tag\":\"$1\",\"value\":\"$2\"}}" \
      | python3 -c "import json,sys;print(('    created ' if json.load(sys.stdin).get('success') else '    FAILED  ')+'$1 $2')"
  }
  for issuer in $CAA_ISSUERS; do _caa issue "$issuer"; done
  _caa iodef "$iodef"
}

# The full record set. mox's own output plus what mox does not emit: the host's A/AAAA
# and, when configured, the BIMI record — published only if the logo actually answers,
# since a BIMI record pointing at a 404 is worse than none (receivers cache the failure).
sync_dns() {
  local tmp ip4 ip6 url rc=0
  tmp="$(mktemp)"
  msg "Syncing DNS (source of truth: mox config dnsrecords $MAIL_DOMAIN; provider $DNS_PROVIDER)..."
  rsh "cd $MOX_HOME && ./mox config dnsrecords '$MAIL_DOMAIN' 2>/dev/null" > "$tmp" \
    || { rm -f "$tmp"; die "mox config dnsrecords failed on $HOST"; }
  url="$(bimi_url)"
  if [ -n "$url" ]; then
    if curl -sf -o /dev/null --max-time 15 "$url"; then
      printf 'default._bimi.%s. TXT "v=BIMI1; l=%s; a="\n' "$MAIL_DOMAIN" "$url" >> "$tmp"
    else
      warn "BIMI logo $url is not reachable — NOT publishing default._bimi yet"
    fi
  fi
  ip4="$(host_ip4)"
  ip6="$(host_ip6)"
  local args=(--records-file "$tmp" --origin "$MAIL_DOMAIN" --mail-host "$MAIL_HOSTNAME"
              --extra-a "$MAIL_HOSTNAME=$ip4")
  [ -n "$ip6" ] && args+=(--extra-a "$MAIL_HOSTNAME=$ip6")
  case "$DNS_PROVIDER" in
    cloudflare)
      args+=(--provider cloudflare --token-file "$CF_TOKEN_FILE" --zone-id "$(cf_zone_id)" --apply)
      [ "${PRUNE:-0}" = "1" ] && args+=(--prune) ;;
    manual) args+=(--provider doh --print-zone) ;;
    none)   args+=(--print-zone) ;;
  esac
  python3 "$COCX_DIR/tools/mail-dns.py" "${args[@]}" || rc=$?
  rm -f "$tmp"
  [ "$DNS_PROVIDER" = "manual" ] && [ "$rc" != 0 ] && warn "publish the records above at your DNS host, then: cocx dns"
  return "$rc"
}

# The DS record is the one DANE link that cannot be automated: the DNS host signs the
# zone, but the DS lives in the PARENT zone and only the registrar can put it there.
show_ds() {
  if [ "$DNS_PROVIDER" = "cloudflare" ]; then
    curl -s --max-time 25 "$CF_API/zones/$(cf_zone_id)/dnssec" -H "Authorization: Bearer $(cf_token)" \
      | python3 -c "
import json, sys
r = json.load(sys.stdin).get('result') or {}
print('  zone DNSSEC status:', r.get('status'))
print()
print('  Add this DS record at the REGISTRAR for $MAIL_DOMAIN:')
for k in ('key_tag', 'algorithm', 'digest_type', 'digest'):
    print(f'    {k:12} {r.get(k)}')
print()
print('  one-line:', r.get('ds'))"
  else
    echo "  DNS_PROVIDER=manual: enable DNSSEC at your DNS host; it shows the DS to give the registrar."
  fi
  echo
  echo "  Currently published DS (parent zone, via DoH):"
  doh "$MAIL_DOMAIN" DS | sed 's/^/    /'
  echo "  Registry view (RDAP):"
  curl -sL --max-time 20 "https://rdap.org/domain/$MAIL_DOMAIN" \
    | python3 -c 'import json,sys; print("    secureDNS:", json.load(sys.stdin).get("secureDNS"))' 2>/dev/null \
    || echo "    (RDAP lookup failed)"
}
