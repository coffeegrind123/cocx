# shellcheck shell=bash
# Hosting-provider actions, through an operator-supplied hook.
#
# Two things a fresh VPS commonly needs that are NOT host configuration: a PTR (rDNS)
# equal to MAIL_HOSTNAME, and outbound port 25 unblocked. Both are provider ACCOUNT
# actions with a different API at every host, so cocx defines the interface and the
# operator supplies the implementation as an executable (see hooks/provider.example):
#
#   $PROVIDER_HOOK set-rdns <ip> <hostname>   make PTR(ip) == hostname; idempotent
#   $PROVIDER_HOOK open-smtp                  remove any outbound-SMTP block; idempotent
#
# The hook runs on the OPERATOR machine (where provider credentials live), never on the
# mail host. Exit 0 = done or already right; non-zero = cocx warns and carries on.
#
# These run on the install path and on explicit request (`cocx set-rdns`, `cocx
# open-smtp`) only — never during a routine update. A run should not reach into the
# provider account on its own. `cocx check` verifies both outcomes regardless, over DoH
# and a live port probe, whether or not a hook exists.

provider_hook() {
  [ -n "${PROVIDER_HOOK:-}" ] || return 1
  [ -x "$PROVIDER_HOOK" ] || { warn "PROVIDER_HOOK=$PROVIDER_HOOK is not executable — skipping"; return 1; }
}

provider_set_rdns() {
  local ip4 ip6 ip
  if ! provider_hook; then
    info "no PROVIDER_HOOK — set the PTR for this host's addresses to $MAIL_HOSTNAME in your provider's panel"
    return 0
  fi
  ip4="$(host_ip4)"
  ip6="$(host_ip6)"
  # BOTH families. mox sends over v6 whenever the box has it, and a v6 sender with no PTR
  # is flagged by Google (550-5.7.25) — visible only in DMARC aggregate reports.
  for ip in $ip4 $ip6; do
    msg "Provider: PTR $ip -> $MAIL_HOSTNAME..."
    "$PROVIDER_HOOK" set-rdns "$ip" "$MAIL_HOSTNAME" 2>&1 | sed 's/^/    /' \
      || warn "provider hook failed for $ip"
  done
  info "PTR publication can lag the API; \`cocx check\` re-verifies over DoH."
}

provider_open_smtp() {
  if ! provider_hook; then
    info "no PROVIDER_HOOK — if \`cocx check\` reports outbound :25 BLOCKED, ask your provider to lift it"
    return 0
  fi
  msg "Provider: ensuring outbound SMTP is not blocked..."
  "$PROVIDER_HOOK" open-smtp 2>&1 | sed 's/^/    /' || warn "provider hook open-smtp failed"
}
