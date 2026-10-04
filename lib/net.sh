# shellcheck shell=bash
# Host networking that mail depends on: /etc/hosts, a validating resolver, the firewall.

# mox checks iprev (forward-confirmed reverse DNS) by resolving its own IP, and Go reads
# /etc/hosts BEFORE DNS — so a stale public-IP line there overrides a perfectly correct
# PTR and mox reports "does not match hostname". Provider images commonly ship such a
# line. The Debian-convention 127.0.1.1 entry stays, so the box still resolves its name.
fix_etc_hosts() {
  msg "Ensuring /etc/hosts does not override the public IP's reverse lookup..."
  local ip4 ip6
  ip4="$(host_ip4)"
  ip6="$(host_ip6)"
  rsh "MH='$MAIL_HOSTNAME' IPS='$ip4 $ip6' bash -s" <<'EOS'
set -e
for IP in $IPS; do
  # Drop only lines for this IP that do NOT name the mail hostname; a correct line stays.
  stale=$(awk -v ip="$IP" -v mh="$MH" '$1 == ip { ok = 0; for (i = 2; i <= NF; i++) if ($i == mh) ok = 1; if (!ok) print }' /etc/hosts)
  if [ -z "$stale" ]; then
    echo "    ok (no stale line for $IP)"
    continue
  fi
  cp -a /etc/hosts "/etc/hosts.bak-$(date +%Y%m%d-%H%M%S)"
  awk -v ip="$IP" -v mh="$MH" '$1 == ip { ok = 0; for (i = 2; i <= NF; i++) if ($i == mh) ok = 1; if (!ok) next } { print }' \
    /etc/hosts > /etc/hosts.cocx-new
  # Write IN PLACE, never rename over it: /etc/hosts is a bind mount in containers and on
  # some VPS platforms, where a rename fails with "Device or resource busy".
  cat /etc/hosts.cocx-new > /etc/hosts
  rm -f /etc/hosts.cocx-new
  printf '%s\n' "$stale" | sed 's/^/    removed stale mapping: /'
done
# cloud-init regenerates /etc/hosts on boot when manage_etc_hosts is on, which would put
# the line straight back. Say so rather than letting it reappear after a reboot.
if grep -rqsE '^[[:space:]]*manage_etc_hosts:[[:space:]]*(true|True|localhost)' /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d/ 2>/dev/null; then
  echo "    !! cloud-init manage_etc_hosts is on: it may restore the line on reboot."
  echo "       Set manage_etc_hosts: false in /etc/cloud/cloud.cfg.d/ (cocx check re-verifies)."
fi
EOS
}

# A DNSSEC-VALIDATING resolver is a hard prerequisite for DANE, not a nicety: mox decides
# whether to publish and honour TLSA by asking its resolver whether answers are authentic
# (the AD bit). Provider resolvers usually do not validate, so mox sees an "unsigned"
# zone and keeps its TLSA commented out even after the zone IS signed.
#
# unbound listens on loopback and goes FIRST in resolv.conf; the existing resolvers stay
# BELOW as fallback, so if unbound dies resolution degrades to slower-but-working rather
# than taking the box offline. resolv.conf is only touched after unbound is PROVEN to
# answer with the AD bit set.
install_unbound() {
  [ "${DNSSEC_RESOLVER:-yes}" = "yes" ] || return 0
  msg "Ensuring unbound (DNSSEC-validating resolver — required for DANE)..."
  rsh 'bash -s' <<'EOS'
set -e
if ! command -v unbound >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unbound unbound-anchor >/dev/null 2>&1
fi
mkdir -p /etc/unbound/unbound.conf.d
cat > /etc/unbound/unbound.conf.d/cocx.conf <<'CONF'
# Managed by cocx. Loopback only: this resolver serves THIS host and must never be public.
server:
    # Extended DNS Errors turn a generic SERVFAIL into an actionable DNSSEC message.
    ede: yes
    val-log-level: 2
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow
    do-ip6: yes
CONF
# Debian creates the root trust anchor only from the unit's start helper, so checkconf
# fails on a fresh install. Bootstrap it here; unbound-anchor exits 1 when it WROTE or
# updated the file, which is success for our purpose.
if [ ! -s /var/lib/unbound/root.key ]; then
  install -d -o unbound -g unbound /var/lib/unbound
  runuser -u unbound -- unbound-anchor -a /var/lib/unbound/root.key || true
  [ -s /var/lib/unbound/root.key ] || { echo "    !! could not bootstrap the DNSSEC trust anchor"; exit 1; }
fi
unbound-checkconf >/dev/null
systemctl enable unbound >/dev/null 2>&1 || true
systemctl restart unbound
sleep 2

# systemd-resolved owns /etc/resolv.conf on Ubuntu (a symlink to its stub). Editing the
# symlink target would be overwritten; point resolved's upstream at unbound instead and
# keep its stub, which passes the AD bit through.
if [ -L /etc/resolv.conf ] && systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNS=127.0.0.1\nDNSSEC=allow-downgrade\n' > /etc/systemd/resolved.conf.d/cocx.conf
  systemctl restart systemd-resolved
fi

ok=1
dig @127.0.0.1 +short com. ns >/dev/null 2>&1 || ok=0
if [ "$ok" = 1 ] && [ "$(dig @127.0.0.1 +dnssec org. ns 2>/dev/null | grep -c 'flags:.* ad' || true)" -eq 0 ]; then ok=0; fi
if [ "$ok" = 0 ]; then
  echo "    !! unbound is not answering with the AD bit — leaving resolv.conf untouched"
  exit 0
fi
echo "    unbound validates DNSSEC (AD bit set)"

if [ -L /etc/resolv.conf ]; then
  echo "    resolv.conf is managed by systemd-resolved (upstream now unbound)"
else
  if ! grep -q '^nameserver 127.0.0.1' /etc/resolv.conf; then
    cp -a /etc/resolv.conf "/etc/resolv.conf.bak-$(date +%Y%m%d-%H%M%S)"
    { echo "nameserver 127.0.0.1"; grep -v '^nameserver 127.0.0.1' /etc/resolv.conf; } > /etc/resolv.conf.new
    mv /etc/resolv.conf.new /etc/resolv.conf
    echo "    resolv.conf now prefers unbound (previous resolvers kept as fallback)"
  fi
fi
# "options trust-ad" is REQUIRED: Go (so mox) discards the AD bit unless the resolver is
# trusted — loopback-only nameservers or this option. With fallback resolvers present,
# mox otherwise reports "Domain does not appear to be DNSSEC-signed" forever while dig
# plainly shows AD. Safe with the fallbacks: they never set AD, so if unbound dies DANE
# degrades to "not validated" rather than trusting an unvalidated answer.
if [ ! -L /etc/resolv.conf ] && ! grep -q '^options .*trust-ad' /etc/resolv.conf; then
  echo "options trust-ad" >> /etc/resolv.conf
  echo "    added: options trust-ad"
fi
EOS
}

# Mail ports, plus 80/443 when mox owns the web side. 587/143 are NOT opened: mox enables
# only the implicit-TLS variants (465 submissions, 993 IMAPS).
#
# FIREWALL=auto opens ports only where something is actually filtering. Every filter
# found is handled, v4 AND v6: once an AAAA exists for the mail host, senders try v6
# FIRST, so a v6 chain that drops 25 blackholes inbound mail while every v4 check stays
# green.
open_ports() {
  [ "${FIREWALL:-auto}" = "off" ] && return 0
  local ports="25 465 993"
  # caddy-external: 80/443 belong to whoever runs that Caddy, not to cocx.
  if [ "$WEBSERVER" = "caddy" ] || [ "$WEBSERVER" = "mox" ]; then
    ports="$ports 80 443"
  fi
  msg "Ensuring firewall allows: $ports..."
  rsh "PORTS='$ports' bash -s" <<'EOS'
set -e
did=0
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  for p in $PORTS; do ufw allow "$p/tcp" >/dev/null; done
  echo "    ufw: allowed $PORTS"; did=1
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  for p in $PORTS; do firewall-cmd -q --permanent --add-port="$p/tcp" || true; done
  firewall-cmd -q --reload
  echo "    firewalld: allowed $PORTS"; did=1
fi
if [ "$did" = 0 ]; then
  # iptables (legacy or nft-backed) with a filtering INPUT chain.
  for fam in iptables ip6tables; do
    command -v "$fam" >/dev/null || continue
    rules=$("$fam" -S INPUT 2>/dev/null) || continue
    if printf '%s\n' "$rules" | grep -qE '^-P INPUT (DROP|REJECT)|-j (DROP|REJECT)'; then
      for p in $PORTS; do
        "$fam" -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null \
          || "$fam" -I INPUT -p tcp -m tcp --dport "$p" -j ACCEPT
      done
      echo "    $fam: allowed $PORTS"; did=1
    fi
  done
  if [ "$did" = 1 ]; then
    if command -v netfilter-persistent >/dev/null; then
      netfilter-persistent save >/dev/null 2>&1
    elif [ -d /etc/iptables ]; then
      iptables-save > /etc/iptables/rules.v4
      command -v ip6tables-save >/dev/null && ip6tables-save > /etc/iptables/rules.v6
    else
      echo "    !! rules are live but NOT persistent (install iptables-persistent)"
    fi
  fi
fi
if [ "$did" = 0 ] && command -v nft >/dev/null; then
  # Native nftables: an inet/ip/ip6 filter input hook chain with policy drop.
  nft -j list chains 2>/dev/null | python3 -c '
import json, sys
for c in json.load(sys.stdin).get("nftables", []):
    c = c.get("chain")
    if c and c.get("hook") == "input" and c.get("policy") == "drop":
        print(c["family"], c["table"], c["name"])' | while read -r fam tbl chain; do
    for p in $PORTS; do
      nft list chain "$fam" "$tbl" "$chain" | grep -qE "tcp dport $p accept" \
        || nft insert rule "$fam" "$tbl" "$chain" tcp dport "$p" accept
    done
    echo "    nft $fam $tbl $chain: allowed $PORTS"
    [ -f /etc/nftables.conf ] && echo "    !! live nft rules are not written back to /etc/nftables.conf — add them there"
  done
fi
[ "$did" = 0 ] && ! nft list ruleset 2>/dev/null | grep -q 'policy drop' && echo "    no filtering firewall found — nothing to open"
true
EOS
}
