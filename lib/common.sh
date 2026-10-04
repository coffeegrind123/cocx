# shellcheck shell=bash
# Shared plumbing: output, remote execution, DNS-over-HTTPS lookups, host facts.
#
# Every function that touches the mail host goes through rsh(), which is the ONLY place
# that knows whether the host is remote (ssh) or this machine (HOST=local). Nothing else
# may call ssh directly, or local mode silently runs half its steps somewhere else.

msg()  { printf '==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# rsh <command string>
#   Runs the string with bash on the mail host, as root, with stdin passed through — so
#   both `rsh 'cmd'` and `rsh "VAR='x' bash -s" <<'EOS' ... EOS` work in every mode.
#
#   Non-root SSH users go through `sudo -n` (no prompt: a password prompt inside a
#   heredoc-fed session would hang forever rather than fail).
rsh() {
  local cmd="$*"
  if [ "$HOST" = "local" ]; then
    bash -c "$cmd"
    return
  fi
  if [ "$SSH_USER" != "root" ]; then
    cmd="sudo -n bash -c $(printf '%q' "$cmd")"
  fi
  # shellcheck disable=SC2086  # SSH_OPTS is a deliberately word-split option list
  ssh -o BatchMode=yes -o ConnectTimeout=15 ${SSH_OPTS:-} -p "$SSH_PORT" \
      ${SSH_KEY:+-i "$SSH_KEY"} "$SSH_USER@$HOST" "$cmd"
}

# rsh_q <command string> — like rsh but never fails the caller, for probes whose ANSWER
# is carried in the exit code (systemctl is-active/is-failed, grep -c, test). Under
# `set -e` + `pipefail` a bare probe exiting non-zero aborts the whole health check at the
# assignment, silently skipping every check after it. That happened twice in the system
# this was extracted from: once hiding a broken filter, once failing a healthy one.
rsh_q() { rsh "$* 2>/dev/null || true" 2>/dev/null | tr -d '\r'; }

# The host's primary global addresses. Global scope only for v6: a link-local (fe80::)
# or ULA address is not routable and has no reverse zone to publish a PTR into.
#
# PUBLIC_IP4 / PUBLIC_IP6 override detection for hosts behind 1:1 NAT (the route source
# address is then private, and SPF/PTR/A must carry the public one).
host_ip4() {
  [ -n "${PUBLIC_IP4:-}" ] && { printf '%s' "$PUBLIC_IP4"; return; }
  rsh_q "ip -4 route get 1.1.1.1 | grep -oP '(?<=src )\\S+' | head -1" | tr -d '\n'
}
host_ip6() {
  [ -n "${PUBLIC_IP6:-}" ] && { printf '%s' "$PUBLIC_IP6"; return; }
  [ "${IPV6:-auto}" = "off" ] && return
  rsh_q "ip -6 addr show scope global | grep -v -E 'temporary|deprecated' | grep -oE 'inet6 [0-9a-f:]+' | awk '{print \$2}' | grep -v -E '^f[cd]' | head -1" | tr -d '\n'
}

# doh <name> <type> — answers from Google's resolver over HTTPS, one per line.
#
# DoH, never dig, for every PUBLIC DNS fact this tool reports. The operator's resolver
# caches negative answers for the zone's SOA minimum (often 30 minutes), so a record
# queried before it was created keeps reading "missing" long after it exists. That has
# produced false "MX is broken" and "rDNS still wrong" alarms; DoH bypasses the cache.
# Also: dig leaks its error text into the value on a timeout, so a not-yet-published
# PTR reads as ";; communications error ..." instead of empty.
doh() {
  curl -s --max-time 20 "https://dns.google/resolve?name=$1&type=$2" \
    | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for a in d.get("Answer", []):
    print(a.get("data", ""))' 2>/dev/null
}

# doh_txt <name> — TXT answers with the quoting and string-splitting removed.
doh_txt() {
  doh "$1" TXT | python3 -c '
import re, sys
for line in sys.stdin:
    parts = re.findall(r"\"((?:[^\"\\\\]|\\\\.)*)\"", line)
    print("".join(parts) if parts else line.strip())'
}

# ptr_name <ip> — the reverse-lookup name for v4 or v6.
ptr_name() {
  python3 -c 'import ipaddress, sys; print(ipaddress.ip_address(sys.argv[1]).reverse_pointer)' "$1"
}

# ship <localdir> <remotedir> <path>... — copy paths (relative to localdir) to the host.
# A tar stream through rsh, so local mode and sudo mode work unchanged.
ship() {
  local src="$1" dst="$2"
  shift 2
  rsh "rm -rf '$dst' && mkdir -p '$dst'"
  tar -C "$src" -cz "$@" | rsh "tar -C '$dst' -xz"
}
