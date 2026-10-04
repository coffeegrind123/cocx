# shellcheck shell=bash
# Host prerequisites and the build toolchain (Go for mox, Node for its TypeScript).
#
# mox is built FROM SOURCE ON THE MAIL HOST, from upstream `main`, with the OpenPGP patch
# series applied (see mox/README.md). So the box carries a Go toolchain and Node. Both are
# installed from upstream tarballs with their published SHA-256 verified — the distro
# packages are routinely too old (Debian 12's Go is 1.19; mox main needs a current Go,
# and Ubuntu 22.04's Node 12 cannot run the TypeScript compiler mox pins).

NODE_MIN_MAJOR=18

ensure_debian() {
  rsh 'test -f /etc/debian_version' 2>/dev/null \
    || die "$HOST is not Debian/Ubuntu — cocx installs packages with apt and units with systemd"
  rsh 'test -d /run/systemd/system' 2>/dev/null \
    || die "$HOST is not running systemd — mox, the junk filter and backups are systemd units"
}

install_prereqs() {
  msg "Ensuring base packages..."
  rsh 'bash -s' <<'EOS'
set -e
need=""
for p in curl ca-certificates python3 dnsutils openssl patch tar iproute2 xz-utils gzip; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || need="$need $p"
done
if [ -n "$need" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # shellcheck disable=SC2086
  apt-get install -y -qq $need >/dev/null
  echo "    installed:$need"
else
  echo "    all present"
fi
id mox >/dev/null 2>&1 || useradd -m -d /home/mox -s /usr/sbin/nologin mox
EOS
}

# Latest stable Go, checksum-verified against go.dev's own JSON index.
install_go() {
  msg "Ensuring Go toolchain (mox main tracks a current Go)..."
  rsh 'bash -s' <<'EOS'
set -e
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64|armhf|i386) ;; *) echo "unsupported architecture for Go: $arch"; exit 1 ;; esac
[ "$arch" = armhf ] && arch=armv6l
[ "$arch" = i386 ] && arch=386
read -r ver file sha < <(curl -fsSL --max-time 30 'https://go.dev/dl/?mode=json' | python3 -c '
import json, sys
arch = sys.argv[1]
rel = json.load(sys.stdin)[0]
f = next(f for f in rel["files"] if f["os"] == "linux" and f["arch"] == arch and f["kind"] == "archive")
print(rel["version"], f["filename"], f["sha256"])' "$arch")
[ -n "$sha" ] || { echo "could not resolve the latest Go release"; exit 1; }
if [ "$(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}')" = "$ver" ]; then
  echo "    $ver (current)"; exit 0
fi
tmp=$(mktemp -d)
curl -fsSL --max-time 300 -o "$tmp/$file" "https://go.dev/dl/$file"
echo "$sha  $tmp/$file" | sha256sum -c --quiet - || { echo "Go tarball CHECKSUM MISMATCH — refusing to install"; rm -rf "$tmp"; exit 1; }
rm -rf /usr/local/go
tar -C /usr/local -xzf "$tmp/$file"
rm -rf "$tmp"
echo "    installed $(/usr/local/go/bin/go version | awk '{print $3}')"
EOS
}

# Node >= NODE_MIN_MAJOR. The system package is used when new enough (it also brings npm);
# otherwise the current LTS from nodejs.org, checksum-verified against SHASUMS256.txt.
# npm matters separately from node: Debian ships them as two packages, and a box with
# node but no npm cannot build the frontend.
install_node() {
  msg "Ensuring Node + npm (compiles mox's TypeScript with upstream's pinned tsc)..."
  rsh "MIN=$NODE_MIN_MAJOR bash -s" <<'EOS'
set -e
major() { "$1" --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/'; }
if command -v node >/dev/null && [ "$(major node)" -ge "$MIN" ] 2>/dev/null && command -v npm >/dev/null; then
  echo "    node $(node --version), npm $(npm --version)"; exit 0
fi
export DEBIAN_FRONTEND=noninteractive
cand=$(apt-cache policy nodejs 2>/dev/null | awk '/Candidate:/ {print $2}' | sed -E 's/^[0-9]+://; s/^([0-9]+).*/\1/')
if [ -n "$cand" ] && [ "$cand" -ge "$MIN" ] 2>/dev/null; then
  apt-get update -qq; apt-get install -y -qq nodejs npm >/dev/null
else
  arch=$(dpkg --print-architecture)
  case "$arch" in amd64) arch=x64 ;; arm64) arch=arm64 ;; armhf) arch=armv7l ;; *) echo "no Node build for $arch"; exit 1 ;; esac
  base=https://nodejs.org/dist/latest-v22.x
  sums=$(curl -fsSL --max-time 30 "$base/SHASUMS256.txt")
  line=$(printf '%s\n' "$sums" | grep -E " node-v[0-9.]+-linux-$arch\.tar\.xz$" | head -1)
  sha=${line%% *}; file=${line##* }
  [ -n "$file" ] || { echo "could not resolve a Node tarball for $arch"; exit 1; }
  tmp=$(mktemp -d)
  curl -fsSL --max-time 300 -o "$tmp/$file" "$base/$file"
  echo "$sha  $tmp/$file" | sha256sum -c --quiet - || { echo "Node tarball CHECKSUM MISMATCH — refusing to install"; rm -rf "$tmp"; exit 1; }
  rm -rf /usr/local/lib/nodejs; mkdir -p /usr/local/lib/nodejs
  tar -C /usr/local/lib/nodejs --strip-components=1 -xJf "$tmp/$file"
  rm -rf "$tmp"
  for b in node npm npx; do ln -sf "/usr/local/lib/nodejs/bin/$b" "/usr/local/bin/$b"; done
fi
hash -r
[ "$(major node)" -ge "$MIN" ] || { echo "node is still older than v$MIN after install"; exit 1; }
echo "    node $(node --version), npm $(npm --version)"
EOS
}
