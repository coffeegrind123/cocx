#!/usr/bin/env bash
# Build mox from upstream `main` with our OpenPGP patch series applied.
#
# WHY A PATCH SERIES AND NOT A FORK
#   mox tracks no useful release cadence, so this project deliberately builds from
#   upstream main on every deploy (cocx). Adding OpenPGP as a fork would mean
#   choosing between "current mox" and "our features" on every single deploy. A series
#   that re-applies to whatever main is today keeps both.
#
#   Upstream will not take this patch: issue #23 ("anti-featurerequest: don't add
#   PGP/S-MIME signing") is closed with the author agreeing PGP "is best left to
#   clients". So the series is permanent, and it is built to survive rebases rather
#   than to be merged: almost everything lives in NEW files (webmail/pgp.ts,
#   webmail/openpgp.js) which can never conflict, and the edits to upstream files are
#   kept to the smallest possible hunks.
#
# WHAT THIS NEEDS
#   node + npm   (compiles the TypeScript; upstream's own pinned tsc/esbuild)
#   go           (builds the binary)
#   curl, patch
#   NOT git — the source arrives as a tarball, so no clone and no working tree to
#   maintain. Nothing here touches any git repository.
#
# THE CONTROL, AND WHY IT RUNS EVERY TIME
#   Before applying anything, this rebuilds upstream's OWN webmail.js from upstream's
#   own TypeScript and asserts it comes out byte-identical to the file upstream ships.
#   That single check is what makes the whole approach trustworthy: it proves our
#   toolchain is a faithful stand-in for theirs, so any difference in the final file is
#   OUR patch and nothing else. Without it, a toolchain drift (a tsc minor bump, a
#   different line ending, a lost tab) would silently rewrite all 322 KB of webmail.js
#   and the patch would become impossible to review — and impossible to distinguish
#   from a patch that did not apply.
#
# usage:
#   ./build.sh                     # resolve upstream main, build to ./out/mox
#   ./build.sh --commit <sha>      # pin an exact upstream commit
#   ./build.sh --check             # run the control + apply the series, but skip `go build`
#   ./build.sh --regen             # after editing src/*.ts: rebuild and REFRESH the patches
#   ./build.sh --series-hash       # print the hash of every build input (the stamp's 2nd half)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The build tree defaults OUTSIDE the repo. Network and shared filesystems (9p, SMB,
# some FUSE mounts) intermittently fail `rm -rf` on a deep tree with "Directory not
# empty" — hit for real on mox's vendor/golang.org/x/text. Since the tree is wiped and
# re-extracted on every run (see below), that turns into a build that cannot start. It is
# also markedly faster on a local filesystem: this unpacks a 33 MB tarball and runs a Go
# build in it. Override with MOX_BUILD_DIR if you want it somewhere specific.
WORK="${MOX_BUILD_DIR:-${TMPDIR:-/tmp}/mox-pgp-build}"
OUT="$HERE/out"
COMMIT=""
MODE="build"

while [ $# -gt 0 ]; do
  case "$1" in
    --commit) COMMIT="$2"; shift 2 ;;
    --check)  MODE="check"; shift ;;
    --regen)  MODE="regen"; shift ;;
    --series-hash) MODE="series-hash"; shift ;;
    -h|--help) sed -n '1,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Hash of EVERY build input we own, so a change to any of them forces a rebuild.
#
# This used to hash only patches/*.patch and src/pgp.ts, so editing src/pgpwkd.go (the
# WKD proxy's SSRF guard), the vendored openpgp.js, this script or tools/ produced the
# same stamp: the deploy reported "already current" and the fix never shipped until
# upstream main happened to move. Sorted file list, then contents, so a rename counts too.
series_hash() {
  ( cd "$HERE" && find build.sh patches src tools -type f -print0 | LC_ALL=C sort -z \
      | xargs -0 sha256sum ) | sha256sum | cut -c1-12
}
if [ "$MODE" = "series-hash" ]; then series_hash; exit 0; fi

say() { printf '\033[36m[mox-build]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[mox-build] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

for t in node npm curl patch; do command -v "$t" >/dev/null || die "$t is required"; done
[ "$MODE" = "check" ] || command -v go >/dev/null || die "go is required (use --check to skip the Go build)"

# ---------------------------------------------------------------- 1. fetch upstream
if [ -z "$COMMIT" ]; then
  say "resolving upstream main…"
  COMMIT="$(curl -fsSL https://api.github.com/repos/mjl-/mox/commits/main \
            | sed -nE 's/^  "sha": "([0-9a-f]{40})",?$/\1/p' | head -1)"
  [ -n "$COMMIT" ] || die "could not resolve upstream main (GitHub API rate limit? pass --commit <sha>)"
fi
say "upstream commit: $COMMIT"

# THE TREE IS ALWAYS EXTRACTED FRESH. The tarball is cached; the working tree is not.
#
# Reusing the tree across runs breaks this script in two ways, and the second one is
# much worse than the first:
#   1. `patch --forward` refuses an already-applied patch, so the second run dies
#      claiming "upstream has moved under it" — a diagnostic that sends you to debug a
#      rebase conflict that does not exist.
#   2. THE CONTROL SILENTLY BECOMES A TAUTOLOGY. It saves webmail.js as the "upstream"
#      reference and then rebuilds and compares — but on a reused tree that saved copy
#      is the ALREADY-PATCHED file, so it compares the patched output against itself and
#      prints PASSED. The single check that everything else here rests on would quietly
#      stop checking anything.
# Extracting fresh costs about a second and makes both impossible.
TARBALL="$WORK/mox-$COMMIT.tar.gz"
SRC="$WORK/src"
mkdir -p "$WORK"
if [ ! -s "$TARBALL" ]; then
  say "downloading source tarball…"
  curl -fsSL -o "$TARBALL.part" "https://codeload.github.com/mjl-/mox/tar.gz/$COMMIT" \
    || die "could not download the source tarball"
  mv -f "$TARBALL.part" "$TARBALL"
fi
# The source tree is wiped and re-extracted every run, and node_modules is NOT preserved
# across that wipe — the toolchain is installed fresh into the fresh tree below.
#
# It USED to be parked across the wipe and reused whenever node_modules/.bin/tsc merely
# EXISTED. That silently reused a STALE toolchain the moment upstream bumped a pinned
# version, and it caused a production deploy failure: upstream moved from the classic
# TypeScript compiler to TypeScript 7 (the Go `tsgo`), the parked tree still held a
# partial older install whose @typescript/typescript-<platform> package was missing
# lib.d.ts, and tsgo aborted with
#     panic: bundled: .../typescript-linux-x64/lib/lib.d.ts does not exist;
#            this executable may be misplaced
# `npm install` over a "present but corrupt" package does not self-heal — npm sees the
# version already satisfied and skips repopulating its files — so reuse could not recover
# on its own. A fresh extraction has no node_modules, so the install below is always
# clean. The npm cache (~/.npm) still makes it a ~2 s reconcile rather than a re-download,
# so dropping the parking costs effectively nothing — and this only runs when a rebuild is
# actually needed (cocx skips the whole build when the upstream commit and our
# patch series are both unchanged), i.e. exactly when the toolchain is most likely to have
# moved too.
rm -rf "$SRC"
mkdir -p "$SRC"
tar xz -C "$SRC" --strip-components=1 -f "$TARBALL" || die "could not extract the source tarball"
cd "$SRC"

# ---------------------------------------------------------------- 2. toolchain
# Fresh tree ⇒ no node_modules yet ⇒ always a clean install of upstream's pinned
# tsc + esbuild. --ignore-scripts: we are running a third party's package.json on a build
# host. (esbuild 0.28 and tsgo 7 both ship their platform binaries as plain
# optional-dependency packages, so they run without their install scripts — verified on
# the node 20 / npm 9 build host.)
say "installing upstream's pinned tsc + esbuild…"
npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 \
  || npm install --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 \
  || die "npm install failed"
# Smoke-test the exact entrypoints tools/tsc.sh will invoke, so a broken/partial install
# fails HERE with a clear message instead of 40 lines later as a mid-build tsgo panic.
# `tsc --version` is enough: tsgo loads its bundled lib.d.ts even for --version, so a
# misplaced/incomplete platform package aborts (measured — the failure this replaces).
if ! [ -x node_modules/.bin/tsc ] || ! [ -x node_modules/.bin/esbuild ]; then
  die "npm install did not produce node_modules/.bin/{tsc,esbuild}"
fi
node_modules/.bin/tsc --version >/dev/null 2>&1 \
  || die "installed tsc cannot run — toolchain install is incomplete (tsgo platform package missing lib.d.ts?)"
node_modules/.bin/esbuild --version >/dev/null 2>&1 \
  || die "installed esbuild cannot run — toolchain install is incomplete"

# Upstream's own tsc.sh is the spec our tools/tsc.sh copies. If it changes, ours has
# silently drifted — and a drifted frontend build is exactly the failure the control
# below is meant to catch, so say which one it is rather than leaving a mystery diff.
if ! diff -q <(sed 's/[[:space:]]*$//' tsc.sh) /dev/null >/dev/null 2>&1; then :; fi
UPSTREAM_TSC_HASH="$(sha256sum tsc.sh | cut -c1-16)"
KNOWN_TSC_HASH="$(cat "$HERE/tools/.upstream-tsc-hash" 2>/dev/null || true)"
if [ -n "$KNOWN_TSC_HASH" ] && [ "$UPSTREAM_TSC_HASH" != "$KNOWN_TSC_HASH" ]; then
  say "⚠ upstream tsc.sh CHANGED ($KNOWN_TSC_HASH -> $UPSTREAM_TSC_HASH)"
  say "  re-read it against mox/tools/tsc.sh before trusting this build,"
  say "  then update mox/tools/.upstream-tsc-hash"
fi

# The generated API bindings. `PGPEncrypted` is added to a Go struct in webmail/api.go,
# and webmail/api.json + webmail/api.ts are DERIVED from it — by upstream's own tooling,
# vendored, so this needs no network. They are regenerated rather than patched: they are
# generated files that upstream rewrites whenever its API changes, so patching them would
# conflict on every such change AND leave two sources of truth for one struct.
#
# Both are byte-reproducible from a pristine tree (verified), which is what makes it safe
# to regenerate them here instead of shipping them.
gen_api() {
  ( cd webmail && go tool sherpadoc -adjust-function-names none Webmail ) > webmail/api.json
  go tool sherpats -bytes-to-string -slices-nullable -maps-nullable -nullable-optional api \
    < webmail/api.json > webmail/api.ts
}

# ---------------------------------------------------------------- 3. THE CONTROL
say "control: regenerating upstream's own api.json/api.ts and webmail.js from upstream's own sources…"
cp webmail/webmail.js "$WORK/webmail.js.upstream"
cp webmail/api.json "$WORK/api.json.upstream"
cp webmail/api.ts "$WORK/api.ts.upstream"

if command -v go >/dev/null; then
  export GOFLAGS="${GOFLAGS:--mod=vendor}"
  gen_api || die "could not run upstream's API codegen (go tool sherpadoc/sherpats)"
  cmp -s webmail/api.json "$WORK/api.json.upstream" || die "control FAILED — regenerating
  upstream's own webmail/api.json did not reproduce it. Our codegen invocation has drifted
  from upstream's genapidoc.sh; compare them before trusting this build."
  cmp -s webmail/api.ts "$WORK/api.ts.upstream" || die "control FAILED — regenerating
  upstream's own webmail/api.ts did not reproduce it. Compare our sherpats flags against
  upstream's gents.sh."
  say "control PASSED — API codegen reproduces upstream byte-for-byte"
else
  say "⚠ no go — skipping the API codegen control (--check mode)"
fi

"$HERE/tools/tsc.sh" webmail/webmail.js webmail/webmail.ts webmail/api.ts webmail/lib.ts lib.ts
if cmp -s webmail/webmail.js "$WORK/webmail.js.upstream"; then
  say "control PASSED — our toolchain reproduces upstream's webmail.js byte-for-byte"
else
  cp "$WORK/webmail.js.upstream" webmail/webmail.js
  die "control FAILED — our TypeScript toolchain does not reproduce upstream's webmail.js.
  Every later diff would be toolchain noise rather than our patch. Compare mox/tools/tsc.sh
  against $SRC/tsc.sh and check the pinned tsc/esbuild versions in package.json."
fi

# ---------------------------------------------------------------- 4. apply the series
say "copying in our new files…"
# New files cannot conflict with upstream, which is why as much as possible lives here.
cp "$HERE/src/pgp.ts" webmail/pgp.ts
cp "$HERE/src/openpgp.js" webmail/openpgp.js
cp "$HERE/src/pgp_test.go" webmail/pgp_test.go
cp "$HERE/src/pgpwkd.go" webmail/pgpwkd.go

say "applying patches…"
shopt -s nullglob
for p in "$HERE"/patches/*.patch; do
  # --forward makes an already-applied patch an error rather than an interactive prompt
  # that hangs a deploy. Any failure leaves .rej files next to the target.
  patch -p1 --forward --no-backup-if-mismatch < "$p" >/dev/null \
    || die "patch $(basename "$p") did not apply against $COMMIT.
  Upstream has moved under it. Inspect the .rej files in $SRC, fix the patch, and re-run
  with --regen. Small hunks are the point: keep the fix in webmail/pgp.ts where possible."
  say "  applied $(basename "$p")"
done

# ---------------------------------------------------------------- 5. rebuild frontend
# Codegen FIRST: the webmail.ts patch references SubmitMessage.PGPEncrypted, which does
# not exist in api.ts until it has been regenerated from the patched Go. Getting this
# order wrong fails loudly (a tsc type error), which is the right way round.
if command -v go >/dev/null; then
  say "regenerating the API bindings from the patched Go…"
  gen_api || die "API codegen failed against the patched webmail/api.go"
  cmp -s webmail/api.ts "$WORK/api.ts.upstream" \
    && die "api.ts is unchanged after patching — SubmitMessage.PGPEncrypted did not reach
  the generated bindings, so the compose hook cannot compile. Did 0003-webmail-api-go.patch apply?"
fi

say "rebuilding webmail.js with pgp.ts…"
"$HERE/tools/tsc.sh" webmail/webmail.js webmail/webmail.ts webmail/pgp.ts webmail/api.ts webmail/lib.ts lib.ts

if cmp -s webmail/webmail.js "$WORK/webmail.js.upstream"; then
  die "webmail.js is unchanged after applying the series — the UI patch did not take effect.
  This is the silent-failure case: the Go build would succeed and ship stock mox."
fi
say "webmail.js: $(stat -c%s "$WORK/webmail.js.upstream") -> $(stat -c%s webmail/webmail.js) bytes"

# ---------------------------------------------------------------- 5b. reachability
# esbuild TREE-SHAKES. Any export of pgp.ts that webmail.ts does not reach is silently
# dropped from the bundle — and "silently" is the whole problem: the TypeScript compiles,
# the patch applies, the Go build succeeds, the binary ships, encrypted mail even
# decrypts, and the KEY MANAGEMENT UI simply does not exist, so there is no way to get a
# key in and the feature is unusable. It happened exactly once during development, which
# is why this check exists.
#
# Each marker is a distinctive string from a different reachable-only-via-UI code path.
# The bogus marker is the control: without it a grep that matched everything (or a
# webmail.js that failed to write) would report a clean pass.
say "checking the bundle actually contains each feature…"
MARKERS=(
  'Decrypted in your browser' \
  'BAD SIGNATURE' \
  'OpenPGP keys' \
  'Generate a key' \
  'revocation certificate' \
  'Type the last 8 characters' \
  'Encrypt with OpenPGP' \
  'cannot encrypt to' \
  'encrypted but unsigned' \
  'Autocrypt' \
  'Look up' \
  'keys.openpgp.org'
)
for marker in "${MARKERS[@]}"
do
  # ⚠ ASCII ONLY. esbuild escapes non-ASCII in string literals ("Look up…" is emitted as
  # the seven characters Look up\u2026), so a marker containing so much as an ellipsis can
  # never match and this check fails for a reason that has nothing to do with the code.
  # It cost a build cycle: the die below confidently blamed the tree-shaker while the
  # feature was present and correct. The guard right after this loop enforces it.
  grep -aqF "$marker" webmail/webmail.js \
    || die "the bundle is missing \"$marker\".
  Most likely esbuild tree-shook that code away because nothing in webmail.ts reaches it —
  add the missing entry point to the webmail.ts patch. But check the marker itself first:
  if it contains non-ASCII, esbuild escaped it and the marker is simply unmatchable."
done
# Enforce the ASCII rule above, so a future non-ASCII marker fails loudly HERE with the
# real reason rather than as a bogus tree-shaking report.
for marker in "${MARKERS[@]}"; do
  printf '%s' "$marker" | LC_ALL=C grep -q '[^ -~]' \
    && die "marker \"$marker\" contains non-ASCII. esbuild escapes those in the bundle, so
  it can never match. Use an ASCII-only substring of the same string."
done || true

if grep -aqF 'zzz_this_marker_must_not_exist' webmail/webmail.js; then
  die "control marker FOUND — the grep above matches anything, so it proves nothing."
fi
say "all feature markers present (and the control is absent)"

if [ "$MODE" = "regen" ]; then
  say "refreshing patches from the working tree…"
  "$HERE/tools/regen-patches.sh" "$SRC" "$COMMIT"
fi

# ---------------------------------------------------------------- 6. build
if [ "$MODE" = "check" ]; then
  say "check complete (skipped the Go build)"
  exit 0
fi

# xpgpArmor is the trust boundary between a browser and mail this server DKIM-signs and
# sends under our domain's reputation. Gate the build on it rather than hoping.
if command -v go >/dev/null; then
  say "testing the armor validator + WKD guards…"
  go test ./webmail/ -run 'TestPGPArmor|TestWKD' -count=1 >/dev/null \
    || die "armor/WKD tests FAILED — the validator on SubmitMessage.PGPEncrypted is the
  check standing between a browser and outgoing mail we sign. Not shipping this."
  say "armor validator tests passed"
fi

say "building the binary…"
mkdir -p "$OUT"
CGO_ENABLED=0 go build -o "$OUT/mox" || die "go build failed"

# The build stamp, read by cocx to decide whether a rebuild is needed.
#
# `mox version` CANNOT be used for this on a patched build: built from a source tree it
# reports "(devel)-go1.26.5" with no commit at all, so a version regex finds nothing and
# every deploy rebuilds forever. It also could not see a change to OUR patches. The
# stamp records both axes.
SERIES_HASH="$(series_hash)"
printf '%s %s\n' "$COMMIT" "$SERIES_HASH" > "$OUT/mox.buildstamp"
say "built $OUT/mox ($(du -h "$OUT/mox" | cut -f1))"
say "stamp: upstream=${COMMIT:0:12} series=$SERIES_HASH"
