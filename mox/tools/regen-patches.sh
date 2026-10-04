#!/usr/bin/env bash
# Regenerate mox/patches/*.patch from an edited build tree.
#
# Workflow this supports: `build.sh --check` leaves a patched tree in mox/.build; you
# edit the upstream files there until the change is right; then `build.sh --regen`
# calls this to write the diffs back out as the committed series.
#
# It diffs against a FRESHLY DOWNLOADED pristine copy of the same commit rather than
# against anything in the build tree. The build tree has our new files copied in and
# the patches already applied, so diffing it against itself would produce an empty
# series that looks like success.
#
# Uses plain `diff -u`. No git: the series must be applicable with `patch -p1` on a
# host that only has curl and coreutils, and nothing here should touch a repository.
set -euo pipefail

SRC="${1:?usage: regen-patches.sh <build-tree> <commit>}"
COMMIT="${2:?usage: regen-patches.sh <build-tree> <commit>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Only these upstream files may be patched. Anything else belongs in a NEW file —
# new files never conflict on a rebase, which is the whole design of this series.
# Adding a path here is a deliberate decision to accept future rebase pain for it.
FILES=(
  "webmail/webmail.go"
  "webmail/webmail.ts"
  "webmail/api.go"
  "Makefile"
)

# webmail/pgpwkd.go and webmail/pgp_test.go are NEW files copied in by build.sh, not
# patches — new files cannot conflict on a rebase, which is why the WKD proxy is a whole
# file with only a 6-line route hook in webmail.go.
#
# NOT patched, on purpose: webmail/api.json and webmail/api.ts are GENERATED from
# webmail/api.go by upstream's own vendored tooling, and build.sh regenerates them. A
# patch against a generated file would conflict every time upstream touches its API and
# would create a second source of truth for one Go struct.

PRISTINE="$(mktemp -d)"
trap 'rm -rf "$PRISTINE"' EXIT
curl -fsSL "https://codeload.github.com/mjl-/mox/tar.gz/$COMMIT" | tar xz -C "$PRISTINE" --strip-components=1

# One patch per upstream file, numbered, so a rebase failure names exactly one file.
i=1
for f in "${FILES[@]}"; do
  name="$(printf '%04d-%s.patch' "$i" "$(echo "$f" | tr '/.' '--')")"
  if diff -q "$PRISTINE/$f" "$SRC/$f" >/dev/null 2>&1; then
    rm -f "$HERE/patches/$name"
    echo "  unchanged: $f"
  else
    {
      echo "# mox OpenPGP series — $f"
      echo "# generated against upstream $COMMIT by mox/tools/regen-patches.sh"
      echo "# Keep the hunks small: everything that can live in webmail/pgp.ts should."
      diff -u --label "a/$f" --label "b/$f" "$PRISTINE/$f" "$SRC/$f" || true
    } > "$HERE/patches/$name"
    echo "  wrote $name ($(grep -c '^+' "$HERE/patches/$name") added lines)"
  fi
  i=$((i + 1))
done
