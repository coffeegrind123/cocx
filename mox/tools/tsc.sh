#!/usr/bin/env bash
# Node-only port of mox's own `tsc.sh`.
#
# Identical compiler and bundler invocations, identical pinned versions
# (typescript + esbuild come from mox's package.json, installed with `npm ci`), and the
# same final space->tab pass — except that pass runs through tools/unexpand.mjs instead
# of `go run unexpand.go`, so the frontend build needs no Go.
#
# ⚠ EVERY FLAG BELOW IS COPIED FROM UPSTREAM AND MUST STAY COPIED. They are not style
# preferences: --strict, --noUnusedLocals and --noImplicitReturns are what make our
# pgp.ts fail the build rather than ship a silent bug, and --newLine lf plus the
# unexpand pass are what make the regenerated webmail.js byte-comparable to the
# committed one. Change one and the control in build.sh starts failing for a reason
# that has nothing to do with the patch being applied.
#
# If upstream ever edits its tsc.sh, this file has drifted and build.sh says so.
#
# 2026-08-31: upstream added esbuild --keep-names (mjl-/mox 5569ba0a374b, "web interfaces:
# fix various broken functionality from misgenerate js code"). It is NOT cosmetic — without
# it esbuild renames functions and classes, which broke real functionality upstream, and it
# changes the bundle byte-for-byte, so the control in build.sh fails without it. Copied here
# and .upstream-tsc-hash re-pinned e92fdd9db9e8c1d4 -> d38b3bc08782b671.
#
# usage: tsc.sh <outfile.js> <entry.ts> [more.ts ...]      (run from the mox source root)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out=$1
shift

./node_modules/.bin/tsc \
  --noEmitOnError true --pretty false --newLine lf --strict \
  --allowUnreachableCode false --allowUnusedLabels false \
  --noFallthroughCasesInSwitch true --noImplicitReturns true \
  --noUnusedLocals true --noImplicitThis true --noUnusedParameters true \
  --target es2022 --module es2022 --outDir .js "$@" \
  | sed -E 's/^([^\(]+)\(([0-9]+),([0-9]+)\):/\1:\2:\3: /'

./node_modules/.bin/esbuild --log-level=warning --bundle --keep-names \
  --outfile=".js/$(basename "$out").spaces.js" \
  ".js/${1%.ts}.js"

node "$here/unexpand.mjs" ".js/$(basename "$out").spaces.js" "$out" 2
rm -f ".js/$(basename "$out").spaces.js"
