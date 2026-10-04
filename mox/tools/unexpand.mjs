// Node reimplementation of mox's `unexpand.go`, the last stage of its tsc.sh:
// convert every run of `width` LEADING spaces into a tab.
//
// WHY REIMPLEMENT IT. mox runs `go run unexpand.go -t 2`, which makes its frontend
// build depend on the Go toolchain. We compile the TypeScript on a build host that has
// node but not necessarily Go, and — more importantly — we need the output to be
// BYTE-IDENTICAL to what upstream commits, or every regenerated webmail.js would carry
// a whole-file whitespace diff and the patch series would become unreviewable.
//
// This is the same state machine as the Go original, transcribed: spaces are counted
// only at the start of a line, a tab is emitted on reaching `width`, and any leftover
// spaces are flushed verbatim when a non-space byte arrives. Operating on BYTES rather
// than a decoded string matters — a multi-byte UTF-8 sequence must pass through
// untouched, and decoding then re-encoding is where that quietly stops being true.
//
// Verified: rebuilding upstream's own webmail.js through this pipeline reproduces the
// committed file exactly. That check is the control in build.sh; keep it passing.

import { readFileSync, writeFileSync } from 'fs';

const [, , infile, outfile, widthArg] = process.argv;
if (!infile || !outfile) {
  console.error('usage: unexpand.mjs <in> <out> [tabwidth=2]');
  process.exit(2);
}
const width = Number(widthArg || 2);
if (!Number.isInteger(width) || width <= 0) {
  console.error('tab width must be a positive integer');
  process.exit(2);
}

const input = readFileSync(infile);
const out = Buffer.allocUnsafe(input.length);   // output is never longer than input
let n = 0;
let nspace = 0;
let start = true;

const flush = () => { for (; nspace > 0; nspace--) out[n++] = 0x20; };

for (const b of input) {
  if (start && b === 0x20) {
    if (++nspace === width) { out[n++] = 0x09; nspace = 0; }
  } else {
    flush();
    out[n++] = b;
    start = b === 0x0a;
  }
}
flush();

writeFileSync(outfile, out.subarray(0, n));
