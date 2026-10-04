# mox + OpenPGP — a maintained patch series

cocx runs [mox](https://www.xmox.nl/) built from upstream `main` on every update. This
directory adds **OpenPGP to mox's own webmail** as a patch series that re-applies to
whatever `main` is today, so you keep both current mox and the feature.

The PGP UI lives **inside mox's webmail**. Keys are stored in the browser; the server
never sees a private key and cannot read encrypted mail.

```
mox/
├── build.sh                  fetch upstream -> control -> apply -> rebuild -> go build
├── src/
│   ├── pgp.ts                the whole frontend feature (new file, never conflicts)
│   ├── pgpwkd.go             WKD key-lookup proxy with an SSRF guard (new file)
│   ├── pgp_test.go           Go tests for the armor validator and the SSRF guard (new file)
│   ├── openpgp.js            vendored openpgp.js 6.3.1, unmodified (LGPL)
│   └── openpgp.LICENSE
├── patches/                  the ONLY edits to upstream files
│   ├── 0001-webmail-webmail-go.patch    embed + serve /openpgp.js
│   ├── 0002-webmail-webmail-ts.patch    import, render hook, toolbar button, compose box
│   ├── 0003-webmail-api-go.patch        SubmitMessage.PGPEncrypted + multipart/encrypted
│   └── 0004-Makefile.patch              add pgp.ts to the webmail.js target
└── tools/
    ├── tsc.sh                node-only port of upstream's tsc.sh
    ├── unexpand.mjs          node port of upstream's unexpand.go
    ├── regen-patches.sh      rewrite patches/ from an edited build tree
    └── .upstream-tsc-hash    tripwire: upstream's tsc.sh changing means ours drifted
```

## Build it

```sh
./build.sh                 # resolve upstream main, build ./out/mox
./build.sh --commit <sha>  # pin an exact upstream commit
./build.sh --check         # control + apply + frontend, skip the Go build
./build.sh --regen         # after editing src/pgp.ts or the tree: refresh patches/
```

Needs `node`, `npm`, `go`, `curl`, `patch`. **Not git** — the source arrives as a
tarball, so there is no clone and no working tree to maintain.

`cocx` ships this directory to the mail host and runs it there; you rarely run it by
hand. `./build.sh --series-hash` prints the hash of every build input — the second half
of the build stamp, so a change to ANY file here (not only the patches) forces a rebuild.

## Why a patch series and not a fork

mox has no useful release cadence, so this project tracks `main` and rebuilds on every
deploy. A fork would force a choice between "current mox" and "our features" every
single time. A series that re-applies to today's `main` keeps both.

**Upstream will never take this patch.** Issue
[#23](https://github.com/mjl-/mox/issues/23) ("anti-featurerequest: don't add PGP/S-MIME
signing") is closed with the author agreeing PGP "is best left to clients". So the series
is permanent, and it is designed to survive rebases rather than to be merged:

- everything that can live in a **new file** does (`webmail/pgp.ts`, `webmail/openpgp.js`)
  — new files cannot conflict, ever;
- the edits to upstream files are three hunks totalling **33 added lines**, each anchored
  on text that has been stable for years;
- `tools/regen-patches.sh` has an explicit allowlist of patchable upstream files. Adding
  a path to it is a deliberate decision to accept future rebase pain for that file.

We agree with upstream's reasoning, incidentally: the webmail **is** a client, and that
is exactly where the key lives here.

## The control, and why it is the most important thing in this directory

Before applying anything, `build.sh` rebuilds **upstream's own `webmail.js` from
upstream's own TypeScript** and asserts it comes out byte-identical to the file upstream
ships.

That check is what makes the whole approach trustworthy. `webmail.js` is 322 KB of
generated code committed to upstream's repo. If our toolchain differed from theirs even
slightly — a tsc minor version, a line ending, a lost tab — regenerating it would rewrite
the entire file, our patch would be indistinguishable from toolchain noise, and a patch
that *failed to apply* would look exactly like one that worked.

It passes today: `tools/tsc.sh` and `tools/unexpand.mjs` are transcriptions of upstream's
`tsc.sh` and `unexpand.go`, using the tsc and esbuild versions pinned in upstream's own
`package.json`.

⚠ **Do not "clean up" the flags in `tools/tsc.sh`.** They are copied verbatim from
upstream. `--strict`, `--noUnusedLocals` and `--noImplicitReturns` are what make `pgp.ts`
fail the build instead of shipping a silent bug; `--newLine lf` plus the unexpand pass
are what make the control possible at all.

## The other check: tree-shaking

esbuild drops any export of `pgp.ts` that `webmail.ts` does not reach. This bit us once:
the TypeScript compiled, the patch applied, the Go build succeeded, the binary shipped,
encrypted mail even decrypted — and **the entire key-management UI did not exist**,
because nothing imported `pgpKeysView`. There was no way to get a key in, so the feature
was unusable, and nothing anywhere said so.

`build.sh` now greps the bundle for one marker per UI path, plus a deliberately bogus
marker as a control (a grep that matches everything proves nothing). If you add a feature
reachable only from a new entry point, add a marker.

⚠ **Markers must be ASCII, and `build.sh` enforces it.** esbuild escapes non-ASCII in
string literals — `'Look up…'` is emitted as the seven characters `Look up…` — so a
marker containing so much as an ellipsis can never match. That cost a build cycle: the
check failed and confidently reported tree-shaking while the feature was present and
correct, which is the same class of misleading diagnostic the check exists to prevent.
There is now an explicit pre-check that rejects a non-ASCII marker with the real reason,
and the tree-shaking message is phrased as the likely cause rather than the only one.

## What it does

**Reading.** Opening a `multipart/encrypted` or `multipart/signed` message hands
rendering to `pgpRender()`:

- **Detection is structural**, from mox's own `api.Part` tree — the RFC 3156 shape, not
  a guess from filenames or content types. A `.asc` attachment on an ordinary message is
  not an encrypted message, and a signed message is not an encrypted one.
- **Byte-exact signature verification.** mox's `ParsedMessage` carries
  `HeaderOffset`/`BodyOffset`/`EndOffset` into the raw file, so the signed entity's exact
  transmitted octets are addressable directly. RFC 3156 §5 signs headers *and* body as
  sent; verifying anything a parser has decoded fails as `invalid`, i.e. it accuses every
  correctly signed message of being forged.
- **Decryption happens in the browser**, over `/msg/<id>/raw`, with keys from IndexedDB.
- The decrypted payload is a complete MIME entity and is parsed here (minimally: text,
  alternative, mixed, attachments), because the server never sees it and there are no
  offsets to lean on. Anything unparseable degrades to showing the decrypted bytes as
  text — better than an error.
- **Four distinct signature states.** Valid-and-verified, valid-but-key-never-verified,
  BAD, and unsigned. "Signed" alone is not a verdict, and rendering the middle two alike
  teaches people to ignore the banner.
- HTML parts render only on request, in an **empty `sandbox`** iframe. mox's normal HTML
  view is protected by a server-side CSP that a decrypted body cannot use, so the
  containment is rebuilt client-side. Decrypting something does not make it trustworthy.

**Keys.** A `PGP` button beside `Settings` opens the keyring: import, generate, mark
verified (confirmed by fingerprint), export public key, delete (confirmed by typing the
last 8 fingerprint characters). Private keys are stored S2K-passphrase-encrypted; an
unprotected key pasted in is re-encrypted before it is written. The passphrase is never
stored — unlock is per session, in memory.

**Sending.** A checkbox in the compose window, next to the TLS selector. mox's
`SubmitMessage` composes the MIME itself and cannot express `multipart/encrypted`, so the
series adds **one field** to it — `PGPEncrypted`, the ASCII armor:

- **The armor, not a raw MIME message.** The server keeps control of every header, so a
  compromised or buggy client cannot inject a `Bcc`, a second body or a forged `Date`
  into a message this server DKIM-signs and sends under our domain's reputation. Go-side
  `xpgpArmor()` validates it is a real armored MESSAGE (not a key block, not a signature,
  not arbitrary text), rejects anything outside printable ASCII, and normalises to CRLF.
- The plaintext MIME entity is built in the browser, encrypted to every recipient's key
  **plus our own** — without encrypt-to-self the copy in `Sent` is unreadable forever,
  and that is not fixable after the fact.
- **A missing key refuses the send.** Never a fallback to plaintext.
- Signed when the key is unlocked; if it is locked you get one prompt, and sending
  unsigned needs an explicit confirmation.
- **Bcc uses hidden recipients.** On an encrypted message every recipient's key ID is in
  the PKESK packets, so plain Bcc is not blind — openpgp's `wildcard` replaces them all
  with an all-zero key ID. Only used when there is a Bcc, since it costs recipients a
  trial decryption per key.
- ⚠ **The Subject is not encrypted** — RFC 3156 leaves it in the outer header. The
  checkbox's tooltip says so.

**Key discovery.** Three sources, none of which establishes trust — everything discovered
lands as `unverified` and still needs a fingerprint compared out of band. Discovery
answers "is there a key claiming to be this address", never "is this really them".

| Source | Where | Needs a proxy? |
|---|---|---|
| **Autocrypt** | the `Autocrypt:` header on mail they already sent | no — no network at all |
| **WKD** | the address's own domain, so the most authoritative | **yes** — see below |
| **HKPS** | keys.openpgp.org | no — it sends `access-control-allow-origin: *` |

Autocrypt shows an offer bar above any message carrying a key we do not hold — including
plaintext ones, since a first contact is rarely encrypted. If the sender's key differs
from one already held, it says so loudly rather than importing over it: that means either
a rotation or a message that is not from them. WKD/HKPS are reachable from the keyring
("Find someone's key") and from the compose indicator, which offers "Look up…" for any
recipient with no usable key.

⚠ **WKD is the reason there is a Go file in this series.** WKD is defined for mail
clients and WKD hosts send no CORS headers — measured against a live host:
`openpgpkey.gnupg.org/.well-known/openpgpkey/gnupg.org/hu/nq6t9teux7edsnwdksswydu4o9i5es3f`
returns 200 with a real 2,517-byte key and **no `Access-Control-Allow-Origin`**, so the
browser is blocked before it sees the bytes. `webmail/pgpwkd.go` proxies it. That makes
the mail server fetch a URL named by a logged-in user, i.e. an SSRF primitive, so it is
behind the webmail session, validates the domain, refuses redirects, caps size and time,
and checks the address **at dial time** (`net.Dialer.Control`) against private, loopback,
link-local, CGNAT and multicast ranges — pre-resolving would lose to DNS rebinding. It
returns the bytes unvalidated as a key on purpose: mox vendors no OpenPGP implementation,
and openpgp.js in the browser does that check, so a host answering 200 with an error page
is a miss rather than a hit.

### The generated API bindings are regenerated, not patched

`webmail/api.json` and `webmail/api.ts` are derived from `webmail/api.go` by upstream's
own vendored tooling (`go tool sherpadoc` → `go tool sherpats`). `build.sh` runs both.

They are **not** in `patches/`, deliberately: they are generated files that upstream
rewrites whenever its API changes, so patching them would conflict constantly *and* leave
two sources of truth for one Go struct. Both are byte-reproducible from a pristine tree —
which `build.sh` verifies as a control, exactly like the `webmail.js` one — so
regenerating them is safe.

⚠ **Order matters and is enforced.** Codegen must run before `tsc`, because the
`webmail.ts` hook references `SubmitMessage.PGPEncrypted`, which does not exist in
`api.ts` until the patched Go has been reflected. Getting it wrong is a loud tsc type
error, not a silent miscompile — which is the right way round.

## Verified end-to-end against a running mox (2026-08-12)

`mox localserve` (accepts all mail, loops submissions back to itself) plus a headless
browser. Reproduce with `./out/mox localserve -dir /tmp/moxls`, then
http://localhost:1080/webmail/ (mox@localhost / moxmoxmox).

| Checked | Result |
|---|---|
| `GET /webmail/openpgp.js` | 200, 394,552 bytes, `application/javascript`; a bogus path 403s |
| Lazy load | the browser fetched openpgp.js only on first PGP use |
| Keyring UI | opens, generates a v4 ECC key, shows the fingerprint in groups of four |
| Revocation certificate | prompted exactly once, not stored |
| Compose checkbox | "Encrypt with OpenPGP" present next to the TLS selector |
| Recipient indicator | live "— key found for all 1 recipient(s)" |
| Encrypt in browser | 724 bytes of armor, signed |
| `MessageSubmit` w/ `PGPEncrypted` | accepted; message composed as `multipart/encrypted; protocol="application/pgp-encrypted"` with the `Version: 1` and `encrypted.asc` parts |
| **Plaintext on the wire** | **absent** — the marker string appears nowhere in the raw message |
| DKIM | the delivered copy carries a `DKIM-Signature`; mox still signs a PGP body |
| Detection on read | classified `pgp-mime`, ciphertext at part `1.2`, from the real message |
| **Decrypt in the UI** | **"Decrypted in your browser." + the plaintext**, in mox's own message pane |
| Signature banner | "Signed by Mox Test <mox@localhost> — key verified out of band." |
| Locked state | "This message is encrypted. Unlock your private key to read it." + Unlock button |

⚠ **One step is NOT verified: clicking the compose Send button in headless Chrome.**
It reproducibly blocks the renderer — zero CPU on every renderer process, no JS error,
no unhandled rejection, and no request reaching the server. Everything it is made of
works in that same browser: `decryptKey` (134 ms), `encrypt` (724 bytes), the recipient
scan, and `MessageSubmit` with a real `PGPEncrypted` payload posted from page JS, which
produced a correctly encrypted delivered message. So the crypto, the MIME building, the
API field and the server composition are all proven; only the click path through mox's
`withStatus`/fieldset wrapper is not. It looks like a headless-automation artifact
rather than a defect, but that is **not proven** — click Send once in a real browser
before trusting it.

### A real bug this testing found

`idb()` opened the keyring at a fixed version 1 and created the object store in
`onupgradeneeded`. If the database already existed at version 1 *without* the store, no
upgrade fires, so the store was never created and every read threw `NotFoundError`
forever — and `refresh()` had no catch, so the pane rendered "No keys yet." A broken
keyring and an empty one looked identical. Now `idb()` opens at whatever version exists
and reopens one higher to create a missing store, and a failed read renders an error
instead of an empty list.

## Traps

1. **`openpgp.js` is a separate file, not bundled.** mox's `WebappFile` INLINES
   `webmail.js` into the HTML of *every* page load, so bundling ~400 KB of crypto there
   would be paid on every request by every user and cached by nobody. It is fetched
   lazily on first PGP use. Keeping it unmodified and unbundled also keeps LGPL
   compliance simple.
2. **Keys are per browser profile.** Clearing site data, or using another device, means
   importing again. There is no server-side copy — that is the design, not an oversight.
3. **`mox version` cannot identify a patched build.** Built from a source tree it reports
   `(devel)-go1.26.5` with no commit, so a version regex finds nothing and would
   rebuild on every update forever. `build.sh` writes `out/mox.buildstamp`
   (`<upstream-commit> <series-hash>`) instead, which also catches *our* patches changing
   — something `mox version` never could.
4. **A rebase failure is loud and localised.** `build.sh` aborts naming the patch, and
   `patch` leaves `.rej` files in `mox/.build/mox-<sha>/`. Fix the tree there, then
   `./build.sh --regen`. Prefer moving the fix into `pgp.ts`, where it cannot conflict
   again.
5. **`npm ci` runs a third party's `package.json`** on the build host, so it runs with
   `--ignore-scripts`.
6. **Never edit the build tree** expecting it to persist — it is wiped and re-extracted
   on every run, and `--regen` is the only thing that reads changes back out of it.
7. **The build tree lives OUTSIDE the repo** (`/tmp/mox-pgp-build`, override with
   `MOX_BUILD_DIR`; cocx uses `/home/mox/.build`). On network and shared filesystems
   (9p, SMB, some FUSE mounts) `rm -rf` on a deep tree intermittently fails with
   "Directory not empty" — hit for real on mox's `vendor/golang.org/x/text`, which
   stopped the build before it could start. It is also much faster on local disk.
