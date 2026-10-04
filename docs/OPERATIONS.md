# Operating a cocx mail server

The map of how the pieces fit, and — more usefully — the traps each one hides. Almost
every failure below is **silent**: mail keeps flowing on one path while another is broken,
and the only evidence is in places nobody reads by default. `cocx check` exists to read
them for you; this document explains what it is checking and why.

**Everything here is reproduced by `cocx`.** Do not hand-configure the box — change
`cocx.conf` (or cocx itself) and re-run. Every run reconciles the whole state, so manual
drift is repaired rather than discovered.

## Contents

1. [Updating — the run IS the update mechanism](#updating)
2. [Topology](#topology)
3. [IPv6 — five parts, all or nothing](#ipv6)
4. [DNS](#dns)
5. [DANE and DNSSEC](#dane-and-dnssec)
6. [MTA-STS, CAA, TLS policy](#mta-sts-caa-tls-policy)
7. [Deliverability](#deliverability)
8. [Role addresses and probing](#role-addresses-and-probing)
9. [The junk filter](#the-junk-filter)
10. [Backups, restore, reset](#backups-restore-reset)
11. [File map](#file-map)

## Updating

mox's admin UI warns that `CheckUpdates` is disabled. That is deliberate: mox's updater
watches tagged **releases**, and cocx tracks upstream **`main`**, which runs ahead of them
and carries fixes the releases do not. Keeping current is instead the job of `cocx`
itself — run it (from a cron job or your deploy pipeline) and mox moves to the latest
upstream commit.

That only works if updating is cheap, or people stop running it. So the host keeps a
stamp, `/home/mox/.mox-buildstamp` = `<upstream commit> <series hash>`, and the ~2 minute
build is skipped when both match. The series hash covers **every** file in `mox/` (see
`mox/build.sh --series-hash`), so a change to any part of the patch series — not only the
`.patch` files — forces a rebuild.

`mox version` cannot do this job: built from a source tree it reports `(devel)-go1.x.y`
with no commit, and it could never see a change to the patches.

Safety: the build writes `mox.new`; it is swapped in only after `mox config test` passes
against the live config, and the previous binary is kept as `mox.prev`. `cocx rollback`
swaps back (and clears the stamp so the next run rebuilds).

## Topology

### `WEBSERVER=caddy` / `caddy-external`

```
          :80/:443  Caddy (reuse_private_keys, issuer pinned)
             │
  mta-sts.D, autoconfig.D ──────────── reverse_proxy ──> 127.0.0.1:81   mox: MTA-STS policy, autoconfig
  mail.D  /webmail/ /webapi/ / ─────── reverse_proxy ──> 127.0.0.1:1080 mox: webmail, account (PUBLIC_WEBMAIL=yes)
          /admin* ──> 404                                127.0.0.1:1080 mox: admin — via `cocx tunnel` only
          /bimi/  ──> file_server /var/lib/cocx/bimi

  :25 / :465 / :993 ─────────────────────────────────> mox directly, public v4 + v6
```

1. **mox does no ACME.** It runs `quickstart -existing-webserver`: it binds neither 80
   nor 443 and obtains no certificates. Caddy obtains them through cocx's vhost and mox
   reads the files straight out of Caddy's storage. Remove the vhost and mail keeps
   listening on 25/465/993 with a certificate that quietly expires.
2. **Renewal needs a mox restart.** Caddy renews in place; mox reads certificates only at
   startup. `mox-certwatch.path` watches the certificate and runs
   `/usr/local/sbin/cocx-sync-hostkey`, which re-syncs the DANE key copy and restarts mox.
   Without it, mail TLS expires ~60 days after the last restart with no error anywhere.
3. **The issuer is pinned.** Caddy's default is Let's Encrypt with ZeroSSL as a silent
   fallback. mox reads from a path that contains the issuer's directory name, so a
   fallback would leave mox serving the old certificate until it expired. Pinned, a
   failure is loud in Caddy's log instead. (`CADDY_ISSUER=letsencrypt-staging` for trial
   runs; `internal` for tests only.)
4. **Caddy ≥ 2.8 is enforced by version, not presence.** `reuse_private_keys` does not
   exist before 2.8, and distro repositories still ship 2.6. A guard on "is caddy
   installed" silently keeps the old one.
5. **The stock Debian Caddyfile** (a `:80` placeholder site) is replaced by a minimal one
   that imports `/etc/caddy/cocx-mail.caddy`. Any other Caddyfile is kept and only gains
   the import line, so cocx can share a Caddy with your other sites. Every vhost change
   is `caddy validate`d before reload and rolled back if rejected.
6. **`/` on mta-sts/autoconfig redirects to `ROOT_REDIRECT`** — exactly `/`, never a
   prefix. Search engines find these hostnames through Certificate Transparency logs and
   report mox's 404 as a crawl error. A prefix redirect would break Thunderbird
   autoconfig, whose path (`/mail/config-v1.1.xml`) is not under `/.well-known/`. And do
   not add a `robots.txt` `Disallow`: it blocks the fetch, so the crawler never sees the
   redirect and the 404 stays indexed.

### `WEBSERVER=mox`

mox owns 80/443 and does its own ACME. Webmail/account/webapi are enabled on the public
listener when `PUBLIC_WEBMAIL=yes` (account at `/account/`, since `/` would swallow every
other path); admin stays on the loopback listener. The BIMI logo and the `/` redirects are
mox `WebHandlers` named `cocx-*` in `domains.conf`, reconciled on every run — handlers you
add yourself are never touched. No cert-watch unit is needed: mox renews and reloads its
own certificates.

## IPv6

mox **sends over IPv6 whenever the box has it**, even when only IPv4 is configured. From
mox's own config documentation: *"If both outgoing IPv4 and IPv6 connectivity is possible,
and only one family has explicitly configured addresses, both address families are still
used for outgoing connections."* So "IPv4 only" is not an option on a dual-stack box —
removing the v6 listen address only stops the address being **declared**, and then mail
leaves from an address that is in neither SPF nor reverse DNS.

That failure is invisible. DKIM still aligns, so DMARC passes and nothing bounces. The only
evidence is in DMARC aggregate reports, as `spf=fail` and Google's
`550-5.7.25` (sender has no reverse DNS) on every v6-sent message.

cocx declares v6 end to end. The fix is five interlocking parts, all or nothing:

| # | Part | Done by |
|---|---|---|
| 1 | v6 firewall opens 25/465/993 | `open_ports` (v4 **and** v6 chains) |
| 2 | mox listens on the v6 address | quickstart's listener is kept, never stripped |
| 3 | SPF carries `ip6:` | emitted by `mox config dnsrecords` once (2) holds |
| 4 | the mail hostname has an `AAAA` | final DNS sync |
| 5 | v6 PTR → mail hostname | provider hook `set-rdns` (both families) |

⚠ **The AAAA goes last.** Senders try AAAA first, so an AAAA published while the v6 firewall
is closed or mox is not listening on v6 blackholes inbound mail — while v4 keeps working
and every ordinary check stays green. cocx publishes only the A record before
certificates, and the AAAA in the final sync.

⚠ Forward-confirmed rDNS needs **both** directions: PTR → hostname *and* hostname → IP.

`cocx check` verifies all five, explicitly, because nothing else will tell you.
`IPV6=off` is only for boxes with no usable v6; on a box that has global v6 it is flagged,
because mox will send over it anyway.

## DNS

The **source of truth is `mox config dnsrecords <domain>`** on the mail host — never a
hand-maintained list. DKIM rotation, a new MTA-STS policy id, or DANE records appearing
after DNSSEC is validated all flow through on the next run.

| Record | Purpose |
|---|---|
| `mail` A + AAAA | the SMTP host (added by cocx; mox does not emit them) |
| `@` MX | inbound routing |
| `@` TXT SPF, `mail` TXT SPF | `ip4:`/`ip6:` + `mx`; the host's own SPF for DSNs |
| `<year>a/b._domainkey` TXT | DKIM, two active keys; spares are a config change away |
| `_dmarc` TXT | `p=reject` with aggregate reporting |
| `mta-sts` CNAME + `_mta-sts` TXT | MTA-STS policy (`mode: enforce`) |
| `_smtp._tls` TXT (×2) | TLSRPT for the domain and the host |
| `_25._tcp.mail` TLSA | DANE — held back as PENDING until the zone validates |
| `autoconfig` CNAME, `_autodiscover/_imaps/_submissions._tcp` SRV | client autoconfiguration |
| `_imap/_submission/_pop3/_pop3s._tcp` SRV `0 0 0 .` | RFC 2782 "not offered" — mox only enables 465 and 993 |
| `default._bimi` TXT | BIMI logo — published only once the logo URL actually answers |

- **Never proxy a mail record** (Cloudflare grey cloud only). An MX pointing at anycast
  IPs blackholes inbound mail; proxied mta-sts/autoconfig break certificate issuance for
  hostnames the mail listeners share.
- **Records are updated in place, never deleted and recreated.** A delete-then-create
  leaves a window in which the MX does not resolve, cached by resolvers for the TTL.
- **Pruning is opt-in** (`cocx dns --prune`). Orphans — a retired DKIM selector — are
  reported on every run and deleted only on request. The deletion scope is a strict
  allowlist of mail-only record shapes, because the zone usually also holds a website; at
  the apex, only a `v=spf1` TXT is in scope, never a verification token sharing the name.
  CAA is never in scope.
- **The `.` SRV target is valid on Cloudflare** (it rejects only the empty string). An
  assumption to the contrary once made mox's own DNS check report gaps.
- **Verify over DoH, never `dig`.** A resolver that was asked for a record before it
  existed caches the negative answer for the zone's SOA minimum (often 30 minutes), and
  keeps reporting it missing after it is published. `DNS_PROVIDER=manual` and `cocx check`
  use DoH for this reason. General rule: a negative DNS result means nothing unless
  something you **know** exists is found by the same method in the same cache state.
- **`/etc/hosts` can defeat a correct PTR.** Go reads `/etc/hosts` before DNS, so a
  provider-image line mapping the public IP to another name makes mox report an iprev
  mismatch while the public PTR is right. cocx removes such lines (and warns when
  cloud-init would restore them on reboot). Do not use an inbound message's `iprev=pass`
  as evidence about your own rDNS — that field describes the sender.

## DANE and DNSSEC

DANE pins the SHA-256 of the TLS public key in DNS. It is the strongest part of this setup
and the easiest to break catastrophically: once a TLSA is published and the zone is signed,
a mismatch does not degrade — DANE-enforcing senders refuse the mail.

Three conditions, each of which silently disables DANE:

1. **A stable key.** In the Caddy modes, `reuse_private_keys` keeps the key across
   renewals. In mox mode, mox's own host keys (RSA + ECDSA in `config/hostkeys/`) never
   rotate, and it publishes one TLSA per key.
2. **mox must be able to read it.** mox opens `HostPrivateKeyFiles` as the unprivileged
   `mox` user, unlike certificates, which root opens. Caddy's key is private to the caddy
   user, so mox would refuse to start. cocx keeps a mox-owned copy
   (`config/dane-mail.key`) re-synced on every renewal. `HostPrivateKeyFiles` is a child
   of `TLS` (three tabs), a sibling of `KeyCerts` — at two tabs mox rejects it.
3. **A validated zone, seen through a validating resolver.**
   - The DNS host signs the zone (cocx enables it on Cloudflare); the **DS record goes
     to the registrar**, because it lives in the parent zone. No DNS API can do this —
     `cocx ds` prints it.
   - mox decides whether to publish/honour TLSA by asking its resolver for the AD bit.
     Provider resolvers rarely validate, so cocx runs **unbound** on loopback, first in
     `resolv.conf`, with the previous resolvers kept below as a fallback (resolution
     degrades instead of failing if unbound dies). `resolv.conf` is only touched after
     unbound is proven to answer with AD.
   - **`options trust-ad` is required.** Go discards the AD bit unless every nameserver
     is loopback or this option is set. Without it mox reports "Domain does not appear to
     be DNSSEC-signed" forever while `dig` plainly shows AD. Safe with the fallbacks: they
     never set AD, so a dead unbound degrades DANE to "not validated", fail-safe.
   - **After adding the DS, flush unbound**: it cached the signed proof that no DS
     existed. `unbound-control flush_zone <domain>` and the parent TLD.

`cocx check` compares the published TLSA against the key actually served on port 25 — the
one drift that otherwise shows up only as mail that stops arriving.

**Key rollover.** In the Caddy modes one TLSA is published, deliberately: the key does not
rotate, and a spare "next" key Caddy never uses is a standing source of confusion. When
you do plan a rotation, **add the rollover first**: put the next key as a second
`HostPrivateKeyFiles` entry (mox emits a second TLSA), `cocx dns`, wait well past the TTL,
switch the web server to the new key, then drop the old entry and `cocx dns --prune`.

## MTA-STS, CAA, TLS policy

- **MTA-STS `max_age` is one week** (quickstart writes one day). Senders cache *and
  enforce* the policy for that long: longer is stronger against an active attacker and
  slower to recover from a mail-host change. ⚠ Change the **policy first**, then DNS, and
  every change needs a new `PolicyID` — senders compare it to decide whether to refetch.
  cocx does both, in that order.
- **CAA is additive only.** It lists every issuer the web side might use (Caddy's ZeroSSL
  fallback is `sectigo.com`) plus an `iodef` to your mailbox. Cloudflare injects its own
  CAA records the moment any exists on a zone with Universal SSL, including `issuewild`;
  they are load-bearing, so never delete them and never publish `issuewild ";"`.
- **Cipher suites.** Scanners flag two TLS 1.2 CBC suites on port 25. mox has no
  cipher-suite setting; the only lever is `MinVersion: TLSv1.3` on the public listener.
  It is deliberately **not** set: under MTA-STS enforce and DANE, a sender that cannot
  complete a verified handshake does not fall back to plaintext — it fails to deliver. A
  TLS 1.3 floor would silently lose mail from TLS 1.2-only senders to fix a policy score.

## Deliverability

**Outbound port 25** is blocked by default at many hosts, while inbound is not — so mail
arrives fine and the outbound queue silently backs up. `cocx check` reads a real `220`
banner from Google's MX, not merely an open socket. Probe ports against a host that
listens on them: an MX serves only 25, so testing 587 there reports "blocked" with no
firewall at all. While 25 is blocked, mox's queue fills with its own DMARC aggregate
reports; leave them — they deliver once it opens, and the queue draining is the clearest
sign that it has.

**rDNS** for every sending address must equal the mail hostname. Both are provider
account settings: implement them in a [provider hook](../README.md#provider-hooks).

**Other tooling that rebuilds the firewall** (a deploy script that flushes `INPUT` and
re-adds its own port list) wipes the mail ports — and inbound mail stops while every web
check stays green. Re-run `cocx update` after such a run, or teach that tool about 25,
465 and 993 for both address families.

**Blocklists** — `cocx blocklists`. It queries from the host through its own resolver,
because Spamhaus refuses public resolvers and answers `127.255.255.x`, an error code that
parses as "listed". It distinguishes clean / listed / refused, and runs the standard
positive controls first (`127.0.0.2`, `dbltest.com`): a clean sweep with failing controls
means the queries are broken, not that you are clean.

**A new domain lands in spam at first**, with everything correctly configured. mail-tester
10/10 and zero listings do not override reputation, which needs domain age and history.
What helps: recipients marking "Not spam"; Google Postmaster Tools (it reuses a Search
Console TXT if you have one). What not to do: route through a smarthost — it discards the
DANE/DNSSEC chain, and the advice is for tainted IPs; pay-to-delist services that relist.
Microsoft is a separate regime (SNDS, JMRP), unaffected by public reputation.

**Rejections are usually mox being right**: `spf-policy` (the sender's own domain forbids
that IP), `iprev fail` (raises the junk threshold), a 451 on first contact from a sender
with no reputation (legitimate servers retry). Rejected mail is kept briefly in the
account's **Rejects** mailbox. Test acceptance from a real provider mailbox; a hand-rolled
SMTP client usually fails SPF and teaches nothing.

## Role addresses and probing

- `postmaster@` needs no configuration: mox routes it for every domain via `mox.conf`
  `Postmaster`. `abuse@` has no such case and is what blocklist operators and feedback
  loops write to — when it bounces, a complaint becomes a listing. cocx adds every name in
  `ROLE_ADDRESSES` (default `abuse`).
- ⚠ **mox answers `250` to `RCPT TO` for every address** and rejects unknown ones only at
  `DATA` (`550 5.1.1 no such user`). An RCPT-only probe reports every address as valid.
  Carry a known-bogus control address through `DATA`.
- ⚠ Probing with `MAIL FROM:<…@example.com>` is refused (`550 5.7.27`): example.com
  publishes a null MX. Use a mail-configured sender domain. With Python's `smtplib`, use
  `s.mail()`/`s.rcpt()` — `docmd('MAIL FROM:', ...)` inserts a space mox rejects.

## The junk filter

mox cannot filter on message bodies: its rulesets match headers only, their only action is
"deliver to mailbox", and it has no milter/sieve hook. So `filter/mail-filter.js` runs
**after delivery, over IMAP**, every `JUNK_FILTER_INTERVAL`, and moves junk to `Junk`.

That is not a consolation prize: quickstart sets `AutomaticJunkFlags` with
`JunkMailboxRegexp ^(junk|spam)`, so every move **trains mox's bayesian filter**, which
does run at SMTP time — and which classifies nothing at all while the Junk mailbox is
empty.

**Scoring, not a keyword list.** Scam pretexts rotate (Nigeria → Syria → Ukraine → Gaza);
the advance-fee *structure* does not. A verdict needs `score ≥ threshold` **and** two
categories scoring at least `minCategoryScore`, or one `solo` category maxed out.

| Category | Cap | Solo | Signal |
|---|---|---|---|
| `structural` | — | — | To == From, placeholder To, not addressed to us, replies steered to another freemail address, freemail sender |
| `advance_fee` | 8 | yes | the money skeleton |
| `appeal` | 6 | no | "Dear Friend", "urgent help" |
| `crisis_pretext` | **4** | **no** | capped **below** the threshold: naming a conflict can never convict alone |
| `seo_outreach` | 6 | yes | backlink/ranking pitches |

Lessons the ham tests encode: a 1-point signal must not count as a whole category; a
forwarded abuse report *contains* the scam, so quoted text is split off and capped (not
discarded — or a pasted "Original Message" line would be a bypass); and fixtures must be
the real wording, not a paraphrase. **It never deletes**, and it keeps a UID high-water
mark so a message you rescue from Junk is not re-judged. The account's own domain is
always allowed: mox enforces your DMARC `p=reject` at SMTP time, so outsiders cannot
forge it.

```sh
cocx filter-dry-run           # score everything new, move nothing; names every signal
cocx filter-explain <uid>     # one message, full breakdown
journalctl -u cocx-mail-filter
```

Tune per box by copying `filter/rules.json` to `/etc/cocx/mail-filter-rules.json` on the
host (cocx then points the unit at it). Credentials are in `/etc/cocx/mail-filter.env`,
read only by systemd — **never `source` it**: generated passwords can contain `#`, which a
shell truncates as a comment and which then fails as an IMAP auth error.

`cocx check` treats the filter as three separate facts — timer active, credentials
present, sweeps completing — because each fails independently, and "timer active, zero
sweeps" means it never succeeds.

## Backups, restore, reset

**Backups** run nightly at `BACKUP_TIME` as `/usr/local/sbin/cocx-backup`:

- **`mox backup`, never tar of the data directory.** mox's databases are held open by the
  running server; mox's docs are explicit that copying them live can produce unusable
  files. A tar would *usually* restore — the worst failure mode a backup can have.
- Every snapshot is checked with `mox verifydata` before it is kept, the archive is
  re-read, and its content is asserted (both config files, the DKIM keys, the databases,
  and the DANE host keys in mox mode) — a byte count alone accepts a structurally wrong
  archive.
- Rotation is count-based (`BACKUP_KEEP`, daily/weekly/monthly via hardlinks), so missed
  runs do not delete history.
- ⚠ The archive holds the DKIM private keys and every message: directory 0700, files
  0600. **Backups are local to the box** — copy them off-host for disaster recovery.

**Restore**: `cocx restore <archive> --yes`. mox is stopped, the live `config/` and
`data/` are moved to `restore-aside-<time>/` (never deleted), the archive is unpacked and
config-tested, and if mox does not come up on it the previous state is put back.

**Reset** (`cocx reset --yes`) empties every mailbox and stashes the four report
databases behind the admin DMARC/TLS summaries, keeping all configuration — a clean
baseline when old noise hides a new problem. A verified backup runs first and a failure
aborts; mox is stopped while the databases move (they are held open); the databases are
stashed, never deleted (`cocx restore-reports <stash>`); and the reset verifies the server
still works, because an empty mailbox is also exactly what a broken server looks like.

## File map

| On the host | |
|---|---|
| `/home/mox/{mox,mox.prev,config/,data/}` | mox; `.mox-buildstamp`; `patchsrc/` build inputs |
| `/root/cocx-quickstart.out` | generated passwords (0600) — `cocx credentials` |
| `/etc/caddy/cocx-mail.caddy` | the mail vhost (caddy mode); `/etc/cocx/caddy-mail.caddy` for caddy-external |
| `/usr/local/sbin/cocx-sync-hostkey` | DANE key copy + restart, run by `mox-certwatch.path` |
| `/etc/unbound/unbound.conf.d/cocx.conf` | the validating resolver |
| `/opt/cocx/filter/`, `/etc/cocx/mail-filter.env` | junk filter + its credentials |
| `/usr/local/sbin/cocx-backup`, `/etc/cocx/backup.env`, `BACKUP_DIR` | backups |

Change passwords with `mox setaccountpassword` / `mox setadminpassword` on the host; the
filter's copy is in `/etc/cocx/mail-filter.env`.
