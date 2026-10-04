# cocx

**mox, but ours.** A fully featured self-hosted mail server — [mox](https://www.xmox.nl/)
built from upstream `main` with an OpenPGP webmail patch series — and the tooling to
install it on a bare Debian/Ubuntu box, keep it current, and prove it is healthy.

One command provisions a bare machine and updates a live one:

```sh
cp cocx.conf.example cocx.conf   # edit: domain, host, web/DNS modes
./cocx                           # install if absent, update if present, then health-check
```

## What you get

| Area | What cocx sets up |
|---|---|
| Server | mox from upstream `main` + the [OpenPGP series](mox/README.md) (encrypt/decrypt/sign in webmail, keys never leave the browser, Autocrypt/WKD/HKPS discovery). Rebuilt only when upstream or the series changes; previous binary kept for `cocx rollback`. |
| TLS | Caddy (installed and managed, or your own) with key reuse pinned for DANE, **or** mox's own ACME. Certificate renewals are picked up automatically. |
| Authentication | SPF (v4 **and** v6), DKIM (two active selectors + spares), DMARC `p=reject` with reporting, rDNS checked for both families |
| Transport security | MTA-STS `enforce` (1-week max age), TLSRPT, DANE (TLSA) behind a local DNSSEC-validating resolver |
| DNS | The whole record set from `mox config dnsrecords`, synced to Cloudflare (DNS-only, update-in-place, opt-in prune) or printed and **verified over DoH** for any DNS host. DNSSEC signing, CAA. |
| Inbox | BIMI logo (self-asserted), autoconfig/autodiscover, `abuse@` + `postmaster@`, optional public webmail (admin UI tunnel-only) |
| Junk | A body-aware scoring filter that moves junk to Junk over IMAP — which also trains mox's SMTP-time bayesian filter |
| Ops | Nightly `mox backup` snapshots, verified and rotated (7/4/6); `restore`; a clean-baseline `reset`; `check` covering every fact that silently breaks mail |

## Requirements

- **Target**: Debian 12+/Ubuntu 22.04+ with systemd, root or passwordless sudo. Ports 25,
  465, 993 reachable (and 80/443 for ACME). Go and Node are installed from upstream with
  checksums verified — the build runs on the box.
- **Operator machine**: bash, ssh, python3, curl, tar. Or run on the box with `HOST=local`.
- **Provider**: a PTR you can set, and outbound :25 unblocked. Many hosts block 25 by
  default; `cocx check` tells you. Automate both with a [provider hook](#provider-hooks).

## Configuration

Everything lives in `cocx.conf` ([annotated example](cocx.conf.example)); keep one file
per server and select with `-c`. The decisions that matter:

| Setting | Options |
|---|---|
| `WEBSERVER` | `caddy` — cocx installs Caddy ≥ 2.8 and owns a mail vhost (other sites can share it) · `caddy-external` — you run Caddy; cocx writes the snippet and reads `CADDY_CERT_DIR` · `mox` — mox owns 80/443 and does ACME itself |
| `DNS_PROVIDER` | `cloudflare` (API token at `CF_TOKEN_FILE`) · `manual` (print + DoH-verify) · `none` |
| `PUBLIC_WEBMAIL` | `yes` exposes webmail + account at `https://MAIL_HOSTNAME/`; admin is never public |
| `PROVIDER_HOOK` | executable for rDNS + outbound-SMTP unblocking ([below](#provider-hooks)) |

## Commands

```
cocx                      install or update, then check (the normal command)
cocx check                every silent failure mode, from outside; changes nothing
cocx dns [--prune]        re-sync / print + verify DNS; --prune retires stale records
cocx ds                   the DS record to publish at your registrar (DANE's last link)
cocx set-rdns | open-smtp run the provider hook
cocx filter-dry-run       score new mail, move nothing;  filter-explain <uid> for one message
cocx backup | restore <archive> [--yes] | reset [--yes] | restore-reports <stash>
cocx rollback             previous mox binary
cocx tunnel [port]        SSH tunnel to the admin/webmail UI
cocx credentials          the generated admin + account passwords
```

Destructive commands (`restore`, `reset`) are dry runs unless given `--yes`, and both keep
what they replace (`restore-aside-*/`, `reset-stash-*/`) rather than deleting it.

## Provider hooks

rDNS and outbound-SMTP blocks are hosting-account settings with a different API at every
provider, so cocx defines an interface instead of shipping integrations. Copy
[`hooks/provider.example`](hooks/provider.example) somewhere **outside the repo**,
implement `set-rdns <ip> <hostname>` and `open-smtp` against your provider's API, and set
`PROVIDER_HOOK`. Without one, `cocx check` still verifies both and tells you what to fix.

## Development

```sh
make test     # unit tests: filter, DNS sync (fake Cloudflare + DoH), BIMI, CLI + real Caddy
make lint     # shellcheck everything
make e2e      # real install in a systemd container, both web modes (needs Docker)
make scrub    # secret/identifier scan (also the pre-commit hook: make hooks)
```

`make hooks` enables a pre-commit scan that blocks private keys, assigned secrets, routable
IPs and real email addresses, plus a **private denylist** you keep at
`~/.config/cocx/scrub-denylist` (your domain, IPs, account IDs, secret values). The
denylist lives outside the repo because it is itself the sensitive data.

## Documentation

- [docs/OPERATIONS.md](docs/OPERATIONS.md) — how the pieces fit, and the traps each one
  hides: topology, DNS, DANE/DNSSEC, IPv6, deliverability, the junk filter, backups.
- [mox/README.md](mox/README.md) — the OpenPGP patch series and how it survives rebases.

## Licences

cocx's own code: MIT. mox: MIT (built from source, not vendored). `mox/src/openpgp.js` is
openpgp.js, LGPL-3.0, shipped unmodified as a separate file (see
`mox/src/openpgp.LICENSE`).
