#!/usr/bin/env python3
"""Reconcile the DNS records a mox install needs.

Source of truth is `mox config dnsrecords <domain>` run ON THE MAIL HOST — never a
hand-maintained copy. mox regenerates that zone fragment from its live config, so DKIM
key rotation, a new MTA-STS policy id, or newly-signed DANE records all flow through on
the next run.

Providers:
    cloudflare  create/update records through the API. Everything DNS-only (grey
                cloud): an MX pointing at Cloudflare's anycast IPs silently blackholes
                inbound mail, and proxied mta-sts/autoconfig break certificate
                issuance for the hostnames the SMTP/IMAP listeners share.
    doh         read-only: resolve every desired record over DNS-over-HTTPS and report
                OK / MISSING / DIFFERS. For any DNS host without an API here.

Usage:
    mail-dns.py --records-file F --origin example.com --provider doh
    mail-dns.py --records-file F --origin example.com --provider cloudflare \\
                --token-file T (--zone-id ID | --zone-name example.com) [--apply] [--prune]
    mail-dns.py --records-file F --origin example.com --print-zone

Without --apply the cloudflare provider is a dry run and prints the diff it would make.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

CF_API = os.environ.get("COCX_CF_API", "https://api.cloudflare.com/client/v4")
DOH_API = os.environ.get("COCX_DOH_API", "https://dns.google/resolve")
TTL = 300


# --------------------------------------------------------------------------- parsing
def parse_zone(text, origin):
    """Parse mox's zone fragment into [{'name','type',...}].

    Deliberately narrow: it handles exactly the shapes `mox config dnsrecords` emits
    (incl. TXT split across lines inside parentheses) rather than pretending to be a
    general RFC 1035 parser. A line whose FIRST non-space char is ';' is a comment —
    ';' must not be stripped generally, because TXT values legitimately contain it
    (`v=DKIM1;h=sha256;p=...`).
    """
    records = []
    buf = ""
    depth = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if depth == 0:
            t = line.lstrip()
            # mox comments TLSA records with ";;" until the zone is DNSSEC-signed. Those
            # are not noise — they are the DANE records waiting on DNSSEC, and silently
            # dropping them would hide why DANE never comes up. Surface them as pending.
            if t.startswith(";;") and " TLSA " in t:
                rec = _parse_record(t.lstrip(";").strip(), origin)
                if rec:
                    rec["pending"] = "DANE: waiting for the zone to be DNSSEC-validated (DS at the registrar)"
                    records.append(rec)
                continue
            if t.startswith(";") or t.startswith("$"):
                continue
        for ch, in_q in _scan(line):
            if in_q:
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
        buf += (" " if buf else "") + line.strip()
        if depth > 0:
            continue
        rec = _parse_record(buf, origin)
        if rec:
            records.append(rec)
        buf = ""
    return records


def _scan(s):
    """Yield (char, inside_quotes) so parens inside TXT strings don't confuse depth."""
    in_q = False
    esc = False
    for ch in s:
        if esc:
            esc = False
            yield ch, in_q
            continue
        if ch == "\\":
            esc = True
            yield ch, in_q
            continue
        if ch == '"':
            yield ch, in_q
            in_q = not in_q
            continue
        yield ch, in_q


def _fqdn(name, origin):
    name = name.rstrip(".")
    return name if name else origin


def _parse_record(line, origin):
    line = line.replace("(", " ").replace(")", " ")
    # Optional TTL and class, so cocx's own --print-zone output parses back too.
    m = re.match(r'^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?(TXT|MX|CNAME|SRV|A|AAAA|TLSA|CAA)\s+(.*)$', line.strip())
    if not m:
        return None
    name, rtype, rest = m.group(1), m.group(2), m.group(3).strip()
    name = _fqdn(name, origin)

    if rtype == "TXT":
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', rest)
        content = "".join(parts) if parts else rest.strip('"')
        return {"name": name, "type": "TXT", "content": content}

    if rtype == "MX":
        p = rest.split()
        return {"name": name, "type": "MX", "content": p[1].rstrip("."), "priority": int(p[0])}

    if rtype == "CNAME":
        return {"name": name, "type": "CNAME", "content": rest.split()[0].rstrip(".")}

    if rtype in ("A", "AAAA"):
        return {"name": name, "type": rtype, "content": rest.split()[0]}

    if rtype == "CAA":
        # mox suggests CAA in standalone mode. CAA is reconciled separately and only
        # ADDITIVELY (Cloudflare injects its own CAA records, which are load-bearing), so
        # it is reported here rather than silently dropped.
        return {"name": name, "type": "CAA", "skip": "CAA is managed by cocx's CAA step (CAA_ISSUERS)"}

    if rtype == "SRV":
        prio, weight, port, target = rest.split()[:4]
        # "target ." with port 0 is the RFC 2782 "service not available" marker — it says
        # POP3 and plaintext submission are deliberately not offered (mox only enables
        # 465/993). Cloudflare accepts "." and rejects only the EMPTY string — tested,
        # after an assumption to the contrary made mox's own DNS check report gaps.
        target = target.strip()
        if target.rstrip(".") == "":
            target = "."
        labels = name.split(".")
        return {
            "name": name, "type": "SRV",
            "data": {
                "service": labels[0], "proto": labels[1],
                "name": ".".join(labels[2:]) or origin,
                "priority": int(prio), "weight": int(weight),
                "port": int(port), "target": "." if target == "." else target.rstrip("."),
            },
        }

    if rtype == "TLSA":
        parts = rest.split()
        if len(parts) < 4:
            return {"name": name, "type": "TLSA", "skip": "unparseable TLSA"}
        usage, selector, mtype, cert = parts[0], parts[1], parts[2], parts[3]
        return {
            "name": name, "type": "TLSA",
            "data": {
                "usage": int(usage), "selector": int(selector),
                "matching_type": int(mtype), "certificate": cert.lower(),
            },
        }
    return None


def desired(records_text, origin, extra_a):
    want = parse_zone(records_text, origin)
    for spec in extra_a:
        n, _, ip = spec.partition("=")
        if ip:
            want.insert(0, {"name": n, "type": "AAAA" if ":" in ip else "A", "content": ip})
    pending = [r for r in want if r.get("pending")]
    skipped = [r for r in want if r.get("skip")]
    want = [r for r in want if not r.get("skip") and not r.get("pending")]
    return want, pending, skipped


def zone_line(r):
    """One record back as a zone-file line, for --print-zone (manual DNS)."""
    n = r["name"] + "."
    if r["type"] == "TXT":
        v = r["content"]
        chunks = " ".join('"' + v[i:i + 255].replace('"', '\\"') + '"' for i in range(0, len(v), 255))
        return f"{n:40} {TTL} IN TXT   {chunks}"
    if r["type"] == "MX":
        return f"{n:40} {TTL} IN MX    {r['priority']} {r['content']}."
    if r["type"] == "CNAME":
        return f"{n:40} {TTL} IN CNAME {r['content']}."
    if r["type"] in ("A", "AAAA"):
        return f"{n:40} {TTL} IN {r['type']:5} {r['content']}"
    d = r.get("data") or {}
    if r["type"] == "SRV":
        t = d["target"] if d["target"] == "." else d["target"] + "."
        return f"{n:40} {TTL} IN SRV   {d['priority']} {d['weight']} {d['port']} {t}"
    if r["type"] == "TLSA":
        return f"{n:40} {TTL} IN TLSA  {d['usage']} {d['selector']} {d['matching_type']} {d['certificate']}"
    return f"; unprintable {r}"


# ----------------------------------------------------------------------- cloudflare
def cf(token, method, path, body=None):
    req = urllib.request.Request(
        f"{CF_API}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"success": False, "errors": [{"message": f"HTTP {e.code}"}]}
    except urllib.error.URLError as e:
        return {"success": False, "errors": [{"message": str(e.reason)}]}


def key_of(r):
    return (r["name"].lower(), r["type"], (r.get("data") or {}).get("port"))


# Which records is this tool ALLOWED to consider deleting?
#
# A strict allowlist, not a heuristic, because the same zone usually holds a website: the
# apex A, www, other services. Getting this wrong does not degrade mail — it takes the
# site off the internet. A record must match an explicit mail-only shape to even be a
# deletion candidate.
#
# The apex is the sharp edge: our SPF TXT shares the name with unrelated TXT (site
# verification tokens). Hence the content check — at the apex, only "v=spf1..." is ours.
# CAA is never in scope: Cloudflare injects its own and they are load-bearing.
def is_mail_managed(r, origin, mailhost):
    name = r["name"].lower().rstrip(".")
    typ = r["type"]
    content = str(r.get("content") or "")
    o, mh = origin.lower(), mailhost.lower()

    if typ == "MX" and name == o:
        return True
    if typ in ("A", "AAAA") and name == mh:
        return True
    if typ == "CNAME" and name in (f"mta-sts.{o}", f"autoconfig.{o}"):
        return True
    if typ == "SRV" and re.match(
        r"^_(autodiscover|imaps?|submissions?|pop3s?)\._tcp\." + re.escape(o) + r"$", name
    ):
        return True
    if typ == "TLSA" and name.endswith(f"._tcp.{mh}"):
        return True
    if typ == "TXT":
        if name in (o, mh):
            return content.startswith("v=spf1")
        if name in (f"_dmarc.{o}", f"_mta-sts.{o}", f"default._bimi.{o}"):
            return True
        if name in (f"_smtp._tls.{o}", f"_smtp._tls.{mh}"):
            return True
        if name.endswith(f"._domainkey.{o}"):
            return True
    return False


def same(existing, want):
    """Compare a Cloudflare record against a desired one.

    Dispatch on whether the DESIRED record carries structured `data` (SRV, TLSA) rather
    than naming types one by one: special-casing SRV alone once made TLSA hit
    want["content"], KeyError, and abort the sync for every record after it.
    """
    if existing["type"] != want["type"]:
        return False
    if "data" in want:
        e, w = existing.get("data") or {}, want["data"]
        # Only the meaningful fields: Cloudflare does NOT echo SRV service/proto/name
        # (it derives them from the record name), so comparing every key made each record
        # look permanently different and rewrote all of them on every run.
        fields = {
            "SRV":  ("priority", "weight", "port", "target"),
            "TLSA": ("usage", "selector", "matching_type", "certificate"),
        }.get(want["type"])
        if not fields:
            return all(str(e.get(k)).lower() == str(w.get(k)).lower() for k in w)
        return all(str(e.get(k)).lower().rstrip(".") == str(w.get(k)).lower().rstrip(".")
                   for k in fields)
    if existing.get("content", "").rstrip(".") != want["content"].rstrip("."):
        return False
    if want["type"] == "MX" and int(existing.get("priority", -1)) != int(want["priority"]):
        return False
    return True


def txt_tag(content):
    """The stable prefix that identifies WHICH TXT a value is (v=spf1, v=DKIM1, ...)."""
    return content.split("=")[0][:12] if "=" in content else content[:12]


def run_cloudflare(a, want, pending, skipped):
    token = open(os.path.expanduser(a.token_file)).read().strip()
    zone_id = a.zone_id
    if not zone_id:
        res = cf(token, "GET", f"/zones?name={urllib.parse.quote(a.zone_name or a.origin)}")
        zones = res.get("result") or []
        if not res.get("success") or not zones:
            print(f"ERROR: no Cloudflare zone named {a.zone_name or a.origin}: {res.get('errors')}", file=sys.stderr)
            return 2
        zone_id = zones[0]["id"]

    res = cf(token, "GET", f"/zones/{zone_id}/dns_records?per_page=5000")
    if not res.get("success"):
        print("ERROR listing zone:", res.get("errors"), file=sys.stderr)
        return 2
    existing = {}
    for r in res["result"]:
        existing.setdefault(key_of(r), []).append(r)

    creates, updates, unchanged = [], [], []
    for w in want:
        cur = existing.get(key_of(w), [])
        # TXT is multi-valued (SPF + verification tokens coexist at the apex), so match on
        # a stable prefix instead of assuming one record per name.
        if w["type"] == "TXT":
            cur = [c for c in cur if txt_tag(c.get("content", "")) == txt_tag(w["content"])]
        elif w["type"] == "TLSA":
            # Several TLSA can share a name (mox mode publishes RSA + ECDSA). Pair by
            # exact certificate first so neither is "updated" into the other.
            exact = [c for c in cur if same(c, w)]
            cur = exact or [c for c in cur if not any(same(c, o) for o in want if o is not w)]
        if not cur:
            creates.append(w)
        elif same(cur[0], w):
            unchanged.append(w)
        else:
            updates.append((cur[0], w))

    mailhost = a.mail_host or f"mail.{a.origin}"
    keep_ids = {c["id"] for c, _ in updates}
    for w in want + skipped + pending:
        for c in existing.get(key_of(w), []):
            if w["type"] == "TXT" and txt_tag(c.get("content", "")) != txt_tag(w.get("content", "")):
                continue
            if w["type"] == "TLSA" and "data" in w and not same(c, w):
                continue
            keep_ids.add(c["id"])
    orphans = [r for r in res["result"]
               if is_mail_managed(r, a.origin, mailhost) and r["id"] not in keep_ids]

    report(want, creates, updates, unchanged, skipped, pending, orphans, a.prune)
    if not a.apply:
        print("\n(dry run — pass --apply to write)")
        return 0

    rc = 0
    if a.prune:
        for r in orphans:
            out = cf(token, "DELETE", f"/zones/{zone_id}/dns_records/{r['id']}")
            rc |= result_line("pruned", r, out)
    for r in creates:
        out = cf(token, "POST", f"/zones/{zone_id}/dns_records", body_of(r))
        rc |= result_line("created", r, out)
    # Updates are a PUT against the existing record id, never delete-and-recreate: a gap
    # in the MX — cached by resolvers for the TTL — sends senders to the apex A instead.
    for c, w in updates:
        out = cf(token, "PUT", f"/zones/{zone_id}/dns_records/{c['id']}", body_of(w))
        rc |= result_line("updated", w, out)
    return rc


def body_of(r):
    body = {"type": r["type"], "name": r["name"], "ttl": TTL, "proxied": False}
    if "data" in r:
        body["data"] = r["data"]
    else:
        body["content"] = r["content"]
    if "priority" in r:
        body["priority"] = r["priority"]
    return body


def desc(r):
    v = r.get("content") or json.dumps(r.get("data"))
    return f"{r['type']:6} {r['name']:44} {str(v)[:70]}"


def result_line(verb, r, out):
    ok = bool(out.get("success"))
    print(f"  {verb if ok else 'FAILED':9}{desc(r)}" + ("" if ok else f"  {out.get('errors')}"))
    return 0 if ok else 1


def report(want, creates, updates, unchanged, skipped, pending, orphans, prune):
    print(f"== {len(want)} desired records ==")
    for r in creates:
        print(f"  CREATE   {desc(r)}")
    for c, w in updates:
        print(f"  UPDATE   {desc(w)}\n           was: {str(c.get('content') or c.get('data'))[:70]}")
    print(f"  unchanged: {len(unchanged)}")
    for sk in skipped:
        print(f"  SKIP     {sk['type']:6} {sk['name']:44} {sk['skip']}")
    for pd in pending:
        print(f"  PENDING  {pd['type']:6} {pd['name']:44} {pd['pending']}")
    if orphans:
        verb = "PRUNE" if prune else "ORPHAN"
        for r in orphans:
            print(f"  {verb:8} {desc(r)}")
        if not prune:
            print(f"  ({len(orphans)} stale mail record(s) — pass --prune to delete)")
    else:
        print("  orphans: none")


# ------------------------------------------------------------------------------ doh
RTYPE = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "TLSA": 52}


def doh(name, rtype):
    q = urllib.parse.urlencode({"name": name, "type": rtype})
    try:
        with urllib.request.urlopen(f"{DOH_API}?{q}", timeout=20) as r:
            d = json.load(r)
    except Exception as e:
        return None, str(e)
    # Only answers of the asked type: a CNAME chain also comes back in Answer.
    return [a["data"] for a in d.get("Answer", []) if a.get("type") == RTYPE[rtype]], None


def norm_answer(rtype, data):
    if rtype == "TXT":
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
        return "".join(parts) if parts else data
    if rtype in ("CNAME",):
        return data.rstrip(".").lower()
    if rtype == "MX":
        p, t = data.split(None, 1)
        return f"{int(p)} {t.rstrip('.').lower()}"
    if rtype in ("A", "AAAA"):
        return str(ipaddress.ip_address(data))
    if rtype == "SRV":
        p, w, port, t = data.split()[:4]
        t = "." if t.rstrip(".") == "" else t.rstrip(".").lower()
        return f"{int(p)} {int(w)} {int(port)} {t}"
    if rtype == "TLSA":
        u, s, m, c = data.split()[:4]
        return f"{int(u)} {int(s)} {int(m)} {c.lower()}"
    return data


def norm_want(r):
    t = r["type"]
    if t == "TXT":
        return r["content"]
    if t == "CNAME":
        return r["content"].lower()
    if t == "MX":
        return f"{r['priority']} {r['content'].lower()}"
    if t in ("A", "AAAA"):
        return str(ipaddress.ip_address(r["content"]))
    d = r["data"]
    if t == "SRV":
        return f"{d['priority']} {d['weight']} {d['port']} {d['target'].lower()}"
    if t == "TLSA":
        return f"{d['usage']} {d['selector']} {d['matching_type']} {d['certificate']}"
    return ""


def run_doh(want, pending, skipped):
    """Verify every desired record is publicly resolvable with the desired value.

    DoH because the local resolver caches negative answers for the SOA minimum: a record
    queried before it existed keeps reading as missing for up to 30 minutes after it is
    published, which has produced false alarms before.
    """
    bad = 0
    print(f"== verifying {len(want)} records over DoH ({DOH_API}) ==")
    for r in want:
        answers, err = doh(r["name"], r["type"])
        if answers is None:
            print(f"  ERROR    {desc(r)}  ({err})")
            bad += 1
            continue
        got = {norm_answer(r["type"], a) for a in answers}
        exp = norm_want(r)
        if exp in got:
            print(f"  ok       {desc(r)}")
            continue
        # TXT: a value of the same kind but different content is DIFFERS, not MISSING.
        rel = [g for g in got if r["type"] != "TXT" or txt_tag(g) == txt_tag(exp)]
        verdict = "DIFFERS" if rel else "MISSING"
        print(f"  {verdict:8} {desc(r)}" + (f"\n           published: {sorted(rel)[0][:70]}" if rel else ""))
        bad += 1
    for sk in skipped:
        print(f"  SKIP     {sk['type']:6} {sk['name']:44} {sk['skip']}")
    for pd in pending:
        print(f"  PENDING  {pd['type']:6} {pd['name']:44} {pd['pending']}")
    print(f"  {len(want) - bad} ok, {bad} to fix")
    return 1 if bad else 0


# ----------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--records-file", required=True)
    ap.add_argument("--origin", required=True, help="the mail domain")
    ap.add_argument("--provider", choices=("cloudflare", "doh"), default=None)
    ap.add_argument("--print-zone", action="store_true", help="print desired records as zone lines")
    ap.add_argument("--zone-id", default="")
    ap.add_argument("--zone-name", default="", help="Cloudflare zone to look the id up by (default: origin)")
    ap.add_argument("--token-file", default="~/.config/cocx/cloudflare_token")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--prune", action="store_true",
                    help="also DELETE mail-managed records that are no longer wanted (e.g. a "
                         "retired DKIM selector). Reported always; deleted only with --prune AND --apply.")
    ap.add_argument("--mail-host", default=None, help="SMTP hostname, scopes prune (default mail.<origin>)")
    ap.add_argument("--extra-a", action="append", default=[],
                    help="name=ip A/AAAA records to ensure (the mail host's own addresses)")
    a = ap.parse_args(argv)

    want, pending, skipped = desired(open(a.records_file).read(), a.origin, a.extra_a)
    if not want:
        print("ERROR: no records parsed — is the records file really `mox config dnsrecords` output?",
              file=sys.stderr)
        return 2

    if a.print_zone:
        print(f"; records for {a.origin} — generated by cocx from `mox config dnsrecords`")
        for r in want:
            print(zone_line(r))
        for r in pending:
            print(";; " + zone_line(r) + "    ; " + r["pending"])
        if not a.provider:
            return 0
    if a.provider == "cloudflare":
        return run_cloudflare(a, want, pending, skipped)
    if a.provider == "doh":
        return run_doh(want, pending, skipped)
    if not a.print_zone:
        ap.error("one of --provider or --print-zone is required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
