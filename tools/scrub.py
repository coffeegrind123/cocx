#!/usr/bin/env python3
"""Refuse to let secrets or deployment-specific identifiers into the repository.

Two layers, because they catch different things:

  1. GENERIC rules (below, in the repo): the SHAPE of a secret — a private key block, a
     password/token assignment with a real-looking value, a routable IP literal, an
     email address on a real domain. These catch secrets nobody thought to list.

  2. A PRIVATE DENYLIST (outside the repo, $COCX_SCRUB_DENYLIST, default
     ~/.config/cocx/scrub-denylist): literal strings that identify one particular
     deployment — its domain, IPs, provider account IDs, and the VALUES of its secrets.
     It lives outside the repo because the list itself is the sensitive data. A hit is
     reported by entry NUMBER, never by value, so this tool cannot leak what it guards.

Usage:
    tools/scrub.py              scan every tracked + untracked-but-not-ignored file
    tools/scrub.py --staged     scan the staged index (what the pre-commit hook runs)
    tools/scrub.py FILE...      scan specific files

Exit 1 on any finding. A missing denylist is a WARNING, not a pass-through silently:
the generic layer still runs, and the warning says the deployment layer did not.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DENYLIST = Path(os.environ.get("COCX_SCRUB_DENYLIST", Path.home() / ".config/cocx/scrub-denylist"))

# Generic rules that a specific file is allowed to trip, by design. The denylist is
# NEVER exempted for any file — there is no legitimate reason for a deployment's
# identifiers to appear anywhere.
#   openpgp.js: vendored crypto library; contains key-block markers and long constants.
#   pgp.ts:     parses armor, so it names the "PRIVATE KEY BLOCK" markers literally.
#   scrub.py:   this file describes the patterns it hunts.
EXEMPT = {
    "mox/src/openpgp.js": {"private-key", "email", "ipv4", "ipv6", "assigned-secret"},
    "mox/src/pgp.ts": {"private-key"},
    "mox/patches/0003-webmail-api-go.patch": {"private-key"},
    "tools/scrub.py": {"private-key", "assigned-secret"},
}

# Addresses that are fine to name: documentation/example domains, and well-known public
# endpoints the scripts genuinely talk to.
OK_EMAIL_DOMAIN = re.compile(
    r"(^|\.)(example\.(com|org|net)|example|localhost|invalid|test|gmail\.com|b\.com|gnupg\.org)$", re.I)
OK_IPS = {
    "142.251.127.27",  # a Google MX, the outbound-:25 probe target
    "1.1.1.1", "8.8.8.8", "9.9.9.9",
    "217.69.76.60",    # a public host, the WKD SSRF guard's "must stay reachable" control
}

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")),
    ("assigned-secret", re.compile(
        r"(?i)\b[A-Z0-9_]*(passw(or)?d|secret|token|api[_-]?key)[A-Z0-9_]*\s*[:=]\s*['\"]?"
        r"(?![$<{(])(?!example|changeme|xxx|your)[A-Za-z0-9_\-+/=.]{16,}")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")),
    ("ipv6", re.compile(r"(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])")),
]


def ip_ok(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return True  # not actually an IP (a version string, an OID)
    if text in OK_IPS:
        return True
    doc4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    doc6 = ipaddress.ip_network("2001:db8::/32")
    if ip.version == 4 and any(ip in n for n in doc4):
        return True
    if ip.version == 6 and ip in doc6:
        return True
    return not ip.is_global or ip.is_multicast


def load_denylist() -> list[str]:
    if not DENYLIST.is_file():
        return []
    out = []
    for line in DENYLIST.read_text(errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.lower())
    return out


def git(*args: str) -> bytes:
    return subprocess.run(["git", "-C", str(REPO), *args], check=True, capture_output=True).stdout


def staged_files() -> list[tuple[str, bytes]]:
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split(b"\0")
    return [(n.decode(), git("show", f":{n.decode()}")) for n in names if n]


def tree_files() -> list[tuple[str, bytes]]:
    names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    out = []
    for n in names:
        if not n:
            continue
        p = REPO / n.decode()
        if p.is_file():
            out.append((n.decode(), p.read_bytes()))
    return out


def scan(path: str, data: bytes, deny: list[str]) -> list[str]:
    findings = []
    text = data.decode("utf-8", errors="replace")
    exempt = EXEMPT.get(path, set())
    lower = text.lower()

    # The PATH is content too: a file named after a deployment leaks just as well.
    for i, d in enumerate(deny, 1):
        if d in path.lower():
            findings.append(f"{path}: path matches denylist entry #{i}")

    for i, d in enumerate(deny, 1):
        start = 0
        while (k := lower.find(d, start)) >= 0:
            line = text.count("\n", 0, k) + 1
            findings.append(f"{path}:{line}: denylist entry #{i}")
            start = k + len(d)

    for lineno, line in enumerate(text.splitlines(), 1):
        for name, rx in RULES:
            if name in exempt:
                continue
            for m in rx.finditer(line):
                hit = m.group(0)
                if name == "email" and OK_EMAIL_DOMAIN.search(hit.split("@", 1)[1]):
                    continue
                if name in ("ipv4", "ipv6") and ip_ok(m.group(1)):
                    continue
                findings.append(f"{path}:{lineno}: {name}: {hit[:80]}")
    return findings


def main(argv: list[str]) -> int:
    deny = load_denylist()
    if argv[:1] == ["--staged"]:
        files = staged_files()
    elif argv:
        files = [(a, Path(a).read_bytes()) for a in argv]
    else:
        files = tree_files()

    findings = []
    for path, data in files:
        findings += scan(path, data, deny)

    if not deny:
        print(f"scrub: WARNING — no denylist at {DENYLIST}; only the generic rules ran.", file=sys.stderr)
    if findings:
        print("scrub: BLOCKED — remove these before committing:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"scrub: clean ({len(files)} files, {len(deny)} denylist entries, {len(RULES)} generic rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
