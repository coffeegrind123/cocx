#!/usr/bin/env python3
"""IMAP side of `cocx reset`, run ON the mail host (piped to `python3 - <verb>`).

    inventory   count messages per mailbox, change nothing
    expunge     delete every message in every mailbox, verify each is empty after

Credentials come from /etc/cocx/mail-filter.env (written by cocx at install), parsed as
plain KEY=value — never through a shell, because generated passwords can contain '#'.
"""
import imaplib
import re
import ssl
import sys

ENV = "/etc/cocx/mail-filter.env"


def creds():
    env = dict(re.findall(r"^([A-Z_]+)=(.*)$", open(ENV).read(), re.M))
    return env["MOX_IMAP_HOST"], int(env.get("MOX_IMAP_PORT") or 993), env["MOX_ACCOUNT"], env["MOX_ACCOUNT_PASSWORD"]


def mailboxes(m):
    ok, boxes = m.list()
    for b in boxes or []:
        mm = re.match(r'^\(([^)]*)\) "([^"]*)" (.*)$', b.decode())
        if mm and "\\Noselect" not in mm.group(1):
            yield mm.group(3).strip('"')


def main(verb):
    host, port, user, pw = creds()
    try:
        m = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
        m.login(user, pw)
    except Exception as e:
        print(f"    IMAP login to {host}:{port} failed: {e}")
        return 1

    total = failed = 0
    for name in mailboxes(m):
        st, _ = m.select(f'"{name}"', readonly=(verb == "inventory"))
        if st != "OK":
            print(f"    skip {name:22} ({st})")
            continue
        st, data = m.search(None, "ALL")
        ids = data[0].split()
        if verb == "inventory":
            if ids:
                print(f"    {name:24} {len(ids)} msg")
            total += len(ids)
            continue
        if not ids:
            continue
        try:
            m.store(b",".join(ids), "+FLAGS", r"(\Deleted)")
            m.expunge()
            st, d2 = m.search(None, "ALL")
            left = len(d2[0].split())
            print(f"    {name:24} deleted {len(ids)}, remaining {left}")
            failed += 1 if left else 0
            total += len(ids)
        except Exception as e:
            print(f"    {name:24} ERROR {e}")
            failed += 1
    print(f"    ---- {total} messages {'in mailboxes' if verb == 'inventory' else 'deleted'}")
    m.logout()
    return 1 if failed else 0


if __name__ == "__main__":
    if sys.argv[1:2] not in (["inventory"], ["expunge"]):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
