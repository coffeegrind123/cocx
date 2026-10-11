#!/usr/bin/env python3
"""Read or set one account's AutomaticJunkFlags.NeutralMailboxRegexp in mox's domains.conf.

Runs ON the mail host, fed over stdin (`rsh "python3 - get admin" < remote/junk-neutral.py`).

    get <account> [domains.conf]            print the current value
    set <account> <regexp> [domains.conf]   replace it; prints "old -> new" or "already ..."

Exit codes: 0 ok · 2 no such account · 3 the account has no NeutralMailboxRegexp line
(AutomaticJunkFlags off or hand-edited) — left alone, the operator owns that config.

Scoped to ONE account on purpose: the line exists once per account, and an operator's
other accounts may carry a deliberate value. domains.conf is sconf: top-level keys at
column 0, accounts one tab in, their settings deeper.
"""
import os
import re
import sys

DEFAULT_PATH = '/home/mox/config/domains.conf'
KEY = re.compile(r'^(\t+NeutralMailboxRegexp: )(.*)$', re.M)


def account_span(text, account):
    accounts = re.search(r'^Accounts:\n', text, re.M)
    if not accounts:
        return None
    head = re.compile(r'^\t' + re.escape(account) + r':\n', re.M).search(text, accounts.end())
    if not head:
        return None
    # The block ends at the next account (one tab) or the next top-level key (no tab).
    nxt = re.compile(r'^(\t[^\t\n]|[^\t\n])', re.M).search(text, head.end())
    return head.end(), nxt.start() if nxt else len(text)


def main(argv):
    if len(argv) < 2 or argv[0] not in ('get', 'set') or (argv[0] == 'set' and len(argv) < 3):
        sys.stderr.write(__doc__)
        return 64
    mode, account = argv[0], argv[1]
    want = argv[2] if mode == 'set' else None
    rest = argv[3:] if mode == 'set' else argv[2:]
    path = rest[0] if rest else DEFAULT_PATH

    text = open(path, encoding='utf-8').read()
    span = account_span(text, account)
    if span is None:
        sys.stderr.write(f'no account "{account}" in {path}\n')
        return 2
    start, end = span
    m = KEY.search(text, start, end)
    if not m:
        sys.stderr.write(f'account "{account}" has no NeutralMailboxRegexp (AutomaticJunkFlags off?)\n')
        return 3

    cur = m.group(2)
    if mode == 'get':
        print(cur)
        return 0
    if cur == want:
        print(f'already {want}')
        return 0

    out = text[:m.start(2)] + want + text[m.end(2):]
    tmp = path + '.cocx-tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(out)
    st = os.stat(path)
    os.chmod(tmp, st.st_mode & 0o7777)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except PermissionError:
        pass  # not root (tests): ownership is already ours
    os.replace(tmp, path)
    print(f'{cur} -> {want}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
