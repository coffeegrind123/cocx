#!/usr/bin/env python3
"""remote/junk-neutral.py: must change exactly one account's NeutralMailboxRegexp and
nothing else in domains.conf, and must refuse rather than guess. Run: make test"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("jn", ROOT / "remote" / "junk-neutral.py")
jn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jn)

QUICKSTART = '^(inbox|introbox|neutral|postmaster|dmarc|tlsrpt|rejects)'
WANT = '^(introbox|neutral|postmaster|dmarc|tlsrpt|rejects)'

# The shape quickstart writes (tabs are significant in sconf), plus a second account with a
# deliberate value of its own and a commented-out key that must never match.
CONF = (
    'Domains:\n'
    '\texample.com:\n'
    '\t\tLocalpartCatchallSeparator: +\n'
    'Accounts:\n'
    '\tadmin:\n'
    '\t\tDomain: example.com\n'
    '\t\tDestinations:\n'
    '\t\t\tadmin@example.com: nil\n'
    '\t\tRejectsMailbox: Rejects\n'
    '\t\tAutomaticJunkFlags:\n'
    '\t\t\tEnabled: true\n'
    '\t\t\tJunkMailboxRegexp: ^(junk|spam)\n'
    f'\t\t\tNeutralMailboxRegexp: {QUICKSTART}\n'
    '\t\tJunkFilter:\n'
    '\t\t\tThreshold: 0.950000\n'
    '\tother:\n'
    '\t\tDomain: example.com\n'
    '\t\t# NeutralMailboxRegexp: ^(commented)\n'
    '\t\tAutomaticJunkFlags:\n'
    '\t\t\tEnabled: true\n'
    '\t\t\tNeutralMailboxRegexp: ^(inbox|custom)\n'
    '\tbare:\n'
    '\t\tDomain: example.com\n'
    'MonitorDNSBLs:\n'
    '\t- sbl.spamhaus.org\n'
)


def conf(text=CONF):
    f = tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False)
    f.write(text)
    f.close()
    os.chmod(f.name, 0o600)
    return f.name


def run(*args):
    return jn.main(list(args))


class JunkNeutral(unittest.TestCase):
    def test_get(self):
        p = conf()
        self.assertEqual(run('get', 'admin', p), 0)
        self.assertEqual(run('get', 'other', p), 0)

    def test_set_changes_only_that_account(self):
        p = conf()
        self.assertEqual(run('set', 'admin', WANT, p), 0)
        got = open(p).read()
        self.assertEqual(got, CONF.replace(f'NeutralMailboxRegexp: {QUICKSTART}', f'NeutralMailboxRegexp: {WANT}'))
        self.assertIn('NeutralMailboxRegexp: ^(inbox|custom)', got)  # other account untouched
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)          # mode preserved

    def test_set_other_account_skips_comment(self):
        p = conf()
        self.assertEqual(run('set', 'other', WANT, p), 0)
        got = open(p).read()
        self.assertIn('# NeutralMailboxRegexp: ^(commented)', got)
        self.assertIn(f'NeutralMailboxRegexp: {QUICKSTART}', got)    # admin untouched

    def test_idempotent(self):
        p = conf()
        run('set', 'admin', WANT, p)
        before = open(p).read()
        self.assertEqual(run('set', 'admin', WANT, p), 0)
        self.assertEqual(open(p).read(), before)

    def test_unknown_account(self):
        p = conf()
        self.assertEqual(run('set', 'nobody', WANT, p), 2)
        self.assertEqual(open(p).read(), CONF)

    def test_account_name_is_not_a_prefix_match(self):
        p = conf()
        self.assertEqual(run('get', 'adm', p), 2)

    def test_no_key_in_account(self):
        # "bare" has no AutomaticJunkFlags; the key in the NEXT block must not be borrowed.
        p = conf()
        self.assertEqual(run('set', 'bare', WANT, p), 3)
        self.assertEqual(open(p).read(), CONF)

    def test_usage(self):
        self.assertEqual(run('set', 'admin'), 64)
        self.assertEqual(run('frob', 'admin'), 64)


if __name__ == '__main__':
    unittest.main(verbosity=1)
