#!/usr/bin/env python3
"""tools/mail-dns.py against REAL `mox config dnsrecords` output (tests/fixtures, captured
from mox quickstart in both modes) and against in-process fakes of the Cloudflare API and
a DoH resolver. Run: python3 tests/test_mail_dns.py  (or: make test)"""
import contextlib
import http.server
import importlib.util
import io
import json
import os
import re
import threading
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def load_tool():
    spec = importlib.util.spec_from_file_location("mail_dns", ROOT / "tools" / "mail-dns.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


md = load_tool()
ORIGIN = "example.com"
MH = "mail.example.com"


class FakeCloudflare(http.server.BaseHTTPRequestHandler):
    """Just enough of /zones and /dns_records to drive the sync, with a request log."""
    records: list = []
    log: list = []
    next_id = 1000

    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else None

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path.endswith("/zones"):
            return self._send({"success": True, "result": [{"id": "zone1", "name": ORIGIN}]})
        if u.path.endswith("/dns_records"):
            return self._send({"success": True, "result": FakeCloudflare.records})
        self._send({"success": False}, 404)

    def do_POST(self):
        b = self._body()
        FakeCloudflare.next_id += 1
        rec = dict(b, id=str(FakeCloudflare.next_id))
        FakeCloudflare.records.append(rec)
        FakeCloudflare.log.append(("POST", b["type"], b["name"]))
        self._send({"success": True, "result": rec})

    def do_PUT(self):
        rid = self.path.rsplit("/", 1)[1]
        b = self._body()
        for i, r in enumerate(FakeCloudflare.records):
            if r["id"] == rid:
                FakeCloudflare.records[i] = dict(b, id=rid)
        FakeCloudflare.log.append(("PUT", b["type"], b["name"], rid))
        self._send({"success": True})

    def do_DELETE(self):
        rid = self.path.rsplit("/", 1)[1]
        FakeCloudflare.records = [r for r in FakeCloudflare.records if r["id"] != rid]
        FakeCloudflare.log.append(("DELETE", rid))
        self._send({"success": True})


class FakeDoH(http.server.BaseHTTPRequestHandler):
    answers: dict = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        name, rtype = q["name"][0], q["type"][0]
        data = FakeDoH.answers.get((name, rtype), [])
        body = json.dumps({"Status": 0, "Answer": [
            {"name": name, "type": md.RTYPE[rtype], "data": d} for d in data]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = md.main(argv)
    return rc, out.getvalue()


class Parse(unittest.TestCase):
    def setUp(self):
        self.mox = md.parse_zone((FIX / "dnsrecords-mox-mode.zone").read_text(), ORIGIN)
        self.caddy = md.parse_zone((FIX / "dnsrecords-caddy-mode.zone").read_text(), ORIGIN)

    def test_counts_per_type(self):
        types = {}
        for r in self.mox:
            types[r["type"]] = types.get(r["type"], 0) + 1
        # 2 DKIM + 2 SPF + 2 TLSRPT + DMARC + MTA-STS = 8 TXT; 7 SRV; 2 CNAME; MX; 2 TLSA; CAA
        self.assertEqual(types, {"TXT": 8, "SRV": 7, "CNAME": 2, "MX": 1, "TLSA": 2, "CAA": 1})

    def test_multiline_dkim_is_joined_whole(self):
        dkim = [r for r in self.mox if r["name"] == "2026a._domainkey.example.com"][0]
        self.assertTrue(dkim["content"].startswith("v=DKIM1;h=sha256;p=MIIB"))
        self.assertTrue(dkim["content"].endswith("IDAQAB"))
        self.assertNotIn('"', dkim["content"])
        self.assertNotIn(" ", dkim["content"])

    def test_commented_tlsa_is_pending_not_dropped(self):
        tlsa = [r for r in self.mox if r["type"] == "TLSA"]
        self.assertEqual(len(tlsa), 2)
        self.assertTrue(all(r.get("pending") for r in tlsa))
        self.assertEqual(tlsa[0]["data"]["usage"], 3)

    def test_caa_is_reported_as_skip(self):
        caa = [r for r in self.mox if r["type"] == "CAA"]
        self.assertEqual(len(caa), 1)
        self.assertIn("CAA", caa[0]["skip"])

    def test_null_srv_target(self):
        pop = [r for r in self.mox if r["name"] == "_pop3._tcp.example.com"][0]
        self.assertEqual(pop["data"]["target"], ".")
        self.assertEqual(pop["data"]["port"], 0)

    def test_caddy_mode_has_no_tlsa_before_dane_setup(self):
        self.assertFalse([r for r in self.caddy if r["type"] == "TLSA"])

    def test_semicolons_inside_txt_survive(self):
        dmarc = [r for r in self.mox if r["name"] == "_dmarc.example.com"][0]
        self.assertEqual(dmarc["content"], "v=DMARC1;p=reject;rua=mailto:dmarcreports@example.com!10m")

    def test_zone_line_roundtrip(self):
        want, _, _ = md.desired((FIX / "dnsrecords-mox-mode.zone").read_text(), ORIGIN, [])
        again = md.parse_zone("\n".join(md.zone_line(r) for r in want), ORIGIN)
        norm = lambda rs: sorted(md.norm_want(r) + r["name"] for r in rs)
        self.assertEqual(norm(want), norm(again))


class Scope(unittest.TestCase):
    def test_prune_scope_is_an_allowlist(self):
        m = lambda name, typ, content="": md.is_mail_managed(
            {"name": name, "type": typ, "content": content}, ORIGIN, MH)
        self.assertTrue(m("example.com", "TXT", "v=spf1 mx ~all"))
        self.assertFalse(m("example.com", "TXT", "google-site-verification=abc"))
        self.assertFalse(m("example.com", "A", "192.0.2.1"))
        self.assertFalse(m("www.example.com", "CNAME"))
        self.assertFalse(m("example.com", "CAA"))
        self.assertTrue(m("old._domainkey.example.com", "TXT", "v=DKIM1"))
        self.assertTrue(m(MH, "AAAA"))


class Cloudflare(unittest.TestCase):
    def setUp(self):
        FakeCloudflare.records = []
        FakeCloudflare.log = []
        self.srv, url = serve(FakeCloudflare)
        md.CF_API = url
        self.tok = ROOT / "tests" / ".tmp-token"
        self.tok.write_text("t")
        self.args = ["--records-file", str(FIX / "dnsrecords-mox-mode.zone"), "--origin", ORIGIN,
                     "--provider", "cloudflare", "--token-file", str(self.tok), "--zone-name", ORIGIN,
                     "--extra-a", f"{MH}=192.0.2.10", "--extra-a", f"{MH}=2001:db8::10"]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tok.unlink(missing_ok=True)

    def test_dry_run_writes_nothing(self):
        rc, out = run(self.args)
        self.assertEqual(rc, 0)
        self.assertIn("dry run", out)
        self.assertEqual(FakeCloudflare.log, [])

    def test_apply_then_idempotent(self):
        rc, _ = run(self.args + ["--apply"])
        self.assertEqual(rc, 0)
        posts = [l for l in FakeCloudflare.log if l[0] == "POST"]
        # 8 TXT + 7 SRV + 2 CNAME + 1 MX from mox (TLSA pending, CAA skipped) + A + AAAA
        self.assertEqual(len(posts), 20)
        self.assertTrue(all(r["proxied"] is False for r in FakeCloudflare.records))
        FakeCloudflare.log = []
        rc, out = run(self.args + ["--apply"])
        self.assertEqual(FakeCloudflare.log, [], out)
        self.assertIn("unchanged: 20", out)

    def test_drift_is_repaired_in_place(self):
        run(self.args + ["--apply"])
        mx = [r for r in FakeCloudflare.records if r["type"] == "MX"][0]
        mx["content"] = "elsewhere.example.net"
        FakeCloudflare.log = []
        run(self.args + ["--apply"])
        self.assertEqual(FakeCloudflare.log, [("PUT", "MX", ORIGIN, mx["id"])])

    def test_orphan_reported_and_only_pruned_on_request(self):
        run(self.args + ["--apply"])
        FakeCloudflare.records.append({"id": "old1", "type": "TXT", "name": "2020old._domainkey.example.com",
                                       "content": "v=DKIM1;p=AAAA"})
        FakeCloudflare.records.append({"id": "site", "type": "TXT", "name": ORIGIN,
                                       "content": "google-site-verification=keep-me"})
        FakeCloudflare.log = []
        rc, out = run(self.args + ["--apply"])
        self.assertIn("ORPHAN", out)
        self.assertNotIn(("DELETE", "old1"), FakeCloudflare.log)
        rc, out = run(self.args + ["--apply", "--prune"])
        self.assertIn(("DELETE", "old1"), FakeCloudflare.log)
        self.assertNotIn(("DELETE", "site"), FakeCloudflare.log)

    def test_two_tlsa_records_are_not_updated_into_each_other(self):
        text = re.sub(r"^;; (_25\._tcp)", r"\1", (FIX / "dnsrecords-mox-mode.zone").read_text(), flags=re.M)
        p = ROOT / "tests" / ".tmp-zone"
        p.write_text(text)
        try:
            args = [a if a != str(FIX / "dnsrecords-mox-mode.zone") else str(p) for a in self.args]
            run(args + ["--apply"])
            self.assertEqual(len([r for r in FakeCloudflare.records if r["type"] == "TLSA"]), 2)
            FakeCloudflare.log = []
            rc, out = run(args + ["--apply"])
            self.assertEqual(FakeCloudflare.log, [], out)
        finally:
            p.unlink()


class DoH(unittest.TestCase):
    def setUp(self):
        self.srv, url = serve(FakeDoH)
        md.DOH_API = url
        want, _, _ = md.desired((FIX / "dnsrecords-caddy-mode.zone").read_text(), ORIGIN, [f"{MH}=192.0.2.10"])
        self.want = want
        FakeDoH.answers = {}
        for r in want:
            line = md.zone_line(r).split(None, 4)[4]
            FakeDoH.answers.setdefault((r["name"], r["type"]), []).append(line)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def args(self):
        return ["--records-file", str(FIX / "dnsrecords-caddy-mode.zone"), "--origin", ORIGIN,
                "--provider", "doh", "--extra-a", f"{MH}=192.0.2.10"]

    def test_all_published_passes(self):
        rc, out = run(self.args())
        self.assertEqual(rc, 0, out)
        self.assertIn("0 to fix", out)

    def test_missing_and_differs_are_distinguished(self):
        del FakeDoH.answers[("example.com", "MX")]
        FakeDoH.answers[("_dmarc.example.com", "TXT")] = ['"v=DMARC1;p=none"']
        rc, out = run(self.args())
        self.assertEqual(rc, 1)
        self.assertRegex(out, r"MISSING\s+MX")
        self.assertRegex(out, r"DIFFERS\s+TXT\s+_dmarc")

    def test_other_txt_at_same_name_does_not_satisfy_spf(self):
        FakeDoH.answers[("example.com", "TXT")] = ['"google-site-verification=x"']
        rc, out = run(self.args())
        self.assertRegex(out, r"MISSING\s+TXT\s+example\.com ")


if __name__ == "__main__":
    os.chdir(ROOT)
    unittest.main(verbosity=1)
