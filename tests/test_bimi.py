#!/usr/bin/env python3
"""tools/bimi-logo.py: the validator must reject every way a logo gets silently dropped,
and convert must turn an ordinary logo into one that passes. Run: make test"""
import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bimi", ROOT / "tools" / "bimi-logo.py")
bimi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bimi)

GOOD = ('<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">'
        '<title>Example</title><rect x="0" y="0" width="100" height="100" fill="#fff"/>'
        '<circle cx="50" cy="50" r="30" fill="#c00"/></svg>')


def write(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".svg", delete=False)
    f.write(text)
    f.close()
    return f.name


class Check(unittest.TestCase):
    def errs(self, text):
        return bimi.problems(write(text))[0]

    def test_control_good_logo_passes(self):
        errs, warns = bimi.problems(write(GOOD))
        self.assertEqual(errs, [])
        self.assertEqual(warns, [])

    def test_each_violation_is_caught(self):
        cases = {
            "baseProfile": GOOD.replace(' baseProfile="tiny-ps"', ""),
            "square": GOOD.replace('viewBox="0 0 100 100"', 'viewBox="0 0 100 50"'),
            "title": GOOD.replace("<title>Example</title>", ""),
            "script": GOOD.replace("</svg>", "<script>x()</script></svg>"),
            "outside": GOOD.replace("</svg>", '<use href="https://x.example/a.svg#b"/></svg>'),
            "handler": GOOD.replace("<circle ", '<circle onclick="x()" '),
            "x attribute": GOOD.replace("<svg ", '<svg x="1" '),
            "32 KB": GOOD.replace("</svg>", "<desc>" + "a" * 40000 + "</desc></svg>"),
        }
        for want, text in cases.items():
            with self.subTest(want):
                self.assertTrue(any(want.split()[0] in e for e in self.errs(text)), self.errs(text))

    def test_missing_plate_is_a_warning_not_an_error(self):
        errs, warns = bimi.problems(write(GOOD.replace('<rect x="0" y="0" width="100" height="100" fill="#fff"/>', "")))
        self.assertEqual(errs, [])
        self.assertTrue(warns)


class Convert(unittest.TestCase):
    def test_converts_a_plain_nonsquare_logo(self):
        src = write('<svg xmlns="http://www.w3.org/2000/svg" width="300" height="100" onload="x()">'
                    '<script>x()</script><rect width="300" height="100" fill="#00f"/></svg>')
        out = src + ".out.svg"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = bimi.main(["convert", src, "-o", out, "--title", "Example", "--background", "#fff"])
        self.assertEqual(rc, 0)
        self.assertEqual(bimi.problems(out), ([], []))
        self.assertIn('viewBox="0 -100 300 300"', Path(out).read_text())


if __name__ == "__main__":
    unittest.main(verbosity=1)
