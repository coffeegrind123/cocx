#!/usr/bin/env python3
"""Validate or produce a BIMI logo (SVG Tiny Portable/Secure).

BIMI shows this logo beside your mail in inboxes that support it. Without a paid Mark
Certificate (VMC/CMC) the logo is "self-asserted": Yahoo, AOL, Fastmail and others show
it; Gmail and Apple Mail require the certificate and ignore it. It also needs DMARC at
p=quarantine or p=reject — under p=none BIMI is ignored outright.

Receivers silently ignore a logo that is not SVG Tiny PS, so cocx refuses to ship one
that fails `check`. The profile constraints enforced here (draft-svg-tiny-ps-abrotman):

    root      <svg version="1.2" baseProfile="tiny-ps">, a <title>, a SQUARE viewBox,
              and no x/y attributes
    content   no <script>, <image>, <foreignObject>, animation, event handlers, or
              references to anything outside the file
    plate     opaque and full-bleed recommended: clients crop to a circle or rounded
              square themselves, so a transparent corner shows their background (warned)
    size      <= 32 KB (the draft's recommendation; several validators enforce it)

Usage:
    bimi-logo.py check logo.svg
    bimi-logo.py convert in.svg -o logo.svg --title "Example" [--background "#112233"]
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
MAX_BYTES = 32 * 1024
FORBIDDEN = {"script", "image", "foreignObject", "animate", "animateMotion", "animateColor",
             "animateTransform", "set", "iframe", "video", "audio", "canvas", "a", "filter",
             "mask", "clipPath", "pattern", "switch"}

ET.register_namespace("", SVG_NS)
ET.register_namespace("xlink", XLINK_NS)


def local(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def parse_viewbox(v):
    try:
        x, y, w, h = (float(p) for p in re.split(r"[\s,]+", v.strip()))
        return x, y, w, h
    except Exception:
        return None


def problems(path):
    """(errors, warnings) for one file. Errors make receivers drop the logo."""
    errs, warns = [], []
    raw = open(path, "rb").read()
    if len(raw) > MAX_BYTES:
        errs.append(f"{len(raw)} bytes > {MAX_BYTES} (32 KB)")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        return [f"not well-formed XML: {e}"], warns
    if root.tag != f"{{{SVG_NS}}}svg":
        errs.append(f"root element is {root.tag}, want <svg> in the SVG namespace")
    if root.get("version") != "1.2":
        errs.append('root needs version="1.2"')
    if root.get("baseProfile") != "tiny-ps":
        errs.append('root needs baseProfile="tiny-ps"')
    for a in ("x", "y"):
        if a in root.attrib:
            errs.append(f"root must not carry an {a} attribute")
    vb = parse_viewbox(root.get("viewBox", ""))
    if not vb:
        errs.append("root needs a viewBox")
    elif abs(vb[2] - vb[3]) > 1e-6:
        errs.append(f"viewBox must be square (is {vb[2]:g} x {vb[3]:g})")
    title = root.find(f"{{{SVG_NS}}}title")
    if title is None or not (title.text or "").strip():
        errs.append("needs a non-empty <title> directly under <svg>")
    for el in root.iter():
        name = local(el.tag)
        if name in FORBIDDEN:
            errs.append(f"<{name}> is not allowed in SVG Tiny PS")
        for k, v in el.attrib.items():
            if local(k).lower().startswith("on"):
                errs.append(f"<{name}> has event handler {local(k)}")
            if local(k) == "href" and not v.startswith("#"):
                errs.append(f"<{name}> references outside the file: {v[:60]}")
            if "url(" in v and not re.fullmatch(r"\s*url\(\s*#[^)]+\)\s*", v) and local(k) != "style":
                errs.append(f"<{name}> {local(k)} uses a non-local url()")
            if local(k) == "style" and re.search(r"url\(\s*['\"]?(?!#)", v):
                errs.append(f"<{name}> style uses a non-local url()")
    # The plate: the first painted child should cover the whole viewBox.
    first = next((c for c in root if local(c.tag) not in ("title", "desc", "defs")), None)
    if vb and (first is None or not covers(first, vb)):
        warns.append("no opaque full-bleed background as the first shape; clients crop to a "
                     "circle/rounded square and transparent corners show their background "
                     "(convert --background adds one)")
    return errs, warns


def covers(el, vb):
    if local(el.tag) != "rect" or el.get("fill", "").lower() in ("none", "transparent", ""):
        return False
    try:
        x, y = float(el.get("x", 0)), float(el.get("y", 0))
        w, h = float(el.get("width", 0)), float(el.get("height", 0))
    except ValueError:
        return False
    return x <= vb[0] and y <= vb[1] and x + w >= vb[0] + vb[2] and y + h >= vb[1] + vb[3]


def convert(src, dst, title, background):
    root = ET.parse(src).getroot()
    if local(root.tag) != "svg":
        sys.exit(f"{src}: root is not <svg>")
    removed = []
    for parent in list(root.iter()):
        for child in list(parent):
            if local(child.tag) in FORBIDDEN:
                parent.remove(child)
                removed.append(local(child.tag))
        for k in list(parent.attrib):
            if local(k).lower().startswith("on"):
                del parent.attrib[k]
    for a in ("x", "y"):
        root.attrib.pop(a, None)

    vb = parse_viewbox(root.get("viewBox", ""))
    if not vb:
        try:
            w = float(re.sub(r"[a-z%]+$", "", root.get("width", "")))
            h = float(re.sub(r"[a-z%]+$", "", root.get("height", "")))
        except ValueError:
            sys.exit(f"{src}: no viewBox and no numeric width/height to derive one from")
        vb = (0.0, 0.0, w, h)
    x, y, w, h = vb
    if abs(w - h) > 1e-6:
        # Pad the short side, centring the artwork — never scale it out of proportion.
        side = max(w, h)
        x -= (side - w) / 2
        y -= (side - h) / 2
        w = h = side
    root.set("viewBox", f"{x:g} {y:g} {w:g} {h:g}")
    root.set("version", "1.2")
    root.set("baseProfile", "tiny-ps")
    for a in ("width", "height"):
        root.attrib.pop(a, None)

    for t in root.findall(f"{{{SVG_NS}}}title"):
        root.remove(t)
    t = ET.Element(f"{{{SVG_NS}}}title")
    t.text = title
    root.insert(0, t)
    if background:
        plate = ET.Element(f"{{{SVG_NS}}}rect", {
            "x": f"{x:g}", "y": f"{y:g}", "width": f"{w:g}", "height": f"{h:g}", "fill": background})
        root.insert(1, plate)

    ET.ElementTree(root).write(dst, encoding="utf-8", xml_declaration=True)
    if removed:
        print(f"removed: {', '.join(sorted(set(removed)))}", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("svg")
    v = sub.add_parser("convert")
    v.add_argument("svg")
    v.add_argument("-o", "--output", required=True)
    v.add_argument("--title", required=True, help="brand name, becomes <title>")
    v.add_argument("--background", default="", help="opaque plate colour, e.g. '#ffffff'")
    a = ap.parse_args(argv)

    if a.cmd == "convert":
        convert(a.svg, a.output, a.title, a.background)
        path = a.output
    else:
        path = a.svg
    errs, warns = problems(path)
    for w in warns:
        print(f"warning: {w}")
    for e in errs:
        print(f"ERROR: {e}")
    if errs:
        return 1
    print(f"{path}: valid SVG Tiny PS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
