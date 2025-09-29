#!/usr/bin/env python3
# reporters/build_report.py
import json
from pathlib import Path
import sys
import html
import glob
import os

def find_latest_mapped():
    p = Path("data/final")
    files = sorted(p.glob("*mapped.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    return files[0] if files else None

def render_discovery(d):
    out = []
    out.append(f"<h3>Port {d.get('port')} - service: {html.escape(str(d.get('service')))}</h3>")
    out.append("<ul>")
    out.append(f"<li><b>banner:</b> {html.escape(str(d.get('banner')))}</li>")
    enr = d.get('enrichment') or {}
    if enr:
        out.append("<li><b>enrichment:</b><ul>")
        if enr.get('endpoints'): out.append(f"<li>endpoints: {html.escape(str(enr.get('endpoints')))}</li>")
        if enr.get('body_snippet'):
            snippet = html.escape(enr.get('body_snippet')[:800])
            out.append(f"<li>body_snippet (truncated):<pre>{snippet}</pre></li>")
        if enr.get('headers'): out.append(f"<li>headers: {html.escape(str(enr.get('headers')))}</li>")
        if enr.get('robots'): out.append(f"<li>robots: {html.escape(str(enr.get('robots')[:400]))}</li>")
        out.append("</ul></li>")
    v = d.get('vuln_candidates') or []
    if v:
        out.append("<li><b>vuln_candidates:</b><ul>")
        for c in v:
            out.append("<li>")
            out.append(f"<b>pattern:</b> {html.escape(str(c.get('pattern')))}<br>")
            if c.get('cve'): out.append(f"<b>cve:</b> {html.escape(str(c.get('cve')))}<br>")
            out.append(f"<b>reason:</b> {html.escape(str(c.get('reason')))}<br>")
            out.append(f"<b>confidence:</b> {html.escape(str(c.get('confidence')))}")
            out.append("</li>")
        out.append("</ul></li>")
    else:
        out.append("<li><b>vuln_candidates:</b> []</li>")
    out.append("</ul>")
    return "\n".join(out)

def collect_evidence_links():
    links = []
    # raw, nmap, final directories
    for pattern in ["data/raw/*", "data/nmap/*", "data/final/*mapped.json"]:
        for p in sorted(glob.glob(pattern)):
            try:
                size = os.path.getsize(p)
            except Exception:
                size = 0
            links.append((p, size))
    return links

def build_report_from_dict(normalized):
    target = normalized.get("target") or "unknown"
    outpath = Path("data/final") / f"report_{target}.html"
    html_lines = []
    html_lines.append("<html><head><meta charset='utf-8'><title>Scan Report</title></head><body>")
    html_lines.append(f"<h1>Scan Report - {html.escape(target)}</h1>")
    html_lines.append("<h2>Summary</h2>")
    html_lines.append("<ul>")
    for d in normalized.get("discoveries", []):
        html_lines.append(f"<li>Port: {d.get('port')} - vuln_candidates: {len(d.get('vuln_candidates') or [])}</li>")
    html_lines.append("</ul>")

    html_lines.append("<h2>Details</h2>")
    for d in normalized.get("discoveries", []):
        html_lines.append(render_discovery(d))

    html_lines.append("<h2>Evidence files</h2>")
    html_lines.append("<ul>")
    for p, size in collect_evidence_links():
        html_lines.append(f"<li>{html.escape(p)} (size: {size} bytes)</li>")
    html_lines.append("</ul>")

    html_lines.append("</body></html>")
    outpath.write_text("\n".join(html_lines), encoding="utf-8")
    return str(outpath)

def main():
    # usage: python reporters/build_report.py [path/to/mapped.json]
    if len(sys.argv) > 1:
        src = Path(sys.argv[1])
    else:
        src = find_latest_mapped()
        if not src:
            print("[error] no mapped.json found in data/final")
            return 2
    print("[info] building report from:", src)
    j = json.load(open(src, encoding='utf-8'))
    out = build_report_from_dict(j)
    print("[info] wrote report:", out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
