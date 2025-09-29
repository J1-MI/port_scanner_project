# reporters/build_report.py
import json
from pathlib import Path
def build_report(normalized: dict):
    out = Path("data/final") / f"report_{normalized['target']}.html"
    html = ["<html><head><meta charset='utf-8'><title>Scan Report</title></head><body>"]
    html.append(f"<h1>Scan Report - {normalized['target']}</h1>")
    html.append("<ul>")
    for d in normalized["discoveries"]:
        html.append(f"<li>Port: {d['port']} - vuln_candidates: {d.get('vuln_candidates')}</li>")
    html.append("</ul></body></html>")
    out.write_text("\n".join(html), encoding="utf-8")
    return str(out)
