#!/usr/bin/env python3
# orchestrator/map_and_update.py
# Map vuln candidates using mappers.vuln_mapper.map_vulns
# Usage: python3 map_and_update.py [path/to/http_enriched.json]
import json
from pathlib import Path
import sys

def find_latest_http_enriched():
    p = Path("data/final")
    files = sorted(p.glob("*http_enriched*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    return files[0] if files else None

def main():
    if len(sys.argv) > 1:
        src = Path(sys.argv[1])
    else:
        src = find_latest_http_enriched()
        if src is None:
            print("[error] no http_enriched file found in data/final")
            return 2
    if not src.exists():
        print(f"[error] source file not found: {src}")
        return 3

    print("[info] using source:", src)
    with open(src, "r", encoding="utf-8") as f:
        j = json.load(f)

    try:
        from mappers.vuln_mapper import map_vulns
    except Exception as e:
        print("[error] could not import map_vulns:", e)
        return 4

    for d in j.get("discoveries", []):
        try:
            d["vuln_candidates"] = map_vulns(d.get("banner") or "", d.get("enrichment", {}))
        except Exception as e:
            print("[warn] mapping failed for port", d.get("port"), e)

    out = src.parent / (src.stem + "_mapped.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(j, f, indent=2, ensure_ascii=False)
    print("[info] wrote mapped file:", out)
    return 0

if __name__ == "__main__":
    sys.exit(main())
