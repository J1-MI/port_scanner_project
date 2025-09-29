#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import json
from pathlib import Path
import sys

def parse_nmap_xml_to_dict(xml_path: Path):
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    ports_info = {}
    for host in root.findall('host'):
        for ports in host.findall('ports'):
            for port in ports.findall('port'):
                try:
                    portid = int(port.get('portid'))
                except Exception:
                    continue
                state_elem = port.find('state')
                state = state_elem.get('state') if state_elem is not None else None
                service_elem = port.find('service')
                svc_name = None
                svc_product = None
                if service_elem is not None:
                    svc_name = service_elem.get('name')
                    # compose product/version if present
                    prod = service_elem.get('product') or ''
                    ver = service_elem.get('version') or ''
                    svc_product = (prod + (' ' + ver if ver else '')).strip() or None
                ports_info[portid] = {"state": state, "service": svc_name, "banner": svc_product}
    return ports_info

def enrich_normalized(normalized_path: Path, nmap_xml_path: Path):
    if not normalized_path.exists():
        print(f"[error] normalized JSON not found: {normalized_path}")
        return 1
    if not nmap_xml_path.exists():
        print(f"[error] nmap xml not found: {nmap_xml_path}")
        return 1

    with open(normalized_path, 'r', encoding='utf-8') as f:
        norm = json.load(f)

    ports_map = parse_nmap_xml_to_dict(nmap_xml_path)

    changed = False
    for d in norm.get('discoveries', []):
        p = d.get('port')
        if p is None:
            continue
        info = ports_map.get(int(p))
        if info:
            # only set when missing or empty
            if (not d.get('service')) and info.get('service'):
                d['service'] = info.get('service')
                changed = True
            if (not d.get('banner')) and info.get('banner'):
                d['banner'] = info.get('banner')
                changed = True

    out = normalized_path.parent / (normalized_path.stem + "_enriched.json")
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(norm, f, indent=2, ensure_ascii=False)
    print(f"[info] wrote enriched normalized file: {out} ({'updated' if changed else 'no changes'})")
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: parse_nmap_to_normalized.py <normalized.json> <nmap.xml>")
        sys.exit(2)
    normalized = Path(sys.argv[1])
    nmapxml = Path(sys.argv[2])
    rc = enrich_normalized(normalized, nmapxml)
    sys.exit(rc)
