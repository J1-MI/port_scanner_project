#!/usr/bin/env python3
# orchestrator/enrich_with_http_and_banners.py
# TCP banner grab + HTTP header/title/body snippet + simple endpoint (form action) extraction
# Produces *_http_enriched.json from a normalized JSON file.

import socket
import json
import requests
from pathlib import Path
import sys
import re
from typing import Optional, Dict, Any

def tcp_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # HTTP probe for common web ports
            if port in (80, 8080, 8000, 443):
                try:
                    s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                except Exception:
                    pass
            data = s.recv(4096)
            return data.decode(errors='ignore').strip()
    except Exception:
        return None

def http_enumerate(ip: str, port: int) -> Dict[str, Any]:
    base = f"http://{ip}:{port}"
    out: Dict[str, Any] = {}
    try:
        r = requests.get(base, timeout=4)
        out['headers'] = dict(r.headers)
        text = r.text or ''
        # title extraction (case-insensitive)
        low = text.lower()
        if '<title>' in low:
            s = low.find('<title>') + 7
            e = low.find('</title>', s)
            if e > s:
                out['title'] = text[s:e].strip()
        # body snippet (first 2000 chars)
        if text:
            out['body_snippet'] = text[:2000]
        # endpoints extraction: find form action attributes and simple hrefs that look like app endpoints
        try:
            actions = re.findall(r'action\s*=\s*["\']([^"\'>\s]+)', text, flags=re.I)
            hrefs = re.findall(r'href\s*=\s*["\']([^"\'>\s]+)', text, flags=re.I)
            candidates = []
            for it in actions + hrefs:
                if len(it) > 0 and not it.lower().startswith('http'):
                    candidates.append(it)
                elif len(it) > 0 and it.lower().startswith('http'):
                    # include path part for absolute urls
                    try:
                        path = re.sub(r'^https?://[^/]+', '', it)
                        if path:
                            candidates.append(path)
                    except Exception:
                        pass
            if candidates:
                # preserve order, dedupe
                seen = []
                for c in candidates:
                    if c not in seen:
                        seen.append(c)
                out['endpoints'] = seen[:50]
        except Exception:
            pass
    except Exception:
        # keep out empty if request fails
        pass
    # robots fallback
    try:
        rr = requests.get(f"http://{ip}:{port}/robots.txt", timeout=3)
        if rr.status_code == 200:
            out.setdefault('robots', rr.text[:2000])
    except Exception:
        pass
    return out

def enrich(normalized_path: Path, ip: str) -> Optional[Path]:
    if not normalized_path.exists():
        print(f"[error] normalized file not found: {normalized_path}")
        return None
    with open(normalized_path, 'r', encoding='utf-8') as f:
        norm = json.load(f)

    changed = False
    for d in norm.get('discoveries', []):
        try:
            p = int(d.get('port'))
        except Exception:
            continue
        # banner grab if missing
        if not d.get('banner'):
            b = tcp_banner(ip, p)
            if b:
                d['banner'] = b[:1000]
                changed = True
        # for common web ports, do HTTP enrichment and include body snippet + endpoints
        if p in (80, 8080, 8000):
            he = http_enumerate(ip, p)
            if he:
                if 'enrichment' not in d or not isinstance(d['enrichment'], dict):
                    d['enrichment'] = {}
                # merge keys but do not overwrite existing ones
                for k, v in he.items():
                    if v and not d['enrichment'].get(k):
                        d['enrichment'][k] = v
                        changed = True

    out_path = normalized_path.parent / (normalized_path.stem + "_http_enriched.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(norm, f, indent=2, ensure_ascii=False)
    print(f"[info] Enriched file written to: {out_path} ({'updated' if changed else 'no changes'})")
    return out_path

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: enrich_with_http_and_banners.py <normalized.json> <target_ip>")
        sys.exit(2)
    normalized = Path(sys.argv[1])
    target = sys.argv[2]
    rc = enrich(normalized, target)
    if rc:
        sys.exit(0)
    else:
        sys.exit(3)
