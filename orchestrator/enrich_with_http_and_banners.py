#!/usr/bin/env python3
import socket, json, requests, time
from pathlib import Path
import sys

def tcp_banner(ip, port, timeout=2.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # HTTP probe for typical web ports
            if port in (80, 8080, 8000, 443):
                try:
                    s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                except Exception:
                    pass
            data = s.recv(4096)
            return data.decode(errors='ignore').strip()
    except Exception:
        return None

def http_enumerate(ip, port):
    base = f"http://{ip}:{port}"
    out = {}
    try:
        r = requests.get(base, timeout=4)
        out['headers'] = dict(r.headers)
        text = r.text or ''
        if '<title>' in text.lower():
            low = text.lower()
            s = low.find('<title>') + 7
            e = low.find('</title>', s)
            if e > s:
                out['title'] = text[s:e].strip()
    except Exception:
        pass
    # robots
    try:
        rr = requests.get(f"http://{ip}:{port}/robots.txt", timeout=3)
        if rr.status_code == 200:
            out['robots'] = rr.text[:2000]
    except Exception:
        pass
    return out

def enrich(normalized_path: Path, ip: str):
    if not normalized_path.exists():
        print(f"[error] normalized file not found: {normalized_path}")
        return 1
    with open(normalized_path, 'r', encoding='utf-8') as f:
        norm = json.load(f)
    changed = False
    for d in norm.get('discoveries', []):
        p = int(d.get('port'))
        if not d.get('banner'):
            b = tcp_banner(ip, p)
            if b:
                d['banner'] = b[:1000]
                changed = True
        if p in (80, 8080, 8000):
            he = http_enumerate(ip, p)
            if he:
                if 'enrichment' not in d:
                    d['enrichment'] = {}
                # merge enrichment (do not overwrite existing keys)
                for k, v in he.items():
                    if v and not d['enrichment'].get(k):
                        d['enrichment'][k] = v
                        changed = True
    out_path = normalized_path.parent / (normalized_path.stem + "_http_enriched.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(norm, f, indent=2, ensure_ascii=False)
    print(f"[info] Enriched file written to: {out_path} ({'updated' if changed else 'no changes'})")
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: enrich_with_http_and_banners.py <normalized.json> <target_ip>")
        sys.exit(2)
    normalized = Path(sys.argv[1])
    target = sys.argv[2]
    rc = enrich(normalized, target)
    sys.exit(rc)
