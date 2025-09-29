# mappers/vuln_mapper.py
# Simple pattern-based vulnerability candidate mapper.
# Checks banner and enrichment (http headers/title/robots) and returns candidates.
# Candidate format: {"pattern": "...", "reason": "...", "confidence": "low|medium|high"}

import re

# pattern rules: you can extend with more specific patterns (or version regexes)
PATTERNS = [
    # Web / server
    {"pattern": "struts", "reason": "Likely Apache Struts framework (check upload/OGNL-related CVEs).", "confidence": "high"},
    {"pattern": "apache", "reason": "Apache HTTP server detected; run version detection and web vuln templates (path traversal, httpd CVEs).", "confidence": "medium"},
    {"pattern": "tomcat", "reason": "Tomcat-related service — check manager/struts/webapps", "confidence": "medium"},
    {"pattern": "nginx", "reason": "Nginx server detected; consider common misconfigurations.", "confidence": "medium"},

    # Microsoft / Windows
    {"pattern": "msrpc", "reason": "Microsoft RPC service present — enumerate MSRPC endpoints and SMB shares.", "confidence": "high"},
    {"pattern": "microsoft windows rpc", "reason": "MSRPC banner — may allow information leak or RPC-specific CVEs.", "confidence": "high"},
    {"pattern": "rdp", "reason": "RDP service detected — check encryption level and exposed RDP vulnerabilities.", "confidence": "medium"},
    {"pattern": "smb", "reason": "SMB-related service — enumerate shares and SMB-specific CVEs (e.g., SMB signing/SMBv1).", "confidence": "high"},
    {"pattern": "tcpwrapped", "reason": "Port reported as tcpwrapped — could be firewall/filter or service requiring specific probe; run targeted NSE scripts.", "confidence": "low"},
]

def _text_from_enrichment(enrichment):
    parts = []
    if not enrichment:
        return ""
    # handle headers naming variation
    headers = enrichment.get("headers") or enrichment.get("http_headers") or {}
    if isinstance(headers, dict):
        parts.append(" ".join(f"{k}:{v}" for k,v in headers.items() if v))
    # title/html_title
    title = enrichment.get("title") or enrichment.get("html_title")
    if title:
        parts.append(title)
    # robots or other textual hints
    robots = enrichment.get("robots") or enrichment.get("notes")
    if robots:
        if isinstance(robots, list):
            parts.extend(robots)
        else:
            parts.append(str(robots))
    return " ".join(parts)

def map_vulns(banner: str, enrichment: dict):
    text = " ".join([s for s in [ (banner or ""), _text_from_enrichment(enrichment) ] if s ])
    text = text.lower()
    candidates = []
    seen = set()
    for rule in PATTERNS:
        p = rule["pattern"].lower()
        if p in text:
            key = p
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "pattern": rule["pattern"],
                "reason": rule["reason"],
                "confidence": rule["confidence"]
            })
    return candidates
