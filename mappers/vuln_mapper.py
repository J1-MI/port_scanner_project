# mappers/vuln_mapper.py
# Pattern-based vulnerability mapper (extended with Struts upload detection)
import re

# pattern rules: extend/adjust as needed
PATTERNS = [
    # Struts / Java web
    {"pattern": "upload.action", "cve": ["CVE-2024-53677"], "reason": "Detected upload.action endpoint (typical Struts file upload handler). Map to CVE-2024-53677 candidate.", "confidence": "high"},
    {"pattern": "struts", "cve": ["CVE-2024-53677"], "reason": "Indication of Apache Struts framework; check for Struts-related CVEs including CVE-2024-53677.", "confidence": "high"},
    {"pattern": "apache-coyote", "cve": [], "reason": "Apache-Coyote (Tomcat connector) identified — Java web app (check Struts/Tomcat issues).", "confidence": "medium"},
    {"pattern": "apache", "cve": [], "reason": "Apache HTTP server detected; consider HTTP-related configuration issues.", "confidence": "medium"},

    # Microsoft / Windows
    {"pattern": "msrpc", "cve": [], "reason": "Microsoft RPC service present — enumerate MSRPC endpoints and SMB shares.", "confidence": "high"},
    {"pattern": "microsoft windows rpc", "cve": [], "reason": "MSRPC banner — may allow information leak or RPC-specific CVEs.", "confidence": "high"},
    {"pattern": "rdp", "cve": [], "reason": "RDP service detected — check encryption level and exposed RDP vulnerabilities.", "confidence": "medium"},
    {"pattern": "smb", "cve": [], "reason": "SMB-related service — enumerate shares and SMB-specific CVEs (e.g., SMB signing/SMBv1).", "confidence": "high"},
    {"pattern": "tcpwrapped", "cve": [], "reason": "Port reported as tcpwrapped — could be firewall/filter or service requiring specific probe; run targeted NSE scripts.", "confidence": "low"},
]

def _text_from_enrichment(enrichment):
    parts = []
    if not enrichment:
        return ""
    headers = enrichment.get("headers") or enrichment.get("http_headers") or {}
    if isinstance(headers, dict):
        parts.append(" ".join(f"{k}:{v}" for k,v in headers.items() if v))
    title = enrichment.get("title") or enrichment.get("html_title")
    if title:
        parts.append(title)
    robots = enrichment.get("robots") or enrichment.get("notes")
    if robots:
        if isinstance(robots, list):
            parts.extend(robots)
        else:
            parts.append(str(robots))
    return " ".join(parts)

def map_vulns(banner: str, enrichment: dict):
    """Return list of candidate dicts: {cve:[...], pattern, reason, confidence}"""
    text = " ".join([s for s in [ (banner or ""), _text_from_enrichment(enrichment) ] if s ])
    text_l = text.lower()
    candidates = []
    seen = set()
    for rule in PATTERNS:
        p = rule["pattern"].lower()
        if p in text_l:
            key = p
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "pattern": rule["pattern"],
                "cve": rule.get("cve", []),
                "reason": rule["reason"],
                "confidence": rule["confidence"]
            })
    return candidates
