# mappers/vuln_mapper.py
SIMPLE_MAP = [
    {"pattern": "Struts", "cve": ["CVE-2024-53677"], "priority": 9},
    {"pattern": "Apache-Coyote", "cve": [], "priority": 3},
    {"pattern": "nginx", "cve": [], "priority": 3},
]

def map_vulns(banner: str, headers: dict):
    found = []
    b = (banner or "").lower()
    for r in SIMPLE_MAP:
        if r["pattern"].lower() in b:
            found.append({"cve": r["cve"], "pattern": r["pattern"], "priority": r["priority"]})
    return found
