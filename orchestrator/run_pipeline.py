#!/usr/bin/env python3
import subprocess, json, sys, os
from pathlib import Path
from mappers.vuln_mapper import map_vulns
from reporters.build_report import build_report

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
NMAP_DIR = ROOT / "data" / "nmap"
FINAL_DIR = ROOT / "data" / "final"
RAW_DIR.mkdir(parents=True, exist_ok=True)
NMAP_DIR.mkdir(parents=True, exist_ok=True)
FINAL_DIR.mkdir(parents=True, exist_ok=True)

def run_masscan(target):
    cmd = ["bash", str(ROOT / "scanners" / "masscan_runner.sh"), target]
    subprocess.run(cmd, check=True, cwd=str(ROOT / "scanners"))
    return RAW_DIR / f"masscan_{target}.json"

def run_nmap(target, masscan_json):
    cmd = ["bash", str(ROOT / "scanners" / "nmap_runner.sh"), target, str(masscan_json)]
    subprocess.run(cmd, check=True, cwd=str(ROOT / "scanners"))
    return NMAP_DIR / f"nmap_{target}.xml"

def normalize(masscan_json, nmap_xml, target):
    # 간단 표준화: masscan JSON 파싱해서 discoveries 생성
    with open(masscan_json, "r", encoding="utf-8") as f:
        mass = json.load(f)
    # masscan 출력이 리스트 형태일 경우 처리
    ports = []
    for entry in mass:
        for p in entry.get("ports", []):
            ports.append({"port": p.get("port"), "proto": p.get("proto"), "state": p.get("services")})
    normalized = {"target": target, "discoveries": []}
    for p in ports:
        normalized["discoveries"].append({
            "port": p["port"],
            "proto": p.get("proto", "tcp"),
            "state": "open",
            "service": None,
            "banner": None,
            "nmap_xml": str(nmap_xml),
            "vuln_candidates": []
        })
    out = FINAL_DIR / f"normalized_{target}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)
    return out

def map_and_report(normalized_json):
    with open(normalized_json, "r", encoding="utf-8") as f:
        norm = json.load(f)
    # 각 discovery에 대해 매핑(샘플: banner 기반)
    for d in norm["discoveries"]:
        # map_vulns은 최소한 banner 혹은 service를 인자로 받음
        d["vuln_candidates"] = map_vulns(d.get("banner") or "", {})
    report_path = build_report(norm)
    print("Report generated:", report_path)

def main():
    if len(sys.argv) < 2:
        print("Usage: run_pipeline.py <target_ip>")
        sys.exit(1)
    target = sys.argv[1]
    mass = run_masscan(target)
    nmap = run_nmap(target, mass)
    normalized = normalize(mass, nmap, target)
    map_and_report(normalized)

if __name__ == "__main__":
    main()
