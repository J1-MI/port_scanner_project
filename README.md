# Port Scanner Project — Progress README

## 프로젝트 개요

이 레포는 포트 스캐닝 → 자산 식별 → 취약점 매핑 → 리포트(증거 포함)를 자동화하는 모의해킹용 포트 스캐너 파이프라인입니다. Kali 환경에서 실행되며 `masscan`, `nmap`, `nuclei` 등 외부 툴과 연동하도록 설계되어 있습니다.

> 현재 이 문서는 2025-09-29 기준 진행 상황과 사용법, 남은 작업을 정리한 개발용 README(Progress)입니다.

---

## 현재 상태 요약

* 포트 스캔( masscan / nmap ) → 결과 저장( JSON / XML ) 파이프라인 구성 완료
* Nmap XML 파싱(`orchestrator/parse_nmap_to_normalized.py`) 구현
* HTTP/배너 수집 및 본문·endpoints 추출(`orchestrator/enrich_with_http_and_banners.py`) 구현 및 본문 스니펫 추출 패치 적용
* 취약점 매핑(`mappers/vuln_mapper.py`) 확장 — 기본 패턴 및 `upload.action` → `CVE-2024-53677` 매핑 규칙 포함
* 매핑 자동화 스크립트(`orchestrator/map_and_update.py`) 보강: 최신 `*_http_enriched.json` 자동 탐지 지원
* 리포트 빌드 스크립트(간이/기존)를 통해 HTML 리포트 생성 가능
* 192.168.219.103 타깃 스캔에서 다음을 확보:

  * 80/tcp: Apache (nikto 발견: 보안 헤더 미설정, TRACE 허용 등)
  * 8080/tcp: 업로드 폼 발견 (`<form action="upload.action">`), `enrichment.body_snippet` 및 `enrichment.endpoints` 수집됨 → 매핑 결과 `CVE-2024-53677` 후보 등록

---

## 레포 구조(요약)

```
orchestrator/                # 파이프라인 스크립트 (parse/enrich/map/run)
mappers/                     # vuln mapping 규칙
reporters/                   # 리포트 생성 스크립트
scanners/                    # 스캐너 호출 래퍼(옵션)
data/
  raw/                       # 스캐너·툴 출력 보관
  nmap/
  final/                     # normalized / enriched / mapped JSON 및 HTML 리포트
```

---

## 빠른 시작(개발자용)

> Kali VM에서 실행을 전제로 합니다. 가상환경(.venv) 사용 권장.

1. 가상환경 활성화

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. 기본 스캔(예시)

```bash
# masscan / nmap 실행 (환경에 맞게 조정)
python3 orchestrator/run_pipeline.py 192.168.219.103
```

3. nmap 서비스 식별만 수동 실행시

```bash
nmap -sV -p 1-65535 -oX data/nmap/nmap_targets.xml 192.168.219.103
python3 orchestrator/parse_nmap_to_normalized.py data/final/normalized_192.168.219.103.json data/nmap/nmap_targets.xml
```

4. HTTP enrichment (본문/엔드포인트 추출 포함)

```bash
python3 orchestrator/enrich_with_http_and_banners.py data/final/normalized_192.168.219.103_enriched.json 192.168.219.103
```

5. 매핑 및 리포트

```bash
python3 -m orchestrator.map_and_update
python3 reporters/build_report.py
```

---

## 주요 파일(설명)

* `orchestrator/parse_nmap_to_normalized.py` : nmap XML → normalized JSON의 service/banner 업데이트
* `orchestrator/enrich_with_http_and_banners.py` : banner grab, HTTP 헤더·title·body_snippet·endpoints 수집
* `orchestrator/map_and_update.py` : 최신 http_enriched.json 자동 탐지 후 `mappers.vuln_mapper.map_vulns` 실행
* `mappers/vuln_mapper.py` : 패턴 기반 vuln candidate 매핑 규칙
* `reporters/build_report.py` : mapped JSON → HTML 리포트 (간단화 가능)

---

## 현재 확보된 증거(예)

* `data/final/normalized_192.168.219.103_enriched_http_enriched_mapped_http_enriched.json` : 8080의 `body_snippet` 및 `endpoints:["upload.action"]`
* `data/raw/nikto_192.168.219.103.txt` : 80에서의 구성 취약점 보고서
* `data/nmap/nse_http_192.168.219.103.txt` : nmap http 관련 NSE 출력

---

## 남은 작업(우선순위)

1. 매퍼 고도화: 정규식 기반 버전 추출, CVE DB(또는 NVD) 연동, confidence 계산 로직 추가
2. 템플릿 통합: nuclei / nmap NSE 결과를 자동으로 vuln_candidates와 연결
3. 리포트 개선: mapped JSON의 `enrichment`와 스캔 로그 파일 경로를 HTML에 자동으로 포함
4. 파이프라인 견고화: 입출력 파일 버전 혼선 제거, 에러 핸들링, 로그 정리
5. 서비스 확장: SMTP/FTP/DB 등 기타 프로토콜에 대한 배너 수집 및 매퍼 규칙 추가

---

## 안전/윤리 지침

* 업로드/익스플로잇 테스트는 반드시 **테스트 환경(스냅샷 포함)** 에서만 수행
* 외부 대상(허가되지 않은 시스템)에 대한 공격/익스플로잇 금지
* 로그/증거 파일에는 민감 정보가 포함될 수 있으니 접근 제어 필요

---

## 빠른 체크리스트 (다음 스프린트)

* [ ] 매퍼: 버전 추출 정규식 추가
* [ ] nuclei 연동: 템플릿 실행 → 결과 매핑 자동화
* [ ] reporters: 증거 파일 링크 포함 및 HTML 개선
* [ ] CI: 파이프라인 자동 실행 스크립트 추가

---

## 커밋·PR 가이드

* 변경은 작은 단위로: `orchestrator/`, `mappers/`, `reporters/` 각각 별도의 PR 권장
* 테스트 데이터는 `data/raw/`에 저장하고 절대 민감 정보 커밋 금지

---

## 연락 및 참고

* 프로젝트 소유자: J1-MI (레포지토리 소유자)
* 주요 참고 자료: Nmap, Nuclei, Nikto, OWASP 가이드 참조

*끝*
