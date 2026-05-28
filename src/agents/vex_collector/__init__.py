"""VEX (Vulnerability Exploitability eXchange) 콜렉터.

벤더가 "이 CVE 는 우리 제품에 영향 없음" 공식 선언을 수집해 tb_vex 에 적재.
Trivy 매칭 결과 INSERT 직전 SVC_VULN 이 이 테이블을 JOIN — status=not_affected
이면 자동 dismiss(FALSE_POSITIVE_VEX). 운영자 큐 부담 80%↓.

지원 소스 (CSAF 2.0 JSON):
  - Red Hat CSAF VEX  (access.redhat.com/security/data/csaf/v2/vex/)
  - OpenVEX 표준 JSON (CNCF — 외부 maintainer 발행)

ALAS-as-VEX 는 Trivy DB 가 이미 흡수해 별도 콜렉터 불필요.
"""
