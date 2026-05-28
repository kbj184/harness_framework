"""네트워크 장비 PSIRT 통합 수집 (Trivy 미커버).

4 벤더 통합:
  - Cisco openVuln API   (JSON, OAuth)
  - F5 K-articles RSS    (XML)
  - Palo Alto Security   (RSS)
  - Fortinet PSIRT       (RSS)

자산 매칭은 NEVRA/purl 불가 — 모델명 + 펌웨어 버전 정규식.
tb_vendor_advisory 에 vendor_source=PSIRT_{vendor} 로 적재.
"""
