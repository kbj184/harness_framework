"""ISMS-P 정보자산 대장 (전사 통합본 xlsx) → 정규화 자산 레코드 ETL.

단일 소스(엑셀) 일괄 적재용. 외부 수집 채널 없이 워크북 내부 정보만으로
카테고리별 결정론 식별(asset_id_hash) + §9 master 매핑 수행.

설계 SSOT: pipearchi/docs/isms-ledger-ingestion-plan.md (§8 식별 / §9 적재 / §10 CVE)
"""
