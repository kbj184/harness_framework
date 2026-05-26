"""SBOM Ingest 에이전트.

Ansible(package_facts) 등 자산이 직접 보내는 SBOM JSON 을 S3에서 받아
tb_asset_software 에 적재한다. 콜렉터가 아니라 ingest 패턴 — 외부 호출 없음.

지원 입력 형식:
    target-a.json 류 — Ansible package_facts 결과 (rpm/dpkg/포터블)
"""
