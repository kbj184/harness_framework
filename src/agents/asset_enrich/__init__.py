"""asset_enrich — ECS Ansible 중앙 오케스트레이션 보강 데이터 적재.

ECS Fargate Ansible Container가 카테고리별(IDC_NW / ONPREM_UNIX / STORE_NW / STORE_PC)
수집한 결과를 S3에 PutObject 하면, 이 Lambda 가 S3 이벤트로 호출되어
tb_asset_master UPDATE + tb_asset_software UPSERT 한다.

Phase: P4 (구현 예정). 본 디렉터리는 P1 에서 DDL·구조만 선반영.
구현계획: docs/asset-enrich-pipeline.md
"""
