-- tb_asset_master 운영구분(op_class) 컬럼 추가 마이그레이션 (멱등)
-- 목적: 자산목록 UI의 "운영구분" 필터/컬럼 지원. 운영(PROD)/스테이지(STAGE)/개발(DEV)/DR.
--       수집기·머지가 채우지 않는 관리자 수동 입력 필드 — 초기값 전부 NULL.
-- 생성일: 2026-06-12
-- 적용: Aurora PostgreSQL VPC 내 수동 실행 (DB 직접 접속 불가 시 ECS Task/Bastion 경유)
-- ⚠ 컬럼 삭제·이름 변경 없음. ADD COLUMN IF NOT EXISTS — 멱등. 백필 없음(수동 관리).

ALTER TABLE tb_asset_master
    ADD COLUMN IF NOT EXISTS op_class VARCHAR(20);

COMMENT ON COLUMN tb_asset_master.op_class
    IS '운영구분(관리자 수동 입력). PROD(운영)/STAGE(스테이지)/DEV(개발)/DR. 초기 NULL';
