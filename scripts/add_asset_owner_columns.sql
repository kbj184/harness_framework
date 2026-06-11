-- tb_asset_master 담당부서/담당자 일급 컬럼 승격 마이그레이션 (멱등)
-- 목적: attributes->'EXCEL'->>'owner_dept' / 'owner_user_nm' (JSONB)을 일급 컬럼으로 승격하여
--       자산목록 쿼리 성능 개선 및 신규 자산목록 UI 지원
-- 생성일: 2026-06-11
-- 적용: Aurora PostgreSQL VPC 내 수동 실행 (DB 직접 접속 불가 시 ECS Task/Bastion 경유)
-- ⚠ 컬럼 삭제·이름 변경 없음. ADD COLUMN IF NOT EXISTS — 멱등.

-- 1. 컬럼 추가
ALTER TABLE tb_asset_master
    ADD COLUMN IF NOT EXISTS owner_dept    VARCHAR(100),
    ADD COLUMN IF NOT EXISTS owner_user_nm VARCHAR(100);

COMMENT ON COLUMN tb_asset_master.owner_dept    IS 'ISMS 대장 담당부서명 (attributes.EXCEL.owner_dept 승격)';
COMMENT ON COLUMN tb_asset_master.owner_user_nm IS 'ISMS 대장 담당자명 (attributes.EXCEL.owner_user_nm 승격)';

-- 2. 기존 행 백필
--    JSONB 키명 근거: collect_cmdb/src/agents/excel_ledger/load_master.py _attributes()
--      owner_dept    → attributes->'EXCEL'->>'owner_dept'
--      owner_user_nm → attributes->'EXCEL'->>'owner_user_nm'
--    NULL 조건: 이미 채워진 행(재실행)은 건너뜀.
UPDATE tb_asset_master
SET
    owner_dept    = attributes -> 'EXCEL' ->> 'owner_dept',
    owner_user_nm = attributes -> 'EXCEL' ->> 'owner_user_nm'
WHERE
    (owner_dept IS NULL OR owner_user_nm IS NULL)
    AND attributes -> 'EXCEL' IS NOT NULL;

-- 3. 선택 인덱스 (자산목록 부서별 필터 지원)
--    NOTE: CONCURRENTLY는 트랜잭션 외부에서 실행 필요. 운영 락 회피.
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_master_owner_dept
--     ON tb_asset_master (owner_dept)
--     WHERE owner_dept IS NOT NULL;
