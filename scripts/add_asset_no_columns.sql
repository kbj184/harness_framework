-- tb_asset_master 에 표시용 자산번호 컬럼 추가 (멱등)
-- 형식: {카테고리접두사}-{등록연도}-{6자리 전역 0패딩}
-- 예) CSVR-2026-000001, PC-2026-013885
-- ⚠️ Aurora VPC 내부 — 파일 산출 후 사용자가 직접 적용

-- 1. 시퀀스 생성
CREATE SEQUENCE IF NOT EXISTS seq_asset_master_no;

-- 2. 전역 카운터 컬럼 추가 (컬럼이 이미 존재하면 무시)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tb_asset_master' AND column_name = 'asset_seq'
    ) THEN
        ALTER TABLE tb_asset_master
            ADD COLUMN asset_seq BIGINT DEFAULT nextval('seq_asset_master_no');
    END IF;
END$$;

-- 3. GENERATED ALWAYS 표시용 자산번호 컬럼 추가 (컬럼이 이미 존재하면 무시)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tb_asset_master' AND column_name = 'asset_no'
    ) THEN
        ALTER TABLE tb_asset_master
            ADD COLUMN asset_no VARCHAR(20) GENERATED ALWAYS AS (
                CASE category_cd
                    WHEN 'HW_SVR'   THEN 'SVR'
                    WHEN 'CLD_SVR'  THEN 'CSVR'
                    WHEN 'SW_WAS'   THEN 'WAS'
                    WHEN 'SW_DB'    THEN 'DB'
                    WHEN 'CLD_DB'   THEN 'CDB'
                    WHEN 'HW_NET'   THEN 'NET'
                    WHEN 'HW_SEC'   THEN 'SEC'
                    WHEN 'CLD_SEC'  THEN 'CSEC'
                    WHEN 'CLD_STG'  THEN 'CSTG'
                    WHEN 'HW_STG'   THEN 'STG'
                    WHEN 'SW_APP'   THEN 'APP'
                    WHEN 'HW_PC'    THEN 'PC'
                    WHEN 'SW_PKG'   THEN 'PKG'
                    WHEN 'INFO_DOC' THEN 'DOC'
                    WHEN 'HW_POS'   THEN 'POS'
                    WHEN 'HW_VM'    THEN 'VM'
                    WHEN 'HW_HV'    THEN 'HV'
                    ELSE 'AST'
                END || '-' || (EXTRACT(YEAR FROM reg_dt)::int)::text || '-' || lpad(asset_seq::text, 6, '0')
            ) STORED;
    END IF;
END$$;

-- 4. 인덱스 생성
CREATE INDEX IF NOT EXISTS idx_master_asset_no ON tb_asset_master (asset_no);

-- 5. 컬럼 주석
COMMENT ON COLUMN tb_asset_master.asset_seq IS '전역 단일 카운터 (카테고리 무관). asset_no 생성용 surrogate';
COMMENT ON COLUMN tb_asset_master.asset_no  IS '표시용 자산번호. {접두사}-{등록연도}-{6자리}. 예) PC-2026-013885';
