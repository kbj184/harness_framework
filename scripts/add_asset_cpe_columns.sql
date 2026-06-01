-- tb_asset_master 에 시나리오 schema 정합 컬럼 추가 (멱등)
-- 적용 후 Parser Agent 가 cpe_* / criticality_score 를 채워야 KISA/PSIRT 매칭·SSVC 차등 작동
ALTER TABLE tb_asset_master
  ADD COLUMN IF NOT EXISTS cpe_vendor        VARCHAR(200),
  ADD COLUMN IF NOT EXISTS cpe_product       VARCHAR(200),
  ADD COLUMN IF NOT EXISTS cpe_version       VARCHAR(100),
  ADD COLUMN IF NOT EXISTS criticality_score SMALLINT,
  ADD COLUMN IF NOT EXISTS isms_yn           CHAR(1) DEFAULT 'N';

-- 매칭 인덱스 (선택)
CREATE INDEX IF NOT EXISTS idx_asset_cpe_vendor_product
  ON tb_asset_master (cpe_vendor, cpe_product)
  WHERE cpe_vendor IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_asset_criticality
  ON tb_asset_master (criticality_score)
  WHERE lifecycle_state = 'ACTIVE';

COMMENT ON COLUMN tb_asset_master.cpe_vendor        IS 'Parser Agent 가 부여한 CPE vendor (KISA/PSIRT 매칭 입력)';
COMMENT ON COLUMN tb_asset_master.cpe_product       IS 'Parser Agent 가 부여한 CPE product';
COMMENT ON COLUMN tb_asset_master.cpe_version       IS 'Parser Agent 가 부여한 CPE version';
COMMENT ON COLUMN tb_asset_master.criticality_score IS 'C+I+A 합산 3~9 (SSVC 2단계 P0-A/B/C 차등 근거)';
COMMENT ON COLUMN tb_asset_master.isms_yn           IS 'ISMS-P 인증 대상 여부 (Y/N)';
