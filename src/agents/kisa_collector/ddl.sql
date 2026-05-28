-- ============================================================================
-- kisa_collector DDL — tb_vendor_advisory 신규
--
-- 본 테이블은 Trivy 미커버 advisory 통합 저장:
--   - KISA / 금융보안원 (한국 한정 SW)
--   - 네트워크 장비 PSIRT (Cisco / F5 / Palo Alto / Fortinet — psirt_collector 가 사용)
--
-- vendor_source 컬럼으로 출처 구분.
-- ============================================================================

CREATE TABLE IF NOT EXISTS tb_vendor_advisory (
    advisory_id       VARCHAR(50)  PRIMARY KEY,        -- KISA-12345 / cisco-sa-2024-XXX 등
    vendor_source     VARCHAR(30)  NOT NULL,           -- KISA / FSEC / PSIRT_CISCO / PSIRT_F5 / ...
    severity          VARCHAR(20),                     -- critical / important / moderate / low (선택)
    title             TEXT,
    overview          TEXT,
    affected_model    VARCHAR(200),                    -- 네트워크 장비: Cisco Catalyst 9200 등
    affected_version  VARCHAR(200),                    -- 영향 버전 범위
    fix_command       TEXT,                            -- 조치 명령 / 패치 안내
    cve_ids           TEXT[],                          -- 관련 CVE 배열
    source_url        TEXT,                            -- 원본 URL
    published_at      DATE,
    updated_at        DATE,
    raw_data          JSONB,                           -- 원본 응답 (옵션)
    fetched_at        TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vadv_source
    ON tb_vendor_advisory (vendor_source);

CREATE INDEX IF NOT EXISTS idx_vadv_published
    ON tb_vendor_advisory (published_at DESC);

-- GIN 인덱스 — CVE 매칭 쿼리 (= ANY(cve_ids)) 고속화
CREATE INDEX IF NOT EXISTS idx_vadv_cve_ids
    ON tb_vendor_advisory USING GIN (cve_ids);

COMMENT ON TABLE  tb_vendor_advisory             IS 'Trivy 미커버 advisory 통합 (KISA + 금융보안원 + 네트워크 장비 PSIRT)';
COMMENT ON COLUMN tb_vendor_advisory.vendor_source IS 'KISA / FSEC / PSIRT_CISCO / PSIRT_F5 / PSIRT_PA / PSIRT_FORTI';
COMMENT ON COLUMN tb_vendor_advisory.affected_model   IS '네트워크 장비 한정 — 영향 모델명 (Cisco Catalyst 9200 등)';
COMMENT ON COLUMN tb_vendor_advisory.affected_version IS '영향 펌웨어/SW 버전 범위';
COMMENT ON COLUMN tb_vendor_advisory.cve_ids     IS '관련 CVE 배열 (advisory 1건 : N CVE)';
