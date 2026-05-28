-- ============================================================================
-- trivy_scan DDL — tb_asset_vulnerability
--
-- Trivy 매칭 결과의 최종 적재 테이블.
-- 기존 테이블 존재 시(이전 sprint 에서 만든 16-col 스키마) ALTER 로 누락 컬럼 추가.
-- 신규 환경에서는 CREATE TABLE 로 풀 스키마 생성.
-- ============================================================================

-- 신규 환경용 — IF NOT EXISTS 로 기존 환경에서는 skip
CREATE TABLE IF NOT EXISTS tb_asset_vulnerability (
    vuln_no             BIGSERIAL PRIMARY KEY,
    asset_id_hash       VARCHAR(64)  NOT NULL,
    cve_id              VARCHAR(20)  NOT NULL,
    match_type          VARCHAR(20)  NOT NULL DEFAULT 'TRIVY',
    matched_pkg         VARCHAR(500),
    fixed_version       VARCHAR(200),
    cvss_score          NUMERIC(3,1),
    is_kev              BOOLEAN NOT NULL DEFAULT FALSE,
    epss_score          NUMERIC(5,4),
    epss_trend          NUMERIC(5,4),
    is_exploit_signal   BOOLEAN NOT NULL DEFAULT FALSE,
    criticality_score   SMALLINT,
    ssvc_priority       VARCHAR(5),
    priority_score      NUMERIC(5,2),
    action_due          DATE,
    ssvc_reason         TEXT,
    status              VARCHAR(20)  NOT NULL DEFAULT 'OPEN',
    first_observed_at   TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_observed_at    TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- 기존 환경 마이그레이션 — 누락 컬럼만 추가
ALTER TABLE tb_asset_vulnerability
    ADD COLUMN IF NOT EXISTS match_type        VARCHAR(20)  NOT NULL DEFAULT 'TRIVY',
    ADD COLUMN IF NOT EXISTS matched_pkg       VARCHAR(500),
    ADD COLUMN IF NOT EXISTS fixed_version     VARCHAR(200),
    ADD COLUMN IF NOT EXISTS is_kev            BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS epss_score        NUMERIC(5,4),
    ADD COLUMN IF NOT EXISTS epss_trend        NUMERIC(5,4),
    ADD COLUMN IF NOT EXISTS is_exploit_signal BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS criticality_score SMALLINT,
    ADD COLUMN IF NOT EXISTS priority_score    NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS first_observed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS last_observed_at  TIMESTAMP NOT NULL DEFAULT NOW();

-- 기존 kev_listed → is_kev 동기화 (있을 때만)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tb_asset_vulnerability' AND column_name = 'kev_listed'
    ) THEN
        UPDATE tb_asset_vulnerability
            SET is_kev = COALESCE(kev_listed, FALSE)
        WHERE is_kev IS DISTINCT FROM COALESCE(kev_listed, FALSE);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_vuln_asset       ON tb_asset_vulnerability (asset_id_hash);
CREATE INDEX IF NOT EXISTS idx_vuln_cve         ON tb_asset_vulnerability (cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_match_type  ON tb_asset_vulnerability (match_type);
CREATE INDEX IF NOT EXISTS idx_vuln_status      ON tb_asset_vulnerability (status);

-- 멱등성 — UNIQUE INDEX (제약 대신 인덱스 — 기존 중복 데이터 대응 위해 PARTIAL 옵션)
-- 기존 데이터에 NULL matched_pkg 가 많으면 충돌 가능 — COALESCE 사용
CREATE UNIQUE INDEX IF NOT EXISTS uk_asset_vuln
    ON tb_asset_vulnerability (asset_id_hash, cve_id, COALESCE(matched_pkg, ''));

-- SSVC 대시보드 정렬
CREATE INDEX IF NOT EXISTS idx_vuln_priority
    ON tb_asset_vulnerability (ssvc_priority, priority_score DESC)
    WHERE status = 'OPEN';

-- KEV / Exploit signal 빠른 조회
CREATE INDEX IF NOT EXISTS idx_vuln_kev
    ON tb_asset_vulnerability (cve_id)
    WHERE is_kev = TRUE OR is_exploit_signal = TRUE;

COMMENT ON TABLE  tb_asset_vulnerability IS 'CVE 매칭 결과 (Trivy + KISA + PSIRT + EMBED) + SSVC 우선순위';
COMMENT ON COLUMN tb_asset_vulnerability.match_type     IS 'TRIVY / KISA / PSIRT_{vendor} / EMBED_COSINE / MANUAL';
COMMENT ON COLUMN tb_asset_vulnerability.matched_pkg    IS 'Trivy: 패키지명 또는 purl / PSIRT: 모델명 / CPE';
COMMENT ON COLUMN tb_asset_vulnerability.ssvc_priority  IS 'P0-A(crit≥8) / P0-B(6-7) / P0-C(≤5) / P1 / P2 / P3';
COMMENT ON COLUMN tb_asset_vulnerability.priority_score IS '30×CVSS_norm + 25×EPSS + 25×Exploit + 20×Crit_norm';
COMMENT ON COLUMN tb_asset_vulnerability.status         IS 'OPEN / PATCHED / ACCEPTED / FALSE_POSITIVE / FALSE_POSITIVE_VEX';
