-- ============================================================================
-- trivy_scan DDL — tb_asset_vulnerability
--
-- Trivy 매칭 결과의 최종 적재 테이블.
-- 자산 × CVE × 패키지 = 1행. 향후 KISA/PSIRT/embedding 매처도 같은 테이블 사용
-- (match_type 컬럼으로 출처 구분).
--
-- SSVC 등급 + Priority Score (0~100) 는 후처리 단계에서 UPDATE.
-- ============================================================================

CREATE TABLE IF NOT EXISTS tb_asset_vulnerability (
    vuln_no             BIGSERIAL PRIMARY KEY,

    -- 자산·CVE 식별
    asset_id_hash       VARCHAR(64)  NOT NULL,
    cve_id              VARCHAR(20)  NOT NULL,

    -- 매칭 출처
    match_type          VARCHAR(20)  NOT NULL,    -- TRIVY / KISA / PSIRT_* / EMBED_COSINE / MANUAL
    matched_pkg         VARCHAR(500),             -- 매칭된 패키지명 또는 purl/CPE
    fixed_version       VARCHAR(200),             -- 수정 버전 (Trivy 응답)

    -- 위협 메타 (캐시)
    cvss_score          NUMERIC(3,1),
    is_kev              BOOLEAN NOT NULL DEFAULT FALSE,
    epss_score          NUMERIC(5,4),
    epss_trend          NUMERIC(5,4),             -- 7일 변화량
    is_exploit_signal   BOOLEAN NOT NULL DEFAULT FALSE,

    -- SSVC + Priority (후처리 UPDATE)
    criticality_score   SMALLINT,                 -- 자산 3~9
    ssvc_priority       VARCHAR(5),               -- P0-A/P0-B/P0-C/P1/P2/P3
    priority_score      NUMERIC(5,2),             -- 0.00~100.00
    action_due          DATE,
    ssvc_reason         TEXT,

    -- 라이프사이클
    status              VARCHAR(20)  NOT NULL DEFAULT 'OPEN',
        -- OPEN / PATCHED / ACCEPTED / FALSE_POSITIVE / FALSE_POSITIVE_VEX
    first_observed_at   TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_observed_at    TIMESTAMP    NOT NULL DEFAULT NOW(),

    -- 멱등성: 같은 자산·CVE·매칭패키지 1행
    CONSTRAINT uk_asset_vuln UNIQUE (asset_id_hash, cve_id, matched_pkg),
    CONSTRAINT fk_vuln_asset FOREIGN KEY (asset_id_hash)
        REFERENCES tb_asset_master(asset_id_hash)
);

CREATE INDEX IF NOT EXISTS idx_vuln_asset       ON tb_asset_vulnerability (asset_id_hash);
CREATE INDEX IF NOT EXISTS idx_vuln_cve         ON tb_asset_vulnerability (cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_match_type  ON tb_asset_vulnerability (match_type);
CREATE INDEX IF NOT EXISTS idx_vuln_status      ON tb_asset_vulnerability (status);

-- SSVC 대시보드 정렬 — (ssvc_priority, priority_score DESC)
CREATE INDEX IF NOT EXISTS idx_vuln_priority
    ON tb_asset_vulnerability (ssvc_priority, priority_score DESC)
    WHERE status = 'OPEN';

-- KEV / Exploit signal 우선순위 빠른 조회
CREATE INDEX IF NOT EXISTS idx_vuln_kev
    ON tb_asset_vulnerability (cve_id)
    WHERE is_kev = TRUE OR is_exploit_signal = TRUE;

COMMENT ON TABLE  tb_asset_vulnerability IS 'CVE 매칭 결과 (Trivy + KISA + PSIRT + EMBED) + SSVC 우선순위';
COMMENT ON COLUMN tb_asset_vulnerability.match_type     IS 'TRIVY / KISA / PSIRT_{vendor} / EMBED_COSINE / MANUAL';
COMMENT ON COLUMN tb_asset_vulnerability.matched_pkg    IS 'Trivy: 패키지명 또는 purl / PSIRT: 모델명 / CPE';
COMMENT ON COLUMN tb_asset_vulnerability.ssvc_priority  IS 'P0-A(crit≥8) / P0-B(6-7) / P0-C(≤5) / P1 / P2 / P3';
COMMENT ON COLUMN tb_asset_vulnerability.priority_score IS '30×CVSS_norm + 25×EPSS + 25×Exploit + 20×Crit_norm';
COMMENT ON COLUMN tb_asset_vulnerability.status         IS 'OPEN / PATCHED / ACCEPTED / FALSE_POSITIVE / FALSE_POSITIVE_VEX';
