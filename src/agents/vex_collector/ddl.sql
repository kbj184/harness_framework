-- ============================================================================
-- vex_collector DDL — tb_vex
--
-- VEX statement 통합 저장. SVC_VULN 이 Trivy 결과 INSERT 직전 이 테이블을
-- JOIN — (cve_id, product_purl/cpe) 매치 + status=not_affected 면 자동 dismiss
-- (tb_asset_vulnerability.status = FALSE_POSITIVE_VEX).
-- ============================================================================

CREATE TABLE IF NOT EXISTS tb_vex (
    vex_no             BIGSERIAL PRIMARY KEY,

    -- 영향 대상
    cve_id             VARCHAR(20)  NOT NULL,
    product_purl       VARCHAR(500),
    product_cpe        VARCHAR(500),

    -- 선언 내용 (CSAF 2.0)
    status             VARCHAR(30)  NOT NULL,
        -- not_affected / affected / fixed / under_investigation
    justification      VARCHAR(80),
        -- CSAF 5종:
        --   component_not_present
        --   vulnerable_code_not_present
        --   vulnerable_code_not_in_execute_path
        --   vulnerable_code_cannot_be_controlled_by_adversary
        --   inline_mitigations_already_exist
    impact_statement   TEXT,                            -- 벤더 코멘트 (threats[].impact.details)
    action_statement   TEXT,                            -- 조치 안내 (remediations[].details)

    -- 출처·시각
    vex_source         VARCHAR(30)  NOT NULL,
        -- REDHAT_CSAF / OPENVEX / CISCO_PSIRT / ALAS_VEX
    published_at       DATE,
    fetched_at         TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- 멱등성 — NULL 도 동일하게 취급하는 expression UNIQUE 인덱스
-- (UNIQUE 제약은 NULL 을 distinct 로 보므로, COALESCE 표현식 인덱스 사용)
CREATE UNIQUE INDEX IF NOT EXISTS uk_vex
    ON tb_vex (
        cve_id, vex_source,
        COALESCE(product_purl, ''),
        COALESCE(product_cpe,  '')
    );

-- 매칭 인덱스 (Trivy 결과 JOIN 시 핵심)
CREATE INDEX IF NOT EXISTS idx_vex_cve         ON tb_vex (cve_id);
CREATE INDEX IF NOT EXISTS idx_vex_purl        ON tb_vex (product_purl) WHERE product_purl IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vex_cpe         ON tb_vex (product_cpe)  WHERE product_cpe IS NOT NULL;

-- not_affected 만 조회 (dismiss 용 부분 인덱스)
CREATE INDEX IF NOT EXISTS idx_vex_not_affected
    ON tb_vex (cve_id, product_purl)
    WHERE status = 'not_affected';

COMMENT ON TABLE  tb_vex             IS 'VEX statement (CSAF 2.0 / OpenVEX) — Trivy FP 자동 dismiss 입력';
COMMENT ON COLUMN tb_vex.status      IS 'not_affected / affected / fixed / under_investigation';
COMMENT ON COLUMN tb_vex.justification IS 'CSAF 5종 — vulnerable_code_not_in_execute_path 등';
COMMENT ON COLUMN tb_vex.vex_source  IS 'REDHAT_CSAF / OPENVEX / CISCO_PSIRT / ALAS_VEX';
