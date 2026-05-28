-- ============================================================================
-- mitre_cwe_collector DDL
--
-- tb_cwe_dictionary : MITRE CWE 약점 사전 (~1,300 항목)
-- 분기 1회 갱신 (cwec_latest.xml.zip)
-- CVE 의 cwe_ids 배열과 JOIN → 약점 분류 + 조치 가이드
-- ============================================================================

CREATE TABLE IF NOT EXISTS tb_cwe_dictionary (
    cwe_id        VARCHAR(20)  PRIMARY KEY,    -- CWE-79 / CWE-89 / ...
    name_en       VARCHAR(500) NOT NULL,
    name_ko       VARCHAR(500),                -- 추후 번역 (NULL 허용)
    description   TEXT,
    abstraction   VARCHAR(20),                 -- Class / Base / Variant / Compound
    parent_cwe    VARCHAR(20),                 -- 상위 CWE (Related_Weakness Nature=ChildOf 첫 항목)
    deprecated    BOOLEAN NOT NULL DEFAULT FALSE,
    mitigations   JSONB,                       -- [{phase, strategy, description}, ...]
    reg_dt        TIMESTAMP NOT NULL DEFAULT LOCALTIMESTAMP,
    upd_dt        TIMESTAMP NOT NULL DEFAULT LOCALTIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cwe_parent
    ON tb_cwe_dictionary (parent_cwe)
    WHERE parent_cwe IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cwe_abstraction
    ON tb_cwe_dictionary (abstraction);

CREATE INDEX IF NOT EXISTS idx_cwe_active
    ON tb_cwe_dictionary (cwe_id)
    WHERE deprecated = FALSE;

COMMENT ON TABLE  tb_cwe_dictionary IS 'MITRE CWE 약점 사전 + mitigations (조치 가이드)';
COMMENT ON COLUMN tb_cwe_dictionary.cwe_id      IS 'CWE-{ID} 표준 식별자 (예: CWE-79)';
COMMENT ON COLUMN tb_cwe_dictionary.abstraction IS 'Class(상위 분류) / Base(주요) / Variant(세부) / Compound(복합)';
COMMENT ON COLUMN tb_cwe_dictionary.parent_cwe  IS 'Related_Weakness Nature=ChildOf 의 첫 항목';
COMMENT ON COLUMN tb_cwe_dictionary.deprecated  IS 'Deprecated 상태 약점 마킹 (true 면 사용 권장 X)';
COMMENT ON COLUMN tb_cwe_dictionary.mitigations IS 'JSONB array — [{phase, strategy, description}]';
