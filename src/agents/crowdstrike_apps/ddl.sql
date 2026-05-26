-- tb_asset_software : 자산별 설치 SW 인벤토리 (CrowdStrike Falcon Discover Applications 기준)
-- 자산(tb_asset_master) × SW(name + vendor + version) 다대다. 자산 1대당 평균 300건.
-- 운영 환경 2,530 자산 가정 시 ~수십만 행 예상. 일 1회 전체 갱신.

CREATE TABLE IF NOT EXISTS tb_asset_software (
    sw_no               BIGSERIAL PRIMARY KEY,

    -- CrowdStrike Discover Application ID (host_id + app_id 결합)
    -- ON CONFLICT 키. 동일 자산·SW·버전이면 같은 row UPDATE.
    cs_app_id           VARCHAR(200) NOT NULL,

    -- 자산 매칭
    cs_agent_id         VARCHAR(100) NOT NULL,                 -- = CrowdStrike device_id
    asset_id_hash       VARCHAR(64),                           -- FK tb_asset_master, backfill 단계에서 채움

    -- SW 식별
    name                VARCHAR(500),                          -- 예: "Google Chrome"
    vendor              VARCHAR(500),                          -- 예: "Google LLC"
    version             VARCHAR(200),                          -- 예: "125.0.6422.142"
    name_vendor         VARCHAR(800),                          -- 예: "Google Chrome:Google LLC"
    name_vendor_version VARCHAR(1000),                         -- CPE 매칭 입력
    software_type       VARCHAR(30),                           -- application / system / driver
    category            VARCHAR(100),                          -- System tools / IT management / ...
    versioning_scheme   VARCHAR(30),                           -- semver / unknown / ...

    -- 사용 흔적
    installation_timestamp TIMESTAMP,
    last_used_user_name VARCHAR(255),
    last_used_user_sid  VARCHAR(100),
    last_used_file_name VARCHAR(500),
    last_used_file_hash VARCHAR(100),
    last_used_timestamp TIMESTAMP,
    first_seen_timestamp TIMESTAMP,

    -- 플래그
    is_suspicious       BOOLEAN,
    is_normalized       BOOLEAN,

    -- CPE 매핑 결과 (별도 후처리로 채움, NULL 허용)
    cpe_uri             VARCHAR(500),

    -- 원본
    cid                 VARCHAR(50),                           -- CrowdStrike customer ID
    host_hostname       VARCHAR(255),                          -- CrowdStrike 응답의 host.hostname (참조용)
    raw_data            JSONB,
    fetched_at          TIMESTAMP NOT NULL DEFAULT LOCALTIMESTAMP,

    CONSTRAINT uk_asset_software_cs_app UNIQUE (cs_app_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_sw_asset       ON tb_asset_software (asset_id_hash);
CREATE INDEX IF NOT EXISTS idx_asset_sw_agent       ON tb_asset_software (cs_agent_id);
CREATE INDEX IF NOT EXISTS idx_asset_sw_name_vendor ON tb_asset_software (name, vendor);
CREATE INDEX IF NOT EXISTS idx_asset_sw_cpe         ON tb_asset_software (cpe_uri);
CREATE INDEX IF NOT EXISTS idx_asset_sw_last_used   ON tb_asset_software (last_used_timestamp);

COMMENT ON TABLE  tb_asset_software IS 'CrowdStrike Falcon Discover 기반 자산별 설치 SW 인벤토리';
COMMENT ON COLUMN tb_asset_software.cs_app_id            IS 'CrowdStrike Application 고유 ID (UNIQUE)';
COMMENT ON COLUMN tb_asset_software.cs_agent_id          IS 'CrowdStrike device_id (= tb_asset_source.source_id WHERE source=CROWDSTRIKE)';
COMMENT ON COLUMN tb_asset_software.asset_id_hash        IS 'tb_asset_master FK, backfill 단계에서 채움';
COMMENT ON COLUMN tb_asset_software.name_vendor_version  IS 'CPE 매칭 입력 (정규화된 name-vendor-version)';
