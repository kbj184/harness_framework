-- tb_asset_software : 자산별 설치 SW 인벤토리 (멀티 소스 통합)
-- 소스: CrowdStrike Falcon Discover Applications + Ansible SBOM(rpm/dpkg) + 앱 의존성(npm/pip/maven 등)
-- 자산(tb_asset_master) × SW 다대다. 운영 환경 2,530자산 × 평균 ~400 SW = 약 100만 행 예상.

CREATE TABLE IF NOT EXISTS tb_asset_software (
    sw_no               BIGSERIAL PRIMARY KEY,

    -- 자산 매칭
    asset_id_hash       VARCHAR(64),                  -- FK tb_asset_master, backfill 단계에서 채움

    -- ── 소스 구분 ──────────────────────────────────────────────
    source              VARCHAR(30) NOT NULL,         -- CROWDSTRIKE / ANSIBLE_RPM / ANSIBLE_DPKG / NPM / PIP / MAVEN / GO / GEM / NUGET
    ecosystem           VARCHAR(30),                  -- rpm / deb / npm / pypi / maven / golang / gem / nuget / msi

    -- ── SW 식별 (공통) ─────────────────────────────────────────
    name                VARCHAR(500),                 -- 패키지/애플리케이션 이름
    vendor              VARCHAR(500),                 -- 벤더/제조사
    version             VARCHAR(200),                 -- 업스트림 버전
    release             VARCHAR(200),                 -- RPM/DEB release (3.amzn2023.0.2 등)
    epoch               VARCHAR(20),                  -- RPM epoch (드물게 사용)
    arch                VARCHAR(20),                  -- x86_64 / aarch64 / noarch / msi / NULL

    -- ── 식별 키 (정규화) ───────────────────────────────────────
    purl                VARCHAR(800),                 -- Package URL (pkg:rpm/amzn/openssl@3.5.5-1.amzn2023.0.3?arch=x86_64)
    name_vendor         VARCHAR(800),                 -- name + vendor 결합
    name_vendor_version VARCHAR(1000),                -- CPE 매칭 입력
    cpe_uri             VARCHAR(500),                 -- 후처리 CPE 매핑 결과

    -- ── 분류 / 메타 ────────────────────────────────────────────
    software_type       VARCHAR(30),                  -- application / system / driver / library
    category            VARCHAR(100),                  -- System tools / IT management / ...
    versioning_scheme   VARCHAR(30),                   -- semver / nevra / unknown
    distribution        VARCHAR(50),                   -- amzn2023 / rhel9 / ubuntu22 / windows11
    source_rpm          VARCHAR(500),                  -- 부모 src.rpm (sub-package 정규화용)

    -- ── 사용 흔적 (CrowdStrike Discover 전용) ──────────────────
    installation_timestamp TIMESTAMP,
    last_used_user_name VARCHAR(255),
    last_used_user_sid  VARCHAR(100),
    last_used_file_name VARCHAR(500),
    last_used_file_hash VARCHAR(100),
    last_used_timestamp TIMESTAMP,
    first_seen_timestamp TIMESTAMP,
    is_suspicious       BOOLEAN,
    is_normalized       BOOLEAN,

    -- ── CrowdStrike 전용 식별자 (NULL 허용) ────────────────────
    cs_app_id           VARCHAR(200),                  -- CrowdStrike Application 고유 ID
    cs_agent_id         VARCHAR(100),                  -- CrowdStrike device_id
    cid                 VARCHAR(50),                   -- CrowdStrike customer ID

    -- ── 참조용 호스트 정보 ─────────────────────────────────────
    host_hostname       VARCHAR(255),                  -- 원본 응답의 hostname (참조용)
    sbom_doc_id         VARCHAR(100),                  -- Ansible SBOM 한 번 수집 문서 단위 추적

    -- ── 원본 / 시각 ────────────────────────────────────────────
    raw_data            JSONB,
    collected_at        TIMESTAMP,                     -- 자산 측 수집 시각 (Ansible: target.collected_at, CS: 응답 시점)
    fetched_at          TIMESTAMP NOT NULL DEFAULT LOCALTIMESTAMP
);

-- 유니크 키 (source별 다른 키)
--   CrowdStrike: cs_app_id 단독
--   그 외(Ansible/npm/...): (asset_id_hash, source, purl)
CREATE UNIQUE INDEX IF NOT EXISTS uk_asset_sw_cs_app
    ON tb_asset_software (cs_app_id)
    WHERE source = 'CROWDSTRIKE' AND cs_app_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uk_asset_sw_purl
    ON tb_asset_software (asset_id_hash, source, purl)
    WHERE source != 'CROWDSTRIKE' AND purl IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_asset_sw_asset       ON tb_asset_software (asset_id_hash);
CREATE INDEX IF NOT EXISTS idx_asset_sw_source      ON tb_asset_software (source);
CREATE INDEX IF NOT EXISTS idx_asset_sw_ecosystem   ON tb_asset_software (ecosystem);
CREATE INDEX IF NOT EXISTS idx_asset_sw_agent       ON tb_asset_software (cs_agent_id);
CREATE INDEX IF NOT EXISTS idx_asset_sw_name_vendor ON tb_asset_software (name, vendor);
CREATE INDEX IF NOT EXISTS idx_asset_sw_purl        ON tb_asset_software (purl);
CREATE INDEX IF NOT EXISTS idx_asset_sw_cpe         ON tb_asset_software (cpe_uri);
CREATE INDEX IF NOT EXISTS idx_asset_sw_last_used   ON tb_asset_software (last_used_timestamp);

COMMENT ON TABLE  tb_asset_software IS '자산별 설치 SW 인벤토리 (CrowdStrike Discover + Ansible SBOM + 앱 의존성 통합)';
COMMENT ON COLUMN tb_asset_software.source              IS 'CROWDSTRIKE / ANSIBLE_RPM / ANSIBLE_DPKG / NPM / PIP / MAVEN / ...';
COMMENT ON COLUMN tb_asset_software.ecosystem           IS 'purl 표준 ecosystem (rpm/deb/npm/pypi/maven/...)';
COMMENT ON COLUMN tb_asset_software.purl                IS 'Package URL 표준 식별자 (pkg:rpm/amzn/openssl@3.5.5-1.amzn2023.0.3?arch=x86_64)';
COMMENT ON COLUMN tb_asset_software.release             IS 'RPM/DEB release (sub-package 정확 매칭에 필수)';
COMMENT ON COLUMN tb_asset_software.epoch               IS 'RPM epoch (버전 비교 우선순위)';
COMMENT ON COLUMN tb_asset_software.arch                IS '아키텍처 (x86_64/aarch64/noarch/msi)';
COMMENT ON COLUMN tb_asset_software.asset_id_hash       IS 'tb_asset_master FK (수집 직후 backfill로 채움)';
COMMENT ON COLUMN tb_asset_software.cs_app_id           IS 'CrowdStrike Application ID — source=CROWDSTRIKE 행만 사용';
COMMENT ON COLUMN tb_asset_software.sbom_doc_id         IS 'Ansible SBOM 한 번 수집 문서 단위 추적 (전체 갱신 vs 증분 구분)';

-- 마이그레이션 (기존 테이블이 있을 때 컬럼 추가)
-- ALTER TABLE tb_asset_software
--   ADD COLUMN IF NOT EXISTS source        VARCHAR(30),
--   ADD COLUMN IF NOT EXISTS ecosystem     VARCHAR(30),
--   ADD COLUMN IF NOT EXISTS release       VARCHAR(200),
--   ADD COLUMN IF NOT EXISTS epoch         VARCHAR(20),
--   ADD COLUMN IF NOT EXISTS arch          VARCHAR(20),
--   ADD COLUMN IF NOT EXISTS purl          VARCHAR(800),
--   ADD COLUMN IF NOT EXISTS distribution  VARCHAR(50),
--   ADD COLUMN IF NOT EXISTS source_rpm    VARCHAR(500),
--   ADD COLUMN IF NOT EXISTS sbom_doc_id   VARCHAR(100),
--   ADD COLUMN IF NOT EXISTS collected_at  TIMESTAMP;
-- UPDATE tb_asset_software SET source='CROWDSTRIKE' WHERE source IS NULL AND cs_app_id IS NOT NULL;
-- ALTER TABLE tb_asset_software ALTER COLUMN cs_app_id DROP NOT NULL;
-- ALTER TABLE tb_asset_software ALTER COLUMN cs_agent_id DROP NOT NULL;
