-- ============================================================================
-- asset_enrich DDL — P1
--
-- 1) tb_asset_master  ALTER  : ECS Ansible 인벤토리 메타 컬럼 추가
-- 2) tb_asset_security CREATE: AhnLab / CrowdStrike 보안 상태 통합 테이블
--
-- 적용 방식:
--   psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f ddl.sql
--
-- 참조: collect_cmdb/docs/asset-enrich-pipeline.md (§4 DB 스키마 변경)
-- ============================================================================


-- ----------------------------------------------------------------------------
-- 1) tb_asset_master — ECS Ansible 인벤토리용 컬럼 추가
--    build_inventory.py 가 category_cd + region_cd 로 필터하고,
--    ansible_user / ansible_connection / credentials_secret_arn 으로
--    동적 inventory 를 만든다.
-- ----------------------------------------------------------------------------

ALTER TABLE tb_asset_master
    ADD COLUMN IF NOT EXISTS ansible_user            VARCHAR(50),
    ADD COLUMN IF NOT EXISTS ansible_connection      VARCHAR(30),
    ADD COLUMN IF NOT EXISTS ansible_network_os      VARCHAR(30),
    ADD COLUMN IF NOT EXISTS credentials_secret_arn  VARCHAR(500),
    ADD COLUMN IF NOT EXISTS region_cd               VARCHAR(20),
    ADD COLUMN IF NOT EXISTS ansible_enriched_at     TIMESTAMPTZ;

COMMENT ON COLUMN tb_asset_master.ansible_user            IS 'Ansible 수집 계정 (root / svc-cmdb / Domain\\svc.cmdb 등)';
COMMENT ON COLUMN tb_asset_master.ansible_connection      IS 'ssh / winrm / network_cli';
COMMENT ON COLUMN tb_asset_master.ansible_network_os      IS 'ios / iosxr / nxos / panos / fortios / junos (network_cli 용)';
COMMENT ON COLUMN tb_asset_master.credentials_secret_arn  IS 'AWS Secrets Manager ARN (SSH 키 / AD 자격증명)';
COMMENT ON COLUMN tb_asset_master.region_cd               IS 'KR1=수도권 / KR2=영남 / KR3=호남 / KR4=충청 (STORE_PC 4지역 병렬)';
COMMENT ON COLUMN tb_asset_master.ansible_enriched_at     IS 'asset_enrich Lambda 마지막 보강 시각';

-- 인벤토리 빌드 성능을 위한 인덱스
CREATE INDEX IF NOT EXISTS idx_master_category_region
    ON tb_asset_master (category_cd, region_cd)
    WHERE lifecycle_state = 'ACTIVE';


-- ----------------------------------------------------------------------------
-- 2) tb_asset_security  : 보안 Agent (AhnLab / CrowdStrike) 보안 상태 통합
--    asset_enrich 와 별도 트랙으로 ahnlab_epp_collector / crowdstrike_alerts
--    가 적재한다. tb_asset_master FK.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tb_asset_security (
    sec_no              BIGSERIAL PRIMARY KEY,
    asset_id_hash       CHAR(32)      NOT NULL,
    source              VARCHAR(30)   NOT NULL,   -- AHNLAB_EPP / CROWDSTRIKE_FALCON
    agent_id            VARCHAR(100),
    av_pattern_version  VARCHAR(50),
    policy_group        VARCHAR(100),
    last_scan_at        TIMESTAMPTZ,
    scan_result         VARCHAR(30),              -- CLEAN / DETECTED / QUARANTINED
    isolation_status    VARCHAR(30),              -- NORMAL / ISOLATED
    collected_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    raw_data            JSONB,

    CONSTRAINT fk_asset_security_asset
        FOREIGN KEY (asset_id_hash) REFERENCES tb_asset_master(asset_id_hash)
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_asset_security_source
    ON tb_asset_security (asset_id_hash, source);

CREATE INDEX IF NOT EXISTS idx_asset_security_source
    ON tb_asset_security (source);

CREATE INDEX IF NOT EXISTS idx_asset_security_scan_at
    ON tb_asset_security (last_scan_at DESC);

CREATE INDEX IF NOT EXISTS idx_asset_security_detected
    ON tb_asset_security (scan_result)
    WHERE scan_result IN ('DETECTED', 'QUARANTINED');

COMMENT ON TABLE  tb_asset_security                IS '보안 Agent 보안 상태 통합 (AhnLab EPP/EDR + CrowdStrike Falcon)';
COMMENT ON COLUMN tb_asset_security.source         IS 'AHNLAB_EPP / CROWDSTRIKE_FALCON';
COMMENT ON COLUMN tb_asset_security.agent_id       IS 'Agent 고유 ID (AhnLab UUID / Falcon device_id)';
COMMENT ON COLUMN tb_asset_security.scan_result    IS '최근 검사 결과 (CLEAN/DETECTED/QUARANTINED)';
COMMENT ON COLUMN tb_asset_security.isolation_status IS 'NORMAL / ISOLATED (격리 상태)';
