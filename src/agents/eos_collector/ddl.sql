-- ============================================================================
-- eos_collector DDL — tb_eos_catalog
--
-- endoflife.date API 에서 제품별 EOL/EOSL 일자를 동기화한다.
-- 자산 OS/SW 가 EOSL 도달 시 SSVC 등급을 1단계 상향하는 입력 데이터.
--
-- 원본: https://endoflife.date/api/{product}.json
-- 한 product 안에 여러 cycle(예: rhel 8 / 9 / 10) → 복합 PK (product, cycle).
-- ============================================================================

CREATE TABLE IF NOT EXISTS tb_eos_catalog (
    product         VARCHAR(80)  NOT NULL,             -- amazon-linux / rhel / ubuntu / windows-server ...
    cycle           VARCHAR(80)  NOT NULL,             -- 8 / 9 / 22.04 / 2023 ...

    release_date    DATE,                              -- 출시일
    eol_date        DATE,                              -- 일반 지원 종료 (EOL)
    support_date    DATE,                              -- Active Support 종료
    extended_date   DATE,                              -- 확장 지원(보안 패치) 종료 = 사실상 EOSL

    lts             BOOLEAN NOT NULL DEFAULT FALSE,    -- LTS 사이클 여부
    latest          VARCHAR(100),                      -- 해당 cycle 의 최신 minor 버전
    link            TEXT,                              -- endoflife.date 상세 페이지

    raw_data        JSONB,                             -- 원본 응답 (감사용)
    fetched_at      TIMESTAMP    NOT NULL DEFAULT LOCALTIMESTAMP,

    PRIMARY KEY (product, cycle)
);

CREATE INDEX IF NOT EXISTS idx_eos_eol
    ON tb_eos_catalog (eol_date)
    WHERE eol_date IS NOT NULL;

-- EOSL(extended_date) 기반 검색 — SSVC 등급 +1 트리거 핵심 인덱스
CREATE INDEX IF NOT EXISTS idx_eos_extended
    ON tb_eos_catalog (extended_date)
    WHERE extended_date IS NOT NULL;

-- 자산 OS 매칭 — tb_asset_master.os_name LIKE product 패턴에서 사용
CREATE INDEX IF NOT EXISTS idx_eos_product
    ON tb_eos_catalog (product);

COMMENT ON TABLE  tb_eos_catalog              IS 'endoflife.date 제품별 EOL/EOSL 카탈로그 (자산 EOSL 판정 입력)';
COMMENT ON COLUMN tb_eos_catalog.product      IS 'endoflife.date product 슬러그 (amazon-linux / rhel / ubuntu / windows-server)';
COMMENT ON COLUMN tb_eos_catalog.cycle        IS '메이저 사이클 (rhel 8/9/10, ubuntu 22.04/24.04 등)';
COMMENT ON COLUMN tb_eos_catalog.eol_date     IS '일반 지원 종료(EOL) — 신규 업데이트 중단';
COMMENT ON COLUMN tb_eos_catalog.extended_date IS '확장(보안) 지원 종료(EOSL) — 보안 패치 중단 = SSVC +1 트리거';
COMMENT ON COLUMN tb_eos_catalog.support_date IS 'Active Support 종료';
