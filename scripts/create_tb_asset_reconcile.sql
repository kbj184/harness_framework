-- tb_asset_reconcile 생성 마이그레이션 (멱등) — ISMS 대장 ↔ 수집 자산 대사 후보 큐
-- 목적: 같은 자산이 대장 해시 ≠ 수집 해시로 별도 master 행 공존 → 후보키 매칭 결과를 적재.
-- Phase 1: 적재 전용. tb_asset_master 무변경(읽기전용).
-- 생성일: 2026-06-12
-- 적용: Aurora PostgreSQL VPC 내 수동 실행 (DB 직접 접속 불가 시 ECS Task/Bastion 경유)
-- ⚠ CREATE TABLE IF NOT EXISTS — 멱등. backend/shcema/ddl/cmdb_reconcile.sql 와 동일.

CREATE TABLE IF NOT EXISTS tb_asset_reconcile (
    reconcile_no   bigserial   PRIMARY KEY,
    ledger_hash    varchar(64) NOT NULL,
    collected_hash varchar(64) NOT NULL,
    axis           varchar(20) NOT NULL,
    match_key      varchar(200),
    confidence     smallint    NOT NULL DEFAULT 0,
    status         varchar(20) NOT NULL DEFAULT 'pending',
    canonical_hash varchar(64),
    reviewer       varchar(100),
    reviewed_at    timestamp,
    reg_dt         timestamp   DEFAULT current_timestamp NOT NULL,
    upd_dt         timestamp   DEFAULT current_timestamp NOT NULL,
    CONSTRAINT uq_reconcile_pair UNIQUE (ledger_hash, collected_hash)
);

CREATE INDEX IF NOT EXISTS idx_reconcile_status    ON tb_asset_reconcile (status);
CREATE INDEX IF NOT EXISTS idx_reconcile_ledger    ON tb_asset_reconcile (ledger_hash);
CREATE INDEX IF NOT EXISTS idx_reconcile_collected ON tb_asset_reconcile (collected_hash);

COMMENT ON TABLE  tb_asset_reconcile               IS 'ISMS 대장 ↔ 수집 자산 대사 후보 큐. Phase1 적재 전용(master 무변경)';
COMMENT ON COLUMN tb_asset_reconcile.axis           IS 'DEVICE_ID(장비 동일성 1:1) | SW_CPE(소프트웨어 이름/CPE 1:N)';
COMMENT ON COLUMN tb_asset_reconcile.confidence     IS '신뢰도 0~100. instance_id 정확일치=95';
COMMENT ON COLUMN tb_asset_reconcile.status         IS 'pending(대기) | confirmed(병합확정) | rejected(별개확정)';
