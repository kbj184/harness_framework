-- ============================================================================
-- tb_asset_vulnerability — 운영자 액션 감사 컬럼 추가
--
-- status 전환 시 누가/언제/왜 변경했는지 추적.
-- ISMS-P 감사 요건 — 위험 수용·오탐 처리에 대한 책임 기록.
-- ============================================================================

ALTER TABLE tb_asset_vulnerability
    ADD COLUMN IF NOT EXISTS acted_by    VARCHAR(50),
    ADD COLUMN IF NOT EXISTS acted_at    TIMESTAMP,
    ADD COLUMN IF NOT EXISTS action_note TEXT;

COMMENT ON COLUMN tb_asset_vulnerability.acted_by    IS '운영자 액션 마지막 수행자 (user_id) — OPEN→IN_PROGRESS/PATCHED/ACCEPTED 시 갱신';
COMMENT ON COLUMN tb_asset_vulnerability.acted_at    IS '운영자 액션 마지막 수행 시각';
COMMENT ON COLUMN tb_asset_vulnerability.action_note IS '운영자 액션 사유/메모 (위험 수용·오탐·조치 내용)';

-- status 코멘트 갱신 — IN_PROGRESS 추가
COMMENT ON COLUMN tb_asset_vulnerability.status IS 'OPEN / IN_PROGRESS / PATCHED / ACCEPTED / FALSE_POSITIVE / FALSE_POSITIVE_VEX';
