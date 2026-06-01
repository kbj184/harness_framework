-- ============================================================================
-- epss_collector DDL — tb_epss_history (7일 이력 보존)
--
-- FIRST EPSS 매일 갱신분을 (cve_id, score_date) 복합 PK 로 누적.
-- 7일 변화량 0.3+ 급상승 감지 → SSVC 등급 +1 트리거의 입력.
-- 보존 기간: 8일 (epss_collector 가 매 실행마다 prune).
-- ============================================================================

CREATE TABLE IF NOT EXISTS tb_epss_history (
    cve_id      VARCHAR(20)  NOT NULL,
    score_date  DATE         NOT NULL,
    epss        NUMERIC(5,4) NOT NULL,
    percentile  NUMERIC(5,4),
    PRIMARY KEY (cve_id, score_date)
);

CREATE INDEX IF NOT EXISTS idx_epss_history_score_date
    ON tb_epss_history (score_date);

COMMENT ON TABLE  tb_epss_history IS 'EPSS 7일 이력 — 급상승 감지 입력 (보존 8일)';
COMMENT ON COLUMN tb_epss_history.score_date IS 'EPSS 산정 날짜 (FIRST 발행)';
