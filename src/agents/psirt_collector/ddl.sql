-- ============================================================================
-- psirt_collector DDL
--
-- 본 콜렉터는 새 테이블을 만들지 않는다. kisa_collector 가 정의한
-- tb_vendor_advisory 를 그대로 사용 (vendor_source 컬럼으로 PSIRT 와 구분).
--
-- vendor_source 값:
--   PSIRT_CISCO   — Cisco openVuln API
--   PSIRT_F5      — F5 K-articles
--   PSIRT_PA      — Palo Alto Security Advisories
--   PSIRT_FORTI   — Fortinet PSIRT
--
-- 추가 인덱스 — vendor_source × affected_model 조회 빈도 증가 대비.
-- ============================================================================

-- vendor_source 기준 인덱스는 kisa_collector ddl.sql 에 이미 정의됨 (idx_vadv_source).
-- 모델 검색 보강 — 네트워크 장비 매칭 시 모델명 LIKE 쿼리에 사용.
CREATE INDEX IF NOT EXISTS idx_vadv_model
    ON tb_vendor_advisory (affected_model)
    WHERE affected_model IS NOT NULL;

-- vendor_source 별 부분 인덱스 — PSIRT 전용 조회 가속.
CREATE INDEX IF NOT EXISTS idx_vadv_psirt
    ON tb_vendor_advisory (vendor_source, published_at DESC)
    WHERE vendor_source LIKE 'PSIRT_%';
