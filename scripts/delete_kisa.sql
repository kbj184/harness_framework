-- 기존 KISA advisory 삭제 (affected_model NULL 상태 정리)
-- 다음 invoke 에서 INSERT 로 재적재 → affected_model 정상 채움
DELETE FROM tb_vendor_advisory WHERE vendor_source='KISA';
