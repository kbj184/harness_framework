-- ============================================================================
-- tb_asset_master 의 cpe_vendor/cpe_product/cpe_version 및 criticality_score
-- 를 manufacturer/model/os_name/category_cd/env_type 으로부터 추론하여 채움.
--
-- Parser Agent 정식 구현 전 임시 fill — KISA/PSIRT 매칭 + SSVC 차등 활성화 목적.
-- 멱등 — UPDATE 만, 기존 NULL 또는 빈 값만 덮어쓰기.
-- ============================================================================

-- ─────────────────────────────────────────────────────────────
-- 1) OS 기반 CPE 추론 (KISA/PSIRT 매칭의 핵심 입력)
-- ─────────────────────────────────────────────────────────────
UPDATE tb_asset_master
SET cpe_vendor = CASE
    WHEN os_name ILIKE 'ubuntu%'        THEN 'canonical'
    WHEN os_name ILIKE 'windows%'       THEN 'microsoft'
    WHEN os_name ILIKE 'cisco ios%'     THEN 'cisco'
    WHEN os_name ILIKE 'macos%'         THEN 'apple'
    WHEN os_name ILIKE 'rhel%'
      OR os_name ILIKE '%red%hat%'      THEN 'redhat'
    WHEN os_name ILIKE 'centos%'        THEN 'centos'
    WHEN os_name ILIKE 'amazon linux%'  THEN 'amazon'
    WHEN os_name ILIKE 'debian%'        THEN 'debian'
    WHEN os_name ILIKE 'suse%'          THEN 'suse'
    WHEN os_name ILIKE 'oracle linux%'  THEN 'oracle'
    WHEN os_name ILIKE 'fortios%'       THEN 'fortinet'
    WHEN os_name ILIKE '%pan-os%'       THEN 'paloaltonetworks'
    WHEN os_name ILIKE '%big-ip%'
      OR os_name ILIKE 'f5 %'           THEN 'f5'
    ELSE NULL
END
WHERE cpe_vendor IS NULL OR cpe_vendor = '';

UPDATE tb_asset_master
SET cpe_product = CASE
    WHEN os_name ILIKE 'ubuntu%'                   THEN 'ubuntu_linux'
    WHEN os_name ILIKE 'windows 10%'               THEN 'windows_10'
    WHEN os_name ILIKE 'windows 11%'               THEN 'windows_11'
    WHEN os_name ILIKE 'windows server 2019%'      THEN 'windows_server_2019'
    WHEN os_name ILIKE 'windows server 2022%'      THEN 'windows_server_2022'
    WHEN os_name ILIKE 'windows server%'           THEN 'windows_server'
    WHEN os_name ILIKE 'cisco ios xe%'             THEN 'ios_xe'
    WHEN os_name ILIKE 'cisco ios%'                THEN 'ios'
    WHEN os_name ILIKE 'macos%'                    THEN 'macos'
    WHEN os_name ILIKE 'rhel%'
      OR os_name ILIKE '%red%hat%'                 THEN 'enterprise_linux'
    WHEN os_name ILIKE 'centos%'                   THEN 'centos'
    WHEN os_name ILIKE 'amazon linux%'             THEN 'amazon_linux'
    WHEN os_name ILIKE 'debian%'                   THEN 'debian_linux'
    WHEN os_name ILIKE 'suse%'                     THEN 'linux_enterprise_server'
    WHEN os_name ILIKE 'fortios%'                  THEN 'fortios'
    WHEN os_name ILIKE '%pan-os%'                  THEN 'pan-os'
    WHEN os_name ILIKE '%big-ip%'                  THEN 'big-ip'
    ELSE NULL
END
WHERE cpe_product IS NULL OR cpe_product = '';

UPDATE tb_asset_master
SET cpe_version = os_version
WHERE (cpe_version IS NULL OR cpe_version = '')
  AND os_version IS NOT NULL AND os_version <> '';

-- ─────────────────────────────────────────────────────────────
-- 2) criticality_score 추론 (env_type + category_cd 기반, 3~9)
--    C+I+A 합산 — 1(낮음)~3(높음) 각 항목별
-- ─────────────────────────────────────────────────────────────
UPDATE tb_asset_master
SET criticality_score = CASE
    -- 네트워크·보안 장비 — 최상위 (9)
    WHEN category_cd = 'HW_NET'                                THEN 9
    WHEN category_cd = 'HW_SEC'                                THEN 9
    -- 하이퍼바이저·WAS — 운영 핵심 (8)
    WHEN category_cd = 'HW_HV'                                 THEN 8
    WHEN category_cd = 'SW_WAS'                                THEN 8
    WHEN category_cd = 'HW_SVR'                                THEN 8
    -- 클라우드 서버 (7) — 변동 가능, 서비스 영향
    WHEN category_cd = 'CLD_SVR'                               THEN 7
    -- 가상머신 (7)
    WHEN category_cd = 'HW_VM'                                 THEN 7
    -- 점포 POS — 결제/카드 (6, ISMS-P 대상)
    WHEN category_cd = 'HW_POS'                                THEN 6
    -- 점포·OA PC (5)
    WHEN category_cd = 'HW_PC'                                 THEN 5
    -- 기타 (env_type fallback)
    WHEN env_type = 'CLOUD'                                    THEN 6
    WHEN env_type = 'IDC'                                      THEN 7
    WHEN env_type = 'STORE'                                    THEN 5
    ELSE 4
END
WHERE criticality_score IS NULL;

-- ─────────────────────────────────────────────────────────────
-- 3) isms_yn — ISMS-P 인증 대상 분류
--    결제·카드·개인정보 처리 자산
-- ─────────────────────────────────────────────────────────────
UPDATE tb_asset_master
SET isms_yn = CASE
    -- 결제 처리 자산 (POS·서버·WAS·네트워크 핵심)
    WHEN category_cd IN ('CLD_SVR','HW_SVR','SW_WAS','HW_WAS',
                         'HW_HV','HW_VM','HW_NET','HW_SEC','HW_POS') THEN 'Y'
    ELSE 'N'
END
WHERE isms_yn IS NULL OR isms_yn = 'N';

-- ─────────────────────────────────────────────────────────────
-- 4) 결과 요약 (참고 출력 — 실제 RAISE 없이 단순 SELECT)
-- ─────────────────────────────────────────────────────────────
-- (psycopg2 execute 환경에서는 SELECT 결과 출력 안 되지만 BEGIN/COMMIT 정합 유지)
