-- ssvc_priority VARCHAR(2) → VARCHAR(5) (P0-A, P0-B, P0-C 4글자 수용)
ALTER TABLE tb_asset_vulnerability
    ALTER COLUMN ssvc_priority TYPE VARCHAR(5);
