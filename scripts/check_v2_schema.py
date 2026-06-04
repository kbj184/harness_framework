"""v2 매칭에 필요한 테이블·컬럼 종합 검증."""
from __future__ import annotations
import json
import sys
import boto3
import psycopg2

REGION = "ap-northeast-2"
SECRET_ID = "cmdb/db-writer"

# v2 매칭 SQL이 참조하는 테이블 + 핵심 컬럼
REQUIRED = {
    "tb_cve":           ["cve_id"],
    "tb_cve_affected":  ["cve_id", "cpe_vendor", "cpe_product", "cpe_version"],
    "tb_cpe_dictionary":["cpe_uri"],
    "tb_asset_master":  ["asset_id_hash", "cpe_vendor", "cpe_product", "cpe_version", "criticality_score", "lifecycle_state"],
    "tb_asset_software":["asset_id_hash", "name", "vendor", "version", "purl"],
    "tb_asset_vulnerability": ["asset_id_hash", "cve_id", "match_type", "matched_pkg", "status"],
    "tb_kev_catalog":   ["cve_id"],
    "tb_epss_score":    ["cve_id", "epss_score"],
    "tb_epss_history":  ["cve_id", "score_date"],
    "tb_exploit_signal":["cve_id", "signal_type"],
    "tb_vendor_advisory":["advisory_id", "vendor_source", "cve_ids", "affected_model", "affected_version"],
    "tb_vex":           ["cve_id", "status", "product_purl", "product_cpe"],
    "tb_sw_cpe_mapping":["sw_signature", "cpe_vendor", "cpe_product", "is_negative"],
    "tb_cve_match_pending":["asset_id_hash", "cve_id", "confidence"],
    "tb_rag_cve_desc":  ["cve_id", "embedding"],
    "tb_eos_catalog":   ["product", "cycle"],
}

def main():
    sm = boto3.client("secretsmanager", region_name=REGION)
    cfg = json.loads(sm.get_secret_value(SecretId=SECRET_ID)["SecretString"])

    conn = psycopg2.connect(
        host=cfg.get("host") or cfg.get("DB_HOST"),
        port=int(cfg.get("port") or cfg.get("DB_PORT") or 5432),
        dbname=cfg.get("dbname") or cfg.get("database") or cfg.get("DB_NAME"),
        user=cfg.get("username") or cfg.get("user") or cfg.get("DB_USER"),
        password=cfg.get("password") or cfg.get("DB_PASSWORD"),
        connect_timeout=10,
    )

    missing_tables = []
    missing_columns = {}

    with conn.cursor() as cur:
        for table, cols in REQUIRED.items():
            cur.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{table}",))
            exists = cur.fetchone()[0]
            if not exists:
                missing_tables.append(table)
                print(f"  [MISSING TABLE] {table}")
                continue
            cur.execute(
                """SELECT column_name FROM information_schema.columns
                   WHERE table_name=%s""", (table,)
            )
            actual = {r[0] for r in cur.fetchall()}
            missing = [c for c in cols if c not in actual]
            if missing:
                missing_columns[table] = missing
                print(f"  [MISSING COLUMNS] {table}: {missing}")
            else:
                print(f"  [OK] {table}")

    conn.close()
    print()
    print(f"Missing tables   : {len(missing_tables)}")
    print(f"Tables w/ missing cols: {len(missing_columns)}")
    return 0 if not missing_tables and not missing_columns else 1

if __name__ == "__main__":
    sys.exit(main())
