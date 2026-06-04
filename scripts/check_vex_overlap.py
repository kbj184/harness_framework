"""tb_asset_vulnerability ∩ tb_vex 정확 분석."""
import json, sys, boto3, psycopg2

sm = boto3.client("secretsmanager", region_name="ap-northeast-2")
cfg = json.loads(sm.get_secret_value(SecretId="cmdb/db-writer")["SecretString"])
conn = psycopg2.connect(
    host=cfg.get("host") or cfg.get("DB_HOST"),
    port=int(cfg.get("port") or 5432),
    dbname=cfg.get("dbname") or cfg.get("DB_NAME"),
    user=cfg.get("username") or cfg.get("user") or cfg.get("DB_USER"),
    password=cfg.get("password") or cfg.get("DB_PASSWORD"),
    connect_timeout=10,
)
with conn.cursor() as cur:
    cur.execute("SELECT COUNT(DISTINCT cve_id) FROM tb_asset_vulnerability WHERE status='OPEN'")
    a_unique = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT cve_id) FROM tb_vex")
    v_unique = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT cve_id) FROM tb_vex WHERE status='not_affected'")
    v_na = cur.fetchone()[0]
    cur.execute("""SELECT COUNT(DISTINCT v.cve_id) FROM tb_asset_vulnerability v
                   JOIN tb_vex x ON x.cve_id = v.cve_id""")
    overlap_all = cur.fetchone()[0]
    cur.execute("""SELECT COUNT(DISTINCT v.cve_id) FROM tb_asset_vulnerability v
                   JOIN tb_vex x ON x.cve_id = v.cve_id AND x.status='not_affected'""")
    overlap_na = cur.fetchone()[0]
    cur.execute("""SELECT COUNT(*) FROM tb_asset_vulnerability v
                   JOIN tb_vex x ON x.cve_id = v.cve_id
                                AND x.status='not_affected'
                   WHERE v.status='OPEN'""")
    matchable_rows = cur.fetchone()[0]

    print(f"asset_vulnerability OPEN CVE 종류:     {a_unique:>6}")
    print(f"VEX 전체 CVE 종류:                     {v_unique:>6}")
    print(f"VEX not_affected CVE 종류:             {v_na:>6}")
    print(f"교집합 (전체):                          {overlap_all:>6}")
    print(f"교집합 (not_affected 만):              {overlap_na:>6}")
    print(f"dismiss 매칭 가능 행 수:               {matchable_rows:>6}")

    # vex_source 분포
    print("\n=== VEX 출처별 ===")
    cur.execute("SELECT vex_source, COUNT(*) FROM tb_vex GROUP BY vex_source ORDER BY 2 DESC")
    for r in cur.fetchall():
        print(f"  {r[0]:20s} {r[1]:>6}")

    # 우리 자산 CVE 상위 30개 (어떤 CVE 가 매칭됐는지)
    print("\n=== 자산 매칭 CVE 상위 10건 ===")
    cur.execute("""SELECT cve_id, COUNT(*) FROM tb_asset_vulnerability
                   WHERE status='OPEN' GROUP BY cve_id ORDER BY 2 DESC LIMIT 10""")
    for r in cur.fetchall():
        print(f"  {r[0]:20s} {r[1]:>6}")
conn.close()
