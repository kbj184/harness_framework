"""tb_asset_software.cpe_uri 후처리 enrich — name/vendor/version → CPE (cpe_for 재사용).

purl 이 없는(또는 Trivy 가 못 잡는) SW — 특히 Windows 설치 앱 — 를 CPE 로 매칭하기 위한
선행 단계. backend 의 SW CPE 매처(matchSwByCpe)가 이 cpe_uri 를 NVD(tb_cve_cpe_match)에 잇는다.

동작: cpe_uri IS NULL 인 행을 (name,vendor,version) 단위로 모아 cpe_for() 로 변환 →
      매핑되면(STD/MANUAL) cpe_uri UPDATE. idempotent (다시 돌려도 NULL 인 것만 채움).
대외비: name 외 PII 없음, 콘솔은 집계만.

사용: python -m scripts.enrich_sw_cpe [--dry-run]
환경: DB_HOST/.. 또는 Secrets Manager(DB_SECRET_NAME, 기본 cmdb/db-writer). VPC 접근 필요.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from src.shared.cpe import cpe_for
from src.shared.db import connect, load_db_config

# cpe_uri 미적재 SW 의 distinct 식별자 (대량 UPDATE 회피 — 시그니처 단위)
# Trivy(purl) 가 이미 커버하는 배포판/언어 패키지(rpm/deb/npm/...)는 제외 — CPE 는
# Trivy 가 못 잡는 SW(Windows=msi→pkg:generic, purl 없음)에만 의미가 있다.
SELECT_SQL = """
SELECT DISTINCT name, vendor, version
  FROM tb_asset_software
 WHERE cpe_uri IS NULL AND name IS NOT NULL
   AND COALESCE(ecosystem, '') NOT IN
       ('rpm', 'deb', 'apk', 'npm', 'pypi', 'maven', 'golang', 'gem', 'nuget')
"""

UPDATE_SQL = """
UPDATE tb_asset_software
   SET cpe_uri = %(cpe_uri)s
 WHERE cpe_uri IS NULL
   AND name = %(name)s
   AND COALESCE(version, '') = COALESCE(%(version)s, '')
   AND COALESCE(ecosystem, '') NOT IN
       ('rpm', 'deb', 'apk', 'npm', 'pypi', 'maven', 'golang', 'gem', 'nuget')
"""


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="UPDATE 후 ROLLBACK (검증만)")
    args = ap.parse_args(argv)

    cfg = load_db_config()
    with connect(cfg) as conn:
        with conn.cursor() as cur:
            cur.execute(SELECT_SQL)
            sigs = cur.fetchall()  # (name, vendor, version)

            tiers: Counter[str] = Counter()
            updated_rows = 0
            mapped_sigs = 0
            for name, vendor, version in sigs:
                res = cpe_for(name or "", version or "")
                tiers[res.tier] += 1
                if res.unmapped or not res.cpe_uri:
                    continue
                mapped_sigs += 1
                cur.execute(UPDATE_SQL, {"cpe_uri": res.cpe_uri, "name": name, "version": version})
                updated_rows += cur.rowcount

        print(f"미적재 시그니처: {len(sigs)}  /  CPE 매핑됨: {mapped_sigs}")
        print("tier 분포:", dict(tiers))
        if args.dry_run:
            conn.rollback()
            print(f"[DRY-RUN] cpe_uri UPDATE {updated_rows}행 후 ROLLBACK")
            return 0
        print(f"✅ cpe_uri 적재 완료 — {updated_rows}행 UPDATE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
