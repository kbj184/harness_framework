"""dry-run — 실제 xlsx 파싱 후 통계·검증 리포트 출력. DB 미적재·백엔드 미호출.

사용: python -m src.agents.excel_ledger.dryrun [xlsx경로] [--json out.json]
검증: 시트별 행수 == 실측 기대치 / asset_id_hash 전역 유니크 / 3차 수동 큐 집계.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import UTC, datetime

from src.agents.excel_ledger.config import EXPECTED_ROWS
from src.agents.excel_ledger.loader import build_batches
from src.agents.excel_ledger.parser import parse_workbook

DEFAULT_PATH = (
    r"C:\itamcmdb\kbjdocs\origin"
    r"\(대외비)2026년 GS리테일 ISMS-P - 정보자산 목록 통합본_v1.0 1.xlsx"
)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows cp949 콘솔 대응

    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=DEFAULT_PATH)
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)

    assets, stats = parse_workbook(args.path)

    print(f"{'시트':<22}{'카테고리':<10}{'행수':>6}{'기대':>6}{'유니크':>7}{'자동':>7}{'수동':>6}  검증")
    print("-" * 80)
    all_ok = True
    tot_rows = tot_auto = tot_review = 0
    for st in stats:
        exp = EXPECTED_ROWS.get(st.category_cd, "?")
        ok_rows = (st.rows == exp)
        ok_uniq = (st.unique_hash == st.rows)
        ok = ok_rows and ok_uniq
        all_ok = all_ok and ok
        mark = "OK" if ok else ("행수x" if not ok_rows else "해시중복x")
        print(f"{st.sheet:<22}{st.category_cd:<10}{st.rows:>6}{str(exp):>6}"
              f"{st.unique_hash:>7}{st.auto:>7}{st.review_queue:>6}  {mark}")
        tot_rows += st.rows
        tot_auto += st.auto
        tot_review += st.review_queue

    print("-" * 80)
    hashes = [a.asset_id_hash for a in assets]
    global_uniq = len(set(hashes))
    print(f"{'합계':<22}{'':<10}{tot_rows:>6}{'':>6}{global_uniq:>7}{tot_auto:>7}{tot_review:>6}")
    print()
    print(f"전체 자산: {tot_rows}  / asset_id_hash 전역 유니크: {global_uniq} "
          f"({'OK 충돌0' if global_uniq == tot_rows else f'★충돌 {tot_rows - global_uniq}건'})")
    cov = (tot_auto / tot_rows * 100) if tot_rows else 0
    print(f"1차 자동 결정론: {tot_auto} ({cov:.1f}%)  /  3차 수동 큐: {tot_review} ({100 - cov:.1f}%)")

    # 수동 큐 사유별 집계
    rb: dict[str, int] = defaultdict(int)
    for a in assets:
        if a.review_flag:
            rb[a.review_flag] += 1
    print("\n[3차 수동 큐 사유별]")
    for flag, n in sorted(rb.items(), key=lambda x: -x[1]):
        print(f"  {flag:<28}{n}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump([s.model_dump() for s in stats], f, ensure_ascii=False, indent=2)
        print(f"\n시트 통계 JSON: {args.json_out}")

    # CPE 매핑 커버리지 (D4) — CPE 원천 있는 카테고리만
    cpe_tier: dict[str, int] = defaultdict(int)
    cpe_total = 0
    for a in assets:
        if a.cpe_tier:
            cpe_tier[a.cpe_tier] += 1
            cpe_total += 1
    print(f"\n[CPE 매핑 — CVE 매칭 대상 {cpe_total}건]")
    for tier in ("STD", "MANUAL", "NO_CPE", "UNKNOWN"):
        if cpe_tier.get(tier):
            print(f"  {tier:<10}{cpe_tier[tier]}")
    mapped = cpe_tier.get("STD", 0) + cpe_tier.get("MANUAL", 0)
    print(f"  → NVD 매칭가능 {mapped} / 미매핑(국산·미지) {cpe_total - mapped}")

    # 적재 payload 매핑 검증 (POST 미실행)
    batches = list(build_batches(assets, datetime.now(UTC), batch_size=500))
    print(f"\n[적재 payload — DB 미전송] batch_size=500 → {len(batches)}배치 "
          f"(첫 배치 {batches[0]['count']}행). 샘플 source row 키: "
          f"{list(batches[0]['rows'][0].keys())}")

    hash_ok = global_uniq == tot_rows
    print(f"\n{'✅ 검증 통과' if (all_ok and hash_ok) else '⚠️ 검증 실패 — 위 표 확인'} (DB 미적재)")
    return 0 if (all_ok and hash_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
