"""FIRST EPSS CSV.gz 수집.

EPSS 스코어 파일:
  https://epss.cyentia.com/epss_scores-current.csv.gz

파일 구조 (헤더 2행 후 CSV):
  #model_version:v2023.03.01,score_date:2024-03-15T00:00:00+0000
  cve,epss,percentile
  CVE-2024-0001,0.12345,0.96789
  ...
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
import re
from datetime import date, datetime
from typing import Any

import httpx

logger = logging.getLogger("collect_cmdb")

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def fetch_epss_csv(url: str = EPSS_URL, timeout: int = 120) -> tuple[date | None, list[dict[str, Any]]]:
    """EPSS CSV.gz 다운로드 + 파싱. (score_date, rows) 반환."""
    logger.info("EPSS 피드 다운로드: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        body = resp.content

    # gzip 해제
    try:
        decompressed = gzip.decompress(body).decode("utf-8")
    except OSError:
        # 일부 환경에서 gzip 아닌 plain으로 오는 경우 대비
        decompressed = body.decode("utf-8")

    lines = decompressed.splitlines()
    if not lines:
        return None, []

    # 첫 줄이 '#...'으로 시작하면 메타 주석. score_date 추출 시도.
    score_date: date | None = None
    header_idx = 0
    if lines[0].startswith("#"):
        m = re.search(r"score_date\s*:\s*(\d{4}-\d{2}-\d{2})", lines[0])
        if m:
            try:
                score_date = datetime.strptime(m.group(1), "%Y-%m-%d").date()
            except ValueError:
                pass
        header_idx = 1  # 다음 줄이 CSV 헤더

    # CSV 읽기
    reader = csv.DictReader(io.StringIO("\n".join(lines[header_idx:])))
    rows: list[dict[str, Any]] = []
    for r in reader:
        cve = (r.get("cve") or "").strip()
        if not cve or not cve.startswith("CVE-"):
            continue
        try:
            epss = float(r.get("epss", "") or 0)
        except ValueError:
            continue
        try:
            pct = float(r.get("percentile", "") or 0)
        except ValueError:
            pct = 0.0
        rows.append({
            "cve_id": cve,
            "epss": epss,
            "percentile": pct,
            "score_date": score_date,
        })
    logger.info("EPSS 항목 %d건 파싱 (score_date=%s)", len(rows), score_date)
    return score_date, rows


UPSERT_SQL = """
INSERT INTO tb_epss_score (cve_id, epss, percentile, score_date, reg_dt, upd_dt)
VALUES (%(cve_id)s, %(epss)s, %(percentile)s, %(score_date)s, LOCALTIMESTAMP, LOCALTIMESTAMP)
ON CONFLICT (cve_id) DO UPDATE SET
    epss       = EXCLUDED.epss,
    percentile = EXCLUDED.percentile,
    score_date = EXCLUDED.score_date,
    upd_dt     = LOCALTIMESTAMP
"""

# 7일 이력 보존 — 매일 갱신분을 tb_epss_history (cve_id, score_date) PK 로 append.
# 7일 변화량 0.3+ 급상승 감지의 입력. 보존 기간 초과 시 별도 정리 job 으로 prune.
HISTORY_INSERT_SQL = """
INSERT INTO tb_epss_history (cve_id, score_date, epss, percentile)
VALUES (%(cve_id)s, %(score_date)s, %(epss)s, %(percentile)s)
ON CONFLICT (cve_id, score_date) DO UPDATE SET
    epss       = EXCLUDED.epss,
    percentile = EXCLUDED.percentile
"""

HISTORY_PRUNE_SQL = """
DELETE FROM tb_epss_history WHERE score_date < CURRENT_DATE - INTERVAL '8 days'
"""


def upsert_epss_rows(conn, rows: list[dict[str, Any]], batch_size: int = 1000) -> int:
    """executemany 대신 chunk 단위 execute로 대용량 대응. tb_epss_score 현재 점수 갱신."""
    count = 0
    with conn.cursor() as cur:
        for i in range(0, len(rows), batch_size):
            chunk = rows[i : i + batch_size]
            cur.executemany(UPSERT_SQL, chunk)
            count += len(chunk)
    return count


def insert_epss_history(
    conn, rows: list[dict[str, Any]], batch_size: int = 1000
) -> tuple[int, int]:
    """tb_epss_history 에 오늘 score_date 의 EPSS 점수 append (UPSERT).

    7일 변화량 감지 입력. score_date 가 NULL 인 행은 skip.
    반환: (적재된 행수, prune된 행수)
    """
    valid = [r for r in rows if r.get("score_date") is not None]
    inserted = 0
    pruned = 0
    with conn.cursor() as cur:
        # 적재
        for i in range(0, len(valid), batch_size):
            chunk = valid[i : i + batch_size]
            cur.executemany(HISTORY_INSERT_SQL, chunk)
            inserted += len(chunk)
        # 보존 기간 초과 prune (8일 이상 지난 행 — 7일 변화량 계산 여유)
        cur.execute(HISTORY_PRUNE_SQL)
        pruned = cur.rowcount or 0
    return inserted, pruned
