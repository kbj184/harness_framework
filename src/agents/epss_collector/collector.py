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


def upsert_epss_rows(conn, rows: list[dict[str, Any]], batch_size: int = 1000) -> int:
    """executemany 대신 chunk 단위 execute로 대용량 대응."""
    count = 0
    with conn.cursor() as cur:
        for i in range(0, len(rows), batch_size):
            chunk = rows[i : i + batch_size]
            cur.executemany(UPSERT_SQL, chunk)
            count += len(chunk)
    return count
