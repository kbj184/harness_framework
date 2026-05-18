"""endoflife.date API 수집 (공개, 인증 불필요)."""

from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import Any

import httpx

logger = logging.getLogger("collect_cmdb")

BASE_URL = "https://endoflife.date/api/{product}.json"

# tb_asset_master.os_version 에 나타나는 OS 커버
PRODUCTS: list[str] = [
    "amazon-linux",
    "centos",
    "centos-stream",
    "rhel",
    "rocky-linux",
    "ubuntu",
    "debian",
    "windows-server",
    "windows",
]


def fetch_eos(product: str, timeout: int = 30) -> list[dict[str, Any]]:
    url = BASE_URL.format(product=product)
    logger.info("EOS fetch: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def _parse_date(v: Any) -> date | None:
    if not v or v is True or v is False:
        return None
    if isinstance(v, str):
        try:
            return datetime.strptime(v, "%Y-%m-%d").date()
        except ValueError:
            return None
    return None


def _parse_bool(v: Any) -> bool:
    return bool(v) if isinstance(v, bool) else False


def transform(product: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for it in items:
        cycle = str(it.get("cycle", "")).strip()
        if not cycle:
            continue
        rows.append({
            "product": product,
            "cycle": cycle,
            "release_date": _parse_date(it.get("releaseDate")),
            "eol_date": _parse_date(it.get("eol")),
            "support_date": _parse_date(it.get("support")),
            "extended_date": _parse_date(it.get("extendedSupport")),
            "lts": _parse_bool(it.get("lts")),
            "latest": str(it.get("latest") or "")[:100] or None,
            "link": it.get("link"),
            "raw_data": json.dumps(it),
        })
    return rows


UPSERT_SQL = """
INSERT INTO tb_eos_catalog (
    product, cycle, release_date, eol_date, support_date, extended_date,
    lts, latest, link, raw_data, fetched_at
) VALUES (
    %(product)s, %(cycle)s, %(release_date)s, %(eol_date)s, %(support_date)s, %(extended_date)s,
    %(lts)s, %(latest)s, %(link)s, %(raw_data)s::jsonb, LOCALTIMESTAMP
)
ON CONFLICT (product, cycle) DO UPDATE SET
    release_date  = EXCLUDED.release_date,
    eol_date      = EXCLUDED.eol_date,
    support_date  = EXCLUDED.support_date,
    extended_date = EXCLUDED.extended_date,
    lts           = EXCLUDED.lts,
    latest        = EXCLUDED.latest,
    link          = EXCLUDED.link,
    raw_data      = EXCLUDED.raw_data,
    fetched_at    = LOCALTIMESTAMP
"""


def upsert_rows(conn, rows: list[dict[str, Any]]) -> int:
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count


def collect_all(conn, products: list[str] = PRODUCTS) -> tuple[int, int]:
    total, upserted = 0, 0
    for p in products:
        try:
            items = fetch_eos(p)
        except httpx.HTTPStatusError as e:
            logger.warning("EOS fetch 실패 (건너뜀): %s → %s", p, e)
            continue
        rows = transform(p, items)
        n = upsert_rows(conn, rows)
        total += len(rows)
        upserted += n
        logger.info("EOS %s: %d 행 업서트", p, n)
    return total, upserted
