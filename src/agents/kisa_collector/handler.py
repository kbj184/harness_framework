"""KISA 보안공지 수집 Lambda 진입점.

EventBridge 일 1회 cron 으로 호출. RSS 다운로드 → 파싱 → tb_vendor_advisory UPSERT.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.kisa_collector.collector import (
    fetch_kisa_rss,
    parse_kisa_rss,
    transform_kisa,
    upsert_advisory_rows,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """KISA 보안공지 RSS → tb_vendor_advisory UPSERT."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("KISA 수집 시작", extra={"agent": "kisa_collector"})

    try:
        rss_text = fetch_kisa_rss()
        items = parse_kisa_rss(rss_text)
        rows = transform_kisa(items)

        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "KISA", started_at)
            try:
                upserted = upsert_advisory_rows(conn, rows)
                dbm.log_collection_end(
                    conn, log_no, "SUCCESS", len(rows), upserted, datetime.now(UTC)
                )
            except Exception as e:
                dbm.log_collection_end(
                    conn, log_no, "FAILED", 0, 0, datetime.now(UTC), str(e)
                )
                raise

        duration_ms = int((time.monotonic() - start) * 1000)
        result = {
            "status": "SUCCESS",
            "started_at": started_at.isoformat(),
            "total_count": len(rows),
            "upserted_count": upserted,
            "duration_ms": duration_ms,
        }
        logger.info("KISA 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("KISA 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
