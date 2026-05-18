"""CISA KEV 수집 Lambda 진입점."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.kev_collector.collector import (
    fetch_kev_feed,
    transform_kev,
    upsert_kev_rows,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """CISA KEV 피드를 tb_kev_catalog에 UPSERT."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("KEV 수집 시작", extra={"agent": "kev_collector"})

    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "KEV", started_at)
            try:
                vulns = fetch_kev_feed()
                rows = transform_kev(vulns)
                upserted = upsert_kev_rows(conn, rows)
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
        logger.info("KEV 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("KEV 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
