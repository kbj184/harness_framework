"""FIRST EPSS 수집 Lambda 진입점."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.epss_collector.collector import (
    fetch_epss_csv,
    insert_epss_history,
    upsert_epss_rows,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("EPSS 수집 시작", extra={"agent": "epss_collector"})

    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "EPSS", started_at)
            try:
                score_date, rows = fetch_epss_csv()
                upserted = upsert_epss_rows(conn, rows) if rows else 0
                # tb_epss_history 7일 이력 append (KEV 등재 전 급상승 감지 입력)
                history_inserted, history_pruned = (0, 0)
                if rows:
                    history_inserted, history_pruned = insert_epss_history(conn, rows)
                logger.info(
                    "EPSS history: inserted=%d pruned=%d",
                    history_inserted, history_pruned,
                )
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
            "score_date": score_date.isoformat() if score_date else None,
            "total_count": len(rows),
            "upserted_count": upserted,
            "history_inserted": history_inserted,
            "history_pruned": history_pruned,
            "duration_ms": duration_ms,
        }
        logger.info("EPSS 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("EPSS 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
