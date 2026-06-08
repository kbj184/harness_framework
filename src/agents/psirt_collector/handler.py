"""네트워크 장비 PSIRT 수집 Lambda 진입점.

벤더 레지스트리(vendors.VENDORS)의 enabled 스펙을 순회 수집 → tb_vendor_advisory UPSERT.
한 벤더 실패해도 나머지 계속(skip). 벤더 추가/활성화는 vendors.py 만 수정.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.psirt_collector.collector import transform_psirt, upsert_advisory_rows
from src.agents.psirt_collector.vendors import VENDORS, collect
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """PSIRT 벤더 통합 수집 → tb_vendor_advisory UPSERT (레지스트리 순회)."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("PSIRT 수집 시작", extra={"agent": "psirt_collector"})

    try:
        # enabled 벤더만 순회 수집 (한 벤더 실패해도 나머지 계속)
        counts: dict[str, int] = {}
        all_items = []
        for spec in VENDORS:
            if not spec.enabled:
                continue
            items = collect(spec)
            counts[spec.source] = len(items)
            all_items.extend(items)

        rows = transform_psirt(all_items)

        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "PSIRT", started_at)
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
            "counts": counts,                       # {vendor_source: 건수}
            "total_count": len(rows),
            "upserted_count": upserted,
            "duration_ms": duration_ms,
        }
        logger.info("PSIRT 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("PSIRT 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
