"""EOS 수집 Lambda 진입점.

EventBridge 주 1회(일요일 KST 04:00) cron 으로 호출되어 endoflife.date 의
제품별 EOL/EOSL 데이터를 tb_eos_catalog 에 UPSERT.

자산 OS 가 EOSL 에 도달하면 SSVC 등급을 1단계 상향하는 입력 데이터다.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.eos_collector.collector import (
    PRODUCTS,
    collect_all,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """endoflife.date 다운로드 + tb_eos_catalog UPSERT.

    event 옵션:
        products: list[str] — 수집할 제품 슬러그 목록 (생략 시 기본 PRODUCTS)
    """
    start = time.monotonic()
    started_at = datetime.now(UTC)
    products = event.get("products") if isinstance(event, dict) else None
    products = products or PRODUCTS

    logger.info("EOS 수집 시작", extra={"agent": "eos_collector", "products": products})

    total = 0
    upserted = 0
    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "EOS", started_at)
            try:
                total, upserted = collect_all(conn, products=products)
                dbm.log_collection_end(
                    conn, log_no, "SUCCESS", total, upserted, datetime.now(UTC)
                )
            except Exception as e:
                dbm.log_collection_end(
                    conn, log_no, "FAILED", total, upserted, datetime.now(UTC), str(e)
                )
                raise

        duration_ms = int((time.monotonic() - start) * 1000)
        result = {
            "status": "SUCCESS",
            "started_at": started_at.isoformat(),
            "products": products,
            "total_count": total,
            "upserted_count": upserted,
            "duration_ms": duration_ms,
        }
        logger.info("EOS 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("EOS 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
