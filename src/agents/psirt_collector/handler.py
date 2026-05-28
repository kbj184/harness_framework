"""네트워크 장비 PSIRT 수집 Lambda 진입점.

4 벤더 (Cisco / F5 / Palo Alto / Fortinet) 통합 호출 → tb_vendor_advisory UPSERT.
Cisco 는 OAuth 미설정 시 skip (warning).
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any

from src.agents.psirt_collector.collector import (
    F5_PSIRT_RSS_URL,
    FORTINET_PSIRT_URL,
    PALOALTO_RSS_URL,
    fetch_cisco_advisories,
    fetch_fortinet_html,
    fetch_psirt_rss,
    parse_cisco_advisories,
    parse_fortinet_html,
    parse_psirt_rss,
    transform_psirt,
    upsert_advisory_rows,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def _collect_cisco() -> list:
    try:
        data = fetch_cisco_advisories()
        return parse_cisco_advisories(data)
    except RuntimeError as e:
        logger.warning("Cisco PSIRT skip: %s", e)
        return []
    except Exception:
        logger.exception("Cisco PSIRT 실패 (skip)")
        return []


def _collect_rss(url: str, vendor_source: str, id_prefix: str) -> list:
    try:
        rss_text = fetch_psirt_rss(url)
        return parse_psirt_rss(rss_text, vendor_source=vendor_source, id_prefix=id_prefix)
    except Exception:
        logger.exception("%s PSIRT 실패 (skip)", vendor_source)
        return []


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """PSIRT 4 벤더 통합 수집 → tb_vendor_advisory UPSERT."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("PSIRT 수집 시작", extra={"agent": "psirt_collector"})

    def _collect_fortinet() -> list:
        """Fortinet 은 HTML 스크래핑 (RSS 미제공). User-Agent 필요."""
        try:
            html_text = fetch_fortinet_html(FORTINET_PSIRT_URL)
            return parse_fortinet_html(html_text)
        except Exception:
            logger.exception("Fortinet PSIRT 실패 (skip)")
            return []

    try:
        # 4 벤더 병렬 수집 (한 벤더 실패해도 나머지 계속)
        cisco_items = _collect_cisco()
        f5_items = _collect_rss(F5_PSIRT_RSS_URL, "PSIRT_F5", "K")
        pa_items = _collect_rss(PALOALTO_RSS_URL, "PSIRT_PA", "PAN-SA-")
        forti_items = _collect_fortinet()

        all_items = cisco_items + f5_items + pa_items + forti_items
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
            "cisco_count": len(cisco_items),
            "f5_count": len(f5_items),
            "paloalto_count": len(pa_items),
            "fortinet_count": len(forti_items),
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
