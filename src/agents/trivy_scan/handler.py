"""Trivy 스캔 Lambda 진입점.

이벤트 두 종류 지원:
  1. 단일 자산 스캔 — event = {"asset_id_hash": "abc123"}
     SBOM 적재 후 직접 invoke 또는 SNS 메시지로 트리거.
  2. 전체 자산 스캔 — event = {"all_assets": true} 또는 빈 dict
     tb_asset_master 의 ACTIVE 자산 전체 순회. EventBridge cron 일일 호출용.

Trivy DB 갱신은 별도 cron 으로 db_refresh 모드 또는 첫 호출 시 자동 다운로드.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any

from src.agents.trivy_scan.collector import (
    DEFAULT_CACHE_DIR,
    download_trivy_db,
    scan_asset,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()

TRIVY_CACHE_DIR = os.environ.get("TRIVY_CACHE_DIR", DEFAULT_CACHE_DIR)

ACTIVE_ASSETS_SQL = """
SELECT DISTINCT s.asset_id_hash
FROM tb_asset_software s
JOIN tb_asset_master m ON m.asset_id_hash = s.asset_id_hash
WHERE m.lifecycle_state = 'ACTIVE'
  AND s.purl IS NOT NULL
ORDER BY s.asset_id_hash;
"""


def _list_active_assets(conn) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(ACTIVE_ASSETS_SQL)
        return [row[0] for row in cur.fetchall()]


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Trivy 스캔 진입점.

    event 분기:
      - {"mode": "db_refresh"}     — DB 다운로드만 (별도 cron)
      - {"asset_id_hash": "..."}   — 단일 자산 스캔
      - {} or {"all_assets": true} — 전체 자산 스캔 (배치)
    """
    start = time.monotonic()
    started_at = datetime.now(UTC)
    mode = event.get("mode") or ("single" if event.get("asset_id_hash") else "all")
    logger.info("Trivy 스캔 시작 mode=%s", mode, extra={"agent": "trivy_scan"})

    # ── DB 갱신 모드 ──
    if mode == "db_refresh":
        try:
            download_trivy_db(db_cache_dir=TRIVY_CACHE_DIR)
            duration_ms = int((time.monotonic() - start) * 1000)
            return {"status": "SUCCESS", "mode": mode, "duration_ms": duration_ms}
        except Exception as e:
            logger.exception("Trivy DB 갱신 실패")
            return {"status": "FAILED", "mode": mode, "error": str(e)}

    # ── 스캔 모드 ──
    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "TRIVY_SCAN", started_at)
            total_assets = 0
            total_vulns = 0
            total_upserted = 0
            failures: list[dict[str, str]] = []

            try:
                if mode == "single":
                    asset_id_hash = event["asset_id_hash"]
                    targets = [asset_id_hash]
                else:
                    targets = _list_active_assets(conn)
                    logger.info("전체 자산 스캔 — %d 자산 대상", len(targets))

                for asset_id_hash in targets:
                    try:
                        stats = scan_asset(
                            conn, asset_id_hash, db_cache_dir=TRIVY_CACHE_DIR
                        )
                        total_assets += 1
                        total_vulns += stats["vulns"]
                        total_upserted += stats["upserted"]
                    except Exception as e:
                        logger.exception("자산 스캔 실패: %s", asset_id_hash)
                        failures.append({"asset_id_hash": asset_id_hash, "error": str(e)})

                dbm.log_collection_end(
                    conn,
                    log_no,
                    "SUCCESS" if not failures else "PARTIAL",
                    total_vulns,
                    total_upserted,
                    datetime.now(UTC),
                )
            except Exception as e:
                dbm.log_collection_end(
                    conn, log_no, "FAILED", 0, 0, datetime.now(UTC), str(e)
                )
                raise

        duration_ms = int((time.monotonic() - start) * 1000)
        result = {
            "status": "SUCCESS" if not failures else "PARTIAL",
            "mode": mode,
            "started_at": started_at.isoformat(),
            "assets_scanned": total_assets,
            "total_vulns": total_vulns,
            "upserted_count": total_upserted,
            "failures": failures,
            "duration_ms": duration_ms,
        }
        logger.info("Trivy 스캔 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("Trivy 스캔 실패")
        return {
            "status": "FAILED",
            "mode": mode,
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
