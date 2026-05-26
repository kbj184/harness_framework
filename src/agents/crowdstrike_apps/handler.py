"""CrowdStrike Falcon Discover Applications 수집 Lambda 진입점 (일 1회)."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from typing import Any

import boto3

from src.agents.crowdstrike_apps.collector import collect_all
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def _load_cs_creds() -> dict[str, str]:
    secret_name = os.environ.get("CROWDSTRIKE_SECRET_NAME", "cmdb/crowdstrike")
    client = boto3.client("secretsmanager")
    return json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Discover Applications 를 수집해 tb_asset_software upsert + asset 매칭."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("CrowdStrike Apps 수집 시작", extra={"agent": "crowdstrike_apps"})

    try:
        cs = _load_cs_creds()
        cfg = dbm.load_db_config()
        max_pages_env = os.environ.get("APPS_MAX_PAGES")
        max_pages = int(max_pages_env) if max_pages_env else None

        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "CS_APPS", started_at)
            try:
                total, upserted = collect_all(
                    conn,
                    base_url=cs["base_url"],
                    client_id=cs["client_id"],
                    client_secret=cs["client_secret"],
                    max_pages=max_pages,
                )
                dbm.log_collection_end(
                    conn, log_no, "SUCCESS", total, upserted, datetime.now(UTC)
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
            "total_count": total,
            "upserted_count": upserted,
            "duration_ms": duration_ms,
        }
        logger.info("CrowdStrike Apps 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("CrowdStrike Apps 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
