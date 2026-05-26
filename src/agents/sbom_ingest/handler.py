"""SBOM Ingest Lambda 진입점 (S3 PutObject 트리거).

자산 호스트가 Ansible playbook 으로 생성한 SBOM JSON 을 S3에 업로드하면
이 Lambda 가 S3 이벤트로 호출되어 tb_asset_software 에 적재한다.

S3 객체 키 컨벤션 (권장):
    s3://gsretail-sbom/{hostname}/{YYYYmmdd_HHMMSS}.json
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
from datetime import UTC, datetime
from typing import Any

import boto3

from src.agents.sbom_ingest.collector import ingest_sbom
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def _load_s3_object(bucket: str, key: str) -> dict[str, Any]:
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=bucket, Key=key)
    return json.loads(obj["Body"].read().decode("utf-8"))


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """S3 PutObject 이벤트 → SBOM JSON 적재."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("SBOM Ingest 시작", extra={"agent": "sbom_ingest"})

    records = event.get("Records", [])
    if not records:
        logger.warning("Records 없음 - 이벤트 형식 확인 필요")
        return {"status": "NO_RECORDS"}

    cfg = dbm.load_db_config()
    total_inserted = 0
    total_matched = 0
    file_count = 0
    failures: list[dict[str, str]] = []

    with dbm.connect(cfg) as conn:
        log_no = dbm.log_collection_start(conn, "SBOM_INGEST", started_at)
        try:
            for rec in records:
                s3 = rec.get("s3", {})
                bucket = s3.get("bucket", {}).get("name")
                key = urllib.parse.unquote_plus(s3.get("object", {}).get("key", ""))
                if not bucket or not key or not key.endswith(".json"):
                    logger.warning("스킵: bucket=%s key=%s", bucket, key)
                    continue

                try:
                    sbom_json = _load_s3_object(bucket, key)
                    sbom_doc_id = f"s3://{bucket}/{key}"
                    inserted, matched = ingest_sbom(conn, sbom_json, sbom_doc_id=sbom_doc_id)
                    total_inserted += inserted
                    total_matched += matched
                    file_count += 1
                except Exception as e:
                    logger.exception("파일 처리 실패: s3://%s/%s", bucket, key)
                    failures.append({"key": key, "error": str(e)})

            dbm.log_collection_end(
                conn, log_no, "SUCCESS" if not failures else "PARTIAL",
                total_inserted, total_matched, datetime.now(UTC),
            )
        except Exception as e:
            dbm.log_collection_end(
                conn, log_no, "FAILED", total_inserted, 0, datetime.now(UTC), str(e),
            )
            raise

    duration_ms = int((time.monotonic() - start) * 1000)
    result = {
        "status": "SUCCESS" if not failures else "PARTIAL",
        "started_at": started_at.isoformat(),
        "files_processed": file_count,
        "rows_inserted": total_inserted,
        "assets_matched": total_matched,
        "failures": failures,
        "duration_ms": duration_ms,
    }
    logger.info("SBOM Ingest 완료: %s", result)
    return result
