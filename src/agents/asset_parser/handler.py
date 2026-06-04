"""Asset Parser Lambda 진입점 (S3 PutObject 트리거).

Collect Agent(aws/crowdstrike 등)가 S3 raw 버킷에 적재한 CommonAsset JSONL.gz 를
s3:ObjectCreated 이벤트로 받아 tb_asset 에 UPSERT 한다.

S3 객체 키 컨벤션:
    s3://<bucket>/<source>/<YYYYmmdd>/<run>.jsonl.gz   (prefix[0] = source)

처리 실패 객체는 같은 버킷의 failed/ prefix 로 복사·격리(멱등 재처리).
prod→dev 이관 시 이 버킷 스냅샷만 복사 후 Parser 재실행 → 동일 자산 재구성.
"""

from __future__ import annotations

import gzip
import json
import time
import urllib.parse
from datetime import UTC, datetime
from typing import Any

import boto3

from src.agents.asset_parser import loader
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def _read_assets(s3, bucket: str, key: str) -> list[dict[str, Any]]:
    """S3 JSONL.gz 객체 → CommonAsset dict 리스트."""
    obj = s3.get_object(Bucket=bucket, Key=key)
    raw = gzip.decompress(obj["Body"].read()).decode("utf-8")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _quarantine(s3, bucket: str, key: str) -> None:
    """처리 실패 객체를 failed/ prefix 로 복사·격리."""
    s3.copy_object(
        Bucket=bucket,
        CopySource={"Bucket": bucket, "Key": key},
        Key=f"failed/{key}",
    )
    logger.warning("격리 완료: s3://%s/failed/%s", bucket, key)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """S3 PutObject 이벤트 → CommonAsset JSONL.gz 적재."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("Asset Parser 시작", extra={"agent": "asset_parser"})

    records = event.get("Records", [])
    if not records:
        logger.warning("Records 없음 - 이벤트 형식 확인 필요")
        return {"status": "NO_RECORDS"}

    cfg = dbm.load_db_config()
    s3 = boto3.client("s3")

    total_upserted = 0
    file_count = 0
    failures: list[dict[str, str]] = []

    for rec in records:
        s3rec = rec.get("s3", {})
        bucket = s3rec.get("bucket", {}).get("name")
        key = urllib.parse.unquote_plus(s3rec.get("object", {}).get("key", ""))
        if not bucket or not key or not key.endswith(".jsonl.gz"):
            logger.warning("스킵: bucket=%s key=%s", bucket, key)
            continue
        if key.startswith("failed/"):
            logger.info("격리 객체 스킵: %s", key)
            continue

        try:
            assets = _read_assets(s3, bucket, key)
            source = key.split("/")[0]
            with dbm.connect(cfg) as conn:
                log_no = loader.log_start(conn, source, len(assets))
                n = loader.upsert_assets(conn, assets)
                loader.log_end(conn, log_no, "SUCCESS", n, 0)
            total_upserted += n
            file_count += 1
            logger.info("적재 완료: s3://%s/%s (%d건)", bucket, key, n)
        except Exception as e:
            logger.exception("파일 처리 실패: s3://%s/%s", bucket, key)
            try:
                _quarantine(s3, bucket, key)
            except Exception:
                logger.exception("격리 실패: s3://%s/%s", bucket, key)
            failures.append({"key": key, "error": str(e)})

    duration_ms = int((time.monotonic() - start) * 1000)
    result = {
        "status": "SUCCESS" if not failures else "PARTIAL",
        "started_at": started_at.isoformat(),
        "files_processed": file_count,
        "rows_upserted": total_upserted,
        "failures": failures,
        "duration_ms": duration_ms,
    }
    logger.info("Asset Parser 완료: %s", result)
    return result
