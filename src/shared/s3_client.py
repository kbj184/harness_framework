"""S3 raw landing 적재 — Collect Agent → S3 (JSONL.gz).

수집기는 backend bulk API 직행 대신 CommonAsset 를 JSONL.gz 로 S3 에 PutObject 한다.
Parser(asset_parser)가 s3:ObjectCreated 이벤트로 소비 → Collect↔Parser 디커플링.

★ 이 버킷이 환경 간 데이터의 원천: prod→dev 이관 시 이 버킷만 스냅샷 복사 후
  dev 에서 Parser 재실행 → deterministic 식별로 동일 자산 트리 재구성.

경로 컨벤션 (source/date prefix = 스냅샷 단위):
    s3://<ASSET_RAW_BUCKET>/<source>/<YYYYmmdd>/<run>.jsonl.gz
"""

from __future__ import annotations

import gzip
import io
import logging
import os
import uuid
from datetime import datetime

import boto3

from src.shared.models import CommonAsset

logger = logging.getLogger("collect_cmdb")


def _bucket() -> str:
    bucket = os.environ.get("ASSET_RAW_BUCKET")
    if not bucket:
        raise RuntimeError("ASSET_RAW_BUCKET 환경변수 미설정")
    return bucket


def _gzip_jsonl(assets: list[CommonAsset]) -> bytes:
    """CommonAsset 리스트 → JSONL.gz (줄당 1 자산)."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for a in assets:
            gz.write((a.model_dump_json() + "\n").encode("utf-8"))
    return buf.getvalue()


def put_assets(
    assets: list[CommonAsset],
    source: str,
    collected_at: datetime,
    s3_client=None,
) -> str:
    """CommonAsset 리스트를 JSONL.gz 로 묶어 S3 에 PutObject. 생성된 Key 반환.

    같은 수집의 모든 자산을 한 객체로 적재한다 (Parser 가 한 번에 소비).
    """
    if not assets:
        raise ValueError("빈 자산 리스트는 적재하지 않는다")

    bucket = _bucket()
    date = collected_at.strftime("%Y%m%d")
    run = f"{collected_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    key = f"{source}/{date}/{run}.jsonl.gz"

    s3 = s3_client or boto3.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_gzip_jsonl(assets))
    logger.info("S3 적재 완료: s3://%s/%s (%d건)", bucket, key, len(assets))
    return key
