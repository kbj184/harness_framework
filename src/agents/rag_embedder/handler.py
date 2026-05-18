"""RAG 임베딩 Lambda 진입점."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any

import boto3

from src.agents.rag_embedder import db as dbm
from src.agents.rag_embedder.embedder import BedrockEmbedder
from src.agents.rag_embedder.textifier import textify, visible_roles_for
from src.shared.logging_config import setup_logging

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Event 옵션:
      force_all: bool  — 모든 행 강제 재임베딩 (content_hash 무시). 기본 False.
    """
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("RAG 임베딩 시작", extra={"agent": "rag_embedder"})

    force_all = bool(event.get("force_all", False)) if isinstance(event, dict) else False
    region = os.environ.get("BEDROCK_REGION", os.environ.get("AWS_REGION", "ap-northeast-2"))

    bedrock = boto3.client("bedrock-runtime", region_name=region)
    embedder = BedrockEmbedder(bedrock_client=bedrock)

    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            rows = dbm.fetch_perception_rows(conn)
            logger.info("Perception 조합 조회: %d건", len(rows))

            existing = dbm.fetch_existing_hashes(conn) if not force_all else {}

            upserts: list[dict[str, Any]] = []
            skipped = 0
            errors = 0

            for row in rows:
                content = textify(row, row)
                ch = dbm.md5(content)

                key = (row["asset_id_hash"], row["perspective"])
                if not force_all and existing.get(key) == ch:
                    skipped += 1
                    continue

                try:
                    vec = embedder.embed(content)
                except Exception as e:
                    errors += 1
                    logger.exception(
                        "embed 실패: asset=%s perspective=%s err=%s", row["asset_id_hash"][:10], row["perspective"], e
                    )
                    continue

                upserts.append(
                    {
                        "asset_id_hash": row["asset_id_hash"],
                        "perspective": row["perspective"],
                        "content": content,
                        "embedding": dbm.embedding_to_pg(vec),
                        "priority": row.get("perceived_priority"),
                        "service_name": row.get("service_name"),
                        "category_cd": row.get("category_cd"),
                        "visible_to_roles": visible_roles_for(row["perspective"]),
                        "content_hash": ch,
                    }
                )

            upserted = dbm.upsert_rag_rows(conn, upserts) if upserts else 0

        duration_ms = int((time.monotonic() - start) * 1000)
        result = {
            "status": "SUCCESS" if errors == 0 else "PARTIAL",
            "started_at": started_at.isoformat(),
            "total_rows": len(rows),
            "upserted": upserted,
            "skipped": skipped,
            "errors": errors,
            "duration_ms": duration_ms,
        }
        logger.info("RAG 임베딩 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("RAG 임베딩 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
