"""v2 매칭 파이프라인 자동 트리거 Lambda.

EventBridge 주기 cron 으로 호출됨. 백엔드의 /api/cmdb/vuln-match/trigger-v2 를
호출해 Trivy import + KISA/PSIRT 매칭 + VEX dismiss + SSVC v2 + Priority Score
파이프라인을 실행한다.

수동 호출에서 자동화로 전환 — 신규 KEV/EPSS/Exploit 신호가 들어오면 즉시
재평가되도록 한다 (ISMS-P 감사 요구 사항: 자동 우선순위 갱신).
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from src.shared.logging_config import setup_logging

logger = setup_logging()

# 백엔드 매칭 endpoint — 환경변수 BACKEND_VULN_MATCH_URL 로 override 가능
DEFAULT_BACKEND_URL = (
    "http://nlb-portal-front-b9f3dcbdc6f16f6f.elb.ap-northeast-2.amazonaws.com"
    "/api/cmdb/vuln-match/trigger-v2"
)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """v2 매칭 트리거 호출.

    event:
      reset (bool, optional)  — true 면 자동 매칭 행 삭제 후 재매칭. 기본 false.
    """
    start = time.monotonic()
    started_at = datetime.now(UTC)
    backend_url = os.environ.get("BACKEND_VULN_MATCH_URL", DEFAULT_BACKEND_URL)
    reset = bool(event.get("reset", False)) if isinstance(event, dict) else False

    logger.info(
        "v2 매칭 트리거 시작 (url=%s, reset=%s)",
        backend_url, reset, extra={"agent": "vuln_match_trigger"},
    )

    try:
        params = {"reset": "true" if reset else "false"}
        with httpx.Client(timeout=180) as client:
            resp = client.post(backend_url, params=params)
            resp.raise_for_status()
            backend_result: dict[str, Any] = resp.json()

        duration_ms = int((time.monotonic() - start) * 1000)
        result = {
            "status": "SUCCESS",
            "started_at": started_at.isoformat(),
            "backend_url": backend_url,
            "reset": reset,
            "backend_result": backend_result,
            "duration_ms": duration_ms,
        }
        logger.info("v2 매칭 트리거 완료: %s", json.dumps(backend_result, ensure_ascii=False))
        return result

    except httpx.HTTPStatusError as e:
        body = e.response.text[:500] if e.response is not None else ""
        logger.exception("v2 매칭 HTTP 오류 %s: %s", e.response.status_code if e.response else "?", body)
        return {
            "status": "FAILED",
            "error": f"HTTP {e.response.status_code if e.response else '?'}",
            "error_body": body,
            "started_at": started_at.isoformat(),
            "duration_ms": int((time.monotonic() - start) * 1000),
        }
    except Exception as e:
        logger.exception("v2 매칭 트리거 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": int((time.monotonic() - start) * 1000),
        }
