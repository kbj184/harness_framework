"""Spring Boot 백엔드 bulk API 클라이언트."""

from __future__ import annotations

import logging
import time

import httpx

from src.shared.models import BulkAssetPayload, BulkAssetResponse

logger = logging.getLogger("collect_cmdb")

MAX_RETRIES = 3
BACKOFF_BASE = 2  # seconds


class BackendApiClient:
    """Spring Boot 백엔드에 자산 데이터를 전송하는 HTTP 클라이언트."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 30) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _build_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._base_url,
            headers={
                "X-Api-Key": self._api_key,
                "Content-Type": "application/json",
            },
            timeout=self._timeout,
        )

    def send_assets(self, payload: BulkAssetPayload) -> BulkAssetResponse:
        """자산 데이터를 백엔드 bulk API로 전송한다. 실패 시 최대 3회 재시도."""
        last_error: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with self._build_client() as client:
                    response = client.post(
                        "/api/cmdb/assets/bulk",
                        content=payload.model_dump_json(),
                    )
                    response.raise_for_status()
                    return BulkAssetResponse.model_validate(response.json())

            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                last_error = e
                if attempt < MAX_RETRIES:
                    wait = BACKOFF_BASE**attempt
                    logger.warning(
                        "백엔드 API 호출 실패 (시도 %d/%d), %d초 후 재시도: %s",
                        attempt,
                        MAX_RETRIES,
                        wait,
                        str(e),
                    )
                    time.sleep(wait)

        raise RuntimeError(f"백엔드 API 호출 {MAX_RETRIES}회 실패: {last_error}")
