"""shared/api_client.py 단위 테스트."""

from datetime import UTC, datetime

import httpx
import pytest

from src.shared.api_client import BackendApiClient
from src.shared.models import AssetSource, BulkAssetPayload, CommonAsset


def _make_payload(count: int = 2) -> BulkAssetPayload:
    now = datetime.now(UTC)
    assets = [
        CommonAsset(source=AssetSource.CROWDSTRIKE, source_id=f"dev-{i}", hostname=f"host-{i}", collected_at=now)
        for i in range(count)
    ]
    return BulkAssetPayload(source=AssetSource.CROWDSTRIKE, collected_at=now, assets=assets)


class TestBackendApiClient:
    def test_send_assets_success(self):
        """정상 응답 시 BulkAssetResponse를 반환한다."""
        response_json = {"success": True, "total_count": 2, "created_count": 1, "updated_count": 1}

        transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json=response_json)
        )

        client = BackendApiClient(base_url="http://localhost:8080", api_key="test-key")
        # Mock transport를 주입하기 위해 _build_client를 오버라이드
        client._build_client = lambda: httpx.Client(  # type: ignore
            base_url="http://localhost:8080",
            headers={"X-Api-Key": "test-key", "Content-Type": "application/json"},
            timeout=30,
            transport=transport,
        )

        payload = _make_payload()
        result = client.send_assets(payload)

        assert result.success is True
        assert result.total_count == 2
        assert result.created_count == 1

    def test_send_assets_includes_api_key_header(self):
        """X-Api-Key 헤더가 요청에 포함된다."""
        captured_headers = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json={"success": True})

        transport = httpx.MockTransport(handler)
        client = BackendApiClient(base_url="http://localhost:8080", api_key="my-secret-key")
        client._build_client = lambda: httpx.Client(  # type: ignore
            base_url="http://localhost:8080",
            headers={"X-Api-Key": "my-secret-key", "Content-Type": "application/json"},
            timeout=30,
            transport=transport,
        )

        client.send_assets(_make_payload())
        assert captured_headers.get("x-api-key") == "my-secret-key"

    def test_send_assets_retries_on_500(self):
        """5xx 에러 시 재시도 후 최종 실패하면 RuntimeError를 발생시킨다."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(500, json={"error": "Internal Server Error"})

        transport = httpx.MockTransport(handler)
        client = BackendApiClient(base_url="http://localhost:8080", api_key="test-key")
        client._build_client = lambda: httpx.Client(  # type: ignore
            base_url="http://localhost:8080",
            headers={"X-Api-Key": "test-key", "Content-Type": "application/json"},
            timeout=30,
            transport=transport,
        )

        with pytest.raises(RuntimeError, match="3회 실패"):
            client.send_assets(_make_payload())

        assert call_count == 3

    def test_send_assets_succeeds_after_retry(self):
        """첫 번째 실패 후 두 번째에 성공하면 정상 응답을 반환한다."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(503, json={"error": "Service Unavailable"})
            return httpx.Response(200, json={"success": True, "total_count": 2, "created_count": 2, "updated_count": 0})

        transport = httpx.MockTransport(handler)
        client = BackendApiClient(base_url="http://localhost:8080", api_key="test-key")
        client._build_client = lambda: httpx.Client(  # type: ignore
            base_url="http://localhost:8080",
            headers={"X-Api-Key": "test-key", "Content-Type": "application/json"},
            timeout=30,
            transport=transport,
        )

        result = client.send_assets(_make_payload())
        assert result.success is True
        assert call_count == 2
