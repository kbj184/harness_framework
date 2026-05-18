"""로컬 End-to-End 테스트: CrowdStrike 수집 → Spring Boot API → PostgreSQL 저장.

사용법:
    export CS_CLIENT_ID="..."
    export CS_CLIENT_SECRET="..."
    export CS_BASE_URL="https://api.us-2.crowdstrike.com"
    python scripts/test_e2e_local.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone

from src.agents.crowdstrike.collector import CrowdStrikeCollector
from src.agents.crowdstrike.transformer import transform_devices
from src.shared.api_client import BackendApiClient
from src.shared.models import AssetSource, BulkAssetPayload


BACKEND_URL = os.environ.get("BACKEND_API_URL", "http://localhost:8080")
BACKEND_API_KEY = os.environ.get("BACKEND_API_KEY", "cmdb-collect-api-key-changeme")


def main():
    client_id = os.environ.get("CS_CLIENT_ID")
    client_secret = os.environ.get("CS_CLIENT_SECRET")
    base_url = os.environ.get("CS_BASE_URL", "https://api.us-2.crowdstrike.com")

    if not client_id or not client_secret:
        print("ERROR: CS_CLIENT_ID, CS_CLIENT_SECRET 환경변수를 설정하세요.")
        sys.exit(1)

    collected_at = datetime.now(timezone.utc)

    # 1. CrowdStrike 수집
    print("[1/3] CrowdStrike 디바이스 수집 중...")
    collector = CrowdStrikeCollector(client_id=client_id, client_secret=client_secret, base_url=base_url)
    devices = collector.collect_all_devices()
    print(f"  → {len(devices)}건 조회")

    if not devices:
        print("  디바이스 없음. 종료.")
        return

    # 2. CommonAsset 변환
    print("[2/3] CommonAsset 변환 중...")
    assets = transform_devices(devices, collected_at)
    print(f"  → {len(assets)}건 변환")

    # 3. 백엔드 API 전송
    print(f"[3/3] 백엔드 API 전송 중... ({BACKEND_URL}/api/cmdb/assets/bulk)")
    api_client = BackendApiClient(base_url=BACKEND_URL, api_key=BACKEND_API_KEY, timeout=30)

    payload = BulkAssetPayload(source=AssetSource.CROWDSTRIKE, collected_at=collected_at, assets=assets)
    result = api_client.send_assets(payload)

    print()
    print("=" * 50)
    print(f"  success:       {result.success}")
    print(f"  total_count:   {result.total_count}")
    print(f"  created_count: {result.created_count}")
    print(f"  updated_count: {result.updated_count}")
    if result.error_message:
        print(f"  error:         {result.error_message}")
    print("=" * 50)
    print()
    print("DB에 저장 완료! DBeaver에서 'SELECT * FROM tb_asset;' 로 확인하세요.")


if __name__ == "__main__":
    main()
