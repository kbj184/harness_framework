"""CrowdStrike Falcon Hosts API 실제 연동 테스트 스크립트.

사용법:
    # 환경변수 설정 후 실행
    export CS_CLIENT_ID="your-client-id"
    export CS_CLIENT_SECRET="your-client-secret"
    export CS_BASE_URL="https://api.crowdstrike.com"  # 또는 us-2, eu-1
    python scripts/test_crowdstrike_live.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.crowdstrike.collector import CrowdStrikeCollector
from src.agents.crowdstrike.transformer import transform_devices


def main():
    client_id = os.environ.get("CS_CLIENT_ID")
    client_secret = os.environ.get("CS_CLIENT_SECRET")
    base_url = os.environ.get("CS_BASE_URL", "https://api.crowdstrike.com")

    if not client_id or not client_secret:
        print("ERROR: CS_CLIENT_ID, CS_CLIENT_SECRET 환경변수를 설정하세요.")
        print()
        print("  export CS_CLIENT_ID='your-client-id'")
        print("  export CS_CLIENT_SECRET='your-client-secret'")
        sys.exit(1)

    print(f"[1/3] CrowdStrike API 연결 중... (base_url: {base_url})")
    collector = CrowdStrikeCollector(client_id=client_id, client_secret=client_secret, base_url=base_url)

    print("[2/3] 디바이스 조회 중 (최대 10건 샘플)...")
    # 테스트이므로 소량만 조회
    devices = collector.collect_all_devices()

    if not devices:
        print("  → 조회된 디바이스 없음")
        return

    print(f"  → 총 {len(devices)}건 조회됨")
    print()

    # 샘플 5건 출력
    sample = devices[:5]
    for i, dev in enumerate(sample, 1):
        print(f"  [{i}] device_id: {dev.device_id}")
        print(f"      hostname:  {dev.hostname}")
        print(f"      platform:  {dev.platform_name}")
        print(f"      os:        {dev.os_version}")
        print(f"      local_ip:  {dev.local_ip}")
        print(f"      last_seen: {dev.last_seen}")
        print(f"      status:    {dev.status}")
        print()

    print("[3/3] CommonAsset 변환 테스트...")
    assets = transform_devices(devices)
    print(f"  → {len(assets)}건 변환 완료")
    print()

    # 첫 번째 자산 JSON 출력
    if assets:
        print("  [샘플 CommonAsset JSON]")
        print(json.dumps(json.loads(assets[0].model_dump_json()), indent=2, ensure_ascii=False))

    print()
    print("연동 테스트 성공!")


if __name__ == "__main__":
    main()
