"""CrowdStrike Falcon Discover — Applications API 실제 호출 테스트.

목적: GS리테일 테넌트가 Falcon Discover for IT Hygiene 모듈을 보유했는지 즉시 확인.

판별:
    200 + resources[] 데이터  → ✅ 라이센스 보유. SW 인벤토리 수집 가능
    403 access denied         → ❌ 라이센스 없음 (scope/구독 모두 가능)
    404                       → endpoint 자체 미지원

사용법:
    export CS_CLIENT_ID="..."
    export CS_CLIENT_SECRET="..."
    export CS_BASE_URL="https://api.crowdstrike.com"   # 또는 us-2, eu-1
    python scripts/test_discover_applications.py

자격증명이 AWS Secrets Manager 에 있는 경우:
    export CS_SECRET_ARN="arn:aws:secretsmanager:ap-northeast-2:...:secret:cmdb/crowdstrike-XXXX"
    python scripts/test_discover_applications.py
    (secret 안에 client_id, client_secret 키 필요)
"""

from __future__ import annotations

import json
import os
import sys

import httpx


def _load_creds() -> tuple[str, str, str]:
    """환경변수 또는 Secrets Manager 에서 자격증명 로드."""
    secret_arn = os.environ.get("CS_SECRET_ARN")
    if secret_arn:
        import boto3

        client = boto3.client("secretsmanager")
        sec = client.get_secret_value(SecretId=secret_arn)
        data = json.loads(sec["SecretString"])
        return (
            data["client_id"],
            data["client_secret"],
            data.get("base_url", "https://api.crowdstrike.com"),
        )

    cid = os.environ.get("CS_CLIENT_ID")
    sec = os.environ.get("CS_CLIENT_SECRET")
    base = os.environ.get("CS_BASE_URL", "https://api.crowdstrike.com")
    if not cid or not sec:
        print("ERROR: CS_CLIENT_ID / CS_CLIENT_SECRET 또는 CS_SECRET_ARN 을 설정하세요.")
        sys.exit(2)
    return cid, sec, base


def _oauth_token(base_url: str, cid: str, sec: str) -> str:
    with httpx.Client(timeout=30) as c:
        r = c.post(
            f"{base_url}/oauth2/token",
            data={"client_id": cid, "client_secret": sec},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        return r.json()["access_token"]


def main() -> None:
    cid, sec, base = _load_creds()
    print(f"[1/3] OAuth2 토큰 발급... (base: {base})")
    token = _oauth_token(base, cid, sec)
    headers = {"Authorization": f"Bearer {token}"}

    # ── 1) Application ID 목록 (10개만) ─────────────────────────────
    print("[2/3] GET /discover/queries/applications/v1 (limit=10)")
    with httpx.Client(timeout=30) as c:
        r = c.get(
            f"{base}/discover/queries/applications/v1",
            headers=headers,
            params={"limit": 10, "sort": "last_used_timestamp|desc"},
        )

    print(f"      status: {r.status_code}")
    try:
        body = r.json()
    except Exception:
        print("      (응답 JSON 파싱 실패)")
        print(r.text[:500])
        sys.exit(1)

    if r.status_code == 403:
        print()
        print("❌ 403 Forbidden — Falcon Discover 라이센스 없음 또는 API Client 권한 부족")
        print()
        print("   errors:")
        for e in body.get("errors", []):
            print(f"     - code={e.get('code')} message={e.get('message')}")
        print()
        print("   해결: CrowdStrike 콘솔에서 다음 중 하나 확인")
        print("     a) Falcon Discover (IT Hygiene) 구독 여부")
        print("     b) API Client scope 에 'Falcon Discover: Read' 추가")
        sys.exit(0)

    if r.status_code == 404:
        print("❌ 404 — endpoint 미지원 (region/플랜)")
        sys.exit(0)

    if r.status_code != 200:
        print(f"❌ 예상치 못한 status {r.status_code}")
        print(json.dumps(body, indent=2, ensure_ascii=False)[:1500])
        sys.exit(1)

    ids = body.get("resources", [])
    total = body.get("meta", {}).get("pagination", {}).get("total")
    print(f"      → application ID {len(ids)}건 (테넌트 전체 total={total})")

    if not ids:
        print()
        print("⚠️  ID 0건 — 권한은 있지만 데이터가 비어 있음 (수집 대상 없음)")
        sys.exit(0)

    # ── 2) Application 상세 ──────────────────────────────────────────
    print("[3/3] GET /discover/entities/applications/v1 (ids 배치)")
    with httpx.Client(timeout=60) as c:
        r2 = c.get(
            f"{base}/discover/entities/applications/v1",
            headers=headers,
            params=[("ids", i) for i in ids],
        )

    print(f"      status: {r2.status_code}")
    if r2.status_code != 200:
        print(json.dumps(r2.json(), indent=2, ensure_ascii=False)[:1500])
        sys.exit(1)

    resources = r2.json().get("resources", [])
    print(f"      → 상세 {len(resources)}건")
    print()

    print("✅ Falcon Discover Applications API 호출 성공")
    print()
    print("─ 샘플 application[0] ─" + "─" * 40)
    print(json.dumps(resources[0], indent=2, ensure_ascii=False))
    print()

    # 핵심 필드만 추출해서 짧은 요약 테이블
    print("─ 상위 10개 요약 ─" + "─" * 50)
    print(f"{'name':40s} {'vendor':25s} {'version':20s}")
    for a in resources[:10]:
        print(
            f"{(a.get('name') or '')[:40]:40s} "
            f"{(a.get('vendor') or '')[:25]:25s} "
            f"{(a.get('version') or '')[:20]:20s}"
        )


if __name__ == "__main__":
    main()
