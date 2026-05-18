"""CrowdStrike Spotlight API (CVE 취약점) 조회 테스트.

사용법:
    export CS_CLIENT_ID="..."
    export CS_CLIENT_SECRET="..."
    export CS_BASE_URL="https://api.us-2.crowdstrike.com"
    python scripts/test_spotlight_live.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from falconpy import SpotlightVulnerabilities, ZeroTrustAssessment, Hosts


def test_spotlight(client_id, client_secret, base_url):
    """Spotlight API — CVE 취약점 조회."""
    print("=" * 60)
    print("[Spotlight API] CVE 취약점 조회")
    print("=" * 60)

    spotlight = SpotlightVulnerabilities(client_id=client_id, client_secret=client_secret, base_url=base_url)

    # open 상태 취약점 조회 (최대 10건 샘플)
    response = spotlight.query_vulnerabilities(
        filter="status:'open'",
        limit=10,
    )

    status_code = response.get("status_code", 0)
    body = response.get("body", {})

    if status_code == 403:
        print("  [FAIL] 권한 없음 (403) -- Spotlight API 접근 권한이 필요합니다.")
        print(f"     errors: {body.get('errors', [])}")
        return False

    if status_code != 200:
        print(f"  [FAIL] 오류 (HTTP {status_code}): {body.get('errors', [])}")
        return False

    vuln_ids = body.get("resources", [])
    total = body.get("meta", {}).get("pagination", {}).get("total", 0)
    print(f"  [OK] 접근 성공! 전체 open 취약점: {total}건")

    if not vuln_ids:
        print("  → 취약점 없음")
        return True

    # 상세 조회 (combined)
    print(f"\n  상세 조회 중 (샘플 {min(5, len(vuln_ids))}건)...")
    detail_resp = spotlight.get_vulnerabilities(ids=vuln_ids[:5])
    detail_body = detail_resp.get("body", {})

    for vuln in detail_body.get("resources", []):
        cve = vuln.get("cve", {})
        host = vuln.get("host_info", {})
        app = vuln.get("app", {})

        print(f"\n  [{cve.get('id', 'N/A')}]")
        print(f"    심각도:    {cve.get('base_score', 'N/A')} ({cve.get('severity', 'N/A')})")
        print(f"    설명:      {(cve.get('description', 'N/A') or 'N/A')[:80]}")
        print(f"    호스트:    {host.get('hostname', 'N/A')}")
        print(f"    소프트웨어: {app.get('product_name_version', 'N/A')}")
        print(f"    상태:      {vuln.get('status', 'N/A')}")
        print(f"    발견일:    {vuln.get('created_timestamp', 'N/A')}")

    return True


def test_zta(client_id, client_secret, base_url):
    """Zero Trust Assessment API — 보안 평가 점수 조회."""
    print("\n" + "=" * 60)
    print("[ZTA API] Zero Trust 보안 평가 점수 조회")
    print("=" * 60)

    # 먼저 호스트 ID를 가져온다
    hosts = Hosts(client_id=client_id, client_secret=client_secret, base_url=base_url)
    host_resp = hosts.query_devices_by_filter_scroll(limit=5)
    host_ids = host_resp.get("body", {}).get("resources", [])

    if not host_ids:
        print("  호스트 없음, 스킵")
        return False

    zta = ZeroTrustAssessment(client_id=client_id, client_secret=client_secret, base_url=base_url)
    response = zta.getAssessmentV1(ids=host_ids)

    status_code = response.get("status_code", 0)
    body = response.get("body", {})

    if status_code == 403:
        print("  [FAIL] 권한 없음 (403) -- ZTA API 접근 권한이 필요합니다.")
        print(f"     errors: {body.get('errors', [])}")
        return False

    if status_code != 200:
        print(f"  [FAIL] 오류 (HTTP {status_code}): {body.get('errors', [])}")
        return False

    resources = body.get("resources", [])
    print(f"  [OK] 접근 성공! {len(resources)}건 조회")

    for assess in resources:
        print(f"\n  [aid: {assess.get('aid', 'N/A')[:16]}...]")
        print(f"    종합 점수:    {assess.get('overall', 'N/A')}")
        print(f"    OS 점수:      {assess.get('os', 'N/A')}")
        print(f"    센서 점수:    {assess.get('sensor_config', 'N/A')}")

    return True


def main():
    client_id = os.environ.get("CS_CLIENT_ID")
    client_secret = os.environ.get("CS_CLIENT_SECRET")
    base_url = os.environ.get("CS_BASE_URL", "https://api.us-2.crowdstrike.com")

    if not client_id or not client_secret:
        print("ERROR: CS_CLIENT_ID, CS_CLIENT_SECRET 환경변수를 설정하세요.")
        sys.exit(1)

    results = {}
    results["Spotlight (CVE)"] = test_spotlight(client_id, client_secret, base_url)
    results["ZTA (보안점수)"] = test_zta(client_id, client_secret, base_url)

    print("\n" + "=" * 60)
    print("API 접근 권한 요약")
    print("=" * 60)
    for api, ok in results.items():
        status = "[OK] 사용 가능" if ok else "[FAIL] 권한 필요"
        print(f"  {api}: {status}")


if __name__ == "__main__":
    main()
