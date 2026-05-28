"""Trivy Scan 단위 테스트 (TDD).

Trivy 바이너리는 실제로 실행하지 않음 (subprocess mock).
SBOM 생성 / 결과 파싱 / DB upsert 로직만 검증.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from src.agents.trivy_scan.collector import (
    build_cyclonedx_sbom,
    parse_trivy_result,
    run_trivy_sbom,
    transform_vulnerabilities,
    upsert_vulnerability_rows,
)


# ───────────────────── 자산 SW 샘플 ─────────────────────

SAMPLE_PACKAGES = [
    {
        "name": "openssl-libs",
        "version": "3.5.5",
        "release": "1.amzn2023.0.3",
        "arch": "x86_64",
        "epoch": None,
        "purl": "pkg:rpm/amzn/openssl-libs@3.5.5-1.amzn2023.0.3?arch=x86_64",
        "ecosystem": "rpm",
    },
    {
        "name": "bind-libs",
        "version": "9.16.50",
        "release": "1.amzn2023.0.1",
        "arch": "x86_64",
        "epoch": None,
        "purl": "pkg:rpm/amzn/bind-libs@9.16.50-1.amzn2023.0.1?arch=x86_64",
        "ecosystem": "rpm",
    },
    {
        # purl 없는 패키지 — SBOM에서 제외돼야 함
        "name": "internal-tool",
        "version": "1.0",
        "purl": None,
        "ecosystem": None,
    },
]


class TestBuildCyclonedxSbom:
    def test_creates_valid_json(self):
        sbom_str = build_cyclonedx_sbom(SAMPLE_PACKAGES)
        sbom = json.loads(sbom_str)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"

    def test_components_from_packages_with_purl(self):
        sbom_str = build_cyclonedx_sbom(SAMPLE_PACKAGES)
        sbom = json.loads(sbom_str)
        # purl 있는 것 2개만 포함
        assert len(sbom["components"]) == 2

    def test_component_fields(self):
        sbom_str = build_cyclonedx_sbom(SAMPLE_PACKAGES)
        sbom = json.loads(sbom_str)
        openssl = next(c for c in sbom["components"] if c["name"] == "openssl-libs")
        assert openssl["type"] == "library"
        assert openssl["version"] == "3.5.5"
        assert openssl["purl"].startswith("pkg:rpm/amzn/openssl-libs@")


# ───────────────────── Trivy 결과 JSON 샘플 ─────────────────────

TRIVY_RESULT_JSON = {
    "SchemaVersion": 2,
    "ArtifactName": "/tmp/sbom.json",
    "ArtifactType": "cyclonedx",
    "Results": [
        {
            "Target": "/tmp/sbom.json",
            "Class": "lang-pkgs",
            "Type": "rpm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl-libs",
                    "PkgIdentifier": {
                        "PURL": "pkg:rpm/amzn/openssl-libs@3.5.5-1.amzn2023.0.3"
                    },
                    "InstalledVersion": "3.5.5-1.amzn2023.0.3",
                    "FixedVersion": "3.5.5-1.amzn2023.0.4",
                    "Status": "fixed",
                    "Severity": "HIGH",
                    "CVSS": {
                        "nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/..."}
                    },
                    "References": ["https://example.com/CVE-2024-1234"],
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "bind-libs",
                    "PkgIdentifier": {
                        "PURL": "pkg:rpm/amzn/bind-libs@9.16.50-1.amzn2023.0.1"
                    },
                    "InstalledVersion": "9.16.50-1.amzn2023.0.1",
                    "FixedVersion": "9.16.51-1.amzn2023.0.1",
                    "Severity": "CRITICAL",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
                {
                    # FixedVersion 없는 경우 (under investigation)
                    "VulnerabilityID": "CVE-2024-9999",
                    "PkgName": "openssl-libs",
                    "InstalledVersion": "3.5.5-1.amzn2023.0.3",
                    "Severity": "MEDIUM",
                },
            ],
        }
    ],
}


class TestParseTrivyResult:
    def test_extracts_all_vulnerabilities(self):
        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        assert len(vulns) == 3

    def test_cve_id(self):
        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        ids = sorted(v["cve_id"] for v in vulns)
        assert ids == ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"]

    def test_fields_populated(self):
        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        first = next(v for v in vulns if v["cve_id"] == "CVE-2024-1234")
        assert first["matched_pkg"] == "openssl-libs"
        assert first["fixed_version"] == "3.5.5-1.amzn2023.0.4"
        assert first["installed_version"] == "3.5.5-1.amzn2023.0.3"
        assert first["severity"] == "HIGH"
        assert first["cvss_score"] == 7.5

    def test_no_fixed_version_handled(self):
        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        nofix = next(v for v in vulns if v["cve_id"] == "CVE-2024-9999")
        assert nofix["fixed_version"] is None

    def test_empty_result(self):
        empty = {"Results": []}
        vulns = parse_trivy_result(json.dumps(empty))
        assert vulns == []


# ───────────────────── transform / upsert ─────────────────────

class TestTransformVulnerabilities:
    def test_adds_asset_id_hash(self):
        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        rows = transform_vulnerabilities("abc123", vulns)
        assert all(r["asset_id_hash"] == "abc123" for r in rows)

    def test_match_type_trivy(self):
        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        rows = transform_vulnerabilities("abc123", vulns)
        assert all(r["match_type"] == "TRIVY" for r in rows)

    def test_default_status(self):
        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        rows = transform_vulnerabilities("abc123", vulns)
        assert all(r["status"] == "OPEN" for r in rows)


class TestUpsertVulnerabilityRows:
    def test_batch_calls(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        vulns = parse_trivy_result(json.dumps(TRIVY_RESULT_JSON))
        rows = transform_vulnerabilities("abc123", vulns)
        count = upsert_vulnerability_rows(conn, rows)
        assert count == len(rows) == 3
        assert cursor.execute.call_count == 3


# ───────────────────── subprocess mock ─────────────────────

class TestRunTrivySbom:
    @patch("src.agents.trivy_scan.collector.subprocess.run")
    def test_returns_result_json(self, mock_run):
        # Mock trivy 출력 — 실제 파일 쓰기 대신 stdout으로 반환
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(TRIVY_RESULT_JSON),
            stderr="",
        )
        result = run_trivy_sbom("/tmp/sbom.json", db_cache_dir="/tmp/trivy-cache")
        assert "CVE-2024-1234" in result
        mock_run.assert_called_once()
        # trivy 명령 검증
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "trivy"
        assert "sbom" in cmd
        assert "/tmp/sbom.json" in cmd

    @patch("src.agents.trivy_scan.collector.subprocess.run")
    def test_nonzero_exit_raises(self, mock_run):
        import subprocess
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="trivy error")
        # nonzero exit → RuntimeError
        try:
            run_trivy_sbom("/tmp/sbom.json")
            assert False, "expected RuntimeError"
        except RuntimeError as e:
            assert "trivy" in str(e).lower()
