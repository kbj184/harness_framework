"""sbom_ingest transformer 단위 테스트.

실제 target-a.json (Amazon Linux 2023, 489 패키지) 으로 동작 검증.
"""

from __future__ import annotations

import json
import os

import pytest

from src.agents.sbom_ingest.transformer import transform, _build_purl, _ecosystem_of, _purl_namespace


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE_FILE = os.path.join(REPO_ROOT, "..", "kbjdocs", "origin", "target-a.json")


class TestPurlBuilder:
    def test_rpm_basic(self):
        p = _build_purl("rpm", "amzn", "openssl", "3.5.5", "1.amzn2023.0.3", None, "x86_64")
        assert p == "pkg:rpm/amzn/openssl@3.5.5-1.amzn2023.0.3?arch=x86_64"

    def test_rpm_with_epoch(self):
        p = _build_purl("rpm", "amzn", "openssl", "3.5.5", "1.amzn2023", "1", "x86_64")
        assert "epoch=1" in p
        assert "arch=x86_64" in p

    def test_rpm_no_release(self):
        p = _build_purl("rpm", "amzn", "attr", "2.5.1", None, None, "x86_64")
        assert p == "pkg:rpm/amzn/attr@2.5.1?arch=x86_64"

    def test_deb_basic(self):
        p = _build_purl("deb", "ubuntu", "openssh-server", "8.9p1-3ubuntu0.4", None, None, "amd64")
        assert p == "pkg:deb/ubuntu/openssh-server@8.9p1-3ubuntu0.4?arch=amd64"


class TestEcosystem:
    def test_rpm_from_source(self):
        assert _ecosystem_of("rpm", None) == "rpm"

    def test_rpm_from_dnf(self):
        assert _ecosystem_of(None, "dnf") == "rpm"

    def test_deb_from_apt(self):
        assert _ecosystem_of(None, "apt") == "deb"

    def test_dpkg(self):
        assert _ecosystem_of("dpkg", None) == "deb"


class TestNamespace:
    def test_amazon(self):
        assert _purl_namespace("Amazon") == "amzn"

    def test_rhel(self):
        assert _purl_namespace("RedHat") == "rhel"

    def test_ubuntu(self):
        assert _purl_namespace("Ubuntu") == "ubuntu"


class TestTransformSynthetic:
    def test_basic_rpm(self):
        sbom_json = {
            "hostname": "test-host",
            "fqdn": "test-host.example.com",
            "distribution": "Amazon",
            "distribution_version": "2023",
            "package_manager": "dnf",
            "collected_at": "2026-05-26T06:29:36Z",
            "packages": {
                "openssl": [{
                    "arch": "x86_64",
                    "epoch": None,
                    "name": "openssl",
                    "release": "1.amzn2023.0.3",
                    "source": "rpm",
                    "version": "3.5.5",
                }],
            },
        }
        sbom, rows = transform(sbom_json, sbom_doc_id="s3://bucket/test.json")
        assert sbom.hostname == "test-host"
        assert len(rows) == 1
        r = rows[0]
        assert r["source"] == "ANSIBLE_RPM"
        assert r["ecosystem"] == "rpm"
        assert r["name"] == "openssl"
        assert r["version"] == "3.5.5"
        assert r["release"] == "1.amzn2023.0.3"
        assert r["arch"] == "x86_64"
        assert r["distribution"] == "amzn2023"
        assert r["host_hostname"] == "test-host"
        assert r["sbom_doc_id"] == "s3://bucket/test.json"
        assert r["purl"] == "pkg:rpm/amzn/openssl@3.5.5-1.amzn2023.0.3?arch=x86_64"

    def test_dpkg(self):
        sbom_json = {
            "hostname": "ubuntu-host",
            "distribution": "Ubuntu",
            "distribution_version": "22.04",
            "package_manager": "apt",
            "packages": {
                "openssh-server": [{
                    "arch": "amd64",
                    "name": "openssh-server",
                    "source": "apt",
                    "version": "8.9p1-3ubuntu0.4",
                }],
            },
        }
        _, rows = transform(sbom_json)
        assert rows[0]["source"] == "ANSIBLE_DPKG"
        assert rows[0]["ecosystem"] == "deb"
        assert rows[0]["distribution"] == "ubuntu2204"

    def test_empty_packages(self):
        sbom_json = {"hostname": "empty", "packages": {}}
        _, rows = transform(sbom_json)
        assert rows == []

    def test_multiple_versions_same_name(self):
        sbom_json = {
            "hostname": "h",
            "distribution": "Amazon",
            "distribution_version": "2023",
            "package_manager": "dnf",
            "packages": {
                "kernel": [
                    {"name": "kernel", "version": "6.1.170", "release": "213.amzn2023", "arch": "x86_64", "source": "rpm"},
                    {"name": "kernel", "version": "6.1.180", "release": "230.amzn2023", "arch": "x86_64", "source": "rpm"},
                ],
            },
        }
        _, rows = transform(sbom_json)
        assert len(rows) == 2  # 다른 버전 별도 행


@pytest.mark.skipif(not os.path.exists(SAMPLE_FILE), reason="target-a.json 없음 (외부 의존)")
class TestTransformRealTargetA:
    """실제 target-a.json (489 패키지) 사용한 통합 검증."""

    def _load(self):
        with open(SAMPLE_FILE, encoding="utf-8") as f:
            return json.load(f)

    def test_row_count_matches_packages(self):
        sbom_json = self._load()
        _, rows = transform(sbom_json)
        assert len(rows) == 489

    def test_all_rows_have_required_fields(self):
        sbom_json = self._load()
        _, rows = transform(sbom_json)
        for r in rows:
            assert r["source"] == "ANSIBLE_RPM"
            assert r["ecosystem"] == "rpm"
            assert r["distribution"] == "amzn2023"
            assert r["name"]
            assert r["purl"]

    def test_sample_attr_package(self):
        sbom_json = self._load()
        _, rows = transform(sbom_json)
        attr = next(r for r in rows if r["name"] == "attr")
        assert attr["version"] == "2.5.1"
        assert attr["release"] == "3.amzn2023.0.2"
        assert attr["arch"] == "x86_64"
        assert attr["purl"] == "pkg:rpm/amzn/attr@2.5.1-3.amzn2023.0.2?arch=x86_64"


class TestUpsertSql:
    def test_sql_has_required_columns(self):
        from src.agents.sbom_ingest.collector import UPSERT_SQL
        for col in ["asset_id_hash", "source", "ecosystem", "purl", "release", "epoch", "arch",
                    "host_hostname", "sbom_doc_id", "raw_data"]:
            assert col in UPSERT_SQL

    def test_delete_prev_sql_targets_ansible_only(self):
        from src.agents.sbom_ingest.collector import DELETE_PREV_SQL
        assert "ANSIBLE_RPM" in DELETE_PREV_SQL
        assert "ANSIBLE_DPKG" in DELETE_PREV_SQL
        assert "CROWDSTRIKE" not in DELETE_PREV_SQL

    def test_match_sql_uses_hostname(self):
        from src.agents.sbom_ingest.collector import MATCH_SQL_HOSTNAME
        assert "host_hostname" in MATCH_SQL_HOSTNAME
        assert "ANSIBLE_" in MATCH_SQL_HOSTNAME
