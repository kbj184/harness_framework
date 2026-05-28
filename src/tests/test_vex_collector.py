"""VEX Collector 단위 테스트 (TDD).

CSAF 2.0 VEX 문서 → tb_vex statement 리스트 추출 검증.
Trivy 매칭 결과 INSERT 직전 SVC_VULN 이 이 테이블 조회 → not_affected 자동 dismiss.
"""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

from src.agents.vex_collector.collector import (
    flatten_product_tree,
    parse_csaf_vex,
    transform_vex,
    upsert_vex_rows,
)


# ───────────────────── CSAF 2.0 VEX 샘플 (Red Hat 형식 모사) ─────────────────────

CSAF_VEX = {
    "document": {
        "category": "csaf_vex",
        "csaf_version": "2.0",
        "title": "Red Hat VEX — CVE-2024-1234",
        "tracking": {
            "id": "RHSA-2024-VEX-1234",
            "current_release_date": "2024-03-15T00:00:00+00:00",
        },
    },
    "product_tree": {
        "branches": [
            {
                "category": "vendor",
                "name": "Red Hat",
                "branches": [
                    {
                        "category": "product_name",
                        "name": "Red Hat Enterprise Linux 9",
                        "branches": [
                            {
                                "category": "product_version",
                                "name": "openssl-3.0.7-27.el9_4",
                                "product": {
                                    "name": "openssl",
                                    "product_id": "redhat:rhel-9:openssl-3.0.7-27.el9_4",
                                    "product_identification_helper": {
                                        "purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9_4?arch=x86_64",
                                    },
                                },
                            },
                            {
                                "category": "product_version",
                                "name": "openssl-libs-3.0.7-27.el9_4",
                                "product": {
                                    "name": "openssl-libs",
                                    "product_id": "redhat:rhel-9:openssl-libs-3.0.7-27.el9_4",
                                    "product_identification_helper": {
                                        "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9_4?arch=x86_64",
                                    },
                                },
                            },
                        ],
                    }
                ],
            }
        ]
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2024-1234",
            "product_status": {
                "known_not_affected": [
                    "redhat:rhel-9:openssl-3.0.7-27.el9_4",
                    "redhat:rhel-9:openssl-libs-3.0.7-27.el9_4",
                ],
                "fixed": [],
                "under_investigation": [],
            },
            "flags": [
                {
                    "label": "vulnerable_code_not_in_execute_path",
                    "product_ids": [
                        "redhat:rhel-9:openssl-3.0.7-27.el9_4",
                        "redhat:rhel-9:openssl-libs-3.0.7-27.el9_4",
                    ],
                }
            ],
            "threats": [
                {
                    "category": "impact",
                    "details": "Code present but not executed in default config.",
                }
            ],
            "remediations": [
                {
                    "category": "workaround",
                    "details": "Disable feature X.",
                }
            ],
        }
    ],
}


class TestFlattenProductTree:
    def test_extracts_product_id_to_purl(self):
        mapping = flatten_product_tree(CSAF_VEX.get("product_tree", {}))
        assert mapping["redhat:rhel-9:openssl-3.0.7-27.el9_4"]["purl"] == (
            "pkg:rpm/redhat/openssl@3.0.7-27.el9_4?arch=x86_64"
        )
        assert mapping["redhat:rhel-9:openssl-libs-3.0.7-27.el9_4"]["purl"] == (
            "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9_4?arch=x86_64"
        )

    def test_empty_tree(self):
        assert flatten_product_tree({}) == {}


class TestParseCsafVex:
    def test_extracts_all_statements(self):
        statements = parse_csaf_vex(CSAF_VEX)
        # 2 패키지 not_affected
        assert len(statements) == 2

    def test_cve_id(self):
        statements = parse_csaf_vex(CSAF_VEX)
        assert all(s.cve_id == "CVE-2024-1234" for s in statements)

    def test_status(self):
        statements = parse_csaf_vex(CSAF_VEX)
        assert all(s.status == "not_affected" for s in statements)

    def test_purl_resolved(self):
        statements = parse_csaf_vex(CSAF_VEX)
        purls = {s.product_purl for s in statements}
        assert "pkg:rpm/redhat/openssl@3.0.7-27.el9_4?arch=x86_64" in purls

    def test_justification(self):
        statements = parse_csaf_vex(CSAF_VEX)
        assert all(
            s.justification == "vulnerable_code_not_in_execute_path"
            for s in statements
        )

    def test_impact_statement(self):
        statements = parse_csaf_vex(CSAF_VEX)
        first = statements[0]
        assert "not executed" in first.impact_statement.lower()

    def test_published_at(self):
        statements = parse_csaf_vex(CSAF_VEX)
        first = statements[0]
        assert first.published_at == date(2024, 3, 15)


# ───────────────────── 다양한 status 케이스 ─────────────────────

CSAF_VEX_FIXED = {
    "document": {
        "category": "csaf_vex",
        "csaf_version": "2.0",
        "tracking": {"current_release_date": "2024-04-01T00:00:00+00:00"},
    },
    "product_tree": {
        "branches": [
            {
                "category": "product_version",
                "name": "bind-9.16.51",
                "product": {
                    "product_id": "bind-fixed",
                    "product_identification_helper": {
                        "purl": "pkg:rpm/redhat/bind@9.16.51",
                    },
                },
            }
        ]
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2024-5678",
            "product_status": {
                "known_not_affected": [],
                "fixed": ["bind-fixed"],
                "under_investigation": [],
                "known_affected": [],
            },
        }
    ],
}


class TestStatusVariations:
    def test_fixed_status(self):
        statements = parse_csaf_vex(CSAF_VEX_FIXED)
        assert len(statements) == 1
        assert statements[0].status == "fixed"
        assert statements[0].product_purl == "pkg:rpm/redhat/bind@9.16.51"


# ───────────────────── transform / upsert ─────────────────────

class TestTransformVex:
    def test_to_db_rows(self):
        statements = parse_csaf_vex(CSAF_VEX)
        rows = transform_vex(statements, vex_source="REDHAT_CSAF")
        assert len(rows) == 2
        assert all(r["vex_source"] == "REDHAT_CSAF" for r in rows)
        assert all(r["status"] == "not_affected" for r in rows)


class TestUpsertVexRows:
    def test_batch_calls(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        statements = parse_csaf_vex(CSAF_VEX)
        rows = transform_vex(statements, vex_source="REDHAT_CSAF")
        count = upsert_vex_rows(conn, rows)
        assert count == 2
        assert cursor.execute.call_count == 2
