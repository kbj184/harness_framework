"""NVD Collector 단위 테스트."""

from __future__ import annotations

from unittest.mock import MagicMock

from src.agents.nvd_collector.collector import (
    _fmt_dt,
    _get_cvss_v3,
    parse_cve,
    split_cpe,
    upsert_cves,
)


def test_fmt_dt():
    from datetime import UTC, datetime
    s = _fmt_dt(datetime(2024, 3, 15, 12, 30, 45, tzinfo=UTC))
    assert s == "2024-03-15T12:30:45.000"


def test_split_cpe_full():
    r = split_cpe("cpe:2.3:o:amazon:amazon_linux:2:*:*:*:*:*:*:*")
    assert r["part"] == "o"
    assert r["vendor"] == "amazon"
    assert r["product"] == "amazon_linux"
    assert r["version"] == "2"


def test_split_cpe_wildcards():
    r = split_cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")
    assert r["version"] is None


def test_split_cpe_invalid():
    r = split_cpe("invalid")
    assert r["vendor"] is None


def test_get_cvss_v3_prefer_31():
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}],
        "cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
    }
    score, severity, vec = _get_cvss_v3(metrics)
    assert score == 9.8
    assert severity == "CRITICAL"
    assert vec == "CVSS:3.1/AV:N"


def test_get_cvss_v3_fallback_30():
    metrics = {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}
    score, severity, _ = _get_cvss_v3(metrics)
    assert score == 7.5
    assert severity == "HIGH"


def test_get_cvss_v3_none():
    assert _get_cvss_v3({}) == (None, None, None)


SAMPLE_ENTRY = {
    "cve": {
        "id": "CVE-2024-1234",
        "published": "2024-03-15T12:00:00.000",
        "lastModified": "2024-03-16T08:00:00.000",
        "descriptions": [
            {"lang": "en", "value": "A sample vulnerability"},
            {"lang": "ko", "value": "샘플 취약점"},
        ],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionEndExcluding": "2.17.0",
                            },
                            {
                                "criteria": "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*",
                                "vulnerable": True,
                            },
                        ]
                    }
                ]
            }
        ],
    }
}


def test_parse_cve_meta():
    p = parse_cve(SAMPLE_ENTRY)
    assert p["meta"]["cve_id"] == "CVE-2024-1234"
    assert p["meta"]["description"] == "A sample vulnerability"
    assert p["meta"]["cvss_v3_score"] == 9.8
    assert p["meta"]["cvss_v3_severity"] == "CRITICAL"


def test_parse_cve_matches():
    p = parse_cve(SAMPLE_ENTRY)
    assert len(p["matches"]) == 2
    m1 = p["matches"][0]
    assert m1["cpe_uri"] == "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
    assert m1["version_end_excluding"] == "2.17.0"


def test_parse_cve_missing_id():
    assert parse_cve({"cve": {}}) == {}


def test_upsert_cves_counts():
    cur = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=None)
    conn = MagicMock()
    conn.cursor = MagicMock(return_value=cur)

    cve_n, cpe_n, match_n = upsert_cves(conn, [SAMPLE_ENTRY])
    assert cve_n == 1
    assert cpe_n == 2
    assert match_n == 2
    # execute 호출: 1 CVE + 2 CPE + 2 match = 5
    assert cur.execute.call_count == 5
