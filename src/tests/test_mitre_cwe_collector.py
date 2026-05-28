"""MITRE CWE Collector 단위 테스트 (TDD)."""

from __future__ import annotations

from unittest.mock import MagicMock

from src.agents.mitre_cwe_collector.collector import (
    parse_cwe_xml,
    transform_cwe,
    upsert_cwe_rows,
)


# MITRE CWE XML 샘플 (실제 cwec_latest.xml 구조 축약, 기본 namespace 포함)
SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.16" Date="2026-05-01">
  <Weaknesses>
    <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
              Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product does not neutralize or incorrectly neutralizes user-controllable input.</Description>
      <Extended_Description>...</Extended_Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000" Ordinal="Primary"/>
      </Related_Weaknesses>
      <Potential_Mitigations>
        <Mitigation>
          <Phase>Architecture and Design</Phase>
          <Strategy>Input Validation</Strategy>
          <Description>Use a vetted library or framework.</Description>
        </Mitigation>
        <Mitigation>
          <Phase>Implementation</Phase>
          <Description>Properly encode output.</Description>
        </Mitigation>
      </Potential_Mitigations>
    </Weakness>
    <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
              Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product constructs all or part of an SQL command...</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000"/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID="20" Name="Improper Input Validation"
              Abstraction="Class" Structure="Simple" Status="Stable">
      <Description>The product receives input...</Description>
    </Weakness>
    <Weakness ID="999" Name="Deprecated"
              Abstraction="Base" Structure="Simple" Status="Deprecated">
      <Description>Deprecated weakness.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


class TestParseCweXml:
    def test_extracts_all_weaknesses(self):
        items = parse_cwe_xml(SAMPLE_XML.encode("utf-8"))
        assert len(items) == 4

    def test_fields_populated(self):
        items = parse_cwe_xml(SAMPLE_XML.encode("utf-8"))
        xss = next(w for w in items if w.cwe_id == "CWE-79")
        assert "Cross-site Scripting" in xss.name_en
        assert xss.abstraction == "Base"
        assert xss.status == "Stable"
        assert xss.parent_cwe == "CWE-74"
        assert "neutralize" in xss.description.lower()

    def test_parent_cwe_optional(self):
        items = parse_cwe_xml(SAMPLE_XML.encode("utf-8"))
        cwe20 = next(w for w in items if w.cwe_id == "CWE-20")
        assert cwe20.parent_cwe is None  # No Related_Weaknesses

    def test_mitigations_collected(self):
        items = parse_cwe_xml(SAMPLE_XML.encode("utf-8"))
        xss = next(w for w in items if w.cwe_id == "CWE-79")
        assert len(xss.mitigations) == 2
        assert xss.mitigations[0]["phase"] == "Architecture and Design"
        assert xss.mitigations[0]["strategy"] == "Input Validation"
        assert "vetted library" in xss.mitigations[0]["description"]


class TestTransformCwe:
    def test_to_db_rows(self):
        items = parse_cwe_xml(SAMPLE_XML.encode("utf-8"))
        rows = transform_cwe(items)
        assert len(rows) == 4
        xss = next(r for r in rows if r["cwe_id"] == "CWE-79")
        assert xss["name_en"]
        assert xss["abstraction"] == "Base"
        assert xss["parent_cwe"] == "CWE-74"
        # mitigations 는 JSON 직렬화된 문자열 또는 list (psycopg2 가 처리)
        assert xss["mitigations"]  # not empty

    def test_skip_deprecated(self):
        """status=Deprecated 는 옵션 — 일단 포함하되 deprecated 마킹."""
        items = parse_cwe_xml(SAMPLE_XML.encode("utf-8"))
        rows = transform_cwe(items)
        ids = [r["cwe_id"] for r in rows]
        assert "CWE-999" in ids  # 포함 (deprecated 컬럼으로 표시)


class TestUpsertCweRows:
    def test_batch_calls(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        items = parse_cwe_xml(SAMPLE_XML.encode("utf-8"))
        rows = transform_cwe(items)
        count = upsert_cwe_rows(conn, rows)
        assert count == 4
        assert cursor.execute.call_count == 4
