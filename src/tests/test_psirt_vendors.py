"""PSIRT 벤더 레지스트리 단위 테스트."""

from __future__ import annotations

from src.agents.psirt_collector.vendors import VENDORS, VendorSpec, collect


def test_existing_four_enabled():
    """기존 4벤더는 활성 상태로 유지된다."""
    enabled = {v.source for v in VENDORS if v.enabled}
    assert {"PSIRT_CISCO", "PSIRT_F5", "PSIRT_PA", "PSIRT_FORTI"} <= enabled


def test_disabled_vendors_have_note():
    """비활성 벤더는 사유(note)를 반드시 갖는다 (roadmap 추적용)."""
    for v in VENDORS:
        if not v.enabled:
            assert v.note, f"{v.source} 비활성인데 note 없음"


def test_vendor_source_naming():
    """모든 vendor_source 는 PSIRT_ 접두 + VARCHAR(30) 이내."""
    for v in VENDORS:
        assert v.source.startswith("PSIRT_")
        assert len(v.source) <= 30


def test_collect_skips_when_no_callable():
    """fetch/parse 미지정(비활성 roadmap) 스펙은 빈 리스트."""
    spec = VendorSpec("PSIRT_X", "x", fetch=None, parse=None, enabled=False)
    assert collect(spec) == []


def test_collect_swallows_fetch_error():
    """fetch 예외 시 skip(빈 리스트) — 한 벤더 실패가 전체를 막지 않는다."""
    def boom():
        raise RuntimeError("network down")

    spec = VendorSpec("PSIRT_X", "x", fetch=boom, parse=lambda raw: [])
    assert collect(spec) == []


def test_collect_returns_parsed():
    """정상 fetch+parse 경로."""
    sentinel = [object()]
    spec = VendorSpec("PSIRT_X", "x", fetch=lambda: "raw", parse=lambda raw: sentinel)
    assert collect(spec) is sentinel
