"""PSIRT 벤더 레지스트리 — 벤더별 fetch+parse 스펙을 한 곳에서 선언.

handler 가 enabled 스펙을 순회하며 collect() 호출 → 한 벤더 실패해도 skip.
새 벤더 추가/활성화 = 이 파일에 VendorSpec 1개 (+ 필요 시 feeds 파서) 추가만 하면 된다.
이 레지스트리가 곧 PSIRT 벤더 커버리지 맵(현황 = enabled/note).

명명: vendor_source = PSIRT_<VENDOR> (tb_vendor_advisory.vendor_source, VARCHAR(30)).

★ 공개(B) 신규 벤더 실측(2026-06): 요청서의 "B.공개"는 "사람이 열람 가능"이지
  "기계 수집 가능 피드"가 아님이 확인됨. Aruba 403 봇차단, Citrix/Broadcom/Infoblox
  JS SPA(RSS·CSAF 부재), Proofpoint 일반 RSS만. → 해당 벤더는 enabled=False + note.
  (이들 CVE는 NVD+CPE(Tier 1/3)로 일부 커버됨. 활성화하려면 벤더별 내부 JSON API
   역설계 또는 내부 제공 피드 URL 필요.)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Any

from src.agents.psirt_collector.collector import (
    F5_PSIRT_RSS_URL,
    FORTINET_PSIRT_URL,
    PALOALTO_RSS_URL,
    PsirtAdvisory,
    fetch_cisco_advisories,
    fetch_fortinet_html,
    fetch_psirt_rss,
    parse_cisco_advisories,
    parse_fortinet_html,
    parse_psirt_rss,
)

logger = logging.getLogger("collect_cmdb")

# 신규 벤더 후보 엔드포인트 (활성화 시 실 URL 확정 필요)
ZDI_RSS_URL = "https://www.zerodayinitiative.com/rss/published/"


@dataclass(frozen=True)
class VendorSpec:
    """벤더 1개의 수집 명세. enabled=False 면 handler 가 건너뜀(fetch/parse 미호출)."""

    source: str                                              # PSIRT_CISCO / PSIRT_ARUBA ...
    label: str                                               # 표시용
    fetch: Callable[[], Any] | None = None                   # raw(str/json) 반환
    parse: Callable[[Any], list[PsirtAdvisory]] | None = None  # raw → advisory 리스트
    account: bool = False                                    # 계정/토큰 필요 여부 (요청서 발급 대기)
    enabled: bool = True
    note: str = ""                                           # 비활성/특이사항 사유


def _rss(source: str, label: str, url: str, id_prefix: str, **kw: Any) -> VendorSpec:
    return VendorSpec(
        source=source,
        label=label,
        fetch=partial(fetch_psirt_rss, url),
        parse=partial(parse_psirt_rss, vendor_source=source, id_prefix=id_prefix),
        **kw,
    )


# ── 레지스트리 ──────────────────────────────────────────────────────────
VENDORS: list[VendorSpec] = [
    # ── 활성 (기존 4벤더, 동작 동일) ──
    VendorSpec(
        "PSIRT_CISCO", "Cisco openVuln",
        fetch=fetch_cisco_advisories, parse=parse_cisco_advisories,
        account=True, note="openVuln OAuth — CISCO_PSIRT_TOKEN 미설정 시 skip",
    ),
    _rss("PSIRT_F5", "F5 K-articles", F5_PSIRT_RSS_URL, "K",
         account=True, note="support.f5.com RSS=HTML(로그인) — my.f5.com 토큰 필요"),
    _rss("PSIRT_PA", "Palo Alto", PALOALTO_RSS_URL, "PAN-SA-"),
    VendorSpec(
        "PSIRT_FORTI", "Fortinet",
        fetch=partial(fetch_fortinet_html, FORTINET_PSIRT_URL), parse=parse_fortinet_html,
    ),

    # ── 비활성 (공개 신규 — 실측상 기계 수집 피드 부재, roadmap) ──
    _rss("PSIRT_ZDI", "ZDI (TippingPoint)", ZDI_RSS_URL, "ZDI-",
         enabled=False, note="RSS 정상이나 ZDI=범용 취약점 브로커 → TippingPoint 자산 매칭 부적합. 제품 필터 설계 후 활성"),
    VendorSpec("PSIRT_CITRIX", "Citrix", enabled=False,
               note="JS SPA — RSS/CSAF 부재. 내부 JSON API 역설계 또는 피드 URL 필요"),
    VendorSpec("PSIRT_ARUBA", "Aruba/HPE", enabled=False,
               note="Aruba 봇차단(403), HPE CSAF 미발견. 피드 URL 확인 필요"),
    VendorSpec("PSIRT_BROADCOM", "Symantec/Broadcom", enabled=False,
               note="JS SPA, RSS 404. 피드 부재"),
    VendorSpec("PSIRT_INFOBLOX", "Infoblox", enabled=False,
               note="JS SPA. 피드 부재"),
    VendorSpec("PSIRT_PROOFPOINT", "Proofpoint", enabled=False,
               note="일반 사이트 RSS만(보안 advisory 아님), 대상 1대"),

    # ── 비활성 (계정 필요 신규 — 요청서 발급 대기, ROI 우선순위) ──
    VendorSpec("PSIRT_RUCKUS", "Ruckus/CommScope", account=True, enabled=False,
               note="★271대(최대). Support 포털 로그인 후 Advisory/RSS. 계정 발급 후 fetch/parse 구현"),
    VendorSpec("PSIRT_JUNIPER", "Juniper", account=True, enabled=False,
               note="SIRT API(Client ID/Secret, 시리얼 필수). 발급 후 fetch/parse 구현"),
]


def collect(spec: VendorSpec) -> list[PsirtAdvisory]:
    """단일 벤더 수집 — fetch+parse. 실패(인증·네트워크·포맷) 시 빈 리스트(skip)."""
    if spec.fetch is None or spec.parse is None:
        return []
    try:
        return spec.parse(spec.fetch())
    except Exception:
        logger.exception("%s PSIRT 실패 (skip)", spec.source)
        return []
