"""정규화 함수 — hostname/IP/계정키/env_type (§8.6 D11, §9.4)."""

from __future__ import annotations

import re

_PAREN_DIGITS = re.compile(r"\((\d{5,})\)")
_ALL_DIGITS = re.compile(r"^\d{5,}$")


def clean(v) -> str:
    """셀 값 → trim + 개행 공백화."""
    if v is None:
        return ""
    return str(v).replace("\n", " ").strip()


def host_norm(v) -> str:
    """hostname 정규화 — 소문자 + trim (FQDN→short는 적재 단계에서)."""
    return clean(v).lower()


def ip_primary(v) -> tuple[str | None, list[str]]:
    """IP 셀 파싱 → (실IP, 전체 IP 목록).

    '121.50.17.84 VIP : 121.50.17.83', '10.56.21.32 10.56.21.31 (L4 VIP)',
    '165.244.243.42 VIP(165.244.243.41) DSR 구성' 등 혼재 → 첫 IP=primary,
    나머지(VIP/service)는 목록 보존. 'N/A'·'-'·'TBD'는 None.
    """
    text = clean(v)
    if not text or text.upper() in ("N/A", "-"):
        return None, []
    ips = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", text)
    if not ips:
        return None, []
    return ips[0], ips


def account_key(raw) -> str:
    """계정 식별자 → 'provider:정규화ID' (§8.6 D11).

    AWS 괄호숫자/맨숫자 → 12자리 zero-pad. 비-AWS는 provider:원문.
    """
    s = clean(raw)
    t = s.lower()
    if "toast" in t:
        return "NHN_TOAST:" + s
    if "kakao" in t:
        return "KAKAO:" + s
    if "nhn" in t:
        return "NHN_CLOUD:" + s
    m = _PAREN_DIGITS.search(s)
    if m:
        return "AWS:" + m.group(1).zfill(12)
    if _ALL_DIGITS.match(s):
        return "AWS:" + s.zfill(12)
    return ("UNKNOWN:" + s) if s else "UNKNOWN:"


def account_provider(account_key_str: str) -> str:
    """account_key → provider 코드."""
    return account_key_str.split(":", 1)[0] if account_key_str else "UNKNOWN"


_IDC_KW = ("하남", "강서", "천안", "센터", "타워", "idc", "전산")
_CLOUD_KW = ("리전", "region", "ap-northeast", "서울 리전", "서울리전")


def env_type(location, default: str) -> str:
    """위치 텍스트 → IDC/CLOUD/STORE/OA (§9.4). default는 시트 기본값."""
    t = clean(location).lower()
    if not t:
        return default
    if any(k in t for k in _CLOUD_KW):
        return "CLOUD"
    if any(k in t for k in _IDC_KW):
        return "IDC"
    return default


def isms_yn(v) -> str | None:
    """인증대상 (o/O/○/- ) → Y/N."""
    t = clean(v)
    if not t or t == "-":
        return "N"
    if t.lower() in ("o", "○", "ｏ") or t == "O":
        return "Y"
    return "Y" if t else "N"


def to_int(v) -> int | None:
    """CIA 등 정수 변환 (실패 시 None)."""
    t = clean(v)
    try:
        return int(float(t))
    except (ValueError, TypeError):
        return None
