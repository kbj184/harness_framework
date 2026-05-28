"""Trivy 스캔 엔진 — SBOM 생성 + Trivy CLI 호출 + 결과 적재.

매번 Lambda 호출 시:
  1) tb_asset_software 에서 (asset_id_hash 또는 카테고리별) 패키지 목록 조회
  2) CycloneDX 1.5 SBOM 생성 (purl 있는 패키지만)
  3) subprocess.run(['trivy', 'sbom', ...]) 호출
  4) Trivy JSON 결과 파싱 → tb_asset_vulnerability INSERT
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("collect_cmdb")

DEFAULT_TRIVY_BIN = "trivy"                       # Dockerfile 에서 PATH 에 설치
DEFAULT_CACHE_DIR = "/tmp/trivy-cache"


# ───────────────────── DB 조회 ─────────────────────

QUERY_PACKAGES_SQL = """
SELECT
    asset_id_hash,
    name, version, release, epoch, arch,
    purl, ecosystem, distribution
FROM tb_asset_software
WHERE asset_id_hash = %(asset_id_hash)s
  AND purl IS NOT NULL
ORDER BY name, version;
"""


def query_asset_software(conn, asset_id_hash: str) -> list[dict[str, Any]]:
    """tb_asset_software 에서 자산의 패키지 목록 조회 (purl 있는 것만)."""
    with conn.cursor() as cur:
        cur.execute(QUERY_PACKAGES_SQL, {"asset_id_hash": asset_id_hash})
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


# distribution → CycloneDX OS metadata 매핑 (Trivy 가 인식하는 family 명)
# Trivy 지원 OS family 키: amazon / centos / rhel / oracle / fedora / alma / rocky /
#   debian / ubuntu / suse / alpine / photon / windows
DISTRIBUTION_TO_OS = {
    # Amazon Linux 2023
    "amzn2023": ("amazon", "2023"),
    "amazon2023": ("amazon", "2023"),
    "amzn2": ("amazon", "2"),
    "amazon2": ("amazon", "2"),
    # RHEL / CentOS / Rocky / Alma
    "rhel7": ("rhel", "7"), "rhel8": ("rhel", "8"), "rhel9": ("rhel", "9"),
    "el7": ("rhel", "7"), "el8": ("rhel", "8"), "el9": ("rhel", "9"),
    "centos7": ("centos", "7"), "centos8": ("centos", "8"),
    "rocky8": ("rocky", "8"), "rocky9": ("rocky", "9"),
    "alma8": ("alma", "8"), "alma9": ("alma", "9"),
    # Ubuntu / Debian
    "ubuntu20.04": ("ubuntu", "20.04"), "ubuntu22.04": ("ubuntu", "22.04"),
    "ubuntu24.04": ("ubuntu", "24.04"),
    "debian11": ("debian", "11"), "debian12": ("debian", "12"),
}


def _infer_os(packages: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """패키지 목록 첫 distribution 값으로 OS family/version 추정."""
    for pkg in packages:
        dist = (pkg.get("distribution") or "").strip().lower()
        if dist and dist in DISTRIBUTION_TO_OS:
            return DISTRIBUTION_TO_OS[dist]
        # purl 에서 추정 fallback — pkg:rpm/amzn/... → amazon
        purl = pkg.get("purl") or ""
        if "pkg:rpm/amzn/" in purl:
            return ("amazon", "2023")           # 기본값
    return (None, None)


# ───────────────────── SBOM 생성 (CycloneDX 1.5) ─────────────────────

def build_cyclonedx_sbom(packages: list[dict[str, Any]]) -> str:
    """패키지 목록 → CycloneDX 1.5 JSON 문자열.

    purl 없는 패키지는 Trivy 가 매칭 못 하므로 제외.
    Trivy 가 OS family 를 인식하도록 metadata.component 에 operating-system 추가.
    """
    os_family, os_version = _infer_os(packages)

    # purl namespace 정규화 (우리 transformer 의 약자 → Trivy 표준)
    # 예: pkg:rpm/amzn/...  → pkg:rpm/amazon/...
    purl_ns_map = {
        "amzn":  "amazon",
        "rhel":  "redhat",
        "el":    "redhat",
    }

    def _normalize_purl(p: str) -> str:
        if not p.startswith("pkg:rpm/"):
            return p
        # pkg:rpm/{ns}/{rest}
        try:
            _, _, after = p.partition("pkg:rpm/")
            ns, slash, rest = after.partition("/")
            if not slash:
                return p
            new_ns = purl_ns_map.get(ns, ns)
            return f"pkg:rpm/{new_ns}/{rest}"
        except Exception:
            return p

    components = []
    for pkg in packages:
        purl = pkg.get("purl")
        if not purl:
            continue
        purl = _normalize_purl(purl)
        components.append({
            "type": "library",
            "bom-ref": purl,
            "name": pkg.get("name", ""),
            "version": pkg.get("version", ""),
            "purl": purl,
        })

    metadata: dict[str, Any] = {"timestamp": "2026-05-28T00:00:00Z"}
    if os_family:
        # Trivy 가 인식하는 표준 패턴 — CycloneDX metadata.component = OS
        metadata["component"] = {
            "type": "operating-system",
            "name": os_family,
            "version": os_version or "unknown",
        }

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    return json.dumps(sbom, ensure_ascii=False)


# ───────────────────── Trivy CLI 호출 ─────────────────────

def run_trivy_sbom(
    sbom_path: str,
    db_cache_dir: str = DEFAULT_CACHE_DIR,
    trivy_bin: str = DEFAULT_TRIVY_BIN,
    timeout: int = 600,
) -> str:
    """trivy sbom 명령 실행. JSON 결과 문자열 반환.

    --skip-db-update 사용 — DB 는 별도 cron 으로 미리 받아둠.
    """
    cmd = [
        trivy_bin, "sbom",
        sbom_path,
        "--format", "json",
        "--skip-db-update",
        "--cache-dir", db_cache_dir,
        "--debug",
    ]
    logger.info("Trivy 실행: %s", " ".join(cmd))
    # SBOM 파일 첫 1500자 로그 (디버그용)
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom_preview = f.read(1500)
        logger.info("SBOM preview (1500 chars): %s", sbom_preview)
    except Exception:
        pass
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"trivy 실행 타임아웃 ({timeout}s)") from e

    # stderr 는 returncode 와 무관하게 항상 로깅 (Trivy 는 INFO 도 stderr 로 보냄)
    if proc.stderr:
        logger.info("Trivy stderr (%d bytes): %s", len(proc.stderr), proc.stderr[:2000])

    if proc.returncode != 0:
        raise RuntimeError(
            f"trivy 종료코드 {proc.returncode}, stderr: {proc.stderr[:500]}"
        )
    return proc.stdout


def diagnose_trivy(db_cache_dir: str = DEFAULT_CACHE_DIR) -> dict[str, Any]:
    """Trivy 환경 진단 — 버전 / 캐시 디렉터리 / DB 상태."""
    import os

    info: dict[str, Any] = {"cache_dir": db_cache_dir}

    # 1) trivy version
    try:
        proc = subprocess.run(
            ["trivy", "--version"], capture_output=True, text=True, timeout=30
        )
        info["version_stdout"] = proc.stdout
        info["version_stderr"] = proc.stderr
        info["version_rc"] = proc.returncode
    except Exception as e:
        info["version_err"] = str(e)

    # 2) cache_dir 내용
    try:
        if os.path.isdir(db_cache_dir):
            entries = []
            for root, dirs, files in os.walk(db_cache_dir):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        entries.append({"path": fp, "size": os.path.getsize(fp)})
                    except Exception:
                        entries.append({"path": fp, "size": "?"})
            info["cache_entries"] = entries[:50]
            info["cache_total_files"] = len(entries)
        else:
            info["cache_dir_exists"] = False
    except Exception as e:
        info["cache_err"] = str(e)

    # 3) /opt 디렉터리 권한
    try:
        info["opt_listing"] = os.listdir("/opt")
    except Exception as e:
        info["opt_err"] = str(e)

    # 4) trivy --download-db-only 직접 실행 (강제 다운로드)
    try:
        proc = subprocess.run(
            ["trivy", "--cache-dir", db_cache_dir, "image", "--download-db-only", "--debug"],
            capture_output=True, text=True, timeout=300
        )
        info["dl_rc"] = proc.returncode
        info["dl_stdout"] = proc.stdout[-1000:]
        info["dl_stderr"] = proc.stderr[-2000:]
    except Exception as e:
        info["dl_err"] = str(e)

    return info


def download_trivy_db(
    db_cache_dir: str = DEFAULT_CACHE_DIR,
    trivy_bin: str = DEFAULT_TRIVY_BIN,
    timeout: int = 600,
) -> None:
    """Trivy DB OCI 이미지 다운로드 (6시간마다 별도 cron 또는 첫 호출 시).

    --download-db-only — 스캔 없이 DB 만 갱신.
    """
    cmd = [trivy_bin, "--cache-dir", db_cache_dir, "image", "--download-db-only"]
    logger.info("Trivy DB 다운로드: %s", db_cache_dir)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"trivy DB 다운로드 실패: {proc.stderr[:500]}"
        )


# ───────────────────── 결과 파싱 ─────────────────────

def parse_trivy_result(result_json: str) -> list[dict[str, Any]]:
    """Trivy JSON 결과 → 취약점 dict 리스트.

    Results[].Vulnerabilities[] 평탄화. CVSS 는 nvd.V3Score 우선.
    """
    data = json.loads(result_json)
    rows: list[dict[str, Any]] = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = vuln.get("VulnerabilityID")
            if not cve_id:
                continue
            cvss = vuln.get("CVSS", {}) or {}
            nvd_score = (cvss.get("nvd") or {}).get("V3Score")
            purl = (vuln.get("PkgIdentifier") or {}).get("PURL")

            rows.append({
                "cve_id": cve_id,
                "matched_pkg": vuln.get("PkgName"),
                "matched_purl": purl,
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "severity": vuln.get("Severity"),
                "cvss_score": nvd_score,
                "vuln_status": vuln.get("Status"),         # fixed/affected/under_investigation
            })
    return rows


# ───────────────────── transform / upsert ─────────────────────

def transform_vulnerabilities(
    asset_id_hash: str, vulns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """파싱된 취약점 → tb_asset_vulnerability INSERT 입력."""
    rows: list[dict[str, Any]] = []
    for v in vulns:
        rows.append({
            "asset_id_hash": asset_id_hash,
            "cve_id": v["cve_id"],
            "match_type": "TRIVY",
            "matched_pkg": v.get("matched_pkg") or v.get("matched_purl"),
            "fixed_version": v.get("fixed_version"),
            "cvss_score": v.get("cvss_score"),
            "status": "OPEN",
        })
    return rows


UPSERT_SQL = """
INSERT INTO tb_asset_vulnerability (
    asset_id_hash, cve_id, match_type, matched_pkg,
    fixed_version, cvss_score, status,
    first_observed_at, last_observed_at
) VALUES (
    %(asset_id_hash)s, %(cve_id)s, %(match_type)s, %(matched_pkg)s,
    %(fixed_version)s, %(cvss_score)s, %(status)s,
    NOW(), NOW()
)
ON CONFLICT (asset_id_hash, cve_id, COALESCE(matched_pkg, '')) DO UPDATE SET
    match_type       = EXCLUDED.match_type,
    fixed_version    = EXCLUDED.fixed_version,
    cvss_score       = COALESCE(EXCLUDED.cvss_score, tb_asset_vulnerability.cvss_score),
    last_observed_at = NOW()
"""


def upsert_vulnerability_rows(conn, rows: list[dict[str, Any]]) -> int:
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count


# ───────────────────── 통합 entry (handler 가 호출) ─────────────────────

def scan_asset(conn, asset_id_hash: str, *, db_cache_dir: str = DEFAULT_CACHE_DIR) -> dict[str, int]:
    """단일 자산 스캔 — DB 조회 → SBOM → Trivy → 결과 적재. 통계 dict 반환."""
    packages = query_asset_software(conn, asset_id_hash)
    if not packages:
        return {"packages": 0, "vulns": 0, "upserted": 0}

    sbom_str = build_cyclonedx_sbom(packages)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        f.write(sbom_str)
        sbom_path = f.name

    try:
        result_json = run_trivy_sbom(sbom_path, db_cache_dir=db_cache_dir)
        vulns = parse_trivy_result(result_json)
        rows = transform_vulnerabilities(asset_id_hash, vulns)
        upserted = upsert_vulnerability_rows(conn, rows)
        conn.commit()
    finally:
        Path(sbom_path).unlink(missing_ok=True)

    return {"packages": len(packages), "vulns": len(vulns), "upserted": upserted}
