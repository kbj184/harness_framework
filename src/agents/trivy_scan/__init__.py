"""Trivy 기반 CVE 매칭 엔진 (★ 핵심 매처).

tb_asset_software 스냅샷 → CycloneDX SBOM 변환 → Trivy CLI 호출 →
CVE 매칭 결과 → tb_asset_vulnerability INSERT.

내장 알고리즘 (Trivy DB가 흡수):
  - NEVRA + rpm_vercmp
  - sub-package 정규화 (bind-libs → bind)
  - 배포판별 분기 (Amazon/RHEL/Ubuntu/Alpine/SUSE 등)
  - purl 매칭 (npm/pypi/maven/go/rust)
  - NVD CPE / ALAS / RHSA / USN / MSRC / GHSA / OSV / KEV / EPSS 통합

→ 우리 5단계 cascade 직접 구현 불필요. Lambda 한 번 호출로 매칭 완료.
"""
