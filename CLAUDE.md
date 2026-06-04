# 프로젝트: CMDB 자산 수집 멀티 에이전트

## 기술 스택
- Python 3.12
- crowdstrike-falconpy (CrowdStrike Falcon API SDK)
- pydantic v2 (데이터 모델)
- httpx (HTTP 클라이언트)
- boto3 (AWS SDK — Secrets Manager)
- AWS Lambda (Docker 컨테이너 이미지)
- AWS SAM (IaC)

## 아키텍처 규칙
- CRITICAL: 모든 에이전트는 `src/agents/{agent_name}/` 하위에 독립적으로 구현한다. 에이전트 간 직접 import 금지.
- CRITICAL: **자산(asset) 수집**(`aws`, `crowdstrike`)은 결과를 **S3 raw 버킷(`ASSET_RAW_BUCKET`)에 JSONL.gz 로 적재**한다 (`src/shared/s3_client.py`의 `put_assets`). `asset_parser` 가 `s3:ObjectCreated` 로 받아 `tb_asset` 에 UPSERT(`src/shared/db.py` 직접 접근). 수집 → S3 → 파서 → DB 구조 — **수집기가 백엔드 API/DB 를 직접 호출하지 않는다** (Phase 2; 이전 Phase 0 의 `POST /api/cmdb/assets/bulk` 직행은 폐기). S3 가 환경 간 원천이라 prod→dev 이관은 버킷 스냅샷 복사 + dev 파서 재실행으로 처리. 그 외 외부 피드/임베딩 등 자산이 아닌 데이터(`kev_collector`, `epss_collector`, `nvd_collector`, `crowdstrike_alerts`, `rag_embedder`)는 `src/shared/db.py`로 DB 직접 접근.
- CRITICAL: CrowdStrike API 자격 증명은 반드시 AWS Secrets Manager에서 로드한다. 코드에 하드코딩 금지.
- 공통 코드는 `src/shared/`에 위치한다 (models, config, api_client, logging).
- 각 에이전트의 Lambda 진입점은 `handler.py`의 `lambda_handler(event, context)` 함수이다.
- Pydantic v2 모델로 데이터 검증을 수행한다. dict/tuple 대신 모델 객체를 사용한다.

## 개발 프로세스
- CRITICAL: 새 기능 구현 시 반드시 테스트를 먼저 작성하고, 테스트가 통과하는 구현을 작성할 것 (TDD)
- 커밋 메시지는 conventional commits 형식을 따를 것 (feat:, fix:, docs:, refactor:)

## 명령어
```bash
pip install -e ".[dev]"          # 개발 의존성 설치
python -m pytest src/tests/      # 테스트 실행
ruff check src/                  # 린트
ruff format src/                 # 포맷팅
mypy src/                        # 타입 체크 (strict 모드)
sam validate                     # SAM 템플릿 검증
sam build                        # SAM 빌드
sam local invoke                 # 로컬 Lambda 실행
sam deploy                       # AWS 배포 (samconfig.toml 사용)
```

## 에이전트

모든 에이전트는 `src/agents/{name}/handler.py`의 `lambda_handler(event, context)`를 진입점으로 한다.

| 에이전트 | 역할 | 데이터 흐름 |
|---|---|---|
| `aws` | EC2 인스턴스 수집 | boto3 → S3 raw (JSONL.gz) → `asset_parser` |
| `crowdstrike` | CrowdStrike Hosts API 디바이스 수집 | falconpy → S3 raw (JSONL.gz) → `asset_parser` |
| `asset_parser` | S3 raw CommonAsset 적재 (S3 트리거) | S3 `s3:ObjectCreated` → `tb_asset` UPSERT, 실패 시 `failed/` 격리 |
| `crowdstrike_alerts` | CrowdStrike Alerts v2 수집 (15분 주기) | falconpy → `tb_cs_alert` 직접 upsert + 자산 매칭 |
| `kev_collector` | CISA KEV 카탈로그 수집 | httpx → `tb_kev_catalog` 직접 upsert |
| `epss_collector` | FIRST EPSS 점수 수집 | httpx CSV → DB 직접 upsert |
| `nvd_collector` | NVD CVE 수집 (days_back 옵션) | NVD API → DB 직접 upsert |
| `mitre_cwe_collector` | MITRE CWE 약점 사전 수집 (분기 1회) | cwec_latest.xml.zip → `tb_cwe_dictionary` |
| `exploit_signal_collector` | Exploit-DB + Metasploit 신호 수집 (rate 15min, Pre-EPSS 선행) | CSV + JSON → `tb_exploit_signal` |
| `kisa_collector` | KISA 보안공지 RSS 수집 (일 1회, Trivy 미커버 한국 advisory) | RSS → `tb_vendor_advisory` |
| `psirt_collector` | 네트워크 장비 PSIRT 4벤더 통합 (Cisco openVuln + F5/PA/Forti RSS) | API + RSS → `tb_vendor_advisory` (PSIRT_*) |
| `trivy_scan` | ★ Trivy 매칭 엔진 (NEVRA/purl 통합) — Docker 컨테이너 + Trivy 바이너리 번들 | tb_asset_software → CycloneDX SBOM → `trivy sbom` → `tb_asset_vulnerability` |
| `vex_collector` | Red Hat CSAF VEX + OpenVEX 수집 (주 1회) — Trivy FP 자동 dismiss 입력 | CSAF JSON → `tb_vex` |
| `rag_embedder` | CMDB 데이터 Bedrock 임베딩 | Bedrock Cohere v4 → pgvector |
