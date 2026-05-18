# 아키텍처

## 디렉토리 구조
```
src/
├── shared/                       # 에이전트 공통 코드
│   ├── config.py                 # 환경변수 + Secrets Manager 설정 로더
│   ├── models.py                 # CommonAsset, AssetSource Pydantic v2 모델
│   ├── api_client.py             # Spring Boot bulk API HTTP 클라이언트
│   └── logging_config.py         # CloudWatch용 구조화 JSON 로깅
├── agents/
│   └── crowdstrike/              # CrowdStrike Hosts API 수집 에이전트
│       ├── handler.py            # Lambda 진입점 (lambda_handler)
│       ├── collector.py          # Falcon API 호출 (디바이스 조회)
│       ├── transformer.py        # CrowdStrike → CommonAsset 변환
│       ├── models.py             # CrowdStrike 전용 Pydantic 모델
│       └── Dockerfile            # Lambda 컨테이너 이미지
└── tests/                        # 단위 테스트
```

## 데이터 흐름
```
EventBridge Schedule (1시간)
    → Lambda (Docker 컨테이너)
        → CrowdStrike Falcon Hosts API (OAuth2)
            → 디바이스 ID 스크롤 조회 (query_devices_by_filter_scroll)
            → 상세 정보 배치 조회 (get_device_details_v2, 5000건/요청)
        → CommonAsset 변환 (transformer)
        → Spring Boot API 전송 (POST /api/cmdb/assets/bulk, 500건 배치)
            → PostgreSQL upsert (ON CONFLICT DO UPDATE)
```

## 패턴
- **에이전트 패턴**: 각 수집 소스(CrowdStrike, AD 등)는 독립된 Lambda 함수로 배포. 에이전트 간 직접 의존 없음.
- **공통 스키마**: 모든 에이전트는 CommonAsset 모델로 데이터를 정규화하여 백엔드에 전송.
- **Secrets Manager**: API 자격 증명은 런타임에 Secrets Manager에서 로드. 환경변수 fallback 지원 (로컬 테스트용).
- **재시도**: API 호출 실패 시 exponential backoff (3회 재시도).

## 인프라
- AWS Lambda (Docker 컨테이너 이미지, Python 3.12 base)
- AWS EventBridge Scheduler (cron 트리거)
- AWS Secrets Manager (API 자격 증명)
- AWS SAM (IaC)
- ECR (컨테이너 이미지 저장소)
