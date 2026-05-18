# Architecture Decision Records

## 철학
외부 자산 수집은 신뢰성과 확장성이 핵심. 에이전트 간 독립성을 유지하고, 장애가 전파되지 않도록 설계한다.

---

### ADR-001: Docker 컨테이너 Lambda 선택
**결정**: Lambda 함수를 Docker 컨테이너 이미지로 패키징
**이유**: crowdstrike-falconpy + httpx + pydantic 등 의존성이 Lambda zip 50MB 제한 초과. 팀이 이미 Docker 기반 배포 사용 중.
**트레이드오프**: cold start가 1-3초 늘어나지만, 스케줄 기반 실행이므로 무관.

### ADR-002: Spring Boot API 경유 데이터 저장
**결정**: Lambda에서 직접 DB 접근 대신 Spring Boot REST API를 통해 저장
**이유**: VPC 배치 불필요(NAT Gateway 비용 절감), 기존 인증/검증/upsert 로직 재사용, DB 접근을 백엔드에 중앙 집중.
**트레이드오프**: 백엔드 의존성 추가. 백엔드 장애 시 수집 실패 가능.

### ADR-003: AWS SAM 선택
**결정**: IaC 도구로 AWS SAM 사용
**이유**: Lambda + EventBridge에 최적화된 AWS 네이티브 도구. sam local invoke로 로컬 테스트 가능. CDK 대비 러닝커브 낮음.
**트레이드오프**: CloudFormation 기반이라 복잡한 인프라 구성 시 제약. 현재 규모에서는 충분.

### ADR-004: crowdstrike-falconpy SDK 사용
**결정**: CrowdStrike 공식 Python SDK 사용 (raw HTTP 대신)
**이유**: OAuth2 토큰 자동 갱신, 페이지네이션 헬퍼, Rate limit 처리 내장. 유지보수 부담 최소화.
**트레이드오프**: SDK 버전 업데이트에 따른 breaking change 가능성. 버전 고정으로 대응.

### ADR-005: API Key 인증 (기계 간 통신)
**결정**: Lambda → 백엔드 통신에 X-Api-Key 헤더 기반 인증 사용
**이유**: 사용자 JWT와 분리하여 기계 간 통신 전용 인증. Secrets Manager에서 관리.
**트레이드오프**: JWT보다 단순하지만 만료/갱신 메커니즘 없음. API Key 노출 시 교체 필요.
