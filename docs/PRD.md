# PRD: CMDB 자산 수집 멀티 에이전트

## 목표
외부 보안/인프라 소스(CrowdStrike EDR, AD, SCCM 등)에서 IT 자산 정보를 자동 수집하여 CMDB에 통합 관리한다.

## 사용자
- ITAM/CMDB 관리자: 수집된 자산 데이터를 관리 포털에서 조회/관리
- 보안 운영팀: 자산별 EDR 에이전트 설치 현황, 취약점 모니터링

## 핵심 기능
1. CrowdStrike Hosts API를 통한 관리 디바이스 자산 수집 (Phase 1)
2. 수집 데이터를 공통 자산 스키마(CommonAsset)로 정규화
3. Spring Boot 백엔드 bulk API를 통한 DB 저장 (upsert)
4. EventBridge 스케줄 기반 주기적 자동 수집 (1시간 간격)
5. 수집 이력 로깅 (성공/실패 건수, 에러 메시지)

## MVP 제외 사항 (Phase 2+)
- Discover API (unmanaged 자산 포함 전수조사)
- Spotlight API (CVE 취약점 수집)
- Zero Trust Assessment API (보안 평가 점수)
- 오케스트레이터 Lambda (멀티 에이전트 조율)
- 수집 데이터 변경 이력 추적 (diff)
