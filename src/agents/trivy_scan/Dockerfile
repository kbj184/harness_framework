FROM public.ecr.aws/lambda/python:3.12

ARG TRIVY_VERSION=0.59.0

# Trivy 바이너리 설치 (단일 binary)
RUN dnf install -y tar gzip && \
    curl -L -o /tmp/trivy.tar.gz \
        https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz && \
    tar xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    dnf clean all

# Trivy DB 사전 다운로드 (이미지 크기 ↑ 약 700MB, 첫 호출 지연 회피)
# 운영 시 EFS 마운트로 대체 가능 — 빌드 시점 고정 DB 가 부담되면 RUN 한 줄 주석 처리.
RUN mkdir -p /opt/trivy-cache && \
    trivy --cache-dir /opt/trivy-cache image --download-db-only

# Python 의존성
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt --target "${LAMBDA_TASK_ROOT}" \
    && pip install --no-cache-dir psycopg2-binary --target "${LAMBDA_TASK_ROOT}"

COPY src/ ${LAMBDA_TASK_ROOT}/src/

# Trivy DB 캐시 경로
ENV TRIVY_CACHE_DIR=/opt/trivy-cache

CMD ["src.agents.trivy_scan.handler.lambda_handler"]
