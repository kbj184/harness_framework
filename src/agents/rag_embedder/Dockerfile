FROM public.ecr.aws/lambda/python:3.12

COPY requirements.txt ${LAMBDA_TASK_ROOT}/
# rag_embedder는 psycopg2-binary가 필요
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt --target "${LAMBDA_TASK_ROOT}" \
    && pip install --no-cache-dir psycopg2-binary --target "${LAMBDA_TASK_ROOT}"

COPY src/ ${LAMBDA_TASK_ROOT}/src/

CMD ["src.agents.rag_embedder.handler.lambda_handler"]
