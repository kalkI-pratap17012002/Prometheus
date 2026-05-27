# syntax=docker/dockerfile:1.6
FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apk add --no-cache curl libstdc++ \
 && apk add --no-cache --virtual .build-deps build-base gcc musl-dev linux-headers

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && apk del .build-deps

COPY . .

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
