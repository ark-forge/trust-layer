FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive     PYTHONUNBUFFERED=1     PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends     build-essential libpq-dev curl ca-certificates     && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir     fastapi==0.136.1 uvicorn==0.46.0     httpx==0.28.1 httpx-sse==0.4.3     pydantic==2.13.4 pydantic-settings==2.14.0     psycopg2-binary==2.9.11     redis==7.2.0     cryptography==48.0.0     stripe     python-multipart     anyio     requests==2.32.3     jinja2     asn1crypto pyasn1     rfc3161-client     sigstore

COPY . /app/

RUN pip install --no-cache-dir -e . 2>/dev/null || pip install --no-cache-dir . 2>/dev/null || true

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3   CMD curl -fsS http://127.0.0.1:8100/ || exit 1

EXPOSE 8100
CMD ["uvicorn", "trust_layer.app:app", "--host", "0.0.0.0", "--port", "8100"]
