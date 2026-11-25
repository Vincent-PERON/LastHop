# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /w
COPY requirements.lock .
# --require-hashes : installation uniquement de paquets dont le hash est épinglé
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --require-hashes -r requirements.lock

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH PYTHONPATH=/srv
# Correctifs de sécurité Debian publiés depuis la construction de l'image de base (scan Trivy : scripts/security-check.sh)
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=root:root app ./app
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root alembic.ini .
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --retries=5 CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]
CMD ["uvicorn", "app.asgi:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header", "--no-access-log"]

FROM runtime AS test
# hadolint ignore=DL3066
USER root
COPY requirements-dev.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements-dev.lock
COPY pyproject.toml .
COPY tests ./tests
USER 10001
CMD ["pytest", "-q"]
