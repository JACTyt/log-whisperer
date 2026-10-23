# Build context: repository root (docker-compose.yml sets it).
FROM python:3.12-slim

# WeasyPrint (PDF reports) needs Pango/HarfBuzz; DejaVu covers report fonts.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.10.11 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv PATH="/opt/venv/bin:$PATH"

WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock backend/README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/src ./src
RUN uv sync --frozen --no-dev

COPY rules /app/rules
COPY backend/config.docker.toml /app/config.toml
ENV LOGW_CONFIG=/app/config.toml OLLAMA_HOST=http://host.docker.internal:11434

RUN useradd --create-home --uid 10001 logw && mkdir -p /data && chown -R logw /data /app/rules/drafts
USER logw
VOLUME ["/data"]
EXPOSE 8000 5514/udp 5514/tcp
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["logw", "serve"]
