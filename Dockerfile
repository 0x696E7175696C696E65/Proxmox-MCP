FROM node:22-alpine AS webbuild
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROXMOX_MCP_ADMIN_SPA_DIR=/app/web/dist

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system proxmox-mcp && adduser --system --ingroup proxmox-mcp proxmox-mcp

COPY pyproject.toml README.md LICENSE alembic.ini /app/
COPY src /app/src
COPY migrations /app/migrations
COPY --from=webbuild /web/dist /app/web/dist

RUN python -m pip install --upgrade pip "setuptools>=83.0.0" wheel \
    && pip install --no-cache-dir . \
    && pip install --no-cache-dir "psycopg[binary]>=3.2" \
    && pip install --no-cache-dir --upgrade "setuptools>=83.0.0" "msgpack>=1.2.1" \
    && python -c "import importlib.metadata as m; assert tuple(map(int, m.version('setuptools').split('.')[:2])) >= (83, 0); assert tuple(map(int, m.version('msgpack').split('.')[:2])) >= (1, 2)"

USER proxmox-mcp
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import ssl, urllib.request; urllib.request.urlopen('https://127.0.0.1:8443/health/live', context=ssl._create_unverified_context())"

CMD ["proxmox-mcp"]
