FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system proxmox-mcp && adduser --system --ingroup proxmox-mcp proxmox-mcp

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src

RUN python -m pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir .

USER proxmox-mcp
EXPOSE 8443

CMD ["proxmox-mcp"]
