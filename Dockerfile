FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system proxmox-mcp && adduser --system --ingroup proxmox-mcp proxmox-mcp

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir .

USER proxmox-mcp
EXPOSE 8080

CMD ["proxmox-mcp"]
