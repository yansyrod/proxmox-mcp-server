# Proxmox MCP Server Dockerfile
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Proxmox MCP Server"
LABEL org.opencontainers.image.description="MCP server for Proxmox VE management"
LABEL org.opencontainers.image.source="https://github.com/yansyrod/proxmox-mcp-server"
LABEL org.opencontainers.image.vendor="yansyrod"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY README.md ./
COPY proxmox_mcp ./proxmox_mcp

RUN pip install --no-cache-dir .

RUN groupadd -g 1001 proxmox && \
    useradd -u 1001 -g proxmox -m -s /bin/sh proxmox && \
    chown -R proxmox:proxmox /app /home/proxmox

USER proxmox

ENV MCP_SERVER_TYPE=proxmox

CMD ["proxmox-mcp-server"]
