# Motor do secpipe como imagem (ADR-0002): TODOS os scanners free embutidos — roda em qualquer CI e local.
# O consumidor não precisa de Python nem instalar scanners: `docker run ghcr.io/pablodlz/secpipe-ai scan .`
FROM python:3.11-slim AS engine

# Versões e checksums (supply-chain: binários pinados e VERIFICADOS).
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SHA256=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a

# Scanners via pip: SAST multi-linguagem (semgrep) + Python (bandit, pip-audit) + fixer (codemodder).
RUN pip install --no-cache-dir semgrep bandit pip-audit codemodder

# gitleaks + trivy: binários Linux pinados, com verificação de sha256. ca-certificates fica (trivy baixa
# a vuln-DB em runtime); curl é removido depois para enxugar a imagem.
RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends curl ca-certificates; \
    curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm -f /tmp/gitleaks.tgz /tmp/trivy.tgz; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*; \
    gitleaks version; trivy --version

# secpipe (CLI)
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# roda como não-root (least privilege)
RUN useradd --create-home --uid 10001 secpipe
USER secpipe
WORKDIR /work
ENTRYPOINT ["secpipe"]
CMD ["scan", "/work"]
