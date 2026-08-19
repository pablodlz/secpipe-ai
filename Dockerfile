# Motor do secpipe como imagem (ADR-0002): portável a qualquer CI e local; consumidor não precisa de Python.
# Fase 0: instala o CLI + Semgrep (pip). Fase 1 adiciona gitleaks/trivy (binários) nesta mesma camada.
FROM python:3.11-slim AS engine

# Ferramentas free de scan (camada de tools — expandir na Fase 1)
#   - semgrep: instalável via pip (SAST multi-linguagem, CE)
#   - gitleaks/trivy: binários (adicionar via download com checksum na Fase 1)
RUN pip install --no-cache-dir semgrep

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Roda como não-root (least privilege)
RUN useradd --create-home --uid 10001 secpipe
USER secpipe

# O alvo é montado em /work pelo CI/local: `docker run -v "$PWD:/work" secpipe scan /work`
WORKDIR /work
ENTRYPOINT ["secpipe"]
CMD ["scan", "/work"]
