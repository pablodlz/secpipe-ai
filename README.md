# security-pipeline (`secpipe`)

> **Motor de segurança reutilizável e gratuito**, **operado pela própria IA** — qualquer projeto o
> aplica **antes** de desenvolver, para que a **IA desenvolvedora** ache, corrija e verifique as
> próprias vulnerabilidades sozinha, sem nada pendente de um humano.
> **Agnóstico de linguagem** (qualquer stack — roda como container, sem exigir Python no consumidor) e
> **agnóstico de IA** (qualquer agente: Claude, Cursor, Copilot, Aider…; qualquer provedor: Claude/OpenAI/Gemini/local).
> Meta: ser **a melhor opção de segurança de custo zero do mercado**, compondo o melhor do free existente.
> Status: **FASE 0 — FOUNDATION** (fundação + esqueleto rodável e testado; **sem** execução real dos
> scanners nem loop de auto-fix ainda).

Este projeto é o **alicerce comum de segurança** dos demais projetos. A ideia: deixar o motor pronto,
depois **plugá-lo em cada projeto**. Por isso, todos os outros projetos dependem deste.

## Princípios

- **Só ferramentas gratuitas.** Semgrep, Bandit, pip-audit, Trivy, gitleaks, OWASP ZAP, Checkov — todas free/open-source. Ver [ADR-0003](docs/adr/0003-tool-selection-free.md).
- **Motor único, referenciado — não copiado.** A lógica vive num lugar (imagem container + CLI), versionada. Projetos **referenciam**; não forkam a lógica. Evita *drift*. Ver [ADR-0002](docs/adr/0002-engine-container-cli.md).
- **Dois modos de consumo, um só motor.** *Referenciado* (recebe updates) **ou** *template* (você é dono do bump). O que muda é o **wrapper**, nunca o motor. Ver [`docs/specs/04-consumption-models.md`](docs/specs/04-consumption-models.md).
- **Contrato JSON/SARIF para a IA.** Todo scanner é normalizado num modelo único de `Finding` (mapeado a CWE) — é o que a IA consome para corrigir. Ver [ADR-0004](docs/adr/0004-sarif-normalization.md).
- **Gate como política, fail-closed.** Severidade que bloqueia é declarada em `.secpipe.yml`; na dúvida, bloqueia.
- **A própria esteira é dependência de alta confiança.** Sendo pública, exige a governança mais rígida (pin por SHA, releases assinadas, zero segredo em PR de fork). Ver [`docs/specs/03-security.md`](docs/specs/03-security.md).
- **Plug-and-play, sem capar desempenho.** Zero-config com defaults seguros e **fortes** (não uma versão capada); `.secpipe.yml` só para tunar. Ver [ADR-0009](docs/adr/0009-plug-and-play-and-dogfooding.md).
- **Dogfooding.** O próprio repo roda a esteira em si mesmo — prova de que funciona e valida "quem guarda o guarda".

## O motor (visão)

```text
        .secpipe.yml (config por projeto)
                 │
   ┌─────────────▼──────────────┐      adapters (free tools)
   │        secpipe (CLI)        │──▶ Semgrep · Bandit · pip-audit
   │  orquestra → normaliza →    │──▶ Trivy (SCA/IaC/img/secret) · gitleaks
   │  aplica política (gate)     │──▶ (fase futura) OWASP ZAP (DAST) · Checkov
   └─────────────┬──────────────┘
                 ▼
    Report normalizado (JSON/SARIF)  ──▶ GitHub code scanning  +  IA (auto-fix, fase futura)
```

O motor é empacotado como **imagem container** (roda em qualquer CI e local) e exposto no GitHub via um
**reusable workflow**. Detalhes: [`docs/specs/02-architecture.md`](docs/specs/02-architecture.md).

## Como um projeto vai consumir (fase futura — exemplos já documentados)

- **Referenciado:** ~5 linhas de workflow chamando `secpipe.reusable.yml@v1` + um `.secpipe.yml`.
- **Template:** *use-as-template* copia só o wrapper + config; o motor continua vindo da imagem versionada.

Exemplos em [`examples/consumer/`](examples/consumer/).

## Rodar o esqueleto (Fase 0)

```bash
pip install -e ".[dev]"
secpipe doctor      # lista quais ferramentas estão disponíveis no PATH (real)
secpipe scan        # roda o pipeline (Fase 0: adapters ainda são esqueleto — reportam "skipped")
```

## Por onde começar a ler

1. [`docs/specs/00-overview.md`](docs/specs/00-overview.md)
2. [`docs/specs/02-architecture.md`](docs/specs/02-architecture.md)
3. [`docs/specs/03-security.md`](docs/specs/03-security.md) — threat model do próprio pipeline.
4. [`docs/specs/04-consumption-models.md`](docs/specs/04-consumption-models.md) — referenciado vs template.
5. [`docs/specs/05-roadmap.md`](docs/specs/05-roadmap.md) — fases e pontos em aberto.

## O que NÃO existe nesta fase

Execução/parsing real dos scanners, DAST, IaC scanning, o loop de auto-fix da IA, e a imagem publicada.
Tudo isso está **arquitetado e documentado** como próximas fases — não implementado.

---
*Open-source sob [Apache-2.0](LICENSE). Fundação (Fase 0); ainda não é um motor pronto para produção.*
