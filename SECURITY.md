# Security Policy — secpipe

> É um produto de segurança **operado por IA** e uma **dependência de alta confiança** (toca vários
> projetos). Por isso, a governança dele é a mais rígida. Threat model: [`docs/specs/03-security.md`](docs/specs/03-security.md).

## Postura

- **Dogfooding:** o próprio repo roda a esteira em si mesmo (scan + gate). Ver [ADR-0009](docs/adr/0009-plug-and-play-and-dogfooding.md).
- **Supply-chain (free):** actions pinadas por SHA (StepSecurity Secure-Repo), egress monitorado no CI (Harden-Runner), postura do repo (OpenSSF Scorecard), releases assinadas + SBOM.
- **Repo público:** **zero segredo** exposto a workflow de PR de fork; sem `pull_request_target` inseguro.
- **Guardrail central:** a IA operadora **não** pode silenciar o próprio achado (política no motor referenciado; anti-supressão; verificador independente). Ver [ADR-0008](docs/adr/0008-ai-operator-guardrails.md).

## Reportar uma vulnerabilidade

Enquanto não houver um canal formal: reportar em privado ao mantenedor (Pablo de Souza Galerani).
**Não** abrir issue pública com detalhe explorável. Um processo de *coordinated disclosure* será
definido antes de o projeto ser amplamente adotado.

## Regras invioláveis (para contribuições)

1. Sem segredos no repositório; gitleaks roda no CI e no pre-commit.
2. Nenhum PR que **enfraqueça a política/gate** ou adicione supressão (`# nosec`/`# noqa`/baseline) sem revisão explícita.
3. Actions de terceiros pinadas por SHA; dependências verificadas (SCA).
4. Toda mudança no **contrato** de achados (`Finding`/SARIF) é versionada (é API pública).
