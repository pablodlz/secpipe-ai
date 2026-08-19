# 06 — Prior Art & References

> Levantamento de mercado e literatura feito **antes** de desenvolver, para **não reinventar** e para
> fundamentar as decisões. Conclusão que guia a arquitetura: **compor ferramentas free best-of-breed +
> adicionar a camada de auto-fix por IA** — em vez de construir orquestrador/scanners do zero.

## Ferramentas de mercado (gratuitas / open-source)

### Orquestração de scanners (o "motor" — já existe grátis)
- **ASH — AWS Automated Security Helper** — motor OSS de orquestração **security-first** (Bandit, Semgrep, Grype, Syft, Checkov, git-secrets, cfn-nag…), isola tools via UV, roda em CI. → **candidato a base de orquestração** do `secpipe`. <https://github.com/awslabs/automated-security-helper>
- **MegaLinter** (OX Security) — orquestra 100+ linters/scanners, GitHub Action ou qualquer CI, relatórios + alguns auto-fixes, muito configurável, free. Foco em qualidade+IaC. <https://megalinter.io>

### Normalização / gestão de vulnerabilidades
- **DefectDojo** — OSS ASPM: ingere e **normaliza/dedup** achados de 500+ tools + SARIF, painel único. → alvo de **exportação** (não reinventar painel). <https://github.com/DefectDojo/django-DefectDojo>

### Remediação (auto-fix determinístico)
- **Pixee / Codemodder** — motor OSS de remediação (`codemodder-python`, `codemodder-java`): transforma achado (SARIF, 50+ tools) em fix mergeável; **não escaneia, só corrige**. → **base do módulo de auto-fix determinístico** (complementar ao auto-fix por IA). <https://github.com/pixee>

### Supply-chain / hardening do CI (o próprio pipeline)
- **OpenSSF Scorecard** — 18+ checks de segurança do repo; grátis em repo público. → módulo + **rodar em nós mesmos**. <https://github.com/ossf/scorecard-action>
- **StepSecurity Harden-Runner** (Community, free) — "EDR" do runner do Actions: monitora egress/arquivo/processo, detecta ameaça em tempo real. → mitiga o risco de exfiltração/supply-chain. <https://github.com/step-security/harden-runner>
- **StepSecurity Secure-Repo** — automatiza **pin de actions por SHA**. → resolve o requisito de pinning. <https://github.com/step-security/secure-repo>
- **OWASP GitHub Actions Security Cheat Sheet** — referência de hardening. <https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html>

### Scanners individuais (todos free — ver ADR-0003)
Semgrep CE, Bandit, pip-audit, Trivy, gitleaks, Checkov/KICS, OWASP ZAP, Grype/Syft/osv-scanner, Dependabot.

## Limitações de custo importantes (o "sem gastar NADA" tem letras miúdas)

- **Semgrep CE (free, LGPL):** limitado a **análise de arquivo único**; avaliações independentes reportam ~44–48% de detecção vs ~72–75% do Pro (pago). Mitigação: combinar Semgrep CE **+ Bandit + ASH**, não depender de um só. A plataforma Semgrep cloud é free só até 10 devs/10 repos privados.
- **Copilot Autofix:** grátis para open-source, **mas só corrige achados do CodeQL** (não Semgrep/Trivy). Por isso precisamos do nosso próprio auto-fix provider-agnostic.
- **CodeQL:** grátis só em repo **público**; privado exige GitHub Advanced Security (pago). → módulo opcional que só liga em consumidor público.
- **Auto-fix comercial (Mobb, Pixeebot, Semgrep Assistant):** pago/hospedado. → reforça construir a camada de IA nós mesmos (self-hosted, free, provider-agnostic).

## Literatura (fundamenta o loop de auto-fix e seus guardrails)

- **Detect–Repair–Verify (DRV)** é o framework reconhecido; a literatura enfatiza **validação pós-reparo** (rerodar checks de segurança **e** testes funcionais) para confirmar mitigação e barrar regressão. → base do guardrail "provar o fix com teste, não com silêncio do scanner".
- **Políticas duplas de LLM — Bug Abstention + Patch Validation** melhoram a qualidade substancialmente (relatam +13pp e +15pp). *Abstention* = saber quando **não** corrigir e escalar (nosso escalonamento por risco); *Validation* = verificador independente. arXiv:2405.15690 (ACM AI-Powered Software 2024).
- **Feedback com execução (execution-grounded)** reduz o excesso de confiança do LLM em pipelines agentic.
- **Pearce et al., "Examining Zero-Shot Vulnerability Repair with LLMs"**, IEEE S&P 2023 — trabalho fundacional; confiabilidade é o desafio central.
- **Surveys/SLR:** "A Survey of LLM-based Automated Program Repair" (arXiv:2506.23749); "A Systematic Literature Review on LLMs for Automated Program Repair" (arXiv:2405.01466).
- **Benchmark:** PATCHEVAL — patching de vulnerabilidades reais (arXiv:2511.11019).
- **Detect–Repair–Verify empírico** para código gerado por LLM (arXiv:2603.00897).

> Observação: o `secpipe` conversa com a ciência do **Omni-Pentest** (firewall de validação, juiz adversarial) — o loop de auto-fix aqui é o **espelho defensivo** do DRV: achar → corrigir → **verificar de forma independente** antes de aceitar.

## Como isso muda a arquitetura (conclusão)

1. **Compor, não reinventar:** o `secpipe` orquestra tools free (ou apoia-se em ASH/MegaLinter) e **normaliza** para um contrato único; não reescreve scanners nem painel (ver ADR-0006).
2. **Diferencial = auto-fix por IA provider-agnostic com guardrails DRV** (o que ninguém entrega grátis+integrado+self-hosted).
3. **Supply-chain do próprio pipeline** usa Scorecard + Harden-Runner + Secure-Repo (free), não solução caseira.
4. **Contrato SARIF+CWE** como entrada universal para a IA (validado pelo modelo do Pixee).
