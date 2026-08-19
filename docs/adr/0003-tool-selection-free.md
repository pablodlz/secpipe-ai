# ADR-0003 — Seleção de ferramentas (só free)

**Status:** Aceito (Fase 0).

## Contexto
Requisito: custo ZERO e cobertura multi-linguagem, com o operador sendo a IA.

## Decisão
Compor apenas ferramentas free/open-source, por dimensão:
- **SAST:** Semgrep CE + Bandit (Python); CodeQL só em repo público (opcional).
- **SCA:** Trivy + pip-audit (Python) / osv-scanner / Grype.
- **Secret:** gitleaks.
- **IaC:** Trivy / Checkov / KICS.
- **DAST (fase futura):** OWASP ZAP (baseline).
- **Orquestração/base:** avaliar reusar ASH (ADR-0006).

## Rejeitados / ressalvas
- **Horusec:** arquivado/descontinuado — NÃO usar.
- **Semgrep CE:** limitado a arquivo único (~44–48% de detecção vs Pro pago) — mitigar combinando com Bandit/ASH; documentar honestamente.
- **CodeQL:** grátis só em repo público (privado exige GHAS pago) — módulo opcional.

## Consequências
- (+) Custo zero, multi-linguagem, sem lock-in.
- (−) CE tem limites; mitigado por combinação de tools e abstração `ScannerPort`.
