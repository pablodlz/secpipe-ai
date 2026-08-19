#!/usr/bin/env bash
# Hardening do repositório no GitHub (supply-chain / ADR-0008 §5, docs/specs/03-security.md).
# Requer: gh CLI autenticado com permissão de admin no repo.
#
# ATENÇÃO: ativa branch protection em 'main'. A partir daí, pushes diretos passam a exigir PR + checks
# verdes. Rode isto quando migrar para o fluxo por PR (não durante o desenvolvimento com push direto).
#
# Uso: ./scripts/setup_github_hardening.sh [owner/repo]   (default: pablodlz/secpipe-ai)
set -euo pipefail
REPO="${1:-pablodlz/secpipe-ai}"

echo ">> Branch protection em $REPO (main): PR obrigatório, checks verdes, sem force-push."
gh api -X PUT "repos/$REPO/branches/main/protection" \
  -H "Accept: application/vnd.github+json" --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["quality-and-security", "secret-scan"] },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON

echo ">> Habilitando Dependabot alerts + security fixes."
gh api -X PUT "repos/$REPO/vulnerability-alerts" -H "Accept: application/vnd.github+json" || true
gh api -X PUT "repos/$REPO/automated-security-fixes" -H "Accept: application/vnd.github+json" || true

cat <<'NOTE'

Feito (via API). Ainda no painel do GitHub (uma vez):
  - Settings > Code security: ligar "Secret scanning" e "Push protection".
  - Actions: os workflows ci-security (Scorecard + Harden-Runner) e publish-image já estão no repo.
  - StepSecurity Secure-Repo: rode para PINAR as actions por SHA (supply-chain).
NOTE
