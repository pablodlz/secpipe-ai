# Verificar a imagem do secpipe (assinada + SBOM + provenance)

A imagem `ghcr.io/pablodlz/secpipe-ai` é assinada **keyless** (Sigstore/cosign via OIDC do GitHub Actions —
sem chave privada guardada) e acompanha um **SBOM CycloneDX** atestado e **provenance SLSA**. Consumidores
podem verificar antes de rodar (`docker run`), e o `secpipe.reusable.yml` já pina a imagem por **digest**.

## Assinatura (cosign)

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/pablodlz/secpipe-ai/.github/workflows/publish-image.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/pablodlz/secpipe-ai@sha256:<DIGEST>
```

## SBOM atestado (CycloneDX)

```bash
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp 'https://github.com/pablodlz/secpipe-ai/.github/workflows/publish-image.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/pablodlz/secpipe-ai@sha256:<DIGEST>
```

## Provenance SLSA

```bash
gh attestation verify oci://ghcr.io/pablodlz/secpipe-ai@sha256:<DIGEST> --owner pablodlz
```

> A identidade OIDC (repo + workflow) fica pública no log de transparência **Rekor** — esperado em OSS.
> Nenhuma chave privada é armazenada; o certificado é efêmero (Fulcio) por execução.
