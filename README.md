# Nimbus Guard

[![CI](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml)

Production-grade, multi-region AWS security scanner that detects high-risk misconfigurations:
- Public S3 buckets
- Over-permissive IAM
- Open EC2 Security Groups
- Missing CloudTrail / MFA

**Stack:** Python (boto3), Docker, Terraform, GitHub Actions (OIDC).  
**Regions:** eu-west-1 (Ireland, primary), eu-west-2 (London, secondary).  
**Outputs:** Markdown + HTML reports; CI can fail on HIGH/CRITICAL.

## Repo Layout
- `scanner/` — Python package `nimbus_guard`
- `terraform/` — IaC (OIDC role, permissions)
- `docker/` — Docker build context
- `.github/workflows/` — CI pipelines
- `scripts/` — helper scripts
- `docs/` — docs and screenshots
- `out/` — generated reports (git-ignored)
- `tests/` — unit/integration tests

## Quickstart (later phases)
- Local scan via Python CLI
- Containerized run via Docker
- CI run via GitHub Actions → OIDC → AWS IAM role
