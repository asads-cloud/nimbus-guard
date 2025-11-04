# Nimbus Guard

[![CI](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml)
[![Nightly](https://github.com/asads-cloud/nimbus-guard/actions/workflows/nightly.yml/badge.svg?style=flat-square)](https://github.com/asads-cloud/nimbus-guard/actions/workflows/nightly.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](./LICENSE)
![Terraform](https://img.shields.io/badge/Terraform-~%3E%205.x-5C4EE5?style=flat-square&logo=terraform)
![Docker](https://img.shields.io/badge/Docker-Desktop-blue?style=flat-square&logo=docker)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)

**Multi-region AWS security scanner** that flags high-risk misconfigurations (public S3, over-permissive IAM, open security groups, missing CloudTrail/MFA), generates Markdown/HTML reports, and can **fail CI** on HIGH/CRITICAL findings.

Built for portfolio credibility: Python (boto3), Docker, Terraform, and GitHub Actions with secure **OIDC** role assumption.

---

## Quick Start

### Local (Python CLI)
From the repo root:
```bash
cd scanner
python -m nimbus_guard.runner
Configure via env:

bash
Copy code
# PowerShell
$env:NG_REGIONS = "eu-west-2,eu-west-1"
$env:NG_FAIL_ON = "HIGH"
$env:NG_OUT     = "..\out"
python -m nimbus_guard.runner
Docker
bash
Copy code
docker run --rm ^
  -v "%CD%\out:/app/out" ^
  -v "%UserProfile%\.aws:/root/.aws:ro" ^
  -e AWS_PROFILE=default ^
  -e NG_REGIONS="eu-west-2,eu-west-1" ^
  nimbus-guard:latest
CI (GitHub Actions + OIDC)
See .github/workflows/ci.yml.
OIDC role name: nimbus-guard-scan (Terraform).

Architecture
GitHub Actions → OIDC → AWS IAM Role (read-only) → Scanner (boto3) → Findings → Report (MD/HTML) → PR gate


Screenshots
Sample HTML/Markdown outputs (generated to /out):

Fail-on-Severity Gate
Exit codes bubble to CI: non-zero when HIGH/CRITICAL present (configurable via NG_FAIL_ON).

Tech Stack & Features
Python 3.12, boto3, Jinja2, Markdown

Dockerized for parity; Terraform for least-priv OIDC role

Regions: eu-west-2 (primary), eu-west-1 (secondary)

Checks: S3, IAM, Security Groups, CloudTrail, Account (root MFA), VPC (flow logs)

Roadmap
Richer report theming, additional services, configuration profiles.

License
MIT — see LICENSE.
