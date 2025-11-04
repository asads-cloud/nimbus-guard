# 🚀 Nimbus Guard — Delivery Playbook

This document summarises **deliverables by phase (0–5)** and provides a quick **demo guide** for showcasing Nimbus Guard; a multi‑region AWS security scanner for automated misconfiguration detection and CI/CD enforcement.

---

## 🧭 1. Project Snapshot

| Attribute | Description |
|------------|--------------|
| **Purpose** | Multi‑region AWS security scanner that flags high‑risk misconfigurations and **fails CI** on `HIGH` / `CRITICAL` findings |
| **Primary Regions** | `eu‑west‑2` (London), `eu‑west‑1` (Ireland) |
| **Tech Stack** | Python 3.12 (boto3, jinja2, markdown, pyyaml), Docker, Terraform (~> 5.x), GitHub Actions (OIDC) |
| **Artifacts per Run** | `nimbus‑guard‑report.md`, `nimbus‑guard‑report.html`, `nimbus‑guard‑report.json`  |

---

## ⚙️ 2. Phase Handoffs

### Phase 0 - Inception & Scope
- Defined business objectives and success criteria.  
- Established deliverables: **portfolio‑grade security scanner** and **recruiter‑ready technical asset**.  
- Chose technology stack and region strategy.  
- CLI outputs: Markdown + HTML + JSON.  
- Introduced **exit codes by severity** for CI gating.

---

### Phase 1 - Repository Bootstrap
- Created Python package structure under `scanner/`.  
- Implemented CLI entry (`runner.py`), checks registry, and `report.py`.  
- Added dependency file `requirements.txt` with:  
  - boto3, jinja2, markdown, pyyaml  
- Standardised local development: **Windows + PowerShell + VS Code**.

---

### Phase 2 - Core Checks
Implemented core misconfiguration detectors for:
- **S3:** Public buckets, ACLs, and block‑public‑access misconfigs  
- **IAM:** Over‑permissive roles and inline policies  
- **EC2 Security Groups:** Rules open to `0.0.0.0/0`  
- **CloudTrail:** Missing or unencrypted trails  
- **Account:** Root MFA, password policy gaps  
- **VPC:** Flow Logs validation  

> Regions configurable; defaults: `eu‑west‑2`, `eu‑west‑1`

---

### Phase 3 - Reporting & Exit Codes
- Added **Markdown + HTML + JSON reporting** using Jinja and Markdown templates.  
- Implemented **Fail‑on‑Severity Gate**: non‑zero exit code when `HIGH` or `CRITICAL` findings occur.  
- Reports stored under `./out` as:  
  - `nimbus‑guard‑report.md`  
  - `nimbus‑guard‑report.html`
  - `nimbus‑guard‑report.json` 

---

### Phase 4 - Dockerization
- Docker image: **`nimbus‑guard:latest`** (Python 3.12‑slim).  
- `.dockerignore` optimised for minimal build context.  
- Validated parity between local CLI and container execution.  

---

### Phase 5 - CI/CD & OIDC Integration
- Configured GitHub Actions workflows:  
  - CI → `.github/workflows/ci.yml` (push, PR, workflow_call)  
  - Nightly → `.github/workflows/nightly.yml` (02:00 UTC)  
- **OIDC Role:** `nimbus‑guard‑scan`  
  - **ARN:** `arn:aws:iam::REDACTED_ACCOUNT_ID:role/nimbus‑guard‑scan`  
- GitHub Secret: `NIMBUS_GUARD_ROLE_ARN`  
- Verified artifact uploads (Markdown + HTML).  
- Live **CI** and **Nightly** badges added to `README.md`.

---

## 🧪 3. How to Demo Nimbus Guard

### 🧩 Local (Python CLI)
```bash
python -m scanner.runner --regions eu-west-2 eu-west-1 --output ./out
```
Then open the generated report:  
```bash
./out/nimbus-guard-report.html
```

---

### 🐳 Docker Run
```bash
docker run --rm \
  -v "$PWD/out:/app/out" \
  -e AWS_REGION=eu-west-2 \
  -e AWS_PROFILE=default \
  nimbus-guard:latest
```

---

### ⚙️ GitHub Actions (OIDC)
- Push a branch or open a PR: CI will auto‑trigger using the OIDC‑assumed role `nimbus‑guard‑scan`.  
- Check **Artifacts** in the Actions tab for the generated `nimbus‑guard‑report.*` files.  

> If `HIGH` or `CRITICAL` findings exist → non‑zero exit → CI fails → PR blocked.

---

## 🗂️ 4. Repository Map (High‑Level)

```bash
/scanner/              # runner.py, report.py, checks/*.py
/.github/workflows/    # ci.yml, nightly.yml
/docs/                 # architecture-diagram.png, sample-report.png, DELIVERY_PLAYBOOK.md
Dockerfile
.dockerignore
requirements.txt
LICENSE
README.md
```

---

## ⚡ 5. Operational Notes

- **Credentials:** No long‑lived AWS keys. CI authenticates via **GitHub OIDC → AWS role**.  
- **Regions:** Add or override regions via CLI args. Default: EU‑West pair.  
- **Extensibility:** Add new checks under `scanner/checks/*.py` and register in the module index.  

---

## 🧱 6. Roadmap (Next Iteration)

| Focus Area | Description |
|-------------|-------------|
| **Service Expansion** | Add RDS snapshot checks, EBS public snapshot detection, KMS rotation validation |
| **Reporting Enhancements** | Themed HTML outputs, team‑specific severity thresholds |
| **Notifications** | Slack/Teams integration and AWS SAR packaging |

---

> **Maintained by:** Asad; Cloud Engineer w/ AWS & Terraform | Specialising in Statistics, Data & Security
