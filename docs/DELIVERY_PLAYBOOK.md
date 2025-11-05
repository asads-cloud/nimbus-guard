# 🚀 Nimbus Guard: Delivery Playbook

This document outlines the **delivery phases**, **technical components**, and **demo workflows** for **Nimbus Guard**, a multi-region AWS security scanner for automated misconfiguration detection and CI/CD enforcement.

It serves as a concise guide for understanding how the project was structured, delivered, and showcased.

---

## 🧭 1. Project Snapshot

| Attribute | Description |
|------------|--------------|
| **Purpose** | Multi-region AWS security scanner that detects high-risk misconfigurations and can **fail CI** on `HIGH` / `CRITICAL` findings |
| **Primary Regions** | `eu-west-2` (London), `eu-west-1` (Ireland) |
| **Tech Stack** | Python 3.12 (boto3, Jinja2, Markdown, PyYAML), Docker, Terraform (~> 5.x), GitHub Actions (OIDC) |
| **Artifacts per Run** | `nimbus-guard-report.md`, `nimbus-guard-report.html`, `nimbus-guard-report.json` |

---

## ⚙️ 2. Delivery Phases

### Phase 0: Inception & Scope
- Defined project objectives and success criteria  
- Established deliverables: **portfolio-grade security automation project**  
- Selected core technologies and AWS region strategy  
- Planned multi-format outputs (Markdown + HTML + JSON)  
- Added **exit codes by severity** to support CI gating  

---

### Phase 1: Repository Bootstrap
- Created modular Python package under `scanner/`  
- Implemented CLI entry point (`runner.py`), checks registry, and reporting module  
- Added dependency file `requirements.txt` (boto3, Jinja2, Markdown, PyYAML)  
- Standardised local development environment (Windows + PowerShell + VS Code)  

---

### Phase 2: Core Security Checks
Implemented foundational AWS misconfiguration checks:

- **S3:** Public buckets, ACLs, and missing block-public-access settings  
- **IAM:** Over-permissive roles and inline policies  
- **EC2 Security Groups:** Rules open to `0.0.0.0/0`  
- **CloudTrail:** Missing or unencrypted trails  
- **Account:** Root MFA and password policy enforcement  
- **VPC:** Flow Logs validation  

> Default scan regions: `eu-west-2`, `eu-west-1` (configurable via CLI or env)

---

### Phase 3: Reporting & Exit Codes
- Added **Markdown, HTML, and JSON reporting** using Jinja2 templates  
- Introduced **Fail-on-Severity Gate**: exits non-zero on `HIGH` or `CRITICAL` issues  
- Reports stored under `./out`:
  - `nimbus-guard-report.md`  
  - `nimbus-guard-report.html`  
  - `nimbus-guard-report.json`  

---

### Phase 4: Dockerisation
- Built and published container image **`nimbus-guard:latest`** (Python 3.12-slim)  
- Created `.dockerignore` for efficient builds  
- Ensured feature parity between CLI and container executions  

---

### Phase 5: CI/CD & OIDC Integration
- Configured GitHub Actions for continuous integration and nightly scans:  
  - **CI:** `.github/workflows/ci.yml` (push, PR, workflow_call)  
  - **Nightly:** `.github/workflows/nightly.yml` (02:00 UTC)  
- **OIDC Role:** `nimbus-guard-scan`  
  - **ARN:** `arn:aws:iam::<account-number>:role/nimbus-guard-scan`  
- GitHub secret: `NIMBUS_GUARD_ROLE_ARN`  
- Verified artifact upload and badge visibility in README  

---

## 🧪 3. Demo Guide

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
docker run --rm   -v "$PWD/out:/app/out"   -e AWS_REGION=eu-west-2   -e AWS_PROFILE=default   nimbus-guard:latest
```

---

### ⚙️ GitHub Actions (OIDC)
- Push a branch or open a PR, CI will automatically assume the OIDC role `nimbus-guard-scan`.  
- Check the **Actions → Artifacts** tab for the generated reports.  

> If `HIGH` or `CRITICAL` findings are present → exit code `2` → CI fails → PR blocked.

---

## 🗂️ 4. Repository Map

```bash
/scanner/              # runner.py, report.py, checks/*.py
/.github/workflows/    # ci.yml, nightly.yml
/docs/                 # architecture-diagram.png, sample-report.png, playbook.md
Dockerfile
.dockerignore
requirements.txt
LICENSE
README.md
```

---

## ⚡ 5. Operational Notes

- **Credentials:** No long-lived AWS keys, CI authenticates via **GitHub OIDC → AWS role**  
- **Regions:** Configurable at runtime; defaults to EU-West pair  
- **Extensibility:** New checks can be added under `scanner/checks/*.py` and registered in the module index  

---

## 🧱 6. Roadmap (Next Iteration)

| Focus Area | Description |
|-------------|-------------|
| **Service Expansion** | Add RDS snapshot checks, EBS public snapshot detection, and KMS rotation validation |
| **Reporting Enhancements** | Themed HTML outputs, customizable severity thresholds |
| **Notifications** | Slack/Teams integrations and AWS SAR packaging |

---

> **Maintained by:** Asad Rana: Cloud Engineer w/ AWS & Terraform | Specialising in Statistics, Data & Security
