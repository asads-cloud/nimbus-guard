# ☁️ Nimbus Guard — Multi‑Region AWS Security Scanner

[![CI](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml)
[![Nightly](https://github.com/asads-cloud/nimbus-guard/actions/workflows/nightly.yml/badge.svg?style=flat-square)](https://github.com/asads-cloud/nimbus-guard/actions/workflows/nightly.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](./LICENSE)
![Terraform](https://img.shields.io/badge/Terraform-~%3E%205.x-5C4EE5?style=flat-square&logo=terraform)
![Docker](https://img.shields.io/badge/Docker-Desktop-blue?style=flat-square&logo=docker)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)

---

## 🧭 Overview

**Nimbus Guard** is a **multi‑region AWS security scanner** engineered for **cloud‑native and DevSecOps environments**.  
It automatically detects **high‑risk misconfigurations** such as:

- Public or unencrypted S3 buckets  
- Over‑permissive IAM roles and policies  
- Open security groups and exposed ports  
- Missing CloudTrail, root MFA, or VPC Flow Logs  

Designed for enterprise CI/CD pipelines, Nimbus Guard delivers **actionable HTML and Markdown reports**, integrates seamlessly with **GitHub Actions via OIDC**, and can **fail builds automatically** when `HIGH` or `CRITICAL` findings are detected.

---

## ⚙️ Key Capabilities

| Category | Description |
|-----------|--------------|
| **Security Detection** | Identifies misconfigurations in core AWS services (S3, IAM, EC2, VPC, CloudTrail, Account) |
| **Multi‑Region Support** | Parallel scanning across multiple AWS regions for wider coverage |
| **Compliance‑Ready Reports** | Generates Markdown, HTML and JSON outputs for audit and CI review |
| **CI/CD Integration** | GitHub Actions (OIDC‑based authentication), Dockerised for environment parity |
| **Fail‑on‑Severity Logic** | Optional gatekeeping; CI fails automatically on defined thresholds |
| **Terraform Integration** | Includes OIDC role definition for least‑privilege, secure CI access |

---

## 🏗️ Architecture Overview

```
┌────────────────────────────┐
│ GitHub Actions (OIDC)     │
└────────────┬──────────────┘
             │
             ▼
      AWS IAM Role (Read‑only)
             │
             ▼
     Nimbus Guard Scanner (boto3)
             │
             ▼
   Findings → Markdown/HTML Report
             │
             ▼
     CI/CD Decision Gate (Exit Codes)
```

- **Auth:** Secure OpenID Connect (OIDC) between GitHub and AWS  
- **Runtime:** Python 3.12 (boto3, Jinja2, Markdown)  
- **Deployment:** Docker container for consistent builds  
- **Provisioning:** Terraform for IAM/OIDC roles and outputs  

---

## 🚀 Getting Started

### 🧩 Local (Python CLI)

```bash
cd scanner
python -m nimbus_guard.runner
```

Set environment variables:

**PowerShell**
```powershell
$env:NG_REGIONS = "eu-west-2,eu-west-1"
$env:NG_FAIL_ON = "HIGH"
$env:NG_OUT     = "..\out"
python -m nimbus_guard.runner
```

### 🐳 Docker Run

```bash
docker run --rm ^
  -v "%CD%\out:/app/out" ^
  -v "%UserProfile%\.aws:/root/.aws:ro" ^
  -e AWS_PROFILE=default ^
  -e NG_REGIONS="eu-west-2,eu-west-1" ^
  nimbus-guard:latest
```

### 🔁 GitHub Actions (OIDC)

See [`ci.yml`](.github/workflows/ci.yml) for reference.  
**Role Name:** `nimbus-guard-scan` provisioned via Terraform.

---

## 📊 Reporting

Nimbus Guard outputs two formats:

| Format | Use Case |
|---------|-----------|
| **Markdown (.md)** | Lightweight, readable summaries for PRs and documentation |
| **HTML (.html)** | Visual, color‑coded dashboards for managers or compliance teams |
|**JSON (.json)** | Structured, machine-readable output for automation & integrations

Reports are generated under `/out`.

---

## 🔥 Severity Gating for CI/CD

Exit codes bubble up to CI:  
- **0** → No findings or only INFO/LOW  
- **2** → At least one `HIGH` or `CRITICAL` issue (configurable via `NG_FAIL_ON`)  

This enables **secure pipeline automation**; deployments can be automatically blocked when misconfigurations appear.

---

## 🧠 Tech Stack & Design Principles

- **Languages:** Python 3.12 (boto3, Jinja2, Markdown)  
- **Infrastructure:** Terraform ≥ 1.13, Docker Desktop  
- **Security Model:** Least‑privilege OIDC IAM role assumption  
- **Regions:** `eu‑west‑2` (primary), `eu‑west‑1` (secondary)  
- **Checks:** S3, IAM, EC2 Security Groups, CloudTrail, VPC Flow Logs, Account MFA  
- **CI/CD:** GitHub Actions, nightly scanning, badge‑driven visibility  

---

## 🛡️ Security & Compliance Alignment

Nimbus Guard supports **best practices for cloud governance**, aligning with:  

- **AWS Well‑Architected Framework (Security & Operations pillars)**  
- **CIS AWS Foundations Benchmark (selected controls)**  
- **ISO 27001 & NCSC Cloud Security Principles**  
- **DevSecOps automation workflows**  

---

## 🧩 Example Use Cases

- Continuous compliance in multi‑account AWS setups  
- Pre‑deployment guardrails in IaC pipelines  
- Security visibility for contractors and consultants  
- Evidence generation for audits or ISO certification reviews  

---

## 🗺️ Potential Expansions

- Expanded AWS service coverage (RDS, ECR, Lambda)  
- Themed HTML dashboards with historical diffing  
- Configurable profiles for tailored scans  
- Slack/Teams alerting integration
- K8s  

---

## 💼 Consultant Relevance

Nimbus Guard exemplifies **modern DevSecOps engineering practices** — integrating **automation**, **security awareness**, and **IaC governance** into a **portable, production‑grade solution**.

It showcases practical expertise in:  
- **AWS Cloud Security** (IAM, S3, VPC, CloudTrail)  
- **Terraform OIDC federation**  
- **Python & Docker DevSecOps tooling**  
- **CI/CD pipeline integration (GitHub Actions)**  

Ideal for roles involving **Cloud Security Engineering**, **AWS DevOps**, **Platform Security**, and **Infrastructure Automation**.

---

## 📄 License

MIT — see [LICENSE](./LICENSE).

---

> **Maintained by:** Asad; Cloud Engineer w/ AWS & Terraform | Specialising in Statistics, Data & Security
