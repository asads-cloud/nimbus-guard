# ☁️ Nimbus Guard: Multi-Region AWS Security Scanner

[![CI](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/asads-cloud/nimbus-guard/actions/workflows/ci.yml)
[![Nightly](https://github.com/asads-cloud/nimbus-guard/actions/workflows/nightly.yml/badge.svg?style=flat-square)](https://github.com/asads-cloud/nimbus-guard/actions/workflows/nightly.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](./LICENSE)
![Terraform](https://img.shields.io/badge/Terraform-~%3E%205.x-5C4EE5?style=flat-square&logo=terraform)
![Docker](https://img.shields.io/badge/Docker-Desktop-blue?style=flat-square&logo=docker)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)

---

## 🧭 Overview

**Nimbus Guard** is a **multi-region AWS security scanner** built to demonstrate **modern DevSecOps and cloud security automation** practices.

It performs deep checks for **high-risk misconfigurations** across multiple AWS services and regions, integrating seamlessly into CI/CD pipelines for continuous visibility and automated gating.

While lightweight, the architecture has been designed for **extensibility**, providing a strong foundation that can evolve to include:

- Kubernetes and container workload scanning  
- Deeper AWS service coverage (RDS, Lambda, ECR, CloudFront, etc.)  
- Integration with AWS Security Hub, GuardDuty, or third-party tooling  
- Team notifications, analytics dashboards, and historical diffing  

---

## ⚙️ Core Capabilities

| Category | Description |
|-----------|--------------|
| **Security Detection** | Identifies misconfigurations across S3, IAM, EC2, VPC, CloudTrail, and Account settings |
| **Multi-Region Coverage** | Executes scans across multiple AWS regions in parallel |
| **Reporting** | Generates Markdown, HTML, and JSON outputs for CI pipelines and compliance reviews |
| **CI/CD Integration** | Designed for GitHub Actions with secure OIDC authentication |
| **Fail-on-Severity Logic** | Optional gating mechanism to block builds on `HIGH` or `CRITICAL` findings |
| **Infrastructure as Code** | Terraform templates for minimal, least-privilege IAM/OIDC setup |

> 💡 **Note:** Nimbus Guard is engineered as a compact yet realistic implementation of a cloud-native security automation workflow, suitable for demonstration, learning, and extension.

---

## 🏗️ Architecture Overview

```
┌────────────────────────────┐
│ GitHub Actions (OIDC)     │
└────────────┬──────────────┘
             │
             ▼
      AWS IAM Role (Read-only)
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
- **Containerized:** Docker-based for consistent builds  
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

Example workflow under [`ci.yml`](.github/workflows/ci.yml).  
**Role Name:** `nimbus-guard-scan` provisioned via Terraform.

---

## 📊 Reporting

| Format | Use Case |
|---------|-----------|
| **Markdown (.md)** | Lightweight summaries for pull requests and reviews |
| **HTML (.html)** | Color-coded dashboards for visual reporting |
| **JSON (.json)** | Machine-readable for downstream automation |

All reports are stored under `/out`.

---

## 🔥 CI/CD Severity Gating

Exit codes propagate to CI for automated build decisions:  

| Exit Code | Description |
|------------|--------------|
| **0** | No findings or only INFO/LOW |
| **2** | One or more `HIGH` or `CRITICAL` findings |

This enables **security-aware automation**, blocking deployments when severe misconfigurations are detected.

---

## 🧠 Design Principles

- **Automation-First:** Built for CI/CD environments  
- **Cloud-Native Security:** Leverages OIDC federation for least-privilege access  
- **Lightweight & Modular:** Each component is simple, self-contained, and easily replaceable  
- **Extensible:** Ready to expand into additional services, integrations, and vulnerability detection layers  

---

## 🧩 Future Expansion

Nimbus Guard can be extended into a more comprehensive cloud security platform:

- 🔐 **AWS Services:** RDS, Lambda, ECR, CloudFront, KMS  
- ☸️ **Kubernetes:** EKS posture management and container misconfig scanning  
- 📈 **Analytics:** Trend tracking and historical result comparisons  
- 💬 **Integrations:** Slack / Teams notifications or Security Hub exports  
- 🧩 **IaC:** Terraform plan scanning for pre-deployment checks  

---

## 🧾 License

MIT: see [LICENSE](./LICENSE).

---

> **Maintained by:** Asad Rana: Cloud Engineer w/ AWS & Terraform | Specialising in Statistics, Data & Security
