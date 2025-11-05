# 🧩 Nimbus Guard Examples

This folder contains two Terraform example environments used to demonstrate **Nimbus Guard** scanning and report generation.

---

## 📁 Structure

| Folder | Description |
|---------|--------------|
| [`secure/`](./secure) | A **compliant** Terraform setup designed to **pass all Nimbus Guard checks**: no HIGH or CRITICAL findings. |
| [`insecure/`](./insecure) | An **intentionally misconfigured** Terraform setup that **fails multiple checks**: used to validate detection of IAM, S3, and SG issues. |

---

## 🧪 Purpose

These examples show how **Nimbus Guard** identifies misconfigurations and generates reports for both **failed** and **passed** infrastructure scans.

- ✅ `secure` → Demonstrates a *clean security baseline*.  
- ❌ `insecure` → Demonstrates *realistic misconfigurations* that trigger findings.

---

## 📊 Reports

Both folders include:
- Terraform code to deploy/destroy test infrastructure.
- Example **HTML or Markdown scan reports**.
- Inline documentation describing what each setup tests.

---

## 🧹 Cleanup

Each example can be deployed and safely destroyed via:

```powershell
terraform init
terraform apply -auto-approve
terraform destroy -auto-approve
```
---
*Use these examples to verify Nimbus Guard’s detection accuracy and visualize security posture differences between compliant and misconfigured AWS environments.*
