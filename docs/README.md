# 📘 Nimbus Guard - Documentation

This directory contains **architectural references**, **sample output reports**, and the **delivery playbook** for the Nimbus Guard project; a multi‑region AWS security scanner designed for automated compliance, misconfiguration detection, and CI/CD enforcement.

---

## 🏗️ System Architecture

The following diagram illustrates the **end‑to‑end architecture** of Nimbus Guard, highlighting CI/CD integration via GitHub Actions OIDC, AWS role assumption, and multi‑region scanning workflows.

<p align="center">
  <img src="./architecture-diagram.png" alt="Nimbus Guard Architecture Diagram" width="850"/>
</p>

**Flow Summary:**  
1️⃣ GitHub Actions initiates the scan using an OIDC‑assumed AWS role.  
2️⃣ The scanner (Python + boto3) enumerates resources across multiple AWS regions.  
3️⃣ Findings are aggregated, templated, and output as Markdown/HTML reports.  
4️⃣ Exit codes bubble to CI to enforce fail‑on‑severity policies.  

---

## 🧾 Sample Report Output

Below is a **visual walkthrough** of a Nimbus Guard security scan report, presented in three panels for readability.

### 🧩 Report Part 1 — Summary & Severity Overview

<p align="center">
  <img src="./sample_report_p1.png" alt="Sample Report Part 1" width="850"/>
</p>

---

### 🧩 Report Part 2 — Findings by Service (S3, IAM, Security Groups)

<p align="center">
  <img src="./sample_report_p2.png" alt="Sample Report Part 2" width="850"/>
</p>

---

### 🧩 Report Part 3 — CloudTrail / Account / VPC Insights

<p align="center">
  <img src="./sample_report_p3.png" alt="Sample Report Part 3" width="850"/>
</p>

---

## 🧭 Additional Resources

| File | Description |
|------|--------------|
| **[DELIVERY_PLAYBOOK.md](./DELIVERY_PLAYBOOK.md)** | Detailed breakdown of each project phase (0–5), handoff notes, and demo instructions |
| **architecture-diagram.png** | Core architectural overview |
| **sample_report_p1‑3.png** | Example visual reports for presentation and documentation |

---

> **Maintained by:** Asad; Cloud Engineer w/ AWS & Terraform | Specialising in Statistics, Data & Security
