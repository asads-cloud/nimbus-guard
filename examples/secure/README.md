# ✅ Secure AWS Terraform Example: Passing Nimbus Guard

This Terraform example provisions a **secure AWS baseline** designed to **pass Nimbus Guard** checks with **no HIGH or CRITICAL findings**.  
It deploys compliant infrastructure across **`eu-west-1`** and **`eu-west-2`** regions, ensuring strong security controls and audit visibility.

---

## 🧩 What This Configuration Ensures

- **Root MFA** – Must be configured manually (Terraform cannot enforce this).  
- **CloudTrail**
  - One **multi-region** trail, **actively logging**.
  - Logs stored in a **private, encrypted S3 bucket** with:
    - **Bucket-level Block Public Access (PAB)**.
    - A **strict, non-public bucket policy**.
- **S3 Account-Level Block Public Access**
  - All four PAB flags are **enabled** at the account level.
- **Security Groups**
  - No world-open ingress (e.g. `0.0.0.0/0` on SSH or RDP).  
  - A single locked-down security group allows SSH **only from your workstation**.
- **VPC**
  - Minimal, single-AZ VPC with public subnet (optional EC2 demo).
- **IAM**
  - A least-privilege role using AWS-managed `ReadOnlyAccess` policy.
  - No IAM users created.
- **VPC Flow Logs**
  - Enabled (to ACTIVE) for any **default VPC** found in `eu-west-1` and `eu-west-2`.
- **Encryption**
  - S3 bucket encryption enabled by default for all CloudTrail logs.

---

## ⚙️ Variables

| Variable | Description | Example |
|-----------|--------------|----------|
| `allowed_ssh_cidr` | Your workstation IP/CIDR for SSH ingress | `203.0.113.4/32` |
| `cloudtrail_bucket_name` | Optional custom bucket name (must be globally unique) | `my-secure-logs-bucket` |

> ⚠️ The `allowed_ssh_cidr` variable is **required**,it is intentionally left empty by default to prevent accidental open SSH access.

---

## 🚀 Quick Start (PowerShell)

```powershell
cd examples/secure
terraform init
terraform plan -var "allowed_ssh_cidr=203.0.113.4/32"
terraform apply -var "allowed_ssh_cidr=203.0.113.4/32" -auto-approve
```

To specify a custom CloudTrail bucket name:

```powershell
terraform apply `
  -var "allowed_ssh_cidr=203.0.113.4/32" `
  -var "cloudtrail_bucket_name=my-secure-logs-bucket" `
  -auto-approve
```

---

## 🧪 Validate with Nimbus Guard

1. After Terraform apply completes, run the **Nimbus Guard scanner** in the same AWS account and region(s).  
2. You should expect:
   - **No HIGH or CRITICAL findings** for:
     - Public S3 buckets  
     - Open security groups (SSH)  
     - IAM wildcard permissions  
     - Missing CloudTrail  

---

## 🧹 Cleanup

When finished, safely destroy the demo resources:

```powershell
terraform destroy -var "allowed_ssh_cidr=203.0.113.4/32" -auto-approve
```

---

## 🔒 Notes & Safety

- Bucket names are randomized by default to avoid collisions.  
- The S3 bucket has **Block Public Access** enabled and **private ACLs only**.  
- The IAM role uses **AWS-managed `ReadOnlyAccess`**, avoiding over-permissive custom policies.  
- No IAM users are created — only a demo EC2-assumable role.

---

## 🧭 Next Steps

- Optionally, add a **tiny EC2 instance** in the public subnet to test SSH connectivity via the locked-down SG.  
- Generate an **outputs summary script** (URLs, IDs, CloudTrail ARNs) for integration testing.  
- Try the **insecure example** to see Nimbus Guard detect intentional misconfigurations.

---

*End of Secure Example, Nimbus Guard PASS Baseline*
