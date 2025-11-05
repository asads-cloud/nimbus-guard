# 🚫 Insecure AWS Terraform Example: FAIL Nimbus Guard

## 📄 Example Nimbus Guard Report (HTML Preview)

<details>
<summary>Click to expand full HTML report</summary>
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nimbus Guard Report</title>
<style>body { font-family: system-ui, Segoe UI, Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; padding: 24px; }h1, h2, h3, h4 { margin-top: 1.25em; }table { border-collapse: collapse; width: 100%; margin: 12px 0; }th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; }th { background: #f5f5f5; }code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }pre { background: #fafafa; border: 1px solid #eee; padding: 12px; overflow: auto; }</style>
<body>
<h1 id="nimbus-guard-report">Nimbus Guard Report</h1>
<p><strong>Run Timestamp (UTC):</strong> 2025-11-05T12:49:36Z<br>
<strong>Total Findings:</strong> 4<br>
<strong>Fail Threshold:</strong> HIGH</p>
<h2 id="findings-by-severity">Findings by Severity</h2>
<table>
<thead>
<tr>
<th style="text-align: right;">Severity</th>
<th style="text-align: right;">Count</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: right;">CRITICAL</td>
<td style="text-align: right;">1</td>
</tr>
<tr>
<td style="text-align: right;">HIGH</td>
<td style="text-align: right;">1</td>
</tr>
<tr>
<td style="text-align: right;">MEDIUM</td>
<td style="text-align: right;">2</td>
</tr>
<tr>
<td style="text-align: right;">LOW</td>
<td style="text-align: right;">0</td>
</tr>
<tr>
<td style="text-align: right;">INFO</td>
<td style="text-align: right;">0</td>
</tr>
</tbody>
</table>
<h2 id="findings-by-service">Findings by Service</h2>
<table>
<thead>
<tr>
<th style="text-align: right;">Service</th>
<th style="text-align: right;">Count</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: right;">iam</td>
<td style="text-align: right;">1</td>
</tr>
<tr>
<td style="text-align: right;">s3</td>
<td style="text-align: right;">2</td>
</tr>
<tr>
<td style="text-align: right;">sg</td>
<td style="text-align: right;">1</td>
</tr>
</tbody>
</table>
<h2 id="details">Details</h2>
<table>
<thead>
<tr>
<th>Severity</th>
<th>Service</th>
<th>Region</th>
<th>Resource</th>
<th>Title</th>
</tr>
</thead>
<tbody>
<tr>
<td>CRITICAL</td>
<td>iam</td>
<td>global</td>
<td>role:ng-insecure-role</td>
<td>Full admin permissions via policy 'ng-insecure-full-admin'</td>
</tr>
<tr>

<tr>
<td>HIGH</td>
<td>sg</td>
<td>eu-west-1</td>
<td>sg-0e17e1743e81</td>
<td>Security Group open to world on ports 80-80</td>
</tr>
<tr>

<tr>
<td>MEDIUM</td>
<td>s3</td>
<td>eu-west-2</td>
<td>account:&lt;account-number&gt;</td>
<td>Account-level PAB incomplete</td>
</tr>
<tr>
<td>MEDIUM</td>
<td>s3</td>
<td>eu-west-1</td>
<td>account:&lt;account-number&gt;&lt;/account-number&gt;</td>
<td>Account-level PAB incomplete</td>
</tr>
</tbody>
</table>
<h3 id="finding-details">Finding Details</h3>
<h4 id="1-critical-iam-roleng-insecure-role">1. CRITICAL — iam — role:ng-insecure-role</h4>
<ul>
<li><strong>Region:</strong> global</li>
<li><strong>Title:</strong> Full admin permissions via policy 'ng-insecure-full-admin'</li>
<li><strong>Severity:</strong> CRITICAL</li>
<li><strong>Service:</strong> iam</li>
<li><strong>Details (YAML-like):</strong></li>
</ul>
<p>policy: ng-insecure-full-admin
reason: Effect=Allow with Action='*' and Resource='*'</p>
<h4 id="2-high-sg-sg-0e17e1743e818ef82">2. HIGH — sg — sg-0e17e1743e818ef82</h4>
<ul>
<li><strong>Region:</strong> eu-west-1</li>
<li><strong>Title:</strong> Security Group open to world on ports 80-80</li>
<li><strong>Severity:</strong> HIGH</li>
<li><strong>Service:</strong> sg</li>
<li><strong>Details (YAML-like):</strong></li>
</ul>
<p>description: null
from_port: 80
group_id: sg-0e17e1743e818ef82
group_name: ng-world-http
ip_protocol: tcp
prefix_list_ids: []
to_port: 80
user_id_group_pairs: []
vpc_id: vpc-04fd865de3d0d8705
world_ipv4: true
world_ipv6: false</p>
<h4 id="3-medium-s3-account&lt;account-number&gt;">3. MEDIUM — s3 — account:&lt;account-number&gt;</h4>
<ul>
<li><strong>Region:</strong> eu-west-2</li>
<li><strong>Title:</strong> Account-level PAB incomplete</li>
<li><strong>Severity:</strong> MEDIUM</li>
<li><strong>Service:</strong> s3</li>
<li><strong>Details (YAML-like):</strong></li>
</ul>
<p>config:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: false
flags_false:
- RestrictPublicBuckets</p>
<h4 id="4-medium-s3-account&lt;account-number&gt;">4. MEDIUM — s3 — account:&lt;account-number&gt;&lt;/account-number&gt;</h4>
<ul>
<li><strong>Region:</strong> eu-west-1</li>
<li><strong>Title:</strong> Account-level PAB incomplete</li>
<li><strong>Severity:</strong> MEDIUM</li>
<li><strong>Service:</strong> s3</li>
<li><strong>Details (YAML-like):</strong></li>
</ul>
<p>config:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: false
flags_false:
- RestrictPublicBuckets</p>
<p><em>Generated by Nimbus Guard. Report is self-contained and link-free.</em></p>
</body>
</html>
</details>


This Terraform example provisions an **intentionally misconfigured AWS environment** designed to **trigger Nimbus Guard findings** for demonstration and testing.  
It deploys infrastructure across **`eu-west-1`** and **`eu-west-2`**, containing a mix of **CRITICAL**, **HIGH**, and **MEDIUM** misconfigurations that a real security scanner should detect.

---

## 🧩 What This Configuration Intentionally Demonstrates

- **IAM (CRITICAL)**
  - Creates a role `ng-insecure-role` with an **inline policy granting `Action="*"` and `Resource="*"`**, simulating full administrative exposure.
- **Security Group (HIGH)**
  - A group `ng-world-http` allows inbound TCP/80 from **`0.0.0.0/0`**, representing a world-open ingress rule.
- **S3 Account-Level Public Access Block (MEDIUM)**
  - Configures account-level S3 **Public Access Block (PAB)** with **one flag disabled (`restrict_public_buckets=false`)**, showing partial compliance.
- **CloudTrail**
  - One **multi-region trail** (`nimbus-multi-region-trail`) correctly configured to log to a secure S3 bucket, used to test proper logging coverage.
- **VPC Flow Logs**
  - **Active flow logs** for all **default VPCs** in both `eu-west-1` and `eu-west-2`, ensuring the scanner detects these as correctly configured.
- **No Root MFA enforcement**
  - Like all Terraform deployments, root MFA cannot be enforced, Nimbus Guard should flag this if it checks the root account.

---

## ⚙️ Variables

| Variable | Description | Example |
|-----------|-------------|----------|
| `cloudtrail_bucket_name` | Globally unique bucket name for CloudTrail logs | `asads-ds-s3-safesw` |

> ⚠️ Must be globally unique. Use only lowercase letters, numbers, and hyphens.

---

## 🚀 Quick Start (PowerShell)

```powershell
cd examples/insecure
terraform init -upgrade
terraform apply -auto-approve -var "cloudtrail_bucket_name=asads-ds-s3-safesw"
```

---

## 🧪 Validate with Nimbus Guard

1. After Terraform apply completes, run the **Nimbus Guard scanner** across `eu-west-1` and `eu-west-2`.
2. You should expect:
   - **CRITICAL**
     - IAM role with `Action="*"` and `Resource="*"`
   - **HIGH**
     - Security group open to world (`0.0.0.0/0` on TCP/80)
   - **MEDIUM**
     - S3 account-level Public Access Block incomplete (`restrict_public_buckets` = false)

All other checks (CloudTrail, bucket policies, VPC Flow Logs) should pass as correctly configured.

---

## 🧹 Cleanup

To safely remove all resources and start fresh:

```powershell
cd examples/insecure
terraform destroy -auto-approve -var "cloudtrail_bucket_name=asads-ds-s3-safesw"
```

---

## 🔍 Notes & Behavior

- This example **intentionally fails** three key checks to validate scanner detection logic.
- CloudTrail, S3 bucket, and flow log configurations are otherwise **fully functional**.
- All resources can be cleanly destroyed using `terraform destroy`.
- The setup uses **only eu-west-1 and eu-west-2**, matching the secure baseline region scope.

---

## 🧭 Next Steps

- Compare this insecure configuration’s findings report to the **secure example** output.  
- Validate that Nimbus Guard:
  - Flags the IAM wildcard as **CRITICAL**.
  - Flags the world-open SG as **HIGH**.
  - Flags the incomplete S3 PAB as **MEDIUM**.
- Then redeploy the **secure baseline** to confirm a **0-finding clean scan**.

---

*End of Insecure Example: Nimbus Guard Detection Test*