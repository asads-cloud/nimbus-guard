
# GitHub OIDC provider (account-scoped)
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # GitHub’s well-known SHA1 root CA thumbprint for token.actions.githubusercontent.com
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = var.tags
}

# Readonly policy
data "aws_iam_policy_document" "nimbus_guard_readonly" {
  statement {
    sid     = "ReadOnlyCore"
    effect  = "Allow"
    actions = [
      # S3
      "s3:Get*", "s3:List*",
      # EC2
      "ec2:Describe*",
      # IAM
      "iam:Get*", "iam:List*",
      # CloudTrail
      "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
      # CloudWatch (metrics/alarms)
      "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
      # CloudWatch Logs
      "logs:Describe*", "logs:Get*", "logs:List*",
      # Organizations
      "organizations:Describe*", "organizations:List*", "organizations:Get*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "nimbus_guard_scan_policy" {
  name        = "nimbus-guard-scan-policy"
  description = "Read-only (Describe/List/Get) permissions for Nimbus Guard scanning"
  policy      = data.aws_iam_policy_document.nimbus_guard_readonly.json
  tags        = var.tags
}

# Role & trust
data "aws_iam_policy_document" "nimbus_guard_trust" {
  statement {
    sid     = "GitHubOIDCTrust"
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = [var.github_audience] # default "sts.amazonaws.com"
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.repo_name}:*"]
    }
  }
}

resource "aws_iam_role" "nimbus_guard_scan" {
  name                 = "nimbus-guard-scan"
  assume_role_policy   = data.aws_iam_policy_document.nimbus_guard_trust.json
  description          = "OIDC-assumable role for Nimbus Guard scans from GitHub Actions"
  max_session_duration = var.max_session_duration
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "nimbus_guard_attach" {
  role       = aws_iam_role.nimbus_guard_scan.name
  policy_arn = aws_iam_policy.nimbus_guard_scan_policy.arn
}
