
#-------------------- Providers (fixed regions) --------------------------------------------------------------

# Home region for CloudTrail + S3 bucket
provider "aws" {
  region = "eu-west-1"
}

# Extra region to show capability
provider "aws" {
  alias  = "w2"
  region = "eu-west-2"
}

data "aws_caller_identity" "this" {}

#-------------------- Account-level S3 PAB --------------------------------------------------------------

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

#-------------------- CloudTrail logs S3 bucket (private) --------------------------------------------------------------

resource "aws_s3_bucket" "ct" {
  bucket        = var.cloudtrail_bucket_name
  force_destroy = true  # allow terraform destroy even if logs exist
}

resource "aws_s3_bucket_ownership_controls" "ct" {
  bucket = aws_s3_bucket.ct.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_versioning" "ct" {
  bucket = aws_s3_bucket.ct.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Bucket-level PAB (all flags true)
resource "aws_s3_bucket_public_access_block" "ct" {
  bucket                  = aws_s3_bucket.ct.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Strict bucket policy: allow CloudTrail service to write; not public.
# NOTE: Use the global service principal ONLY (region-specific principals are invalid in S3 policies).
data "aws_iam_policy_document" "ct_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailGetAcl"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.ct.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.ct.arn}/AWSLogs/${data.aws_caller_identity.this.account_id}/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "ct" {
  bucket     = aws_s3_bucket.ct.id
  policy     = data.aws_iam_policy_document.ct_bucket_policy.json
  depends_on = [aws_s3_bucket_public_access_block.ct]
}

#-------------------- Multi-region CloudTrail (actively logging) --------------------------------------------------------------

resource "aws_cloudtrail" "nimbus" {
  name                          = "nimbus-multi-region-trail"
  s3_bucket_name                = aws_s3_bucket.ct.id
  is_multi_region_trail         = true
  enable_logging                = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # Make sure bucket policy is in place first
  depends_on = [aws_s3_bucket_policy.ct]
}

#-------------------- Default VPC Flow Logs — eu-west-1 and eu-west-2 --------------------------------------------------------------

# eu-west-1
data "aws_vpcs" "default_w1" {
  filter {
    name   = "isDefault"
    values = ["true"]
  }
}

resource "aws_cloudwatch_log_group" "vpc_flow_w1" {
  name              = "/aws/vpc/flow-logs/eu-west-1"
  retention_in_days = 30
}

resource "aws_iam_role" "vpc_flow_w1" {
  name = "vpc-flow-logs-eu-west-1"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_w1" {
  name = "vpc-flow-logs-to-cwl-eu-west-1"
  role = aws_iam_role.vpc_flow_w1.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = "arn:aws:logs:eu-west-1:${data.aws_caller_identity.this.account_id}:log-group:${aws_cloudwatch_log_group.vpc_flow_w1.name}:*"
    }]
  })
}

resource "aws_flow_log" "default_vpc_w1" {
  for_each              = toset(data.aws_vpcs.default_w1.ids)
  vpc_id                = each.value
  log_destination_type  = "cloud-watch-logs"
  log_destination       = aws_cloudwatch_log_group.vpc_flow_w1.arn
  iam_role_arn          = aws_iam_role.vpc_flow_w1.arn
  traffic_type          = "ALL"
}

# eu-west-2 
data "aws_vpcs" "default_w2" {
  provider = aws.w2
  filter {
    name   = "isDefault"
    values = ["true"]
  }
}

resource "aws_cloudwatch_log_group" "vpc_flow_w2" {
  provider          = aws.w2
  name              = "/aws/vpc/flow-logs/eu-west-2"
  retention_in_days = 30
}

resource "aws_iam_role" "vpc_flow_w2" {
  name = "vpc-flow-logs-eu-west-2"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_w2" {
  name = "vpc-flow-logs-to-cwl-eu-west-2"
  role = aws_iam_role.vpc_flow_w2.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = "arn:aws:logs:eu-west-2:${data.aws_caller_identity.this.account_id}:log-group:${aws_cloudwatch_log_group.vpc_flow_w2.name}:*"
    }]
  })
}

resource "aws_flow_log" "default_vpc_w2" {
  provider              = aws.w2
  for_each              = toset(data.aws_vpcs.default_w2.ids)
  vpc_id                = each.value
  log_destination_type  = "cloud-watch-logs"
  log_destination       = aws_cloudwatch_log_group.vpc_flow_w2.arn
  iam_role_arn          = aws_iam_role.vpc_flow_w2.arn
  traffic_type          = "ALL"
}
