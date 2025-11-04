output "nimbus_guard_role_arn" {
  description = "IAM Role ARN for Nimbus Guard GitHub OIDC scans"
  value       = aws_iam_role.nimbus_guard_scan.arn
}
