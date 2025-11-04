#----------------- OIDC ----------------------------------------------------------------------#

module "nimbus_guard_oidc" {
  source = "../../modules/nimbus_guard_oidc"

  github_org = var.github_org
  repo_name  = var.repo_name

  # overrides
  # github_audience       = "sts.amazonaws.com"
  # max_session_duration  = 3600
  # tags                  = { Project = "nimbus-guard", Environment = "dev" }
}

output "nimbus_guard_role_arn" {
  value       = module.nimbus_guard_oidc.nimbus_guard_role_arn
  description = "IAM Role ARN for Nimbus Guard GitHub OIDC scans"
}
