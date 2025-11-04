variable "github_org" {
  description = "GitHub organization or username"
  type        = string
}

variable "repo_name" {
  description = "Repository name"
  type        = string
}

variable "github_audience" {
  description = "OIDC audience"
  type        = string
  default     = "sts.amazonaws.com"
}

variable "max_session_duration" {
  description = "IAM role session duration (seconds)"
  type        = number
  default     = 3600
}

variable "tags" {
  description = "Common tags to apply"
  type        = map(string)
  default     = { Project = "nimbus-guard" }
}
