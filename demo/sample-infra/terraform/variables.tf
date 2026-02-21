# =============================================================================
# Variables for Sample Infrastructure
# =============================================================================

variable "region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "production"
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
  # NOTE: No default — passed at apply time via TF_VAR_db_password or -var flag
}
