variable "target_id" {
  type        = string
  nullable    = false
  description = "Organization account, root, or unit."


  validation {
    condition = (
      length(var.target_id) == 12 ||      # Account ID
      startswith(var.target_id, "ou-") || # OU
      startswith(var.target_id, "r-")     # Root
    )
    error_message = "target_id must be a 12-digit AWS account ID, an OU ID (ou-xxxx-xxxxxxxx), or the root ID (r-xxxx)."
  }
}

# EC2

variable "deny_imds_v1_ec2" {
  type = bool
}

# IAM

variable "deny_iam_user_creation" {
  type = bool
}

variable "deny_saml_provider_not_aws_sso" {
  type        = bool
  description = "Deny creation of IAM SAML providers (Pattern 1 guardrail for AWS SSO only environments)"
}

variable "allowed_iam_users" {
  type        = list(string)
  default     = []
  description = "List of IAM user ARNs that are allowed to be created. Format: arn:aws:iam::ACCOUNT_ID:user/USERNAME"
}

# RDS

variable "deny_rds_unencrypted" {
  type        = bool
  description = "Deny creation of RDS instances and clusters without encryption at rest"
}
