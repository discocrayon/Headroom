variable "target_id" {
  type        = string
  description = "Organization account, root, or unit."

  validation {
    condition = (
      length(var.target_id) == 12 ||       # Account ID
      startswith(var.target_id, "ou-") ||  # OU
      startswith(var.target_id, "r-")      # Root
    )
    error_message = "target_id must be a 12-digit AWS account ID, an OU ID (ou-xxxx-xxxxxxxx), or the root ID (r-xxxx)."
  }
}

# AOSS (OpenSearch Serverless)

variable "deny_aoss_third_party_access" {
  type        = bool
  description = "Deny third-party account access to OpenSearch Serverless resources"
}

variable "aoss_third_party_access_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs permitted to access AOSS resources"

  validation {
    condition = alltrue([
      for account_id in var.aoss_third_party_access_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All account IDs must be valid 12-digit AWS account IDs."
  }
}

# ECR

variable "deny_ecr_third_party_access" {
  type        = bool
  description = "Deny ECR access to accounts outside the organization unless explicitly allowed."
}

variable "ecr_third_party_access_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs permitted to access ECR repositories in this target ID."

  validation {
    condition = alltrue([
      for account_id in var.ecr_third_party_access_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All ecr_third_party_access_account_ids_allowlist must be valid 12-digit AWS account IDs."
  }
}

# S3

variable "deny_s3_third_party_access" {
  type        = bool
  description = "Deny S3 access from third-party accounts except those in the allowlist."
}

variable "s3_third_party_access_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to access S3 buckets in this target ID."

  validation {
    condition = alltrue([
      for account_id in var.s3_third_party_access_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All s3_third_party_access_account_ids_allowlist must be valid 12-digit AWS account IDs."
  }
}

# SQS

variable "deny_sqs_third_party_access" {
  type        = bool
  description = "Deny SQS access from third-party accounts except those in the allowlist"
}

variable "sqs_third_party_access_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs permitted to access SQS queues"

  validation {
    condition = alltrue([
      for account_id in var.sqs_third_party_access_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All account IDs must be valid 12-digit AWS account IDs."
  }
}

# STS

variable "deny_sts_third_party_assumerole" {
  type        = bool
  description = "Deny STS AssumeRole from third-party accounts except those in the allowlist."
}

variable "sts_third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to assume roles in this target ID."

  validation {
    condition = alltrue([
      for account_id in var.sts_third_party_assumerole_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All sts_third_party_assumerole_account_ids_allowlist must be valid 12-digit AWS account IDs."
  }
}
