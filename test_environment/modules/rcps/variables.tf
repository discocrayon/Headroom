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

# KMS

variable "deny_kms_third_party_access" {
  type        = bool
  description = "Deny KMS access to accounts outside the organization unless explicitly allowed."
}

variable "kms_third_party_access_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs permitted to access KMS keys in this target ID."

  validation {
    condition = alltrue([
      for account_id in var.kms_third_party_access_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All kms_third_party_access_account_ids_allowlist must be valid 12-digit AWS account IDs."
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

variable "s3_third_party_access_exempt_bucket_arns" {
  type        = list(string)
  default     = []
  description = "Bucket ARNs the S3 statement spares by NotResource, each expanded to the bucket and its objects: buckets whose grants no account allowlist can express - a wildcard principal, a Federated or CanonicalUser principal, a CloudFront origin access identity, or a public ACL. Format: arn:aws:s3:::BUCKET_NAME"

  validation {
    condition = alltrue([
      for arn in var.s3_third_party_access_exempt_bucket_arns : startswith(arn, "arn:aws:s3:::") && length(arn) > 13 && !strcontains(arn, "/")
    ])
    error_message = "All s3_third_party_access_exempt_bucket_arns must be bucket ARNs of the form arn:aws:s3:::BUCKET_NAME, with a non-empty bucket name and no object key; the statement appends /* itself."
  }
}

# Secrets Manager

variable "deny_secrets_manager_third_party_access" {
  type        = bool
  description = "Deny Secrets Manager access to third-party accounts not in allowlist"
}

variable "secrets_manager_third_party_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs permitted to access Secrets Manager secrets in this target ID"

  validation {
    condition = alltrue([
      for account_id in var.secrets_manager_third_party_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All secrets_manager_third_party_account_ids_allowlist must be valid 12-digit AWS account IDs."
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

variable "sqs_third_party_access_exempt_queue_arns" {
  type        = list(string)
  default     = []
  description = "Queue ARNs the SQS statement spares by NotResource: queues whose grants no account allowlist can express - a wildcard principal, an Allow with NotPrincipal, or a Federated or CanonicalUser principal. Format: arn:aws:sqs:REGION:ACCOUNT_ID:QUEUE_NAME"

  validation {
    condition = alltrue([
      for arn in var.sqs_third_party_access_exempt_queue_arns : can(regex("^arn:aws:sqs:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+(\\.fifo)?$", arn))
    ])
    error_message = "All sqs_third_party_access_exempt_queue_arns must be queue ARNs of the form arn:aws:sqs:REGION:ACCOUNT_ID:QUEUE_NAME."
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

# Service confused deputy

variable "deny_service_confused_deputy" {
  type        = bool
  description = "Deny AWS services acting on behalf of sources outside the organization unless explicitly allowed."
}

variable "service_confused_deputy_source_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs permitted to drive AWS service calls into resources in this target ID."

  validation {
    condition = alltrue([
      for account_id in var.service_confused_deputy_source_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All service_confused_deputy_source_account_ids_allowlist must be valid 12-digit AWS account IDs."
  }
}
