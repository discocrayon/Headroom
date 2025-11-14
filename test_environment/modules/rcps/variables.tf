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

variable "third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to assume roles in this target ID."

  validation {
    condition = alltrue([
      for account_id in var.third_party_assumerole_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All third_party_assumerole_account_ids_allowlist must be valid 12-digit AWS account IDs."
  }
}

variable "enforce_assume_role_org_identities" {
  type        = bool
  description = "Enforce that role assumptions are restricted to organization identities and specified third-party accounts."
}

variable "third_party_s3_access_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to access S3 buckets in this target ID."

  validation {
    condition = alltrue([
      for account_id in var.third_party_s3_access_account_ids_allowlist : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All third_party_s3_access_account_ids_allowlist must be valid 12-digit AWS account IDs."
  }
}

variable "deny_s3_third_party_access" {
  type        = bool
  description = "Deny S3 access from third-party accounts except those in the allowlist."
}
