variable "target_id" {
  type        = string
  nullable    = false
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

variable "third_party_account_ids" {
  type        = list(string)
  nullable    = false
  description = "List of third-party AWS account IDs allowed to assume roles in this organization."

  validation {
    condition = alltrue([
      for account_id in var.third_party_account_ids : length(account_id) == 12 && can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All third_party_account_ids must be valid 12-digit AWS account IDs."
  }
}

