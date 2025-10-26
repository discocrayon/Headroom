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

# EC2

variable "deny_imds_v1_ec2" {
  type    = bool
}
