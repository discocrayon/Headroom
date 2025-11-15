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

variable "deny_ec2_ami_owner" {
  type        = bool
  description = "Deny launching EC2 instances from untrusted AMI owners"
}

variable "allowed_ami_owners" {
  type        = list(string)
  default     = []
  description = "List of allowed AMI owner account IDs or aliases (e.g., 'amazon', 'aws-marketplace', '123456789012')"
}

variable "deny_imds_v1_ec2" {
  type = bool
}

# EKS

variable "deny_eks_create_cluster_without_tag" {
  type        = bool
  description = "Deny EKS cluster creation unless PavedRoad=true tag is present"
}

# IAM

variable "deny_iam_user_creation" {
  type = bool
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
