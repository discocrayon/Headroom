locals {
  # See https://ramimac.me/terraform-minimized-scps for why jsonencode() is needed
  scp_1_content = jsonencode(
    jsondecode(data.aws_iam_policy_document.scp_1.json)
  )
  #
  # This is for validating SCP maximum length at plan time, rather than apply time
  #
  scp_length_1 = length(local.scp_1_content)
  # See https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values
  validation_check_1 = (local.scp_length_1 <= 5120) ? "All good. This is a no-op." : error("[Error] String length exceeds 5120 characters, right now it is ${local.scp_length_1}")
}

#
# Data sources
#

data "aws_iam_policy_document" "scp_1" {
  source_policy_documents = [jsonencode(local.scp_1_denies)]
}

#
# SCP 1
#
# There is a maximum limit of 5 direct SCP attachments per target
# If `FullAWSAccess` has not been removed, there is a max of 4
resource "aws_organizations_policy" "scp_1" {
  count = length(local.included_scp_1_deny_statements) > 0 ? 1 : 0

  name        = "Scp1For-${var.target_id}"
  description = "See Sids for more info"
  content = local.scp_1_content
  type = "SERVICE_CONTROL_POLICY"
}

resource "aws_organizations_policy_attachment" "attach_scp_1_to_account" {
  count = length(local.included_scp_1_deny_statements) > 0 ? 1 : 0

  policy_id = aws_organizations_policy.scp_1[0].id
  target_id = var.target_id
}
