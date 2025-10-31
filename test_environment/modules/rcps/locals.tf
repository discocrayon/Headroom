locals {
  # See https://ramimac.me/terraform-minimized-scps for why jsonencode() is needed
  rcp_1_content = jsonencode(
    jsondecode(data.aws_iam_policy_document.rcp_1.json)
  )
  #
  # This is for validating RCP maximum length at plan time, rather than apply time
  #
  rcp_length_1 = length(local.rcp_1_content)
  # See https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values
  validation_check_1 = (local.rcp_length_1 <= 5120) ? "All good. This is a no-op." : error("[Error] String length exceeds 5120 characters, right now it is ${local.rcp_length_1}")

  rcp_1_policy = {
    "Version" = "2012-10-17"
    "Statement" = [
      {
        "Sid"    = "EnforceOrgIdentities"
        "Effect" = "Deny"
        "Principal" = "*"
        "Action" = [
          "sts:AssumeRole",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount" = var.third_party_account_ids
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    ]
  }
}

#
# Data sources
#

data "aws_iam_policy_document" "rcp_1" {
  source_policy_documents = [jsonencode(local.rcp_1_policy)]
}

