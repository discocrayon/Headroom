#
# RCP 1
#
# There is a maximum limit of 5 direct RCP attachments per target
resource "aws_organizations_policy" "rcp_1" {
  name        = "Rcp1For-${var.target_id}"
  description = "Enforce organization identities for role assumptions"
  content     = local.rcp_1_content
  type        = "RESOURCE_CONTROL_POLICY"
}

resource "aws_organizations_policy_attachment" "attach_rcp_1_to_account" {
  policy_id = aws_organizations_policy.rcp_1.id
  target_id = var.target_id
}

