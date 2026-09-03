# Neither ViewOnlyAccess nor SecurityAudit grants ecr:DescribeRepositoryCreationTemplates,
# so the one read Headroom needs beyond the two managed policies is granted here
data "aws_iam_policy_document" "headroom_ecr_creation_templates" {
  statement {
    sid       = "DescribeECRRepositoryCreationTemplates"
    effect    = "Allow"
    actions   = ["ecr:DescribeRepositoryCreationTemplates"]
    resources = ["*"]
  }
}
