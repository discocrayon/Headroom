resource "aws_iam_role" "org_and_account_info_reader" {
  name = "OrgAndAccountInfoReader"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${aws_organizations_account.security_tooling.id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "org_and_account_info_reader_policy" {
  name        = "OrgAndAccountInfoReaderPolicy"
  description = "Allows listing accounts, describing OUs, and describing tags on accounts and OUs."

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "organizations:DescribeAccount",
          "organizations:DescribeOrganizationalUnit",
          "organizations:ListAccounts",
          "organizations:ListAccountsForParent",
          "organizations:ListChildren",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:ListParents",
          "organizations:ListRoots",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:ListTagsForResource"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "org_and_account_info_reader_attach" {
  role       = aws_iam_role.org_and_account_info_reader.name
  policy_arn = aws_iam_policy.org_and_account_info_reader_policy.arn
}
