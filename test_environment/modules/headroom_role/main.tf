# Headroom IAM Role Module
# Creates a Headroom role with read-only access in a subaccount

resource "aws_iam_role" "headroom" {
  name = "Headroom"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id_to_trust}:root"
        }
      }
    ]
  })
}

# We could have a tighter version of this, but the Security Tooling account having non-sensitive reads is par for the course
resource "aws_iam_role_policy_attachment" "headroom_viewonly" {
  role       = aws_iam_role.headroom.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "headroom_securityaudit" {
  role       = aws_iam_role.headroom.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
