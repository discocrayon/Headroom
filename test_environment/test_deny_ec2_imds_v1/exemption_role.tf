# IAM role carrying the deny_ec2_imds_v1 exemption tag
#
# The SCP exempts callers through aws:PrincipalTag/ExemptFromIMDSv2, which
# reads tags on the IAM role an instance runs as. Tagging the instance exempts
# nothing: no statement in that policy reads instance tags. This role exists so
# the exemption path is tested on the dimension enforcement actually uses.
#
# The tag value is exactly "true". StringNotEquals is case-sensitive, so "True"
# would not exempt.

resource "aws_iam_role" "imdsv1_exempt" {
  provider = aws.fort_knox
  name     = "test-imdsv1-exempt"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })

  tags = {
    ExemptFromIMDSv2 = "true"
  }
}

resource "aws_iam_instance_profile" "imdsv1_exempt" {
  provider = aws.fort_knox
  name     = "test-imdsv1-exempt"
  role     = aws_iam_role.imdsv1_exempt.name
}
