# Test IAM roles with various trust relationships for RCP functionality testing
# These roles are intentionally "useless" and exist solely to test the RCP analysis engine

locals {
  deny_all_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Role 1: Simple third-party account access
resource "aws_iam_role" "third_party_vendor_a" {
  name = "ThirdPartyVendorA"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::999999999999:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 2: Multiple third-party accounts
resource "aws_iam_role" "third_party_vendor_b" {
  name = "ThirdPartyVendorB"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::888888888888:root",
            "arn:aws:iam::777777777777:root"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 3: Wildcard principal (should trigger CloudTrail analysis TODO)
resource "aws_iam_role" "wildcard_role" {
  name = "WildcardRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 4: Service principal only (should be skipped)
resource "aws_iam_role" "lambda_execution" {
  name = "LambdaExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 5: Multiple service principals (should be skipped)
resource "aws_iam_role" "multi_service" {
  name = "MultiServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "ec2.amazonaws.com",
            "ecs-tasks.amazonaws.com",
            "lambda.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 6: Mixed AWS and Service principals
resource "aws_iam_role" "mixed_principals" {
  name = "MixedPrincipalsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS     = "arn:aws:iam::666666666666:root"
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 7: Federated principal with SAML
resource "aws_iam_role" "saml_federation" {
  name = "SAMLFederationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::111111111111:saml-provider/MyProvider"
        }
        Action = "sts:AssumeRoleWithSAML"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 8: Federated principal with Web Identity
resource "aws_iam_role" "oidc_federation" {
  name = "OIDCFederationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 9: Organization account (should be filtered out as not third-party)
resource "aws_iam_role" "org_account_cross_access" {
  name = "OrgAccountCrossAccess"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::111111111111:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 10: Multiple statements with different principal types
resource "aws_iam_role" "complex_multi_statement" {
  name = "ComplexMultiStatementRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::555555555555:root"
        }
        Action = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 11: Third-party with specific user (not root)
resource "aws_iam_role" "third_party_user" {
  name = "ThirdPartyUserRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::444444444444:user/ExternalUser"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 12: Plain account ID format (not ARN)
resource "aws_iam_role" "plain_account_id" {
  name = "PlainAccountIdRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "333333333333"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 13: Mix of ARNs and plain account IDs
resource "aws_iam_role" "mixed_formats" {
  name = "MixedFormatsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::222222222222:root",
            "333333333333"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 14: Role with conditions (third-party account)
resource "aws_iam_role" "conditional_third_party" {
  name = "ConditionalThirdPartyRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::999888777666:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "unique-external-id-12345"
          }
        }
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

# Role 15: Mixed AWS, Service, and Federated (complex scenario)
resource "aws_iam_role" "ultra_complex" {
  name = "UltraComplexRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::999999999999:root",
            "arn:aws:iam::888888888888:user/SpecialUser"
          ]
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::111111111111:saml-provider/CorporateSSO"
        }
        Action = "sts:AssumeRoleWithSAML"
        Condition = {
          StringEquals = {
            "SAML:aud" = "https://signin.aws.amazon.com/saml"
          }
        }
      }
    ]
  })

  inline_policy {
    name   = "DenyAll"
    policy = local.deny_all_policy
  }
}

