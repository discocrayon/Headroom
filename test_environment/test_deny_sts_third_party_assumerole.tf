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

  # Map of all roles for DRY policy attachment
  test_roles = {
    third_party_vendor_a       = aws_iam_role.third_party_vendor_a.id
    third_party_vendor_b       = aws_iam_role.third_party_vendor_b.id
    wildcard_role              = aws_iam_role.wildcard_role.id
    lambda_execution           = aws_iam_role.lambda_execution.id
    multi_service              = aws_iam_role.multi_service.id
    mixed_principals           = aws_iam_role.mixed_principals.id
    saml_federation            = aws_iam_role.saml_federation.id
    oidc_federation            = aws_iam_role.oidc_federation.id
    org_account_cross_access   = aws_iam_role.org_account_cross_access.id
    complex_multi_statement    = aws_iam_role.complex_multi_statement.id
    third_party_user           = aws_iam_role.third_party_user.id
    plain_account_id           = aws_iam_role.plain_account_id.id
    mixed_formats              = aws_iam_role.mixed_formats.id
    conditional_third_party    = aws_iam_role.conditional_third_party.id
    ultra_complex              = aws_iam_role.ultra_complex.id
  }
}

# Role 1: Simple third-party account access (CrowdStrike)
resource "aws_iam_role" "third_party_vendor_a" {
  provider = aws.acme_co
  name     = "ThirdPartyVendorA"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::749430749651:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Role 2: Multiple third-party accounts (Barracuda + Check Point)
resource "aws_iam_role" "third_party_vendor_b" {
  provider = aws.shared_foo_bar
  name     = "ThirdPartyVendorB"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::758245563457:root",
            "arn:aws:iam::517716713836:root"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Role 3: Wildcard principal (should trigger CloudTrail analysis TODO)
resource "aws_iam_role" "wildcard_role" {
  provider = aws.fort_knox
  name     = "WildcardRole"

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
}

# Role 4: Service principal only (should be skipped)
resource "aws_iam_role" "lambda_execution" {
  provider = aws.shared_foo_bar
  name     = "LambdaExecutionRole"

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
}

# Role 5: Multiple service principals (should be skipped)
resource "aws_iam_role" "multi_service" {
  provider = aws.shared_foo_bar
  name     = "MultiServiceRole"

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
}

# Role 6: Mixed AWS and Service principals (CyberArk)
resource "aws_iam_role" "mixed_principals" {
  provider = aws.shared_foo_bar
  name     = "MixedPrincipalsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS     = "arn:aws:iam::365761988620:root"
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Role 7: Federated principal with SAML (CyberArk account with SAML provider)
resource "aws_iam_role" "saml_federation" {
  provider = aws.shared_foo_bar
  name     = "SAMLFederationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::365761988620:saml-provider/MyProvider"
        }
        Action = "sts:AssumeRoleWithSAML"
      }
    ]
  })
}

# Role 8: Federated principal with Web Identity (GitHub Actions - restricted to specific org and main branch)
resource "aws_iam_role" "oidc_federation" {
  provider = aws.shared_foo_bar
  name     = "OIDCFederationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::365761988620:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:acme-corp/*:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

# Role 9: Organization account cross-access (Duckbill Group)
# This demonstrates cross-account access within an organization
resource "aws_iam_role" "org_account_cross_access" {
  provider = aws.shared_foo_bar
  name     = "OrgAccountCrossAccess"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::151784055945:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Role 10: Multiple statements with different principal types (Forcepoint)
resource "aws_iam_role" "complex_multi_statement" {
  provider = aws.shared_foo_bar
  name     = "ComplexMultiStatementRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::062897671886:root"
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
}

# Role 11: Third-party account with assumed role pattern (Sophos)
# Using :root allows any identity in the account to assume (typical for vendor integrations)
resource "aws_iam_role" "third_party_user" {
  provider = aws.shared_foo_bar
  name     = "ThirdPartyUserRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::978576646331:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "unique-external-id-sophos"
          }
        }
      }
    ]
  })
}

# Role 12: Plain account ID format (not ARN) (Vectra)
resource "aws_iam_role" "plain_account_id" {
  provider = aws.shared_foo_bar
  name     = "PlainAccountIdRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "081802104111"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Role 13: Mix of ARNs and plain account IDs (Ermetic + Zesty)
resource "aws_iam_role" "mixed_formats" {
  provider = aws.shared_foo_bar
  name     = "MixedFormatsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::672188301118:root",
            "242987662583"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Role 14: Role with conditions (third-party account) (Duckbill Group)
resource "aws_iam_role" "conditional_third_party" {
  provider = aws.shared_foo_bar
  name     = "ConditionalThirdPartyRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::151784055945:root"
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
}

# Role 15: Mixed AWS, Service, and Federated (complex scenario) (Check Point + CrowdStrike)
resource "aws_iam_role" "ultra_complex" {
  provider = aws.shared_foo_bar
  name     = "UltraComplexRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::292230061137:root",
            "arn:aws:iam::749430749651:root"
          ]
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::365761988620:saml-provider/CorporateSSO"
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
}

# Inline policies for all roles (using for_each for DRY)
resource "aws_iam_role_policy" "deny_all" {
  provider = aws.shared_foo_bar
  for_each = local.test_roles

  name   = "DenyAll"
  role   = each.value
  policy = local.deny_all_policy
}
