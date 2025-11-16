# Test KMS keys with various access patterns for RCP functionality testing
# These keys are intentionally created to test the RCP analysis engine

# Key 1: Third-party vendor access (CrowdStrike) - compliant
resource "aws_kms_key" "third_party_vendor_crowdstrike" {
  provider    = aws.acme_co
  description = "Headroom test - KMS key with CrowdStrike third-party access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.acme_co.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CrowdStrike Access"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::749430749651:root"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "Headroom KMS test - third-party vendor access"
  }
}

resource "aws_kms_alias" "third_party_vendor_crowdstrike" {
  provider      = aws.acme_co
  name          = "alias/headroom-test-crowdstrike"
  target_key_id = aws_kms_key.third_party_vendor_crowdstrike.key_id
}

# Key 2: Multiple third-party accounts (Barracuda + Check Point) - compliant
resource "aws_kms_key" "multiple_third_party_vendors" {
  provider    = aws.shared_foo_bar
  description = "Headroom test - KMS key with multiple third-party vendors"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.shared_foo_bar.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Multiple Vendors"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::758245563457:root",
            "arn:aws:iam::517716713836:root"
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "Headroom KMS test - multiple third-party vendors"
  }
}

resource "aws_kms_alias" "multiple_third_party_vendors" {
  provider      = aws.shared_foo_bar
  name          = "alias/headroom-test-multi-vendor"
  target_key_id = aws_kms_key.multiple_third_party_vendors.key_id
}

# Key 3: Wildcard principal (violation)
resource "aws_kms_key" "wildcard_key" {
  provider    = aws.shared_foo_bar
  description = "Headroom test - KMS key with wildcard principal"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.shared_foo_bar.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Wildcard Access"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "Headroom KMS test - wildcard principal (violation)"
  }
}

resource "aws_kms_alias" "wildcard_key" {
  provider      = aws.shared_foo_bar
  name          = "alias/headroom-test-wildcard"
  target_key_id = aws_kms_key.wildcard_key.key_id
}

# Key 4: Organization-only access (no findings expected)
resource "aws_kms_key" "org_only" {
  provider    = aws.fort_knox
  description = "Headroom test - KMS key with org-only access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.fort_knox.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "Headroom KMS test - org-only access"
  }
}

resource "aws_kms_alias" "org_only" {
  provider      = aws.fort_knox
  name          = "alias/headroom-test-org-only"
  target_key_id = aws_kms_key.org_only.key_id
}

# Key 5: Service principal only (no findings expected)
resource "aws_kms_key" "service_principal" {
  provider    = aws.fort_knox
  description = "Headroom test - KMS key with service principal only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.fort_knox.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "Headroom KMS test - service principal only"
  }
}

resource "aws_kms_alias" "service_principal" {
  provider      = aws.fort_knox
  name          = "alias/headroom-test-service-principal"
  target_key_id = aws_kms_key.service_principal.key_id
}

# Data sources for account IDs (needed for policy document references)
data "aws_caller_identity" "acme_co" {
  provider = aws.acme_co
}

data "aws_caller_identity" "shared_foo_bar" {
  provider = aws.shared_foo_bar
}

data "aws_caller_identity" "fort_knox" {
  provider = aws.fort_knox
}
