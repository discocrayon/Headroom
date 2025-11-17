# Test Secrets Manager secrets for deny_secrets_manager_third_party_access RCP functionality testing

# Secret 1: Secret with CrowdStrike third-party access (compliant)
resource "aws_secretsmanager_secret" "third_party_vendor_a" {
  provider = aws.acme_co
  name     = "headroom-test-vendor-a-secret"

  tags = {
    Purpose = "Headroom Secrets Manager test - third-party vendor"
  }
}

resource "aws_secretsmanager_secret_version" "third_party_vendor_a" {
  provider      = aws.acme_co
  secret_id     = aws_secretsmanager_secret.third_party_vendor_a.id
  secret_string = "test-secret-value-a"
}

resource "aws_secretsmanager_secret_policy" "third_party_vendor_a" {
  provider  = aws.acme_co
  secret_arn = aws_secretsmanager_secret.third_party_vendor_a.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::749430749651:root"  # CrowdStrike
        }
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "*"
      }
    ]
  })
}

# Secret 2: Secret with multiple third-party accounts (compliant - Barracuda + Check Point)
resource "aws_secretsmanager_secret" "third_party_vendor_b" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-vendor-b-secret"

  tags = {
    Purpose = "Headroom Secrets Manager test - multiple third-parties"
  }
}

resource "aws_secretsmanager_secret_version" "third_party_vendor_b" {
  provider      = aws.shared_foo_bar
  secret_id     = aws_secretsmanager_secret.third_party_vendor_b.id
  secret_string = "test-secret-value-b"
}

resource "aws_secretsmanager_secret_policy" "third_party_vendor_b" {
  provider  = aws.shared_foo_bar
  secret_arn = aws_secretsmanager_secret.third_party_vendor_b.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::758245563457:root",  # Barracuda
            "arn:aws:iam::517716713836:root"   # Check Point
          ]
        }
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

# Secret 3: Secret with wildcard principal (violation)
resource "aws_secretsmanager_secret" "wildcard_secret" {
  provider = aws.fort_knox
  name     = "headroom-test-wildcard-secret"

  tags = {
    Purpose = "Headroom Secrets Manager test - wildcard violation"
  }
}

resource "aws_secretsmanager_secret_version" "wildcard_secret" {
  provider      = aws.fort_knox
  secret_id     = aws_secretsmanager_secret.wildcard_secret.id
  secret_string = "test-secret-value-wildcard"
}

resource "aws_secretsmanager_secret_policy" "wildcard_secret" {
  provider  = aws.fort_knox
  secret_arn = aws_secretsmanager_secret.wildcard_secret.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

# Secret 4: Secret with organization account only (compliant, filtered out from results)
resource "aws_secretsmanager_secret" "org_only_secret" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-org-only-secret"

  tags = {
    Purpose = "Headroom Secrets Manager test - org account only"
  }
}

resource "aws_secretsmanager_secret_version" "org_only_secret" {
  provider      = aws.shared_foo_bar
  secret_id     = aws_secretsmanager_secret.org_only_secret.id
  secret_string = "test-secret-value-org"
}

resource "aws_secretsmanager_secret_policy" "org_only_secret" {
  provider  = aws.shared_foo_bar
  secret_arn = aws_secretsmanager_secret.org_only_secret.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.acme_co.account_id
        }
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

# Secret 5: Secret without resource policy (no findings)
resource "aws_secretsmanager_secret" "no_policy_secret" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-no-policy-secret"

  tags = {
    Purpose = "Headroom Secrets Manager test - no policy"
  }
}

resource "aws_secretsmanager_secret_version" "no_policy_secret" {
  provider      = aws.shared_foo_bar
  secret_id     = aws_secretsmanager_secret.no_policy_secret.id
  secret_string = "test-secret-value-no-policy"
}

# No policy attached - this secret will be skipped during analysis
