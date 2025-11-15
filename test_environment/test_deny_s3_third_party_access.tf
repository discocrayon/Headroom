# Test S3 buckets for deny_s3_third_party_access RCP functionality testing

# Third-party account IDs used for testing (common security vendors)
locals {
  test_third_party_crowdstrike = "749430749651"  # CrowdStrike
  test_third_party_barracuda   = "758245563457"  # Barracuda
  test_third_party_checkpoint  = "517716713836"  # Check Point
}

# Bucket 1: Single third-party account access (compliant)
resource "aws_s3_bucket" "single_third_party" {
  provider = aws.acme_co
  bucket   = "headroom-test-single-third-party-${data.aws_caller_identity.acme_co.account_id}"

  tags = {
    Purpose = "Headroom S3 third-party test - single vendor"
  }
}

resource "aws_s3_bucket_policy" "single_third_party" {
  provider = aws.acme_co
  bucket   = aws_s3_bucket.single_third_party.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.test_third_party_crowdstrike}:root"
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.single_third_party.arn,
          "${aws_s3_bucket.single_third_party.arn}/*"
        ]
      }
    ]
  })
}

# Bucket 2: Multiple third-party accounts with different actions (compliant)
resource "aws_s3_bucket" "multiple_third_parties" {
  provider = aws.shared_foo_bar
  bucket   = "headroom-test-multiple-third-parties-${data.aws_caller_identity.shared_foo_bar.account_id}"

  tags = {
    Purpose = "Headroom S3 third-party test - multiple vendors"
  }
}

resource "aws_s3_bucket_policy" "multiple_third_parties" {
  provider = aws.shared_foo_bar
  bucket   = aws_s3_bucket.multiple_third_parties.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${local.test_third_party_barracuda}:root",
            "arn:aws:iam::${local.test_third_party_checkpoint}:root"
          ]
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.multiple_third_parties.arn}/*"
      }
    ]
  })
}

# Bucket 3: Wildcard principal (violation)
resource "aws_s3_bucket" "wildcard_principal" {
  provider = aws.fort_knox
  bucket   = "headroom-test-wildcard-${data.aws_caller_identity.fort_knox.account_id}"

  tags = {
    Purpose = "Headroom S3 third-party test - intentional wildcard violation"
  }
}

resource "aws_s3_bucket_policy" "wildcard_principal" {
  provider = aws.fort_knox
  bucket   = aws_s3_bucket.wildcard_principal.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.wildcard_principal.arn}/*"
      }
    ]
  })
}

# Bucket 4: No policy (should be skipped)
resource "aws_s3_bucket" "no_policy" {
  provider = aws.acme_co
  bucket   = "headroom-test-no-policy-${data.aws_caller_identity.acme_co.account_id}"

  tags = {
    Purpose = "Headroom S3 third-party test - no bucket policy"
  }
}

# Bucket 5: Mixed org and third-party access (compliant)
resource "aws_s3_bucket" "mixed_access" {
  provider = aws.shared_foo_bar
  bucket   = "headroom-test-mixed-access-${data.aws_caller_identity.shared_foo_bar.account_id}"

  tags = {
    Purpose = "Headroom S3 third-party test - mixed org and third-party"
  }
}

resource "aws_s3_bucket_policy" "mixed_access" {
  provider = aws.shared_foo_bar
  bucket   = aws_s3_bucket.mixed_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.acme_co.account_id}:root",
            "arn:aws:iam::${local.test_third_party_crowdstrike}:root"
          ]
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.mixed_access.arn,
          "${aws_s3_bucket.mixed_access.arn}/*"
        ]
      }
    ]
  })
}

# Bucket 6: S3:* wildcard action with specific third-party (compliant)
resource "aws_s3_bucket" "wildcard_action" {
  provider = aws.shared_foo_bar
  bucket   = "headroom-test-wildcard-action-${data.aws_caller_identity.shared_foo_bar.account_id}"

  tags = {
    Purpose = "Headroom S3 third-party test - wildcard action but specific principal"
  }
}

resource "aws_s3_bucket_policy" "wildcard_action" {
  provider = aws.shared_foo_bar
  bucket   = aws_s3_bucket.wildcard_action.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.test_third_party_barracuda}:root"
        }
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.wildcard_action.arn,
          "${aws_s3_bucket.wildcard_action.arn}/*"
        ]
      }
    ]
  })
}

# Data sources for account IDs (already defined in main test_environment, but repeated for clarity)
data "aws_caller_identity" "acme_co" {
  provider = aws.acme_co
}

data "aws_caller_identity" "shared_foo_bar" {
  provider = aws.shared_foo_bar
}

data "aws_caller_identity" "fort_knox" {
  provider = aws.fort_knox
}
