# Test SQS queues for deny_sqs_third_party_access RCP functionality testing

# Third-party account IDs used for testing (common security vendors)
locals {
  test_third_party_crowdstrike = "749430749651"  # CrowdStrike
  test_third_party_barracuda   = "758245563457"  # Barracuda
  test_third_party_checkpoint  = "517716713836"  # Check Point
}

# Queue 1: Single third-party account access (compliant)
resource "aws_sqs_queue" "single_third_party" {
  provider = aws.acme_co
  name     = "headroom-test-single-third-party"

  tags = {
    Purpose = "Headroom SQS third-party test - single vendor"
  }
}

resource "aws_sqs_queue_policy" "single_third_party" {
  provider  = aws.acme_co
  queue_url = aws_sqs_queue.single_third_party.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.test_third_party_crowdstrike}:root"
        }
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage"
        ]
        Resource = aws_sqs_queue.single_third_party.arn
      }
    ]
  })
}

# Queue 2: Multiple third-party accounts with different actions (compliant)
resource "aws_sqs_queue" "multiple_third_parties" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-multiple-third-parties"

  tags = {
    Purpose = "Headroom SQS third-party test - multiple vendors"
  }
}

resource "aws_sqs_queue_policy" "multiple_third_parties" {
  provider  = aws.shared_foo_bar
  queue_url = aws_sqs_queue.multiple_third_parties.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowBarracuda"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.test_third_party_barracuda}:root"
        }
        Action = [
          "sqs:SendMessage",
          "sqs:GetQueueUrl"
        ]
        Resource = aws_sqs_queue.multiple_third_parties.arn
      },
      {
        Sid = "AllowCheckPoint"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.test_third_party_checkpoint}:root"
        }
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage"
        ]
        Resource = aws_sqs_queue.multiple_third_parties.arn
      }
    ]
  })
}

# Queue 3: Wildcard principal (violation)
resource "aws_sqs_queue" "wildcard_principal" {
  provider = aws.fort_knox
  name     = "headroom-test-wildcard-violation"

  tags = {
    Purpose = "Headroom SQS third-party test - intentional wildcard violation"
  }
}

resource "aws_sqs_queue_policy" "wildcard_principal" {
  provider  = aws.fort_knox
  queue_url = aws_sqs_queue.wildcard_principal.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = "sqs:*"
        Resource = aws_sqs_queue.wildcard_principal.arn
      }
    ]
  })
}

# Queue 4: No policy (should be skipped)
resource "aws_sqs_queue" "no_policy" {
  provider = aws.acme_co
  name     = "headroom-test-no-policy"

  tags = {
    Purpose = "Headroom SQS third-party test - no queue policy"
  }
}

# Queue 5: Mixed org and third-party access (compliant)
resource "aws_sqs_queue" "mixed_access" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-mixed-access"

  tags = {
    Purpose = "Headroom SQS third-party test - mixed org and third-party"
  }
}

resource "aws_sqs_queue_policy" "mixed_access" {
  provider  = aws.shared_foo_bar
  queue_url = aws_sqs_queue.mixed_access.id

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
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:GetQueueUrl"
        ]
        Resource = aws_sqs_queue.mixed_access.arn
      }
    ]
  })
}

# Queue 6: Wildcard action with specific third-party (compliant)
resource "aws_sqs_queue" "wildcard_action" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-wildcard-action"

  tags = {
    Purpose = "Headroom SQS third-party test - wildcard action but specific principal"
  }
}

resource "aws_sqs_queue_policy" "wildcard_action" {
  provider  = aws.shared_foo_bar
  queue_url = aws_sqs_queue.wildcard_action.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.test_third_party_barracuda}:root"
        }
        Action = "sqs:*"
        Resource = aws_sqs_queue.wildcard_action.arn
      }
    ]
  })
}

# Queue 7: Organization-only access (no third parties) - not relevant to check
resource "aws_sqs_queue" "org_only" {
  provider = aws.security_tooling
  name     = "headroom-test-org-only"

  tags = {
    Purpose = "Headroom SQS test - org-only access"
  }
}

resource "aws_sqs_queue_policy" "org_only" {
  provider  = aws.security_tooling
  queue_url = aws_sqs_queue.org_only.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "sqs:*"
        Resource = aws_sqs_queue.org_only.arn
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
          }
        }
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

data "aws_caller_identity" "security_tooling" {
  provider = aws.security_tooling
}

# Note: SQS queues are free (charges only for API requests)
# Standard queues used for testing
# Cleanup: terraform destroy -target=aws_sqs_queue.single_third_party etc.
