# Test ECR repositories for deny_ecr_third_party_access RCP functionality testing

# Repository 1: Third-party access (DataDog) - compliant
resource "aws_ecr_repository" "third_party_datadog" {
  provider = aws.acme_co
  name     = "headroom-test-third-party-datadog"

  tags = {
    Purpose = "Headroom ECR third-party access test - DataDog"
  }
}

resource "aws_ecr_repository_policy" "third_party_datadog" {
  provider   = aws.acme_co
  repository = aws_ecr_repository.third_party_datadog.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowDataDog"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::464622532012:root"
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }
    ]
  })
}

# Repository 2: Multiple third-party accounts (Snyk + Docker) - compliant
resource "aws_ecr_repository" "multiple_third_parties" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-multiple-third-parties"

  tags = {
    Purpose = "Headroom ECR third-party access test - multiple vendors"
  }
}

resource "aws_ecr_repository_policy" "multiple_third_parties" {
  provider   = aws.shared_foo_bar
  repository = aws_ecr_repository.multiple_third_parties.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSnykAndDocker"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::198449067068:root",
            "arn:aws:iam::709825985650:root"
          ]
        }
        Action = [
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:DescribeImages"
        ]
      }
    ]
  })
}

# Repository 3: Wildcard principal - violation (blocks RCP deployment)
resource "aws_ecr_repository" "wildcard_violation" {
  provider = aws.fort_knox
  name     = "headroom-test-wildcard-violation"

  tags = {
    Purpose = "Headroom ECR test - intentional wildcard violation"
  }
}

resource "aws_ecr_repository_policy" "wildcard_violation" {
  provider   = aws.fort_knox
  repository = aws_ecr_repository.wildcard_violation.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PublicAccess"
        Effect = "Allow"
        Principal = "*"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
      }
    ]
  })
}

# Repository 4: Organization-only access (no third parties) - not relevant to check
resource "aws_ecr_repository" "org_only" {
  provider = aws.security_tooling
  name     = "headroom-test-org-only"

  tags = {
    Purpose = "Headroom ECR test - org-only access"
  }
}

resource "aws_ecr_repository_policy" "org_only" {
  provider   = aws.security_tooling
  repository = aws_ecr_repository.org_only.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowOrgAccess"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "ecr:*"
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
          }
        }
      }
    ]
  })
}

# Repository 5: No policy - not relevant to check
resource "aws_ecr_repository" "no_policy" {
  provider = aws.shared_foo_bar
  name     = "headroom-test-no-policy"

  tags = {
    Purpose = "Headroom ECR test - no policy"
  }
}

# Note: ECR repositories are free for the first 500MB of storage
# Cleanup: terraform destroy -target=aws_ecr_repository.third_party_datadog etc.
