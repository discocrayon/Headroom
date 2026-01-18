# Data Sources

# Data source to get the current organization
data "aws_organizations_organization" "current" {}

# Data source to get the current caller identity
data "aws_caller_identity" "current" {}

# Data sources for account IDs (used across multiple test files)
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
