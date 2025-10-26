# Data Sources

# Data source to get the current organization
data "aws_organizations_organization" "current" {}

# Data source to get the current caller identity
data "aws_caller_identity" "current" {}
