# AWS Provider Aliases for Cross-Account Access

# Default provider
provider "aws" {
  region = "us-east-1"
}

# Provider for Fort Knox account
provider "aws" {
  alias  = "fort_knox"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${local.fort_knox_account_id}:role/OrganizationAccountAccessRole"
  }
}

# Provider for Shared Foo Bar account
provider "aws" {
  alias  = "shared_foo_bar"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${local.shared_foo_bar_account_id}:role/OrganizationAccountAccessRole"
  }
}

# Provider for ACME Co account
provider "aws" {
  alias  = "acme_co"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${local.acme_co_account_id}:role/OrganizationAccountAccessRole"
  }
}
