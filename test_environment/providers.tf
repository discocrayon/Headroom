# AWS Provider Aliases for Cross-Account Access

# Provider for Fort Knox account
provider "aws" {
  alias  = "fort_knox"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.fort_knox.id}:role/OrganizationAccountAccessRole"
  }
}

# Provider for Shared Foo Bar account
provider "aws" {
  alias  = "shared_foo_bar"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.shared_foo_bar.id}:role/OrganizationAccountAccessRole"
  }
}

# Provider for ACME Co account
provider "aws" {
  alias  = "acme_co"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.acme_co.id}:role/OrganizationAccountAccessRole"
  }
}

# Provider for Security Tooling account
provider "aws" {
  alias  = "security_tooling"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.security_tooling.id}:role/OrganizationAccountAccessRole"
  }
}
