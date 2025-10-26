# Headroom IAM Roles
# Creates Headroom role with read-only policies in each subaccount

# Headroom role in Fort Knox account
module "headroom_fort_knox" {
  source = "./modules/headroom_role"
  providers = {
    aws = aws.fort_knox
  }
  account_id_to_trust = aws_organizations_account.security_tooling.id
}

# Headroom role in Shared Foo Bar account
module "headroom_shared_foo_bar" {
  source = "./modules/headroom_role"
  providers = {
    aws = aws.shared_foo_bar
  }
  account_id_to_trust = aws_organizations_account.security_tooling.id
}

# Headroom role in ACME Co account
module "headroom_acme_co" {
  source = "./modules/headroom_role"
  providers = {
    aws = aws.acme_co
  }
  account_id_to_trust = aws_organizations_account.security_tooling.id
}

# Headroom role in Security Tooling account
module "headroom_security_tooling" {
  source = "./modules/headroom_role"
  providers = {
    aws = aws.security_tooling
  }
  account_id_to_trust = aws_organizations_account.security_tooling.id
}
