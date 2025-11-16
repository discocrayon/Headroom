# Data Sources

# Get the root OU ID
data "aws_organizations_organization" "org" {}

data "aws_organizations_organizational_units" "root_ou" {
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

# Get accounts for each top-level OU
data "aws_organizations_organizational_unit_child_accounts" "acme_acquisition_accounts" {
  parent_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "acme_acquisition"
  ][0]
}

data "aws_organizations_organizational_unit_child_accounts" "high_value_assets_accounts" {
  parent_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "high_value_assets"
  ][0]
}

data "aws_organizations_organizational_unit_child_accounts" "shared_services_accounts" {
  parent_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "shared_services"
  ][0]
}

locals {
  # Account IDs by name
  acme_co_account_id = [
    for account in data.aws_organizations_organizational_unit_child_accounts.acme_acquisition_accounts.accounts :
    account.id if account.name == "acme-co"
  ][0]

  fort_knox_account_id = [
    for account in data.aws_organizations_organizational_unit_child_accounts.high_value_assets_accounts.accounts :
    account.id if account.name == "fort-knox"
  ][0]

  shared_foo_bar_account_id = [
    for account in data.aws_organizations_organizational_unit_child_accounts.shared_services_accounts.accounts :
    account.id if account.name == "shared-foo-bar"
  ][0]
}

# Get the latest Amazon Linux 2023 AMI (free tier eligible)
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}
