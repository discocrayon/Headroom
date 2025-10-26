locals {
  email_user   = split("@", var.base_email)[0]
  email_domain = split("@", var.base_email)[1]
}

resource "aws_organizations_account" "fort_knox" {
  name      = "fort-knox"
  email     = "${local.email_user}+fort-knox@${local.email_domain}"
  parent_id = aws_organizations_organizational_unit.high_value_assets.id

  tags = {
    Environment = "production"
    Owner       = "Cloud Architecture"
    Category    = "high_value_assets"
  }
}

resource "aws_organizations_account" "security_tooling" {
  name      = "security-tooling"
  email     = "${local.email_user}+security-tooling@${local.email_domain}"
  parent_id = aws_organizations_organizational_unit.high_value_assets.id

  tags = {
    Environment = "production"
    Owner       = "Security"
    Category    = "high_value_assets"
  }
}

resource "aws_organizations_account" "shared_foo_bar" {
  name      = "shared-foo-bar"
  email     = "${local.email_user}+shared-foo-bar@${local.email_domain}"
  parent_id = aws_organizations_organizational_unit.shared_services.id

  tags = {
    Environment = "production"
    Owner       = "Traffic"
    Category    = "shared_services"
  }
}

resource "aws_organizations_account" "acme_co" {
  name      = "acme-co"
  email     = "${local.email_user}+acme-co@${local.email_domain}"
  parent_id = aws_organizations_organizational_unit.acme_acquisition.id

  tags = {
    Environment = "production"
    Owner       = "SRE"
    Category    = "acme_acquisition"
  }
}
