# Organizational Units
# These OUs are created under the root of the organization

# High Value Assets OU
resource "aws_organizations_organizational_unit" "high_value_assets" {
  name      = "high_value_assets"
  parent_id = data.aws_organizations_organization.current.roots[0].id
}

# Shared Services OU
resource "aws_organizations_organizational_unit" "shared_services" {
  name      = "shared_services"
  parent_id = data.aws_organizations_organization.current.roots[0].id
}

# ACME Acquisition OU
resource "aws_organizations_organizational_unit" "acme_acquisition" {
  name      = "acme_acquisition"
  parent_id = data.aws_organizations_organization.current.roots[0].id
}
