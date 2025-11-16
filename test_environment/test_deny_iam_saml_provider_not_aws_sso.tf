/*
Terraform fixtures for deny_iam_saml_provider_not_aws_sso check.

Creates SAML provider combinations across accounts to exercise compliant and violating scenarios:
- acme-co: single AWS SSO provider (compliant)
- shared-foo-bar: AWS SSO provider + custom provider (violation)
- fort-knox: single custom provider (violation)

Resources use static metadata documents; they incur no costs.
*/

terraform {
  required_version = ">= 1.5.0"
}

provider "aws" {
  alias  = "acme_co"
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "production"
      Account     = "acme-co"
    }
  }
}

provider "aws" {
  alias  = "shared_foo_bar"
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "production"
      Account     = "shared-foo-bar"
    }
  }
}

provider "aws" {
  alias  = "fort_knox"
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "production"
      Account     = "fort-knox"
    }
  }
}

locals {
  dummy_saml_document = <<-XML
    <?xml version="1.0" encoding="UTF-8"?>
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/idp">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="https://example.com/login"/>
      </IDPSSODescriptor>
    </EntityDescriptor>
  XML
}

# Compliant account: single AWS SSO managed provider
resource "aws_iam_saml_provider" "acme_awssso" {
  provider                    = aws.acme_co
  name                        = "AWSSSO_FAKEINSTANCE_us-east-1"
  saml_metadata_document      = local.dummy_saml_document
}

# Violating account: AWS SSO provider plus custom provider
resource "aws_iam_saml_provider" "shared_awssso" {
  provider                    = aws.shared_foo_bar
  name                        = "AWSSSO_FAKEINSTANCE_us-east-1"
  saml_metadata_document      = local.dummy_saml_document
}

resource "aws_iam_saml_provider" "shared_custom" {
  provider                    = aws.shared_foo_bar
  name                        = "CustomHRProvider"
  saml_metadata_document      = local.dummy_saml_document
}

# Violating account: single custom provider (no AWS SSO provider)
resource "aws_iam_saml_provider" "fort_knox_custom" {
  provider                    = aws.fort_knox
  name                        = "LegacyFederation"
  saml_metadata_document      = local.dummy_saml_document
}
