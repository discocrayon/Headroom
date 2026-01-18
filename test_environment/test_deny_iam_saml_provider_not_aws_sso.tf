/*
Terraform fixtures for deny_iam_saml_provider_not_aws_sso check.

Creates SAML provider combinations across accounts to exercise compliant and violating scenarios:
- acme-co: single AWS SSO provider (compliant)
- shared-foo-bar: AWS SSO provider + custom provider (violation)
- fort-knox: single custom provider (violation)

Resources use static metadata documents; they incur no costs.
*/

locals {
  # Minimum 1000 characters required by AWS provider validation
  dummy_saml_document = <<-XML
    <?xml version="1.0" encoding="UTF-8"?>
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/idp">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
          <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
              <X509Certificate>MIICpDCCAYwCCQDU+pQ4P5tcKzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
    b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
    VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0
    aHl0qnOSHSdFJGP8XKH4Qj7Ldx0X6V5y8m0J8R6h5u8z7ZK8l3nT9jF4N7K1J2M0
    L8P4H7I5K6N3O2Q9R0S1T4U3V2W5X6Y7Z8A9B0C1D2E3F4G5H6I7J8K9L0M1N2O3
    P4Q5R6S7T8U9V0W1X2Y3Z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O9P0Q1R2S3T4U5
    V6W7X8Y9Z0DUMMY0CERTIFICATE0DATA0FOR0TESTING0PURPOSES0ONLY0AAAA
    BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPAwEB
    AQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZaaaabbbbccccddddeeeefffff</X509Certificate>
            </X509Data>
          </KeyInfo>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="https://example.com/login"/>
      </IDPSSODescriptor>
      <Organization>
        <OrganizationName xml:lang="en">Example Organization</OrganizationName>
        <OrganizationDisplayName xml:lang="en">Example Organization</OrganizationDisplayName>
        <OrganizationURL xml:lang="en">https://example.com</OrganizationURL>
      </Organization>
      <ContactPerson contactType="technical">
        <GivenName>Test</GivenName>
        <SurName>User</SurName>
        <EmailAddress>test@example.com</EmailAddress>
      </ContactPerson>
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
