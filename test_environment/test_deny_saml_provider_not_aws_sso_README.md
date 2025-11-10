## Test IAM SAML Providers for deny_saml_provider_not_aws_sso SCP

This Terraform file provisions sample IAM SAML providers across the test accounts to exercise the `deny_saml_provider_not_aws_sso` check.

### Accounts & Providers

- **acme-co**: One AWS SSO-managed provider (`AWSSSO_...`) — **compliant**
- **shared-foo-bar**: AWS SSO-managed provider plus a custom provider — **violation (multiple providers)**
- **fort-knox**: Custom provider only — **violation (incorrect prefix)**

### Usage

```bash
cd test_environment
terraform init
terraform plan -target=aws_iam_saml_provider.acme_awssso -target=aws_iam_saml_provider.shared_awssso -target=aws_iam_saml_provider.shared_custom -target=aws_iam_saml_provider.fort_knox_custom
terraform apply -target=aws_iam_saml_provider.acme_awssso -target=aws_iam_saml_provider.shared_awssso -target=aws_iam_saml_provider.shared_custom -target=aws_iam_saml_provider.fort_knox_custom
```

These resources use dummy metadata documents and incur no AWS charges. Destroy them when finished:

```bash
terraform destroy -target=aws_iam_saml_provider.acme_awssso -target=aws_iam_saml_provider.shared_awssso -target=aws_iam_saml_provider.shared_custom -target=aws_iam_saml_provider.fort_knox_custom
```

### Expected Headroom Results

- `acme-co`: compliant
- `shared-foo-bar`: violation (`multiple_saml_providers_present`) and `provider_prefix_not_awssso`
- `fort-knox`: violation (`provider_prefix_not_awssso`)
