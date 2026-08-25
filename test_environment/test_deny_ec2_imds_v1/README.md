# Expensive Resources - EC2 Test Instances

## Purpose

This directory contains EC2 instances used for testing the `deny_ec2_imds_v1` SCP check. These resources are **intentionally separated** from the main test environment infrastructure so they can be destroyed most of the time to avoid ongoing AWS costs.

## Cost Considerations

- **Instance Type**: `t2.nano` (smallest/cheapest available)
- **Cost per instance**: ~$0.0058/hour (~$4.18/month if left running)
- **Total cost for 5 instances**: ~$0.029/hour (~$20.90/month if left running)

**⚠️ Important**: These instances should only be created when actively testing and should be destroyed immediately after testing is complete.

## Test Instances

### Instance 1: IMDSv1 Enabled (shared-foo-bar account)
- **Provider**: `aws.shared_foo_bar`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_tokens = "optional"` (allows both IMDSv1 and IMDSv2)
- **Tags**: `Name = "test-imdsv1-enabled"`
- **Expected Behavior**: Should be flagged by the `deny_ec2_imds_v1` check as non-compliant

### Instance 2: IMDSv2 Only (acme-co account)
- **Provider**: `aws.acme_co`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_tokens = "required"` (requires IMDSv2, blocks IMDSv1)
- **Tags**: `Name = "test-imdsv2-only"`
- **Expected Behavior**: Should pass the `deny_ec2_imds_v1` check as compliant

### Instance 3: IMDSv1 Enabled but Exempt by Role Tag (fort-knox account)
- **Provider**: `aws.fort_knox`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_tokens = "optional"` (allows both IMDSv1 and IMDSv2)
- **Tags**: `Name = "test-imdsv1-exempt"`
- **IAM Role**: runs as `test-imdsv1-exempt`, which carries `ExemptFromIMDSv2 = "true"`
- **Expected Behavior**: Should pass the `deny_ec2_imds_v1` check, because the SCP
  exempts through `aws:PrincipalTag/ExemptFromIMDSv2` and that tag is on the role

### Instance 4: IMDSv1 Enabled, Instance Tagged but Role Not (shared-foo-bar account)
- **Provider**: `aws.shared_foo_bar`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_tokens = "optional"` (allows both IMDSv1 and IMDSv2)
- **Tags**: `Name = "test-imdsv1-instance-tagged-only"`, `ExemptFromIMDSv2 = "true"`
- **IAM Role**: none
- **Expected Behavior**: **Violation.** No statement in the SCP reads instance
  tags, so this tag exempts nothing. This instance used to read as exempt, which
  is what let an account report zero violations while enforcement would have
  denied every API call the instance made

### Instance 5: Metadata Endpoint Disabled, Tokens Still Optional (acme-co account)
- **Provider**: `aws.acme_co`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_endpoint = "disabled"`, `http_tokens = "optional"`
- **Tags**: `Name = "test-imds-disabled-tokens-optional"`
- **Expected Behavior**: **Violation.** Neither the check nor the SCP looks at
  the endpoint; `http_tokens` decides on its own, matching how
  `deny_ec2_imds_hop_limit` counts a hop limit whatever the endpoint says.
  Nothing can reach IMDS on this instance, so the finding is free to remedy:
  set `http_tokens = "required"`, which AWS accepts alongside a disabled
  endpoint - verified by dry run, contradicting the EC2 guide - and which
  changes no behaviour, because nothing is listening. `http_tokens` is named
  explicitly here because the AMI sets `imds-support=v2.0`, whose `required`
  default would otherwise make this instance compliant and test nothing

## Usage

### Creating the Instances

From the `test_environment/expensive_resources/` directory:

```bash
terraform init
terraform plan
terraform apply
```

### Destroying the Instances

**Always destroy these resources after testing**:

```bash
terraform destroy
```

Or from the parent `test_environment/` directory, you can target this specific module:

```bash
terraform destroy -target=aws_instance.test_imdsv1_enabled -target=aws_instance.test_imdsv2_only -target=aws_instance.test_imdsv1_exempt
```

## Provider Configuration

The `providers.tf` file configures access to three different AWS accounts:
- Configures provider aliases (`fort_knox`, `shared_foo_bar`, `acme_co`)
- Each provider assumes the `OrganizationAccountAccessRole` in the target account
- Account IDs are dynamically looked up from AWS Organizations via data sources in `data.tf`
- Uses the same pattern as `grab_org_info.tf` in the parent test environment

## AMI Selection

The instances use the latest Amazon Linux 2023 AMI, which is:
- Free tier eligible
- Automatically selected via data source in `data.tf`
- HVM virtualization type
- EBS root device type

## Testing Workflow

1. Run `terraform apply` to create the instances
2. Run the Headroom tool to analyze these accounts
3. Verify the `deny_ec2_imds_v1` check produces expected results:
   - Instance 1 should be flagged as non-compliant
   - Instance 2 should be compliant
   - Instance 3 should be compliant (exempt)
4. Run `terraform destroy` to remove the instances and stop incurring costs
