# Expensive Resources - EC2 Test Instances

## Purpose

This directory contains EC2 instances used for testing the `deny_ec2_imds_v1` SCP check. These resources are **intentionally separated** from the main test environment infrastructure so they can be destroyed most of the time to avoid ongoing AWS costs.

## Cost Considerations

- **Instance Type**: `t2.nano` (smallest/cheapest available)
- **Cost per instance**: ~$0.0058/hour (~$4.18/month if left running)
- **Total cost for 5 instances**: ~$0.029/hour (~$20.90/month if left running)

**⚠️ Important**: These instances should only be created when actively testing and should be destroyed immediately after testing is complete.

## Scope

The check these instances exercise gates one statement,
`DenyRunInstancesMetadataHttpTokensOptional`, which is evaluated against a
`RunInstances` request. **None of these instances can be denied by it** - they
have already launched. They exist to show what the scan counts as evidence
that the *next* launch in an account would be denied.

An IMDSv1 instance counts against the account unless it carries
`ExemptFromIMDSv2 = "true"` on the **instance**. That tag stands in for
`aws:RequestTag/ExemptFromIMDSv2` on the relaunch: the `TagSpecifications`
entry that exempts a launch is what puts the tag here. The proxy is imperfect
and accepted - see `../../spec/checks/scps/deny_ec2_imds_v1.md`.

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

### Instance 3: IMDSv1 Enabled, Exempt by Its Own Tag (fort-knox account)
- **Provider**: `aws.fort_knox`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_tokens = "optional"` (allows both IMDSv1 and IMDSv2)
- **Tags**: `Name = "test-imdsv1-exempt"`, `ExemptFromIMDSv2 = "true"`
- **IAM Role**: none. It used to run as `test-imdsv1-exempt`, whose role tag
  exempted the `DenyRoleDeliveryLessThan2` statement; that statement is no
  longer generated and the role is gone
- **Expected Behavior**: **Exemption.** Measured with `RunInstances --dry-run`:
  a launch tagged `ExemptFromIMDSv2=true` is allowed even with
  `http_tokens = "optional"`, and that same tag specification is what put the
  tag on this instance

### Instance 4: IMDSv1 Enabled, Tag Value in the Wrong Case (shared-foo-bar account)
- **Provider**: `aws.shared_foo_bar`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_tokens = "optional"` (allows both IMDSv1 and IMDSv2)
- **Tags**: `Name = "test-imdsv1-tag-value-wrong-case"`, `ExemptFromIMDSv2 = "True"`
- **IAM Role**: none
- **Expected Behavior**: **Violation.** `StringNotEquals` is case-sensitive, so
  `"True"` does not exempt - measured, the same launch tagged `"true"` is
  allowed and tagged `"True"` is denied. The tag *key* is the opposite: IAM
  matches condition key names without regard to case, so `exemptfromimdsv2`
  would exempt

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
   - Instance 3 should be an exemption, not a violation - it carries the tag
     that exempts its relaunch
   - Instances 4 and 5 should be violations: the wrong-case tag value does not
     exempt, and a disabled endpoint is not an excuse
4. Run `terraform destroy` to remove the instances and stop incurring costs
