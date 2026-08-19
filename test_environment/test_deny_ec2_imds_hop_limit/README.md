# Expensive Resources - EC2 IMDS Hop Limit Test Instances

## Purpose

This directory contains EC2 instances used for testing the `deny_ec2_imds_hop_limit` SCP check. These resources are **intentionally separated** from the main test environment infrastructure so they can be destroyed most of the time to avoid ongoing AWS costs.

## Cost Considerations

- **Instance Type**: `t2.nano` (smallest/cheapest available)
- **Cost per instance**: ~$0.0058/hour (~$4.18/month if left running)
- **Total cost for 3 instances**: ~$0.0174/hour (~$12.54/month if left running)

**⚠️ Important**: These instances should only be created when actively testing and should be destroyed immediately after testing is complete.

## The SCP Being Tested

```json
{
  "Sid": "MaxImdsHopLimit",
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "NumericGreaterThan": {
      "ec2:MetadataHttpPutResponseHopLimit": "1"
    }
  }
}
```

A hop limit above 1 lets the IMDS response cross an extra network hop, which is what allows a container or a downstream proxy running on the instance to reach the metadata endpoint.

**This policy is launch-time only.** `ec2:ModifyInstanceMetadataOptions` has no fine-grained condition keys, so the hop limit can still be raised after launch. Closing that gap requires denying `ec2:ModifyInstanceMetadataOptions` outright or restricting it by `aws:PrincipalArn`, which is a separate policy decision and is not covered by this check.

## Test Instances

### Instance 1: Hop Limit 2 (shared-foo-bar account)
- **Provider**: `aws.shared_foo_bar`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_put_response_hop_limit = 2`, endpoint enabled
- **Tags**: `Name = "test-imds-hop-limit-two"`
- **Expected Behavior**: Flagged by the `deny_ec2_imds_hop_limit` check as non-compliant

### Instance 2: Hop Limit 1 (acme-co account)
- **Provider**: `aws.acme_co`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_put_response_hop_limit = 1`, endpoint enabled
- **Tags**: `Name = "test-imds-hop-limit-one"`
- **Expected Behavior**: Passes the check as compliant — 1 is the maximum allowed

### Instance 3: IMDS Disabled (fort-knox account)
- **Provider**: `aws.fort_knox`
- **Instance Type**: `t2.nano`
- **IMDS Configuration**: `http_endpoint = "disabled"`
- **Tags**: `Name = "test-imds-disabled"`
- **Expected Behavior**: Passes the check as compliant. With no reachable metadata endpoint there is no hop to cross, so the hop limit is irrelevant. This instance exercises the `imds_enabled = false` branch of `categorize_result`.

## Usage

### Creating the Instances

From this directory:

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

## Provider Configuration

The `providers.tf` file configures access to three different AWS accounts:
- Configures provider aliases (`fort_knox`, `shared_foo_bar`, `acme_co`)
- Each provider assumes the `OrganizationAccountAccessRole` in the target account
- Account IDs are dynamically looked up from AWS Organizations via data sources in `data.tf`
- Uses the same pattern as `grab_org_info.tf` in the parent test environment

Spreading the three instances across three accounts is deliberate: it gives the placement engine a mixed-compliance organization, so the recommendation logic is exercised rather than trivially returning "safe at root".

## AMI Selection

The instances use the latest Amazon Linux 2023 AMI, which is:
- Free tier eligible
- Automatically selected via data source in `data.tf`
- HVM virtualization type
- EBS root device type

## Testing Workflow

1. Run `terraform apply` to create the instances
2. Run the Headroom tool to analyze these accounts
3. Verify the `deny_ec2_imds_hop_limit` check produces expected results:
   - Instance 1 should be flagged as non-compliant
   - Instance 2 should be compliant
   - Instance 3 should be compliant (IMDS disabled)
4. Run `terraform destroy` to remove the instances and stop incurring costs
