# EC2 AMI Owner Test

Tests `deny_ec2_ami_owner` SCP check functionality.

⚠️ **COST WARNING:** EC2 instances incur costs (~$0.0052/hour for t2.nano = ~$3.75/month per instance if left running).

## Cost Estimate

- 2x t2.nano instances: ~$7.50/month
- **Total: ~$7.50/month if left running**

## Test Scenarios

| Instance | Account | Recorded `ec2:Owner` | AMI Source | Expected Result |
|----------|---------|----------------------|------------|-----------------|
| test-amazon-ami | acme-co | `amazon` | Amazon Linux 2023 | Compliant |
| test-marketplace-ami | shared-foo-bar | `aws-marketplace` | Ubuntu 22.04 | Compliant |

Neither instance records a numeric account. The check records the value
`ec2:Owner` will hold on a relaunch, which is the AMI's `ImageOwnerAlias`
whenever it has one - and both of these do. Only the commented-out custom-AMI
instance would exercise the alias-free branch, so as written this environment
covers half the rule. See `../../spec/checks/scps/deny_ec2_ami_owner.md` for the dry-run
measurements behind that.

## Usage

### Deploy Test Resources

```bash
cd test_environment/test_deny_ec2_ami_owner
terraform init
terraform plan
terraform apply
```

### Run Headroom Analysis

```bash
cd ../..
python -m headroom --config sample_config.yaml
```

### Verify Results

```bash
cat test_environment/headroom_results/scps/deny_ec2_ami_owner/acme-co.json
cat test_environment/headroom_results/scps/deny_ec2_ami_owner/shared-foo-bar.json
```

### Cleanup (IMPORTANT)

```bash
cd test_environment/test_deny_ec2_ami_owner
terraform destroy
```

## Expected Results

**acme-co:** 1 instance using an Amazon-published AMI
- `ami_owner`: Amazon's publishing account, `ami_owner_alias`: `amazon`
- `unique_ami_owners`: `["amazon"]` - the alias, because that is what
  `ec2:Owner` compares against
- Instance: `i-xxxxx` from `ami-xxxxx` (Amazon Linux 2023)

**shared-foo-bar:** 1 instance using Canonical's Ubuntu, listed on Marketplace
- `ami_owner`: Canonical's publishing account,
  `ami_owner_alias`: `aws-marketplace`
- `unique_ami_owners`: `["aws-marketplace"]`
- Instance: `i-yyyyy` from `ami-yyyyy` (Ubuntu 22.04)

## Allowlist Configuration

The generated Terraform includes an `ec2_allowed_ami_owners` list holding the
unique `ec2:Owner` values discovered across the accounts the placement covers:

```hcl
module "scps_acme_co" {
  source    = "../modules/scps"
  target_id = local.acme_co_account_id

  deny_ec2_ami_owner = true
  ec2_allowed_ami_owners = [
    "amazon",
    "aws-marketplace"
  ]
}
```

An alias entry is broader than the AMI that produced it - `amazon` permits
every Amazon-published AMI - and `ec2:Owner` has no narrower form for an
aliased image.

With these instances destroyed, both accounts report zero instances and no
owners. That is a valid result, not a failure: the module renders
`deny_ec2_ami_owner = false` with a comment saying why, because an empty
allowlist would deny every launch rather than none.

## Troubleshooting

**Instance creation slow:** EC2 instances typically launch in 1-2 minutes
**Headroom timeout:** Ensure instances are in "running" status before scanning
**Permission errors:** Verify Headroom role has `ec2:DescribeInstances` and `ec2:DescribeImages`
**AMI not found errors:** Some AMIs may be deregistered; Headroom marks these as "unknown" owner

## Notes

- The check discovers all unique `ec2:Owner` values in the account
- Results carry the AMI ID, the owner account, the owner alias, and the name
- `ec2:Owner` is one of:
  - `amazon` or `aws-marketplace`, when `DescribeImages` returns an
    `ImageOwnerAlias`
  - the numeric `OwnerId`, when it does not - self-built AMIs, AMIs shared
    from another account, and distributions that publish directly
- An AMI whose owner cannot be resolved at all is a violation, with the
  reason recorded in `unknown_ami_owners`
- Custom AMIs can be added by creating an AMI from an existing instance
