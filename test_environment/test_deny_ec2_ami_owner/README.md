# EC2 AMI Owner Test

Tests `deny_ec2_ami_owner` SCP check functionality.

⚠️ **COST WARNING:** EC2 instances incur costs (~$0.0052/hour for t2.nano = ~$3.75/month per instance if left running).

## Cost Estimate

- 2x t2.nano instances: ~$7.50/month
- **Total: ~$7.50/month if left running**

## Test Scenarios

| Instance | Account | AMI Owner | AMI Source | Expected Result |
|----------|---------|-----------|------------|-----------------|
| test-amazon-ami | acme-co | amazon | Amazon Linux 2023 | Compliant (Amazon-owned) |
| test-marketplace-ami | shared-foo-bar | 099720109477 (Canonical) | Ubuntu 22.04 | Depends on allowlist |

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

**acme-co:** 1 instance using Amazon-owned AMI
- AMI Owner: `amazon`
- Instance: `i-xxxxx` from `ami-xxxxx` (Amazon Linux 2023)

**shared-foo-bar:** 1 instance using Canonical-owned AMI
- AMI Owner: `099720109477` (Canonical)
- Instance: `i-yyyyy` from `ami-yyyyy` (Ubuntu 22.04)

## Allowlist Configuration

The generated Terraform will include an `allowed_ami_owners` list with all unique AMI owners discovered:

```hcl
module "scps_acme_co" {
  source    = "../modules/scps"
  target_id = local.acme_co_account_id

  deny_ec2_ami_owner = true
  allowed_ami_owners = [
    "amazon",
    "099720109477"
  ]
}
```

## Troubleshooting

**Instance creation slow:** EC2 instances typically launch in 1-2 minutes
**Headroom timeout:** Ensure instances are in "running" status before scanning
**Permission errors:** Verify Headroom role has `ec2:DescribeInstances` and `ec2:DescribeImages`
**AMI not found errors:** Some AMIs may be deregistered; Headroom marks these as "unknown" owner

## Notes

- The check discovers all unique AMI owners in the account
- Results include AMI ID, owner account ID/alias, and AMI name
- AMI owner can be:
  - AWS account ID (e.g., `111111111111`)
  - AWS alias (e.g., `amazon`, `aws-marketplace`)
  - `unknown` if AMI no longer exists
- Custom AMIs can be added by creating an AMI from an existing instance
