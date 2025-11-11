# EC2 Public IP Test Infrastructure

Tests `deny_ec2_public_ip` SCP check functionality.

⚠️ **COST WARNING:** EC2 instances incur ongoing charges even when stopped (EBS volumes).

## Cost Estimate

- 3x t2.nano instances: ~$3-5/month total
- EBS storage (8GB each): ~$1/month total
- **Total: ~$4-6/month if left running**

## Test Scenarios

| Instance | Account | Public IP | Expected Result |
|----------|---------|-----------|-----------------|
| test-public-ip-violation | shared-foo-bar | Yes | Violation |
| test-no-public-ip-compliant | acme-co | No | Compliant |
| test-public-ip-violation-2 | fort-knox | Yes | Violation |

## Usage

### Deploy Test Resources

```bash
cd test_environment/test_deny_ec2_public_ip/
terraform init
terraform apply

# Wait 1-2 minutes for instances to launch
```

### Run Headroom Analysis

```bash
cd ../..  # Back to repo root
python -m headroom --config sample_config.yaml

# Verify results
cat test_environment/headroom_results/scps/deny_ec2_public_ip/shared-foo-bar.json
cat test_environment/headroom_results/scps/deny_ec2_public_ip/acme-co.json
cat test_environment/headroom_results/scps/deny_ec2_public_ip/fort-knox.json
```

### Cleanup (IMPORTANT)

```bash
cd test_environment/test_deny_ec2_public_ip/
terraform destroy

# Confirm all instances are terminated
```

## Expected Results

**shared-foo-bar:** 1 violation (test-public-ip-violation)
**acme-co:** 1 compliant instance (test-no-public-ip-compliant)
**fort-knox:** 1 violation (test-public-ip-violation-2)

## Troubleshooting

**Instance launch slow:** EC2 instances take 1-2 minutes to launch
**Headroom timeout:** Ensure instances are in "running" status before running
**Permission errors:** Verify Headroom role has `ec2:DescribeInstances` permission
**Public IP not assigned:** Check that the subnet has "auto-assign public IPv4 address" enabled, or use `associate_public_ip_address = true` in the resource

## Technical Notes

- Uses default VPC in each account
- Instances are t2.nano (smallest size, free tier eligible)
- Amazon Linux 2023 AMI (free tier eligible)
- No security groups configured (uses default)
- Instances can be stopped to save costs, but EBS volumes still incur charges
