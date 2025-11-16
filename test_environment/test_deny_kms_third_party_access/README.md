# KMS Third-Party Access Test

Tests `deny_kms_third_party_access` RCP check functionality.

## Overview

This test suite validates the KMS third-party access detection and RCP generation for KMS keys. The test creates KMS keys with various access patterns to ensure Headroom correctly identifies third-party account access and generates appropriate RCP allowlists.

## Cost Information

**KMS keys are FREE** - AWS does not charge for creating or storing KMS keys. You are only charged for API requests made to KMS (encrypt, decrypt, etc.), which this test does not perform.

**Estimated Monthly Cost:** $0 (no charges for key storage or key creation)

## Test Scenarios

| Key | Account | Third-Party Accounts | Actions | Expected Result |
|-----|---------|---------------------|---------|-----------------|
| third_party_vendor_crowdstrike | acme-co | 749430749651 (CrowdStrike) | kms:Decrypt, kms:DescribeKey | Compliant |
| multiple_third_party_vendors | shared-foo-bar | 758245563457 (Barracuda), 517716713836 (Check Point) | kms:Decrypt, kms:Encrypt, kms:GenerateDataKey | Compliant |
| wildcard_key | shared-foo-bar | None (wildcard principal) | kms:Decrypt | Violation |
| org_only | fort-knox | None | N/A | No findings |
| service_principal | fort-knox | None (AWS service only) | N/A | No findings |

### Key Details

1. **third_party_vendor_crowdstrike**: KMS key in acme-co account allowing CrowdStrike (749430749651) to decrypt and describe the key. This simulates a security vendor needing access to encrypted data.

2. **multiple_third_party_vendors**: KMS key in shared-foo-bar account allowing two third-party vendors (Barracuda and Check Point) to encrypt, decrypt, and generate data keys. This tests tracking multiple third-party accounts on a single key.

3. **wildcard_key**: KMS key in shared-foo-bar account with a wildcard principal allowing anyone to decrypt. This is a violation that blocks RCP deployment.

4. **org_only**: KMS key in fort-knox account with only organization account access. No third-party accounts, so no findings expected.

5. **service_principal**: KMS key in fort-knox account allowing CloudWatch Logs service. AWS service principals are not counted as third-party access.

## Usage

### Deploy Test Resources

```bash
cd test_environment/
terraform apply -target=aws_kms_key.third_party_vendor_crowdstrike \
                -target=aws_kms_key.multiple_third_party_vendors \
                -target=aws_kms_key.wildcard_key \
                -target=aws_kms_key.org_only \
                -target=aws_kms_key.service_principal \
                -target=aws_kms_alias.third_party_vendor_crowdstrike \
                -target=aws_kms_alias.multiple_third_party_vendors \
                -target=aws_kms_alias.wildcard_key \
                -target=aws_kms_alias.org_only \
                -target=aws_kms_alias.service_principal
```

### Run Headroom Analysis

```bash
cd ..
python -m headroom --config my_config.yaml

# Verify results
cat test_environment/headroom_results/rcps/deny_kms_third_party_access/acme-co.json
cat test_environment/headroom_results/rcps/deny_kms_third_party_access/shared-foo-bar.json
cat test_environment/headroom_results/rcps/deny_kms_third_party_access/fort-knox.json
```

### Cleanup

```bash
cd test_environment/
terraform destroy -target=aws_kms_alias.third_party_vendor_crowdstrike \
                  -target=aws_kms_alias.multiple_third_party_vendors \
                  -target=aws_kms_alias.wildcard_key \
                  -target=aws_kms_alias.org_only \
                  -target=aws_kms_alias.service_principal \
                  -target=aws_kms_key.third_party_vendor_crowdstrike \
                  -target=aws_kms_key.multiple_third_party_vendors \
                  -target=aws_kms_key.wildcard_key \
                  -target=aws_kms_key.org_only \
                  -target=aws_kms_key.service_principal

# Note: Destroy aliases first, then keys
```

## Expected Results

### acme-co Account

```json
{
  "summary": {
    "account_name": "acme-co",
    "account_id": "111111111111",
    "check": "deny_kms_third_party_access",
    "total_keys_analyzed": 1,
    "keys_third_parties_can_access": 1,
    "keys_with_wildcards": 0,
    "violations": 0,
    "unique_third_party_accounts": ["749430749651"],
    "third_party_account_count": 1,
    "actions_by_account": {
      "749430749651": ["kms:Decrypt", "kms:DescribeKey"]
    }
  },
  "keys_third_parties_can_access": [
    {
      "key_id": "...",
      "key_arn": "arn:aws:kms:us-east-1:111111111111:key/...",
      "region": "us-east-1",
      "third_party_account_ids": ["749430749651"],
      "actions_by_account": {
        "749430749651": ["kms:Decrypt", "kms:DescribeKey"]
      },
      "has_wildcard_principal": false
    }
  ],
  "keys_with_wildcards": []
}
```

### shared-foo-bar Account

```json
{
  "summary": {
    "account_name": "shared-foo-bar",
    "account_id": "222222222222",
    "check": "deny_kms_third_party_access",
    "total_keys_analyzed": 2,
    "keys_third_parties_can_access": 2,
    "keys_with_wildcards": 1,
    "violations": 1,
    "unique_third_party_accounts": ["517716713836", "758245563457"],
    "third_party_account_count": 2,
    "actions_by_account": {
      "758245563457": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
      "517716713836": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    }
  },
  "keys_third_parties_can_access": [...],
  "keys_with_wildcards": [...]
}
```

### fort-knox Account

```json
{
  "summary": {
    "account_name": "fort-knox",
    "account_id": "333333333333",
    "check": "deny_kms_third_party_access",
    "total_keys_analyzed": 0,
    "keys_third_parties_can_access": 0,
    "keys_with_wildcards": 0,
    "violations": 0,
    "unique_third_party_accounts": [],
    "third_party_account_count": 0,
    "actions_by_account": {}
  },
  "keys_third_parties_can_access": [],
  "keys_with_wildcards": []
}
```

## RCP Placement Recommendation

Headroom will recommend:
- **Account-level RCP** for acme-co (allows 749430749651)
- **No RCP** for shared-foo-bar (wildcard principal blocks deployment)
- **No RCP** for fort-knox (no third-party access)

## Troubleshooting

### Key Policy Not Applied

If you see keys with no policy, ensure the Terraform apply completed successfully. KMS keys require explicit policy documents.

### Wildcard Detection

The wildcard_key should trigger a violation. If it doesn't, check the key policy in AWS console to verify the wildcard principal is present.

### Permission Errors

Ensure the Headroom role has:
- `kms:ListKeys` (covered by ViewOnlyAccess)
- `kms:GetKeyPolicy` (covered by ViewOnlyAccess)
- `kms:DescribeKey` (covered by ViewOnlyAccess)

## Notes

- KMS keys cannot be immediately deleted - they are scheduled for deletion with a minimum waiting period of 7 days
- Key aliases must be deleted before keys can be deleted
- Test uses real third-party account IDs that are publicly documented (CrowdStrike, Barracuda, Check Point)
- The `dp:exclude:identity` tag can be used to exclude specific keys from RCP restrictions
