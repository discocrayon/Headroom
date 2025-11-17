# Secrets Manager Third-Party Access Test

Tests `deny_secrets_manager_third_party_access` RCP check functionality.

⚠️ **COST WARNING:** Secrets Manager secrets incur ongoing costs even when unused.

## Cost Estimate

- 5x Secrets Manager secrets: $0.40/secret/month = **$2.00/month**
- Storage for secret values: Negligible for small test values
- **Total: ~$2.00/month if left running**

## Test Scenarios

| Secret | Account | Third-Party Access | Expected Result |
|--------|---------|-------------------|-----------------|
| `headroom-test-vendor-a-secret` | acme-co | CrowdStrike (749430749651) | Compliant - Single third-party |
| `headroom-test-vendor-b-secret` | shared-foo-bar | Barracuda (758245563457) + Check Point (517716713836) | Compliant - Multiple third-parties |
| `headroom-test-wildcard-secret` | fort-knox | Wildcard (*) | Violation - Wildcard principal |
| `headroom-test-org-only-secret` | shared-foo-bar | Org account only | Compliant - Filtered from results |
| `headroom-test-no-policy-secret` | shared-foo-bar | None (no policy) | No findings - No policy attached |

## Usage

### Deploy Test Resources

```bash
cd test_environment/
terraform apply -target=aws_secretsmanager_secret.third_party_vendor_a \
                -target=aws_secretsmanager_secret_version.third_party_vendor_a \
                -target=aws_secretsmanager_secret_policy.third_party_vendor_a \
                -target=aws_secretsmanager_secret.third_party_vendor_b \
                -target=aws_secretsmanager_secret_version.third_party_vendor_b \
                -target=aws_secretsmanager_secret_policy.third_party_vendor_b \
                -target=aws_secretsmanager_secret.wildcard_secret \
                -target=aws_secretsmanager_secret_version.wildcard_secret \
                -target=aws_secretsmanager_secret_policy.wildcard_secret \
                -target=aws_secretsmanager_secret.org_only_secret \
                -target=aws_secretsmanager_secret_version.org_only_secret \
                -target=aws_secretsmanager_secret_policy.org_only_secret \
                -target=aws_secretsmanager_secret.no_policy_secret \
                -target=aws_secretsmanager_secret_version.no_policy_secret

# Secrets are created immediately (no wait time needed)
```

### Run Headroom Analysis

```bash
cd ..
python -m headroom --config my_config.yaml

# Verify results
cat test_environment/headroom_results/rcps/deny_secrets_manager_third_party_access/acme-co.json
```

### Cleanup (IMPORTANT)

```bash
cd test_environment/
terraform destroy -target=aws_secretsmanager_secret.third_party_vendor_a \
                  -target=aws_secretsmanager_secret_version.third_party_vendor_a \
                  -target=aws_secretsmanager_secret_policy.third_party_vendor_a \
                  -target=aws_secretsmanager_secret.third_party_vendor_b \
                  -target=aws_secretsmanager_secret_version.third_party_vendor_b \
                  -target=aws_secretsmanager_secret_policy.third_party_vendor_b \
                  -target=aws_secretsmanager_secret.wildcard_secret \
                  -target=aws_secretsmanager_secret_version.wildcard_secret \
                  -target=aws_secretsmanager_secret_policy.wildcard_secret \
                  -target=aws_secretsmanager_secret.org_only_secret \
                  -target=aws_secretsmanager_secret_version.org_only_secret \
                  -target=aws_secretsmanager_secret_policy.org_only_secret \
                  -target=aws_secretsmanager_secret.no_policy_secret \
                  -target=aws_secretsmanager_secret_version.no_policy_secret
```

## Expected Results

### acme-co

**Expected:** 1 secret with third-party access (vendor-a-secret)
- Third-party accounts: `749430749651` (CrowdStrike)
- Actions: `secretsmanager:GetSecretValue`, `secretsmanager:DescribeSecret`

### shared-foo-bar

**Expected:** 3 secrets total
- 1 secret with third-party access (vendor-b-secret)
  - Third-party accounts: `758245563457` (Barracuda), `517716713836` (Check Point)
  - Actions: `secretsmanager:GetSecretValue`
- 1 secret with org-only access (filtered from results)
- 1 secret without policy (no findings)

### fort-knox

**Expected:** 1 violation (wildcard-secret)
- Has wildcard principal
- Blocks RCP deployment

### security-tooling

**Expected:** No secrets with third-party access

## RCP Deployment Impact

The `deny_secrets_manager_third_party_access` RCP will:

1. **Allow:** Organization accounts to access all secrets (via `aws:PrincipalOrgID`)
2. **Allow:** Third-party accounts in allowlist to access secrets (via `aws:PrincipalAccount`)
3. **Deny:** All other principals from accessing secrets

**Allowlist Generation:**
- Union of all third-party account IDs: `749430749651`, `758245563457`, `517716713836`
- Each secret's specific actions are tracked for documentation purposes

**Wildcard Blocking:**
- The fort-knox wildcard secret prevents RCP deployment at root or OU level
- Account-level RCP can only be deployed to accounts without wildcards

## Third-Party Vendors

The test uses real third-party vendor account IDs:
- **CrowdStrike:** `749430749651` (Security platform)
- **Barracuda:** `758245563457` (Email security)
- **Check Point:** `517716713836` (Network security)

## Troubleshooting

**Secrets created but not showing in results:**
- Ensure secret has a resource policy attached
- Check that Headroom role has `secretsmanager:GetResourcePolicy` permission

**Permission errors:**
- Verify Headroom role has `secretsmanager:ListSecrets` and `secretsmanager:GetResourcePolicy`
- ViewOnlyAccess policy should cover these permissions

**Policy format issues:**
- Ensure Principal field uses correct format (AWS, not Service)
- Validate JSON syntax in policy documents
