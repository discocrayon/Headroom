# Detailed Setup Guide

## IAM Role Requirements

The tool requires two types of IAM roles to be deployed across your AWS Organization:

### 1. Headroom Role (All Accounts)

Deploy a `Headroom` role in **every account** you want to analyze. This role needs permissions to:
- Describe EC2 instances (all regions)
- List IAM users and roles
- Read IAM policies
- Describe EKS clusters (all regions)
- Describe RDS instances (all regions)
- Read S3 bucket policies
- Read ECR repository policies

**Example Terraform**: See [`test_environment/headroom_roles.tf`](https://github.com/discocrayon/Headroom/blob/main/test_environment/headroom_roles.tf)

### 2. OrgAndAccountInfoReader Role (Management Account)

Deploy an `OrgAndAccountInfoReader` role in your [AWS Organizations management account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#organization-structure). This role needs permissions to:
- List AWS Organizations accounts
- Describe organizational units
- Read account tags

**Example Terraform**: See [`test_environment/org_and_account_info_reader.tf`](https://github.com/discocrayon/Headroom/blob/main/test_environment/org_and_account_info_reader.tf)

### Trust Configuration

**All roles must trust the Security Analysis Account** where Headroom runs from.

In the `test_environment/`, this is represented by `aws_organizations_account.security_tooling.id` ([see code](https://github.com/search?q=repo%3Adiscocrayon%2Fheadroom%20aws_organizations_account.security_tooling.id&type=code)).

### SCP Exemption Requirement

**The `Headroom` role must be exempt from any SCP that restricts access by region**, such as a region allowlist built on `aws:RequestedRegion`.

Headroom analyzes every region that is *enabled* for the account. Region enablement is independent of SCPs, so a region an SCP denies is still returned by `ec2:DescribeRegions` and still scanned. If a region-allowlist SCP applies to the `Headroom` role, its API calls in the denied regions fail with `AccessDenied`.

Headroom treats those failures as fatal rather than as an absence of findings, because it cannot distinguish "this region has nothing" from "this region could not be read", and the second silently understates what a generated policy must allow. A read it could not complete therefore aborts the run instead of contributing an empty result. With the exemption in place, an `AccessDenied` unambiguously means a missing permission.

Exempt the role with a condition on the SCP's deny statement:

```json
{
  "Effect": "Deny",
  "NotAction": ["iam:*", "organizations:*", "sts:*"],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": ["us-east-1", "us-west-2"]
    },
    "ArnNotLike": {
      "aws:PrincipalArn": "arn:aws:iam::*:role/Headroom"
    }
  }
}
```

## Execution Options

### Option 1: From the Security Analysis Account (Recommended)

This is the standard execution pattern.

**Setup:**
1. Deploy `Headroom` role in all accounts (trusting Security Analysis Account)
2. Deploy `OrgAndAccountInfoReader` role in management account (trusting Security Analysis Account)
3. Run Headroom from the Security Analysis Account

**Configuration:**
```yaml
management_account_id: '222222222222'
# Do NOT set security_analysis_account_id
```

**Execution flow:**
- Headroom assumes `OrgAndAccountInfoReader` in management account
- Headroom assumes `Headroom` role in each member account

### Option 2: From the Management Account

If you need to run Headroom directly from your management account.

**Setup:**
1. Deploy `Headroom` role in all accounts (trusting Security Analysis Account)
2. Deploy `OrgAndAccountInfoReader` role in management account (trusting Security Analysis Account)
3. Ensure `OrganizationAccountAccessRole` exists in Security Analysis Account (standard AWS Organizations role)
4. Run Headroom from the Management Account

**Configuration:**
```yaml
management_account_id: '222222222222'
security_analysis_account_id: '111111111111'  # Required for this option
```

**Execution flow:**
- Headroom assumes `OrganizationAccountAccessRole` in Security Analysis Account
- Then assumes `OrgAndAccountInfoReader` in management account
- Then assumes `Headroom` role in each member account

## Configuration Parameters

### Required
- `management_account_id`: Your AWS Organizations management account ID

### Optional
- `security_analysis_account_id`: Only required if running from management account (Option 2)
- `exclude_account_ids`: When `true`, excludes account IDs from result files and filenames (default: `false`). This redacts identifiers; it does not skip any account.
- `skip_account_ids`: Account IDs to leave out of analysis entirely (default: `[]`). See [Skipping Accounts](#skipping-accounts).
- `use_account_name_from_tags`: When `true`, uses tag-based account names instead of AWS Organizations names (default: `false`)
- `account_tag_layout`: Tag keys for extracting account metadata (all optional)

### Skipping Accounts

```yaml
skip_account_ids:
  - '333333333333'
  - '444444444444'
```

A skipped account is never scanned, so it writes no result files. Policy
placement only ever sees accounts that have results, which has a consequence
worth being explicit about:

**Skipped accounts do not restrain org-wide policy.** They are absent from the
compliance picture rather than flagged as unknown, so Headroom recommends the
same root-level or OU-level placement it would if the account did not exist.
A generated policy can therefore deny actions a skipped account relies on. Skip
an account only when you accept that outcome for it.

Two things skipping does **not** do:

1. **It does not remove the account from your organization's membership set.**
   That set distinguishes in-org principals from third parties. Dropping a
   skipped account from it would reclassify it as a third party and add it to
   the generated RCP allowlist, widening the policy instead of narrowing it.
2. **It does not delete result files written by earlier runs.** Results already
   on disk keep feeding policy generation. To stop an account from influencing
   generated policy after you skip it, delete its files under
   `{results_dir}/{scps,rcps}/*/`.

Every entry must match an account ID that AWS Organizations reports. An entry
matching nothing aborts the run rather than silently analyzing an account you
believe is excluded. Quote the IDs: unquoted YAML parses them as integers and
the config is rejected.

Because the skip list is consulted before lifecycle-state classification, it
also serves as an escape hatch for an account whose state Headroom cannot
classify and which would otherwise abort the run.

### Account Tag Layout

All tags are optional. The tool works even without these tags on your accounts:

```yaml
account_tag_layout:
  environment: 'Environment'  # Falls back to "unknown" if missing
  name: 'Name'                # Falls back to AWS account name or ID if missing
  owner: 'Owner'              # Falls back to "unknown" if missing
```

**Tag behavior:**
- `environment`: Extracted if present, falls back to "unknown" if missing
- `name`: Only used when `use_account_name_from_tags: true`, falls back to account ID if missing
- `owner`: Extracted if present, falls back to "unknown" if missing

## Test Environment

The [`test_environment/`](https://github.com/discocrayon/Headroom/tree/main/test_environment) folder contains complete Terraform code to set up:
- A sample AWS Organization structure
- All required IAM roles
- Example SCPs and RCPs
- Test resources for validation

You can apply this Terraform from your management account to reproduce a working environment and test Headroom.

## Troubleshooting

### "Access Denied" errors
- Verify trust relationships on IAM roles
- Check that the principal account ID matches where you're running Headroom
- Ensure IAM policies include all required permissions
- If the error names a specific region, check that the `Headroom` role is exempt from any region-allowlist SCP (see [SCP Exemption Requirement](#scp-exemption-requirement)). Headroom scans every *enabled* region, so an SCP that denies a region it can still see aborts the run.

### "AuthFailure" in one region only

`AWS was not able to validate the provided access credentials`, raised from a
single region while every other region succeeds, means the credentials were
minted at the global STS endpoint. Those tokens are valid only in regions that
are enabled by default, so every opt-in region rejects them.

Headroom mints its own credentials regionally, so this points at a session it
did not build. Check for a boto3 `Session` constructed outside
`headroom/aws/sessions.py`, and confirm the region is genuinely enabled rather
than mid-enablement, which reports the same error:

```bash
aws account get-region-opt-status --region-name <region> --account-id <member-account-id>
```

### "Role not found" errors
- Confirm roles are deployed in the correct accounts
- Verify role names match: `Headroom` and `OrgAndAccountInfoReader`
- Check that you're using the correct account IDs in configuration

### Configuration validation errors
- Ensure `management_account_id` is always set
- Only set `security_analysis_account_id` if running from management account
- Validate YAML syntax in your config file
