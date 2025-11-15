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
- Read OpenSearch Serverless access policies

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
- `exclude_account_ids`: When `true`, excludes account IDs from result files and filenames (default: `false`)
- `use_account_name_from_tags`: When `true`, uses tag-based account names instead of AWS Organizations names (default: `false`)
- `account_tag_layout`: Tag keys for extracting account metadata (all optional)

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

### "Role not found" errors
- Confirm roles are deployed in the correct accounts
- Verify role names match: `Headroom` and `OrgAndAccountInfoReader`
- Check that you're using the correct account IDs in configuration

### Configuration validation errors
- Ensure `management_account_id` is always set
- Only set `security_analysis_account_id` if running from management account
- Validate YAML syntax in your config file
