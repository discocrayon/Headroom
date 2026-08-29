# Resource Control Policy (RCP) Module

This module creates and attaches Resource Control Policies (RCPs) to AWS Organizations targets (accounts, OUs, or root).

## Overview

RCPs are AWS Organizations policies that help you enforce security controls on resources across your organization. This module implements RCPs for:
1. Restricting ECR repository access to organization principals
2. Restricting KMS key access to organization principals
3. Restricting S3 bucket access to organization principals
4. Restricting Secrets Manager secret access to organization principals
5. Restricting SQS queue access to organization principals
6. Enforcing organization identity for IAM role assumptions

## Policy Details

Condition 2 below applies only when that allowlist is non-empty. An empty
allowlist omits `aws:PrincipalAccount` rather than emitting `[]`, which could
match nothing and void the Deny; condition 1 alone then denies all outsiders.

There is deliberately no `dp:exclude:identity` resource-tag exemption. Anyone
holding the service's tagging permission could set it, exempting their own
resources from the policy that exists to constrain them.

### ECR Repository Access Restriction

The `deny_ecr_third_party_access` RCP denies all `ecr:*` actions unless one of the following conditions is met:

1. The principal belongs to the organization (checked via `aws:PrincipalOrgID`)
2. The principal account is in the `ecr_third_party_access_account_ids_allowlist`
3. The principal is an AWS service

### KMS Key Access Restriction

The `deny_kms_third_party_access` RCP denies all `kms:*` actions unless one of the following conditions is met:

1. The principal belongs to the organization (checked via `aws:PrincipalOrgID`)
2. The principal account is in the `kms_third_party_access_account_ids_allowlist`
3. The principal is an AWS service

### S3 Bucket Access Restriction

The `deny_s3_third_party_access` RCP denies all `s3:*` actions unless one of the following conditions is met:

1. The principal belongs to the organization (checked via `aws:PrincipalOrgID`)
2. The principal account is in the `s3_third_party_access_account_ids_allowlist`
3. The principal is an AWS service

### Secrets Manager Secret Access Restriction

The `deny_secrets_manager_third_party_access` RCP denies all `secretsmanager:*` actions unless one of the following conditions is met:

1. The principal belongs to the organization (checked via `aws:PrincipalOrgID`)
2. The principal account is in the `secrets_manager_third_party_account_ids_allowlist`
3. The principal is an AWS service

### SQS Queue Access Restriction

The `deny_sqs_third_party_access` RCP denies all `sqs:*` actions unless one of the following conditions is met:

1. The principal belongs to the organization (checked via `aws:PrincipalOrgID`)
2. The principal account is in the `sqs_third_party_access_account_ids_allowlist`
3. The principal is an AWS service

### IAM AssumeRole Restriction

The `deny_sts_third_party_assumerole` RCP denies `sts:AssumeRole` actions unless one of the following conditions is met:

1. The principal belongs to the organization (checked via `aws:PrincipalOrgID`)
2. The principal account is in the `sts_third_party_assumerole_account_ids_allowlist`
3. The principal is an AWS service

## Usage

```hcl
module "account_rcp" {
  source = "./modules/rcps"

  target_id = "111111111111"

  # ECR
  deny_ecr_third_party_access = true
  ecr_third_party_access_account_ids_allowlist = [
    "111111111111"
  ]

  # KMS
  deny_kms_third_party_access = true
  kms_third_party_access_account_ids_allowlist = [
    "222222222222"
  ]

  # S3
  deny_s3_third_party_access = true
  s3_third_party_access_account_ids_allowlist = [
    "444444444444"
  ]

  # Secrets Manager
  deny_secrets_manager_third_party_access = true
  secrets_manager_third_party_account_ids_allowlist = [
    "888888888888"
  ]

  # SQS
  deny_sqs_third_party_access = true
  sqs_third_party_access_account_ids_allowlist = [
    "555555555555"
  ]

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
    "666666666666",
    "777777777777"
  ]
}
```

## Variables

### Required

- `target_id` (string): The AWS Organizations target ID (account ID, OU ID, or root ID)
- `deny_ecr_third_party_access` (bool): Whether to deny ECR access to accounts outside the organization
- `deny_kms_third_party_access` (bool): Whether to deny KMS access to accounts outside the organization
- `deny_s3_third_party_access` (bool): Whether to deny S3 access from third-party accounts
- `deny_secrets_manager_third_party_access` (bool): Whether to deny Secrets Manager access from third-party accounts
- `deny_sqs_third_party_access` (bool): Whether to deny SQS access from third-party accounts
- `deny_sts_third_party_assumerole` (bool): Whether to deny STS AssumeRole from third-party accounts

### Optional

- `ecr_third_party_access_account_ids_allowlist` (list(string), default: []): Allowlist of third-party AWS account IDs permitted to access ECR repositories
- `kms_third_party_access_account_ids_allowlist` (list(string), default: []): Allowlist of third-party AWS account IDs permitted to access KMS keys
- `s3_third_party_access_account_ids_allowlist` (list(string), default: []): Allowlist of third-party AWS account IDs permitted to access S3 buckets
- `secrets_manager_third_party_account_ids_allowlist` (list(string), default: []): Allowlist of third-party AWS account IDs permitted to access Secrets Manager secrets
- `sqs_third_party_access_account_ids_allowlist` (list(string), default: []): Allowlist of third-party AWS account IDs permitted to access SQS queues
- `sts_third_party_assumerole_account_ids_allowlist` (list(string), default: []): Allowlist of third-party AWS account IDs that are permitted to assume roles

## Notes

- RCPs have a maximum size of 5,120 bytes
- There is a maximum limit of 5 direct RCP attachments per target
