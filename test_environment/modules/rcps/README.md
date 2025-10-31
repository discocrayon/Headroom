# Resource Control Policy (RCP) Module

This module creates and attaches Resource Control Policies (RCPs) to AWS Organizations targets (accounts, OUs, or root).

## Overview

RCPs are AWS Organizations policies that help you enforce security controls on resources across your organization. This module specifically implements an RCP that enforces organization identity for role assumptions.

## Policy Details

The RCP created by this module denies `sts:AssumeRole` actions unless one of the following conditions is met:

1. The principal belongs to the organization (checked via `aws:PrincipalOrgID`)
2. The principal account is in the allowed third-party accounts list
3. The resource is tagged with `dp:exclude:identity: true`
4. The principal is an AWS service

## Usage

```hcl
module "account_rcp" {
  source = "./modules/rcps"

  target_id               = "123456789012"
  third_party_account_ids = [
    "111111111111",
    "222222222222"
  ]
}
```

## Variables

- `target_id` (required): The AWS Organizations target ID (account ID, OU ID, or root ID)
- `third_party_account_ids` (required): List of third-party AWS account IDs allowed to assume roles

## Notes

- RCPs have a maximum size of 5,120 bytes
- There is a maximum limit of 5 direct RCP attachments per target

