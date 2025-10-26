## SCPs Module

Implements full set of available SCPs within size limits, should be based on service allowlist SCP.

Intention is to eventually have this Terraform module in the Terraform registry and have companies wrapper it to fit their own needs.

## Usage

```hcl
module "scps" {
  source = "./modules/scps"

  target_id         = "444444444444"  # AWS account ID, OU ID (ou-xxxx), or root ID (r-xxxx)
  deny_imds_v1_ec2  = true
}
```

## Variables

### Required Variables

- **`target_id`** (string): Organization account, root, or unit to attach the SCP to
  - Must be a 12-digit AWS account ID, an OU ID starting with `ou-`, or a root ID starting with `r-`
  - Examples: `"444444444444"`, `"ou-abcd-12345678"`, `"r-abcd"`

### Security Policy Variables

- **`deny_imds_v1_ec2`** (bool): Deny EC2 instances from using IMDSv1 (Instance Metadata Service version 1)

## Architecture

### Single SCP Design

This module creates a single SCP resource (`scp_1`) that conditionally includes multiple policy statements based on the input variables. This approach maximizes efficiency within AWS SCP limits:

- Maximum 5 SCPs can be attached per target (or 4 if `FullAWSAccess` hasn't been removed)
- Each SCP has a 5,120 character limit

### Size Limit Validation

The module validates SCP size at plan time (not apply time) using a local validation check. If the generated SCP exceeds 5,120 characters, Terraform will error during planning with the actual character count.

Reference: [Terraform Minimized SCPs](https://ramimac.me/terraform-minimized-scps) explains why `jsonencode()` is used for size optimization.

### Conditional Statement Inclusion

Policy statements are conditionally included using the pattern in `locals.tf`:
- Each policy is defined with an `include` boolean and a `statement` block
- Only statements where `include = true` are added to the final SCP
- The SCP resource is only created if at least one statement is included

## Security Policies

### IMDSv2 Enforcement (`deny_imds_v1_ec2`)

When enabled, this policy enforces IMDSv2 (Instance Metadata Service version 2) for EC2 instances through two statements:

1. **DenyRoleDeliveryLessThan2**: Denies all actions when `ec2:RoleDelivery < 2.0`
2. **DenyRunInstancesMetadataHttpTokensOptional**: Denies `ec2:RunInstances` when `ec2:MetadataHttpTokens != "required"`

#### Exemptions

Resources can be exempted from IMDSv2 enforcement using the tag `ExemptFromIMDSv2: "true"`:
- IAM roles: Tag the role with `ExemptFromIMDSv2 = "true"` to exempt all instances using that role
- EC2 instances: Include `ExemptFromIMDSv2 = "true"` in request tags when launching instances

## Resources Created

When at least one policy is enabled:
- `aws_organizations_policy.scp_1`: The Service Control Policy
  - Name format: `Scp1For-{target_id}`
  - Description: "See Sids for more info"
- `aws_organizations_policy_attachment.attach_scp_1_to_account`: Attaches the SCP to the specified target

When all policies are disabled, no resources are created.
