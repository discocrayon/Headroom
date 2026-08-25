## SCPs Module

Implements full set of available SCPs within size limits, should be based on service allowlist SCP.

Intention is to eventually have this Terraform module in the Terraform registry and have companies wrapper it to fit their own needs.

## Usage

```hcl
module "scps" {
  source = "./modules/scps"

  target_id                          = "444444444444"  # AWS account ID, OU ID (ou-xxxx), or root ID (r-xxxx)
  deny_ec2_ami_owner                 = true
  ec2_allowed_ami_owners             = ["amazon", "444444444444"]
  deny_ec2_imds_v1                   = true
  deny_ec2_public_ip                 = true
  deny_eks_create_cluster_without_tag = true
  deny_iam_user_creation             = true
  deny_iam_saml_provider_not_aws_sso     = true
  iam_allowed_users                  = [
    "arn:aws:iam::444444444444:user/terraform-user",
    "arn:aws:iam::444444444444:user/github-actions",
  ]
  deny_rds_unencrypted               = true
}
```

## Variables

### Required Variables

- **`target_id`** (string): Organization account, root, or unit to attach the SCP to
  - Must be a 12-digit AWS account ID, an OU ID starting with `ou-`, or a root ID starting with `r-`
  - Examples: `"444444444444"`, `"ou-abcd-12345678"`, `"r-abcd"`

### Security Policy Variables

- **`deny_ec2_ami_owner`** (bool): Deny EC2 instances from launching with AMIs not from approved owners.
  Covers `RunInstances`, `CreateFleet`, `RequestSpotFleet` and `RequestSpotInstances`
- **`ec2_allowed_ami_owners`** (list(string)): List of allowed AMI owner account IDs or aliases (e.g., "amazon", "self")
- **`deny_ec2_imds_v1`** (bool): Deny EC2 instances from using IMDSv1 (Instance Metadata Service version 1)
- **`deny_ec2_public_ip`** (bool): Deny EC2 instances from being launched with public IP addresses
- **`deny_eks_create_cluster_without_tag`** (bool): Deny EKS cluster creation unless PavedRoad=true tag is present
- **`deny_iam_user_creation`** (bool): Deny creation of IAM users not on the allowed list
- **`deny_iam_saml_provider_not_aws_sso`** (bool): Deny creation of IAM SAML providers so only AWS IAM Identity Center (AWS SSO) managed providers remain
- **`iam_allowed_users`** (list(string)): List of IAM user ARNs that are allowed to be created. Format: `arn:aws:iam::ACCOUNT_ID:user/USERNAME`
- **`deny_rds_unencrypted`** (bool): Deny creation of unencrypted RDS databases

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

### IMDSv2 Enforcement (`deny_ec2_imds_v1`)

When enabled, this policy enforces IMDSv2 (Instance Metadata Service version 2) for EC2 instances through two statements:

1. **DenyRoleDeliveryLessThan2**: Denies all actions when `ec2:RoleDelivery < 2.0` - that is, any API call made with credentials fetched over IMDSv1
2. **DenyRunInstancesMetadataHttpTokensOptional**: Denies `ec2:RunInstances` unless the request requires IMDSv2 or disables the metadata endpoint

The two statements gate different things. The first gates calls made by
instances running now; the second gates future launches. A fleet that passes
the first can still be denied by the second, because the second reads a request
parameter rather than the resulting instance.

#### Keeping IMDS-disabled launches possible

The second statement also passes a request that sets
`ec2:MetadataHttpEndpoint = "disabled"`. A launch that turns IMDS off usually
names no `HttpTokens` - there is no metadata service left to require a token
from - so without that clause `ec2:MetadataHttpTokens` is absent, its
`StringNotEquals` is true, and the deny fires. The policy would forbid the one
configuration no credential can be stolen from.

This was measured, not inferred: with an AMI that does not set
`imds-support=v2.0`, a dry-run launch specifying only `HttpEndpoint=disabled`
is denied without the clause and allowed with it. Note that AWS does *not*
reject `HttpTokens` alongside a disabled endpoint, despite what the EC2 guide
says about `ModifyInstanceMetadataOptions`; the clause is needed for the
ordinary shape that omits `HttpTokens`, not because the explicit shape is
rejected.

#### Exemptions

Each statement has its own exemption, and they are different dimensions of the
same tag name. Tagging the **instance** exempts neither.

- **DenyRoleDeliveryLessThan2** exempts on `aws:PrincipalTag/ExemptFromIMDSv2`:
  tag the **IAM role** with `ExemptFromIMDSv2 = "true"` to exempt every instance
  running as that role.
- **DenyRunInstancesMetadataHttpTokensOptional** exempts on
  `aws:RequestTag/ExemptFromIMDSv2`: include `ExemptFromIMDSv2 = "true"` in the
  launch request's instance tag specifications.

Both are matched with `StringNotEquals`, which is case-sensitive: only the exact
value `"true"` exempts, and `"True"` is denied. The tag *key* is the opposite -
IAM matches condition key names without regard to case, so `exemptfromimdsv2`
works as well as `ExemptFromIMDSv2`. Do not rely on that; tag one way and stay
consistent, because a principal carrying both spellings hits what AWS calls an
unexpected condition failure.

### EKS Paved Road Enforcement (`deny_eks_create_cluster_without_tag`)

When enabled, this policy enforces the "paved road" approach for EKS cluster creation, encouraging use of blessed automation and infrastructure-as-code:

**DenyEksCreateClusterWithoutTag**: Denies `eks:CreateCluster` action unless `aws:RequestTag/PavedRoad` equals "true"

#### Purpose

This policy implements a "Module Tag / Paved Road Pattern" to:
- Encourage use of approved automation and infrastructure-as-code tools
- Discourage manual cluster creation via AWS Console or ad-hoc CLI commands
- Maintain consistency in cluster configuration and security posture
- Enable tracking of which clusters were created via approved methods

#### Configuration

To create EKS clusters when this policy is enabled, your automation must include the tag in the creation request:

```bash
aws eks create-cluster --name my-cluster \
  --tags PavedRoad=true \
  ...
```

In Terraform:

```hcl
resource "aws_eks_cluster" "example" {
  name = "my-cluster"

  tags = {
    PavedRoad = "true"
  }
  ...
}
```

#### Tag Matching

- The condition uses `StringNotEquals`, requiring exact match: `PavedRoad` (case-sensitive) must equal `"true"` (string)
- Missing tag or incorrect value (e.g., `"True"`, `"TRUE"`, `"yes"`) will be denied
- The tag must be present in the request tags at cluster creation time

### IAM User Creation Restriction (`deny_iam_user_creation`)

When enabled, this policy denies the creation of IAM users that are not on the allowed list through:

**DenyIamUserCreation**: Denies `iam:CreateUser` action for all IAM user ARNs not specified in `iam_allowed_users`

This policy uses the `NotResource` element to explicitly allow creation of only the IAM users specified in the allowed list. Any attempt to create IAM users not on the allowed list will be denied.

#### Configuration

Specify allowed IAM user ARNs using the format: `arn:aws:iam::ACCOUNT_ID:user/USERNAME`

Example: `arn:aws:iam::444444444444:user/terraform-user`

### AWS SSO SAML Guardrail (`deny_iam_saml_provider_not_aws_sso`)

When enabled, this absolute deny control removes the ability to create new IAM SAML providers by denying `iam:CreateSAMLProvider` with no conditions.

- Ensures organizations rely solely on AWS IAM Identity Center (AWS SSO) federation (`AWSSSO_` prefixed providers)
- Prevents shadow SAML integrations that bypass centralized access management
- Complements detection checks that verify only a single AWS SSO-managed provider exists
- `AWSServiceRoleForSSO` continues to provision the official provider in new accounts and is not affected by SCPs, so denying `iam:CreateSAMLProvider` to all principals blocks only custom provider creation

### Root LeaveOrganization Protection

When the module target is the organization root (values such as `r-root`), a guardrail statement is always included that denies `organizations:LeaveOrganization` for all principals. This prevents detaching the root from the organization, even when no optional checks are enabled.

## Resources Created

When at least one policy is enabled:
- `aws_organizations_policy.scp_1`: The Service Control Policy
  - Name format: `Scp1For-{target_id}`
  - Description: "See Sids for more info"
- `aws_organizations_policy_attachment.attach_scp_1_to_account`: Attaches the SCP to the specified target

When all policies are disabled, no resources are created.
