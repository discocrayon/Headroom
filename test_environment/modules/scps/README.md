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

When enabled, this policy enforces IMDSv2 (Instance Metadata Service version 2)
for **new EC2 instances**, through one statement:

1. **DenyRunInstancesMetadataHttpTokensOptional**: Denies `ec2:RunInstances` unless the request requires IMDSv2

#### Scope: launches only

This policy governs launches. Instances already running with IMDSv1 available
are outside it and stay reachable over IMDSv1 for as long as they live. That
is a scope decision: such instances are expected to be migrated, and this
policy's job is to stop new ones appearing while that happens.

A **DenyRoleDeliveryLessThan2** statement used to accompany this one, on the
same variable, denying every API call made with credentials fetched over
IMDSv1 and exempting by `aws:PrincipalTag/ExemptFromIMDSv2` on the calling
role. It was removed rather than split into its own variable. One variable
gating two statements meant one scan verdict licensing two different kinds of
evidence: a role-tagged IMDSv1 instance was reported as a clean exemption
while the surviving statement - which reads no role tag - would have denied
that account's next launch.

If you need the running fleet covered, that is a different control and needs
its own variable and its own verdict. Do not add a statement to this one.

#### Launches that disable IMDS must still say `HttpTokens=required`

This statement does not test `ec2:MetadataHttpEndpoint`, matching `MaxImdsHopLimit`.
A launch that turns IMDS off usually names no `HttpTokens`, so
`ec2:MetadataHttpTokens` is absent, `StringNotEquals` on an absent key is true,
and the deny fires. Such a launch has to name `HttpTokens=required` anyway.

That is accepted, and measured rather than inferred: AWS does *not* reject
`HttpTokens` alongside a disabled endpoint, despite what the EC2 guide says
about `ModifyInstanceMetadataOptions`. The extra parameter changes no
behaviour, because nothing is listening. Requiring it keeps this statement and
the check that gates it reading one thing, `HttpTokens`, rather than two.

#### Exemptions

**DenyRunInstancesMetadataHttpTokensOptional** exempts on
`aws:RequestTag/ExemptFromIMDSv2`: include `ExemptFromIMDSv2 = "true"` in the
launch request's instance tag specifications.

That is the only exemption. Tagging a **role** exempts nothing - that was
`aws:PrincipalTag`, read by the statement removed above.

Tagging the **instance** is the same act, seen later: the `TagSpecifications`
entry that supplies the request tag is what puts the tag on the instance the
launch creates. Headroom reads the instance's tag for exactly that reason, and
treats a tagged IMDSv1 instance as exempt rather than as a blocker. It is a
proxy and it can be wrong - a tag added afterwards with `CreateTags`, or an
instance whose Terraform never declares it, wears the tag while its relaunch
carries none. That cost is accepted deliberately; see `documentation/CHECKS.md`.

Measured with `RunInstances --dry-run` under this statement: `HttpTokens=optional`
tagged `true` is allowed, tagged `True` is denied, untagged is denied.

It is matched with `StringNotEquals`, which is case-sensitive: only the exact
value `"true"` exempts, and `"True"` is denied. The tag *key* is the opposite -
IAM matches condition key names without regard to case, so `exemptfromimdsv2`
works as well as `ExemptFromIMDSv2`. Do not rely on that; tag one way and stay
consistent, because a request carrying both spellings hits what AWS calls an
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
