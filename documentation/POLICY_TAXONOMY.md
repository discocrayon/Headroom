# AWS Policy Pattern Taxonomy

## Overview

This document categorizes the different patterns of Service Control Policies (SCPs) and Resource Control Policies (RCPs) used in AWS Organizations. Understanding these patterns helps in designing, implementing, and reasoning about organizational security controls.

## Pattern Categories

| # | Pattern | Description | Implementation Mechanism | AWS Constructs |
|---|---------|-------------|-------------------------|----------------|
| 1 | **Absolute Deny** | Deny a specific action unconditionally | Deny statement with no conditions | `Action`, `Resource` |
| 2 | **Conditional Deny** | Deny an action unless a condition is met | Deny statement with condition keys | `Action`, `Resource`, `Condition` |
| 3 | **Module Tag / Paved Road Pattern** | Allow when proper Terraform module is used | Deny statement with module tag condition | `aws:RequestTag` |
| 4 | **Exception Tag Allow** | Exempt resources via a targeted exception tag | Deny statement with exception tag condition | `aws:RequestTag`, `aws:PrincipalTag` |
| 5a | **Account-Level Principal Allowlist** | Deny except for explicitly approved AWS account IDs | Deny statement with principal account condition | `aws:PrincipalAccount` |
| 5b | **Resource ARN Allowlist** | Deny except for explicitly approved resource ARNs | Deny statement with NotResource | `NotResource` |
| 5c | **Condition Key Value Allowlist** | Deny except for explicitly approved condition key values | Deny statement with allowlist of condition values | `Condition` with value list |
| 6 | **Conditional Deny + Allowlist Composition** | Deny unless condition is met AND only allow specific principals/resources | Combination of patterns #2 and #5 | Multiple `Condition` keys |

## Pattern Details

### Pattern 1: Absolute Deny

**Use Case:** Block actions that should never be allowed in any circumstance.

**Example:**
- Deny `iam:CreateSAMLProvider` globally across all accounts
- Prevent use of specific AWS services in the organization

**Policy Structure:**

```json
{
  "Effect": "Deny",
  "Action": "iam:CreateSAMLProvider",
  "Resource": "*"
}
```

**Characteristics:**
- No conditions or exceptions
- Strongest control mechanism
- Should be used sparingly for truly prohibited actions

---

### Pattern 2: Conditional Deny

**Use Case:** Enforce security requirements or compliance standards by denying actions unless specific conditions are met.

**Examples:**
- Require S3 encryption: deny object uploads unless `s3:x-amz-server-side-encryption` is specified
- Require IMDSv2: deny EC2 instance launches unless `ec2:MetadataHttpTokens = "required"`
- Require resource tagging: deny resource creation unless specific tags are present

**Policy Structure:**

```json
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": {
      "ec2:MetadataHttpTokens": "required"
    }
  }
}
```

**Characteristics:**
- Condition must be satisfied for action to be allowed
- Enforces organizational standards
- Can be combined with other patterns (see Pattern 6)

**Implementation Example (from `deny_rds_unencrypted`):**

```json
{
  "Effect": "Deny",
  "Action": [
    "rds:CreateDBInstance",
    "rds:CreateDBCluster",
    "rds:RestoreDBClusterFromS3",
    "rds:CreateBlueGreenDeployment"
  ],
  "Resource": "*",
  "Condition": {
    "Bool": {
      "rds:StorageEncrypted": "false"
    }
  }
}
```

**Codebase Reference:** `test_environment/modules/scps/locals.tf` lines 68-94

---

### Pattern 3: Module Tag / Paved Road Pattern

**Use Case:** Encourage and enforce use of blessed Terraform modules and approved infrastructure-as-code patterns.

**Philosophy:** This is NOT an exception mechanism. Module tags indicate that resources are being created through approved automation, which inherently means they're being created correctly with proper security controls built in.

**Examples:**
- Allow `Module=EKS-Cluster-Creator` to bypass certain restrictions because the module already implements security best practices
- Allow `Module=RDS-Secure-Deployment` to create database instances because it enforces encryption and proper networking

**Policy Structure:**

```json
{
  "Effect": "Deny",
  "Action": "eks:CreateCluster",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestTag/Module": "EKS-Cluster-Creator"
    }
  }
}
```

**Characteristics:**
- Proactive compliance through standardized tooling
- "You're doing it right" signal
- Reduces security burden by centralizing controls in modules
- Different from Pattern 4 (exception tags)

---

### Pattern 4: Exception Tag Allow

**Use Case:** Provide explicit exemptions for specific resources that need to bypass security controls, with clear documentation via tagging.

**Philosophy:** This IS an exception mechanism. Exception tags acknowledge that a resource is non-standard and requires special handling.

**Examples:**
- Allow a launch to answer IMDSv1 when the `RunInstances` request is tagged `ExemptFromIMDSv2=true` (visible afterwards as the instance's own tag)
- Allow specific security group rules for resources tagged `NetworkExemption=legacy-app`

**Implementation Example (from `deny_ec2_imds_v1`):**

```json
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": {
      "ec2:MetadataHttpTokens": "required",
      "aws:RequestTag/ExemptFromIMDSv2": "true"
    }
  }
}
```

**Codebase Reference:** `test_environment/modules/scps/locals.tf`, the
`DenyRunInstancesMetadataHttpTokensOptional` statement. Referenced by Sid
rather than by line number, which goes stale.

**Characteristics:**
- Reactive exemption for specific resources
- "You need an exception" signal
- Should be audited and reviewed regularly
- Provides clear trail of what's been exempted and why

**The tag name is not the exemption; the condition key is.** The same
`ExemptFromIMDSv2` name reads a launch request's tag under `aws:RequestTag`, a
role's tag under `aws:PrincipalTag`, and nothing at all on the instance
itself. A scanner that decides deployability has to check the dimension the
statement reads, or it clears an account whose launches enforcement will
break. See AP-009 in `HOW_TO_ADD_A_CHECK.md`.

**An exemption on a key the scan cannot read needs a proxy, chosen on
purpose.** This one lives on a `RunInstances` request in flight, which no scan
observes. `deny_ec2_imds_v1` reads the *instance's* tag instead, because the
`TagSpecifications` entry that supplies the request tag is what puts the tag
on the instance - so the tag on a running instance is the trace of the
exemption that let it launch, and evidence its relaunch will be exempt too.

A proxy is a judgement, not a lookup, and it must be argued rather than
assumed. This one is wrong when a tag was applied after launch with
`CreateTags`, or when the thing that recreates the instance does not declare
the tag; both leave a tagged instance whose relaunch enforcement denies. That
is accepted here as the cost of honouring a declared exemption. What is not
acceptable is reaching for a same-named tag on a *different* condition key -
`aws:PrincipalTag` is not `aws:RequestTag`, and substituting one for the other
is AP-009, not a proxy.

---

### Pattern 5a: Account-Level Principal Allowlist

**Use Case:** Restrict who can perform sensitive actions by limiting to specific AWS account IDs.

**Focus:** WHO can perform the action (principal-focused).

**Examples:**
- Only specific third-party vendor accounts can assume IAM roles
- Only security tooling accounts can access certain APIs
- Cross-account access limited to trusted accounts

**Implementation Example (from `deny_sts_third_party_assumerole`):**

```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "sts:AssumeRole",
  "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": {
      "aws:PrincipalOrgID": "o-exampleorgid",
      "aws:PrincipalAccount": [
        "111111111111",
        "333333333333"
      ]
    },
    "BoolIfExists": {
      "aws:PrincipalIsAWSService": "false"
    }
  }
}
```

**Codebase Reference:** `test_environment/modules/rcps/locals.tf` lines 8-26

**Characteristics:**
- Uses IAM condition keys about the principal
- Common keys: `aws:PrincipalAccount`, `aws:PrincipalOrgID`
- Useful for third-party integrations and cross-account access

---

### Pattern 5b: Resource ARN Allowlist

**Use Case:** Restrict what resources can be acted upon by specifying allowed resource ARNs.

**Focus:** WHAT can be acted upon (resource-focused).

**Examples:**
- Only specific IAM user ARNs can be created (deny creation of others)
- Only certain S3 buckets can be deleted
- Restrict resource modifications to approved resource paths

**Implementation Example (from `deny_iam_user_creation`):**

```json
{
  "Effect": "Deny",
  "Action": "iam:CreateUser",
  "NotResource": [
    "arn:aws:iam::111111111111:user/approved-user-1",
    "arn:aws:iam::111111111111:user/service/*",
    "arn:aws:iam::222222222222:user/*"
  ]
}
```

**Codebase Reference:** `test_environment/modules/scps/locals.tf` lines 44-48

**Characteristics:**
- Uses `NotResource` to specify exceptions
- Resource ARN patterns can include wildcards
- Useful for phased migrations and allowlisted resources

---

### Pattern 5c: Condition Key Value Allowlist

**Use Case:** Restrict based on specific values of a condition key by allowing only explicitly approved values.

**Focus:** WHICH VALUES of a condition key are allowed.

**Examples:**
- Only allow EC2 instances from specific AMI owners (amazon, aws-marketplace, trusted account IDs)
  - The scanner must record the value the condition key will actually hold,
    not the value that names the same thing elsewhere in the API. `ec2:Owner`
    is the AMI's `ImageOwnerAlias` when it has one and its numeric `OwnerId`
    otherwise, so an allowlist built from `OwnerId` alone denies every
    Amazon and Marketplace AMI - measurements in `documentation/CHECKS.md`
- Only allow S3 buckets with specific encryption types
- Restrict actions based on approved source IPs or VPCs

**Implementation Example (from `deny_ec2_ami_owner`):**

```json
{
  "Effect": "Deny",
  "Action": [
    "ec2:CreateFleet",
    "ec2:RequestSpotFleet",
    "ec2:RequestSpotInstances",
    "ec2:RunInstances"
  ],
  "Resource": "arn:aws:ec2:*::image/*",
  "Condition": {
    "StringNotEquals": {
      "ec2:Owner": [
        "amazon",
        "aws-marketplace",
        "111111111111"
      ]
    }
  }
}
```

**Codebase Reference:** `test_environment/modules/scps/locals.tf` lines 3-20

**Characteristics:**
- Uses `Condition` with a list of approved values
- Condition operators typically `StringNotEquals`, `StringNotLike`, or similar
- Values can be AWS account IDs, aliases (like "amazon"), or other identifiers
- Useful for restricting to trusted sources or approved configurations

---

### Pattern 6: Conditional Deny + Allowlist Composition

**Use Case:** Combine conditional requirements with an allowlist for complex access control scenarios.

**Pattern:** This is a composition of Pattern 2 (Conditional Deny) and Pattern 5 (Allowlists).

**Examples:**
- Region restrictions: Deny all actions unless `aws:RequestedRegion` is in approved list
- Confused deputy protection: Deny an AWS service acting on a caller's behalf unless the source account is in the organization or in an approved list, and only when the request carries a source account at all (`deny_service_confused_deputy`)

**Policy Structure:**

```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": [
        "us-east-1",
        "us-west-2"
      ]
    }
  }
}
```

**Characteristics:**
- Most complex pattern
- Multiple condition keys working together
- May combine multiple patterns
- Useful for sophisticated access control requirements

## Key Distinctions

### Pattern 3 vs Pattern 4: Semantic Difference

Both patterns use tags, but their meaning and intent are fundamentally different:

| Aspect | Pattern 3: Module Tag / Paved Road | Pattern 4: Exception Tag |
|--------|-----------------------------------|--------------------------|
| **Intent** | Proactive compliance | Reactive exemption |
| **Meaning** | "You're doing it right" | "You need an exception" |
| **Philosophy** | Blessed automation | Explicit bypass |
| **Example Tag** | `Module=EKS-Cluster-Creator` | `ExemptFromIMDSv2=true` |
| **Audit Stance** | Encouraged (shows good practice) | Scrutinized (potential risk) |
| **Lifecycle** | Permanent (module is the standard) | Temporary (exception should be resolved) |

**Key Insight:** Pattern 3 encourages correct behavior through tooling. Pattern 4 acknowledges incorrect behavior but provides escape hatch.

### Pattern 5 Variants: Implementation Mechanisms

All Pattern 5 variants use allowlists, but they focus on different aspects of the request:

| Aspect | Pattern 5a: Account Allowlist | Pattern 5b: Resource ARN Allowlist | Pattern 5c: Condition Key Value Allowlist |
|--------|------------------------------|-----------------------------------|------------------------------------------|
| **Focus** | WHO (Principal) | WHAT (Resource) | WHICH VALUES (Condition) |
| **Question** | "Who can perform this action?" | "What can be acted upon?" | "Which condition values are allowed?" |
| **Mechanism** | IAM condition keys | Resource matching | Condition value matching |
| **AWS Constructs** | `aws:PrincipalAccount` | `NotResource` with ARN patterns | `Condition` with value list |
| **Example** | Third-party assume role access | Allowed IAM user paths | Allowed AMI owners |
| **Flexibility** | Account-level granularity | Resource-level granularity | Attribute-level granularity |

**Key Insights:**
- Use 5a when controlling access based on identity
- Use 5b when controlling access based on target resources
- Use 5c when controlling access based on specific condition key values

## Implementation Examples from Headroom Codebase

### Pattern 2 Example: `deny_ec2_public_ip`

**Check:** `headroom/checks/scps/deny_ec2_public_ip.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 3-19

This check identifies EC2 instances with public IP addresses assigned. The SCP denies instance launches when a public IP address would be assigned.

**Policy Structure:**
- Deny `ec2:RunInstances` on instance resources
- When `ec2:AssociatePublicIpAddress` equals "true"

**Headroom's Role:** Scans all accounts and reports existing EC2 instances with their public IP status. This informs deployment decisions and identifies resources that would be impacted by the SCP.

### Pattern 2 Example: `deny_ec2_imds_hop_limit`

**Check:** `headroom/checks/scps/deny_ec2_imds_hop_limit.py`
**Terraform:** `test_environment/modules/scps/locals.tf`

This check identifies EC2 instances whose IMDS hop limit exceeds 1. The SCP denies instance launches that request a higher limit, keeping the metadata response from crossing an extra network hop.

**Policy Structure:**
- Deny `ec2:RunInstances` on instance resources
- When `ec2:MetadataHttpPutResponseHopLimit` is numerically greater than 1

**Headroom's Role:** Scans all accounts and reports each instance's configured hop limit and whether its metadata endpoint is enabled. The hop limit is counted whether or not the endpoint is enabled, because the SCP counts it that way: AWS accepts a launch naming both a hop limit and a disabled endpoint, so the condition key is present and the deny fires. The endpoint state is reported for context - a violation on an instance whose endpoint is off is free to remedy, since nothing reads the hop limit there.

**Note:** This is the first Pattern 2 policy in the codebase to use a numeric comparison rather than a string or boolean match. The pattern is unchanged -- `NumericGreaterThan` expresses the same "deny unless the condition holds" shape as `StringNotEquals` elsewhere.

**Limitation:** The policy only constrains launches. `ec2:ModifyInstanceMetadataOptions` exposes no condition keys, so the hop limit can still be raised on a running instance. Denying that action is a separate decision and is not covered here.

### Pattern 2 Example: `deny_rds_unencrypted`

**Check:** `headroom/checks/scps/deny_rds_unencrypted.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 68-94

This check identifies RDS databases (instances and Aurora clusters) without encryption at rest enabled. The SCP denies database creation operations unless the `rds:StorageEncrypted` condition key is set to "true".

**Policy Structure:**
- Deny `rds:CreateDBInstance`, `rds:CreateDBCluster`, `rds:RestoreDBClusterFromS3`, `rds:CreateBlueGreenDeployment`
- Unless `rds:StorageEncrypted` equals "true"

**Headroom's Role:** Scans all accounts and reports existing databases with their encryption status. This informs deployment decisions and identifies resources that would be impacted by the SCP.

**Note:** The policy enforces encryption for new RDS instances and Aurora/DocumentDB clusters. `rds:CreateDBInstance` is included as a special exception despite not being documented in the AWS Service Authorization Reference, as manual testing confirmed it works.

### Pattern 4: `deny_ec2_imds_v1`

**Check:** `headroom/checks/scps/deny_ec2_imds_v1.py`
**Terraform:** `test_environment/modules/scps/locals.tf`, the
`DenyRunInstancesMetadataHttpTokensOptional` statement
**Tag:** `ExemptFromIMDSv2`

This check identifies EC2 instances with IMDSv1 enabled. The variable gates
one statement, which denies a `RunInstances` call whose
`ec2:MetadataHttpTokens` is not `required` unless the request carries
`ExemptFromIMDSv2=true` under `aws:RequestTag`.

**One variable, one statement.** An earlier revision put a second statement
behind this variable: `DenyRoleDeliveryLessThan2`, denying any API call made
with credentials fetched over IMDSv1, exempted by `aws:PrincipalTag` on the
calling role. Two statements evaluated at different times and exempting on
different keys meant one scan verdict licensing both kinds of evidence, so a
role-tagged IMDSv1 instance was reported as a clean exemption while the
surviving statement - which reads no role tag - would have denied that
account's next launch. It was removed rather than split into its own
variable. A tag on the instance's IAM role now exempts nothing.

**Scope:** enforcement reaches launches only. Every instance the scan sees has
already launched and cannot be denied by the statement; an IMDSv1 instance
counts as evidence that the account's next launch would be. Credential use
from an instance already running is out of scope by decision - covering it
again means a new variable carrying its own verdict, not a second statement
on this one.

### Pattern 1 Example: `deny_iam_saml_provider_not_aws_sso`

**Check:** `headroom/checks/scps/deny_iam_saml_provider_not_aws_sso.py`
**Terraform:** `test_environment/modules/scps/locals.tf`

This check enforces use of AWS IAM Identity Center (AWS SSO) for SAML authentication by identifying non-compliant SAML providers. It implements an absolute deny guardrail once all accounts meet the constraint.

**Policy Structure:**
- Deny `iam:CreateSAMLProvider` unconditionally
- No conditions or exceptions

**Headroom's Role:** Scans all accounts and reports existing SAML providers. Validates that accounts have either zero SAML providers or exactly one AWS SSO-managed provider (with `AWSSSO_` prefix). This informs deployment decisions for the absolute deny policy.

**Compliance Model:** Account is compliant only when:
- Zero SAML providers exist, OR
- Exactly one provider exists with `AWSSSO_` prefix

Any other combination (multiple providers or non-AWS SSO providers) is a violation.

---

### Pattern 2 Example: `deny_lambda_auth_type_none`

**Check:** `headroom/checks/scps/deny_lambda_auth_type_none.py`
**Terraform:** `test_environment/modules/scps/locals.tf`

This check identifies Lambda functions with function URLs using NONE authentication, which allows unauthenticated public access. The SCP denies creating a function URL, updating one, and granting invoke permission on one, unless proper authentication is configured.

**Policy Structure:**
- Deny `lambda:CreateFunctionUrlConfig`, `lambda:UpdateFunctionUrlConfig`, and `lambda:AddPermission`
- When `lambda:FunctionUrlAuthType` equals "NONE"

**Note:** `lambda:AddPermission` is included alongside the two function URL config actions because it grants invoke permission on an existing function URL. Denying only creation and update would leave a path to unauthenticated access on URLs that already exist.

**Headroom's Role:** Scans all accounts and reports Lambda functions with their function URL authentication configuration. This informs deployment decisions and identifies functions that would be impacted by the SCP.

---

### Pattern 5a: `deny_ecr_third_party_access`

**Check:** `headroom/checks/rcps/deny_ecr_third_party_access.py`
**Terraform:** `test_environment/modules/rcps/locals.tf` lines 3-26
**Variable:** `deny_ecr_third_party_access_account_ids_allowlist`

This RCP restricts ECR repository access to organization principals and explicitly allowlisted third-party account IDs. It analyzes ECR repository resource policies to identify external account access patterns.

**Policy Structure:**
- Deny `ecr:*` actions
- Unless `aws:PrincipalOrgID` matches the organization OR `aws:PrincipalAccount` is in the allowlist
- Excludes AWS service principals

**Headroom's Role:** Scans all accounts and analyzes ECR repository policies, identifying which third-party accounts have access and which ECR actions they can perform. This informs the allowlist configuration for RCP deployment. The check also detects wildcard principals that would block RCP deployment.

**Key Feature:** Tracks which specific ECR actions (e.g., `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`) each third-party account is granted, enabling precise understanding of access patterns.

**Fail-Fast Validation:** If any ECR repository policy contains a Federated principal (or other unsupported principal types), the check immediately fails with a clear error message, as these would break when the RCP is deployed.

### Pattern 5a: `deny_sts_third_party_assumerole`

**Terraform:** `test_environment/modules/rcps/locals.tf` lines 27-51
**Variable:** `sts_third_party_assumerole_account_ids_allowlist`

This RCP restricts role assumptions to organization principals and explicitly allowlisted third-party account IDs. It uses `aws:PrincipalOrgID` and `aws:PrincipalAccount` conditions.

**Analysis by:** `headroom/checks/rcps/deny_deny_sts_third_party_assumerole.py`

### Pattern 5a: `deny_kms_third_party_access`

**Check:** `headroom/checks/rcps/deny_kms_third_party_access.py`
**Terraform:** `test_environment/modules/rcps/locals.tf` lines 53-78
**Variable:** `kms_third_party_access_account_ids_allowlist`

This RCP restricts KMS key access to organization principals and explicitly allowlisted third-party account IDs. It blocks all `kms:*` actions for principals outside the organization unless explicitly allowed.

**Policy Structure:**
- Deny `kms:*` (all KMS actions)
- Unless `aws:PrincipalOrgID` matches organization OR `aws:PrincipalAccount` is in allowlist
- Excludes AWS service principals via `aws:PrincipalIsAWSService`

**Headroom's Role:** Scans all accounts and analyzes KMS key policies, identifying which third-party accounts have access and which KMS actions they can perform. This informs the allowlist configuration for RCP deployment. The check also detects wildcard principals that would block RCP deployment.

**Key Feature:** Tracks which specific KMS actions (e.g., `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey`) each third-party account is granted, enabling precise understanding of access patterns across all KMS keys in the account.

**Fail-Fast Validation:** If any KMS key policy contains a Federated principal (or other unsupported principal types), the check immediately fails with a clear error message, as these would break when the RCP is deployed.

### Pattern 5a: `deny_sqs_third_party_access`

**Check:** `headroom/checks/rcps/deny_sqs_third_party_access.py`
**Terraform:** `test_environment/modules/rcps/locals.tf`
**Variable:** `sqs_third_party_access_account_ids_allowlist`

This RCP restricts SQS queue access to organization principals and explicitly allowlisted third-party account IDs. It analyzes SQS queue resource policies to identify external account access patterns.

**Policy Structure:**
- Deny `sqs:*` actions
- Unless `aws:PrincipalOrgID` matches the organization OR `aws:PrincipalAccount` is in the allowlist
- Excludes AWS service principals

**Headroom's Role:** Scans all accounts and analyzes SQS queue policies across all regions, identifying which third-party accounts have access and which SQS actions they can perform. This informs the allowlist configuration for RCP deployment. The check also detects wildcard principals that would block RCP deployment.

**Key Feature:** Tracks which specific SQS actions (e.g., `sqs:SendMessage`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`) each third-party account is granted on which queues, enabling precise understanding of access patterns.

**Fail-Fast Validation:** If any SQS queue policy contains a Federated principal (or other unsupported principal types), the check immediately fails with a clear error message, as these would break when the RCP is deployed.

---

### Pattern 5a: `deny_secrets_manager_third_party_access`

**Check:** `headroom/checks/rcps/deny_secrets_manager_third_party_access.py`
**Terraform:** `test_environment/modules/rcps/locals.tf`
**Variable:** `secrets_manager_third_party_access_account_ids_allowlist`

This RCP restricts Secrets Manager secret access to organization principals and explicitly allowlisted third-party account IDs. It analyzes secret resource policies to identify external account access patterns.

**Policy Structure:**
- Deny `secretsmanager:*` actions
- Unless `aws:PrincipalOrgID` matches the organization OR `aws:PrincipalAccount` is in the allowlist
- Excludes AWS service principals

**Headroom's Role:** Scans all accounts and analyzes Secrets Manager secret policies across all regions, identifying which third-party accounts have access and which Secrets Manager actions they can perform. This informs the allowlist configuration for RCP deployment. The check also detects wildcard principals or non-account principals (like Federated) that would block RCP deployment.

**Key Feature:** Tracks both:
- Which specific Secrets Manager actions (e.g., `secretsmanager:GetSecretValue`, `secretsmanager:DescribeSecret`) each third-party account is granted
- Which secrets each third-party account can access

**Fail-Fast Validation:** If any secret policy contains wildcard principals or non-account principals (like Federated), these are flagged as violations that would break when the RCP is deployed.

---

### Pattern 6: `deny_service_confused_deputy`

**Check:** `headroom/checks/rcps/deny_service_confused_deputy.py`
**Terraform:** `test_environment/modules/rcps/locals.tf`
**Variable:** `service_confused_deputy_source_account_ids_allowlist`

The six RCP statements above all exempt AWS service principals, because a service call carries no `aws:PrincipalOrgID` and the Deny would otherwise match every service integration in the organization. This statement narrows that exemption back down, denying the same six services' actions when an AWS service acts on behalf of a source account outside the organization.

```json
{
  "Sid": "DenyServiceConfusedDeputy",
  "Effect": "Deny",
  "Principal": "*",
  "Action": [
    "ecr:*",
    "kms:*",
    "s3:*",
    "secretsmanager:*",
    "sqs:*",
    "sts:AssumeRole"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": {
      "aws:SourceOrgID": "o-exampleorgid",
      "aws:SourceAccount": [
        "999999999999"
      ]
    },
    "Null": {
      "aws:SourceAccount": "false"
    },
    "Bool": {
      "aws:PrincipalIsAWSService": "true"
    }
  }
}
```

**Policy Structure:**
- Deny `ecr:*`, `kms:*`, `s3:*`, `secretsmanager:*`, `sqs:*` and `sts:AssumeRole` - the union of the six statements' actions, in one statement rather than six, to stay inside the 5,120-character RCP budget
- Only when the caller **is** an AWS service (`Bool`, `true`), which is the inverse of the `BoolIfExists` `false` the other six carry
- Only when the request carries an `aws:SourceAccount` (`Null` = `"false"` reads as "the key is present"). A service call populating only `aws:SourceArn`, or no source keys at all, falls outside this statement entirely - it narrows the service exemption rather than closing it, which is what makes the control deployable without first discovering every service integration in the estate
- Unless that source account belongs to this organization (`aws:SourceOrgID`) or is in the allowlist (`aws:SourceAccount`). An empty allowlist omits the key rather than emitting `[]`, leaving the organization condition to deny every outside source
- `aws:SourceOrgID` is compared with `StringNotEqualsIfExists`, so a source in a standalone account - which belongs to no organization and carries no organization ID - is still denied. An attacker cannot escape the control by using an unattached account

**Why Pattern 6 rather than 5a:** the allowlisted account is not the principal. The principal is the AWS service, and the account being allowlisted is the one that configured it. The statement composes a conditional deny (the `Null` and `Bool` gates) with a condition-key value allowlist on `aws:SourceAccount`, which is the composition Pattern 6 describes - three condition keys - `aws:SourceOrgID`, `aws:SourceAccount` and `aws:PrincipalIsAWSService` - in four entries across three operator blocks, none of them `aws:PrincipalAccount`.

**Headroom's Role:** Reads the source guard on every `Allow` statement that names a `Service` principal, across the six resource types the other RCP checks already analyze - ECR, KMS, S3, Secrets Manager, SQS and IAM role trust policies. Recording that guard costs those six checks nothing, but this check re-runs their six analyzers rather than reusing the results, so every RCP read API is issued twice per account per run. Caching is deliberately not implemented; it is a separate optimization if the duplication proves material. Out-of-organization accounts named by `aws:SourceAccount`, or extracted from `aws:SourceArn`, are unioned into the allowlist. A guard no allowlist can express - `*` in the account, or an ARN yielding no account with no companion `aws:SourceAccount` - is a violation that withholds the statement from that account, the same mechanism a wildcard principal already triggers.

**Key Feature:** Service principals trusted with no source guard are neither listed nor counted. The `Null` gate means the statement never fires on a request carrying no source account, so an unguarded trust needs no allowlist entry and blocks nothing; and because all six analyzers drop an analysis with nothing to report, any estate-wide count taken here would silently undercount. See `documentation/CHECKS.md` for the full disposition table.

**Fail-Fast Validation:** A source guard that cannot be read aborts the run rather than being dropped - `aws:SourceOrgID` on a service principal, a source key under an operator that does not pin it to a value, or an `aws:SourceAccount` value that is neither a twelve-digit account ID nor a wildcard. Silently dropping one would leave its account out of the allowlist, and the deployed RCP would then deny access that account depended on.

---

### Pattern 5b: `deny_iam_user_creation`

**Check:** `headroom/checks/scps/deny_iam_user_creation.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 39-49
**Variable:** `iam_allowed_users`

This check lists all IAM users in accounts. The SCP uses `NotResource` to deny `iam:CreateUser` except for explicitly allowed user ARN patterns.

**Headroom's Role:** Scans accounts and reports existing users, which inform the allowlist configuration.

### Pattern 5c: `deny_ec2_ami_owner`

**Check:** `headroom/checks/scps/deny_ec2_ami_owner.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 3-20
**Variable:** `ec2_allowed_ami_owners`

This check identifies EC2 instances and determines the owner of the AMI used to launch each instance. The SCP denies `ec2:RunInstances` unless the AMI owner is in the allowlist.

**Policy Structure:**
- Deny the launch paths: `ec2:RunInstances`, `ec2:CreateFleet`,
  `ec2:RequestSpotFleet`, `ec2:RequestSpotInstances`
- Scoped to the **image** resource, `arn:aws:ec2:*::image/*`
- Unless `ec2:Owner` is in the approved list (e.g., "amazon", "aws-marketplace", trusted account IDs)

**Why those actions:** they are EC2 actions AWS authorizes against the image
resource with `ec2:Owner`, per the machine-readable service reference at
`https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json`.

`ec2:ModifyFleet` supports the key as well - raising a fleet's target capacity
starts instances from its launch template's AMI - and is excluded as a
deliberate scope decision.

`ec2:RunScheduledInstances`, `ec2:ModifySpotFleetRequest` and
`ec2:CreateLaunchTemplateVersion` are excluded for a different reason: they
list no image resource, so a statement scoped to `image/*` never matches them
and adding them would read as coverage while denying nothing.

**Why the image resource:** `RunInstances` is authorized against every resource
it touches - instance, volume, network interface, image - and `ec2:Owner` exists
only on the image. Scoped to `instance/*` the key is absent from the request
context, `StringNotEquals` on an absent key evaluates true, and the Deny matches
every launch regardless of AMI. The operator is deliberately not
`StringNotEqualsIfExists`: for a Deny statement, denying when the owner cannot
be read is the safe direction.

**Why the allowlist is never empty:** an empty `ec2_allowed_ami_owners` denies
every launch rather than none of them, so Terraform generation aborts rather
than rendering it. See the Allowlist Guard in the Headroom Specification.

**Headroom's Role:** Scans all accounts and reports all EC2 instances with their AMI owners. The unique AMI owners observed across the accounts a placement covers are unioned into `ec2_allowed_ami_owners`. The check helps identify:
- Amazon-owned AMIs (owner: "amazon")
- AWS Marketplace AMIs (various vendor account IDs)
- Custom AMIs (account-owned)
- Unknown AMIs (AMI no longer exists)

## Design Principles

### 1. Start with Least Privilege

Begin with deny-all and add allowlists (Patterns 5a/5b/5c) rather than trying to deny specific bad behaviors.

### 2. Prefer Paved Roads over Exceptions

Use Pattern 3 (Module Tags) to encourage correct behavior rather than Pattern 4 (Exception Tags) to permit incorrect behavior.

### 3. Make Exceptions Explicit and Auditable

When Pattern 4 (Exception Tags) is necessary, ensure tags are:
- Clearly named (`ExemptFromIMDSv2` not `special`)
- Documented with business justification
- Reviewed periodically for removal

### 4. Combine Patterns for Defense in Depth

Use Pattern 6 (Composition) to layer multiple controls:
- Conditional requirements (Pattern 2)
- Plus principal restrictions (Pattern 5a)
- Plus resource restrictions (Pattern 5b)
- Plus condition value restrictions (Pattern 5c)

### 5. Document the "Why"

Every policy should map to one of these patterns with clear documentation of:
- Which pattern is being used
- Why this pattern was chosen
- What it protects against
- Any exceptions or special handling

## Usage in Headroom

Headroom implements checks that analyze compliance with these policy patterns:

1. **Scanning:** Headroom scans AWS accounts to find resources that would be affected by these policies
2. **Categorization:** Results are categorized as violations, exemptions (Pattern 4), or compliant
3. **Allowlist Generation:** For Patterns 5a/5b/5c and the Pattern 6 compositions built on them, Headroom generates the lists of principals/resources/values that should be allowed
4. **Terraform Generation:** Headroom can generate Terraform configurations that implement these patterns

**Workflow:**
```
Scan AWS → Identify Resources → Categorize → Generate Allowlists → Generate Terraform → Apply Policies
```

## References

- [AWS IAM Policy Elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html)
- [AWS Organizations SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [AWS Organizations RCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [AWS IAM Condition Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)

---

**Document Version:** 1.0
**Last Updated:** November 9, 2025
