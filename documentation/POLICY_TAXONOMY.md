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
- Allow IMDSv1 for legacy workloads tagged `ExemptFromIMDSv2=true`
- Allow specific security group rules for resources tagged `NetworkExemption=legacy-app`

**Implementation Example (from `deny_imds_v1_ec2`):**

```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "NumericLessThan": {
      "ec2:RoleDelivery": "2.0"
    },
    "StringNotEquals": {
      "aws:PrincipalTag/ExemptFromIMDSv2": "true"
    }
  }
}
```

**Codebase Reference:** `test_environment/modules/scps/locals.tf` lines 8-20, 27-37

**Characteristics:**
- Reactive exemption for specific resources
- "You need an exception" signal
- Should be audited and reviewed regularly
- Provides clear trail of what's been exempted and why

---

### Pattern 5a: Account-Level Principal Allowlist

**Use Case:** Restrict who can perform sensitive actions by limiting to specific AWS account IDs.

**Focus:** WHO can perform the action (principal-focused).

**Examples:**
- Only specific third-party vendor accounts can assume IAM roles
- Only security tooling accounts can access certain APIs
- Cross-account access limited to trusted accounts

**Implementation Example (from `enforce_assume_role_org_identities`):**

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
        "123456789012",
        "210987654321"
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
- Only allow S3 buckets with specific encryption types
- Restrict actions based on approved source IPs or VPCs

**Implementation Example (from `deny_ec2_ami_owner`):**

```json
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
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

### Pattern 2: `deny_rds_unencrypted`

**Check:** `headroom/checks/scps/deny_rds_unencrypted.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 68-94

This check identifies RDS databases (instances and Aurora clusters) without encryption at rest enabled. The SCP denies database creation operations unless the `rds:StorageEncrypted` condition key is set to "true".

**Policy Structure:**
- Deny `rds:CreateDBInstance`, `rds:CreateDBCluster`, `rds:RestoreDBClusterFromS3`, `rds:CreateBlueGreenDeployment`
- Unless `rds:StorageEncrypted` equals "true"

**Headroom's Role:** Scans all accounts and reports existing databases with their encryption status. This informs deployment decisions and identifies resources that would be impacted by the SCP.

**Note:** The policy enforces encryption for new RDS instances and Aurora/DocumentDB clusters. `rds:CreateDBInstance` is included as a special exception despite not being documented in the AWS Service Authorization Reference, as manual testing confirmed it works.

### Pattern 4: `deny_imds_v1_ec2`

**Check:** `headroom/checks/scps/deny_imds_v1_ec2.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 3-37
**Tag:** `ExemptFromIMDSv2`

This check identifies EC2 instances with IMDSv1 enabled. The SCP denies IMDSv1 configuration unless the instance or principal is tagged with `ExemptFromIMDSv2=true`.

**Two-statement approach:**
1. Deny modification of IAM role delivery to less than version 2.0 (unless principal has exemption tag)
2. Deny launching instances with `MetadataHttpTokens != "required"` (unless request has exemption tag)

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

### Pattern 5a: `enforce_assume_role_org_identities`

**Terraform:** `test_environment/modules/rcps/locals.tf` lines 27-51
**Variable:** `third_party_assumerole_account_ids_allowlist`

This RCP restricts role assumptions to organization principals and explicitly allowlisted third-party account IDs. It uses `aws:PrincipalOrgID` and `aws:PrincipalAccount` conditions.

**Analysis by:** `headroom/checks/rcps/deny_third_party_assumerole.py`

### Pattern 5b: `deny_iam_user_creation`

**Check:** `headroom/checks/scps/deny_iam_user_creation.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 39-49
**Variable:** `allowed_iam_users`

This check lists all IAM users in accounts. The SCP uses `NotResource` to deny `iam:CreateUser` except for explicitly allowed user ARN patterns.

**Headroom's Role:** Scans accounts and reports existing users, which inform the allowlist configuration.

### Pattern 5c: `deny_ec2_ami_owner`

**Check:** `headroom/checks/scps/deny_ec2_ami_owner.py`
**Terraform:** `test_environment/modules/scps/locals.tf` lines 3-20
**Variable:** `allowed_ami_owners`

This check identifies EC2 instances and determines the owner of the AMI used to launch each instance. The SCP denies `ec2:RunInstances` unless the AMI owner is in the allowlist.

**Policy Structure:**
- Deny `ec2:RunInstances`
- Unless `ec2:Owner` is in the approved list (e.g., "amazon", "aws-marketplace", trusted account IDs)

**Headroom's Role:** Scans all accounts and reports all EC2 instances with their AMI owners. This generates a comprehensive list of unique AMI owners that can be used to populate the allowlist. The check helps identify:
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
3. **Allowlist Generation:** For Patterns 5a/5b/5c, Headroom generates the lists of principals/resources/values that should be allowed
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
