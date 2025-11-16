# Policy Checks Reference

## SCP (Service Control Policy) Checks

### EC2 IMDS v1 Check

**Check Name**: `deny_imds_v1_ec2`

**Purpose**: Identifies EC2 instances with Instance Metadata Service (IMDS) v1 enabled, which is a security risk.

**How it Works**:
- Scans all AWS regions for EC2 instances
- Checks metadata options configuration
- Identifies instances without IMDSv2 enforcement

**Policy Coverage**: Denies EC2 operations that would create instances without IMDSv2 enforcement.

**Exemption Support**: Resources tagged with `ExemptFromIMDSv2` (case-insensitive) are excluded from violation reporting.

**Output**:
- List of non-compliant instances (violations)
- List of exempt instances
- List of compliant instances
- Compliance percentage

**Example Violation**:
```json
{
  "instance_id": "i-1234567890abcdef0",
  "region": "us-east-1",
  "metadata_options": {
    "HttpTokens": "optional"
  }
}
```

---

### IAM User Creation Check

**Check Name**: `deny_iam_user_creation`

**Purpose**: Enumerates all IAM users in accounts and auto-generates SCPs with allowlists to restrict future IAM user creation to approved users only.

**How it Works**:
- Lists all IAM users in each account
- Extracts user ARNs, names, and paths
- Generates allowlist for SCP module

**Policy Coverage**: Denies `iam:CreateUser` operations except for users in the allowlist.

**Allowlist Support**: Automatically generates SCPs with IAM user ARN allowlists.

**Output**:
- Complete list of IAM users with ARNs
- User paths and creation dates
- Generated allowlist for Terraform

**Example Output**:
```json
{
  "users": [
    {
      "user_name": "github-actions",
      "user_arn": "arn:aws:iam::111111111111:user/service/github-actions",
      "path": "/service/",
      "create_date": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

### EKS Cluster Tag Check

**Check Name**: `deny_eks_create_cluster_without_tag`

**Purpose**: Enforces "paved road" approach for EKS cluster creation by requiring clusters to be created with `PavedRoad=true` tag.

**How it Works**:
- Scans all AWS regions for EKS clusters
- Checks cluster tags for `PavedRoad=true`
- Identifies clusters created outside approved automation

**Policy Pattern**: Implements "Module Tag / Paved Road Pattern" - encourages use of blessed infrastructure-as-code.

**Policy Coverage**: Denies `eks:CreateCluster` operations unless `aws:RequestTag/PavedRoad` equals "true".

**Output**:
- Compliant clusters (created via approved automation)
- Non-compliant clusters (manual/unapproved creation)
- Regional breakdown

**Example Violation**:
```json
{
  "cluster_name": "manual-test-cluster",
  "region": "us-west-2",
  "tags": {
    "Environment": "dev"
  },
  "reason": "Missing required tag: PavedRoad=true"
}
```

---

### RDS Unencrypted Database Check

**Check Name**: `deny_rds_unencrypted`

**Purpose**: Identifies RDS instances and Aurora clusters without encryption at rest enabled.

**How it Works**:
- Scans all AWS regions for RDS instances and clusters
- Checks encryption status for each database
- Identifies unencrypted databases

**Policy Coverage**: Denies:
- `rds:CreateDBCluster`
- `rds:RestoreDBClusterFromS3`
- `rds:CreateBlueGreenDeployment`
- `rds:CreateDBInstance`

Unless `rds:StorageEncrypted` condition key is true.

**Output**:
- Database identifiers
- Database types (instance/cluster)
- Engine versions
- Encryption status
- Compliance percentage

**Example Violation**:
```json
{
  "db_identifier": "legacy-mysql-db",
  "region": "eu-west-1",
  "db_type": "instance",
  "engine": "mysql",
  "engine_version": "8.0.35",
  "encrypted": false
}
```

---

## RCP (Resource Control Policy) Checks

### STS Third-Party AssumeRole Check

**Check Name**: `deny_sts_third_party_assumerole` (also `deny_deny_sts_third_party_assumerole` for enforcement)

**Purpose**: Identifies IAM roles with trust policies allowing external AWS account access.

**How it Works**:
- Enumerates all IAM roles in account
- Parses trust policies (AssumeRolePolicyDocument)
- Extracts third-party AWS account IDs
- Detects wildcard principals requiring CloudTrail analysis

**Detection**:
- Third-party account IDs from principals
- Wildcard principals (`*`)
- Cross-account access patterns

**Allowlisting**: Generates allowlists for RCP modules to permit known third-party access.

**Output**:
- List of roles with third-party access
- Third-party account IDs
- Wildcard principals
- Role ARNs and trust policies

**Example Output**:
```json
{
  "third_party_accounts": ["444444444444", "555555555555"],
  "roles_with_third_party_access": [
    {
      "role_name": "CrossAccountRole",
      "role_arn": "arn:aws:iam::111111111111:role/CrossAccountRole",
      "third_party_principals": ["arn:aws:iam::444444444444:root"]
    }
  ],
  "wildcard_principals": []
}
```

---

### S3 Third-Party Access Check

**Check Name**: `deny_s3_third_party_access`

**Purpose**: Identifies S3 buckets with policies allowing third-party account access or non-account-based principals.

**How it Works**:
- Lists all S3 buckets
- Retrieves bucket policies
- Parses policies for third-party principals
- Detects Federated/CanonicalUser principals

**Detection**:
- Third-party AWS account IDs
- Federated principals (SAML, OIDC)
- CanonicalUser principals
- Wildcard principals

**Safety**: Prevents RCP deployment for buckets with Federated or CanonicalUser principals (would break access).

**Actions Tracking**: Records which S3 actions are allowed per third-party account and affected buckets.

**Exemption Support**: Buckets tagged with `dp:exclude:identity=true` are exempt from RCP enforcement.

**Output**:
- Third-party accounts accessing buckets
- Bucket names and policies
- Allowed S3 actions per account
- Principals requiring special handling

**Example Output**:
```json
{
  "third_party_accounts": ["666666666666"],
  "buckets_with_third_party_access": [
    {
      "bucket_name": "shared-data-bucket",
      "third_party_accounts": ["666666666666"],
      "allowed_actions": ["s3:GetObject", "s3:ListBucket"],
      "federated_principals": false
    }
  ]
}
```

---

### AOSS (OpenSearch Serverless) Third-Party Access Check

**Check Name**: `deny_aoss_third_party_access`

**Purpose**: Analyzes OpenSearch Serverless data access policies to identify third-party account access.

**How it Works**:
- Lists all AOSS collections
- Retrieves data access policies
- Identifies third-party AWS account principals
- Maps access to collections and indexes

**Detection**:
- Third-party account IDs from policy principals
- Wildcard principals
- Cross-account access patterns

**Output**:
- Collections with third-party access
- Third-party account IDs
- Access levels (read/write)
- Index-level permissions

**Example Output**:
```json
{
  "third_party_accounts": ["777777777777"],
  "collections_with_third_party_access": [
    {
      "collection_name": "shared-analytics",
      "collection_arn": "arn:aws:aoss:us-east-1:111111111111:collection/abc123",
      "third_party_accounts": ["777777777777"]
    }
  ]
}
```

---

### ECR Third-Party Access Check

**Check Name**: `deny_ecr_third_party_access`

**Purpose**: Identifies ECR repositories with resource policies allowing external account access.

**How it Works**:
- Scans all enabled AWS regions for ECR repositories
- Retrieves repository policies
- Extracts third-party account IDs
- Tracks specific ECR actions allowed

**Detection**:
- Third-party AWS account IDs from repository policies
- Wildcard principals
- Specific ECR actions per account

**Actions Tracking**: Records ECR actions like:
- `ecr:BatchGetImage`
- `ecr:GetDownloadUrlForLayer`
- `ecr:BatchCheckLayerAvailability`
- `ecr:PutImage`

**Fail-Fast Validation**: Immediately fails if unsupported principal types (e.g., Federated) are detected.

**Output**:
- Repositories with third-party access
- Third-party account IDs
- Allowed ECR actions per account
- Regional distribution

**Example Output**:
```json
{
  "third_party_accounts": ["888888888888"],
  "repositories_with_third_party_access": [
    {
      "repository_name": "shared-images",
      "region": "us-east-1",
      "third_party_accounts": ["888888888888"],
      "allowed_actions": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    }
  ]
}
```

---

## Check Features

### All Checks Include

- **Current State Checking**: Scans AWS APIs to check actual resource state
- **Compliance Metrics**: Violation counts and compliance percentages
- **Regional Support**: Multi-region scanning where applicable (SCPs, ECR)
- **Detailed Output**: JSON results with complete resource information

### Some Checks Include

- **Exemption Support**: Tag-based exemptions (EC2 IMDSv1, S3)
- **Allowlist Generation**: Auto-generated allowlists (IAM users, third-party accounts)
- **Safety Mechanisms**: Prevents breaking existing access patterns (S3 Federated principals)
- **Wildcard Detection**: Identifies principals requiring CloudTrail analysis

### Future Enhancements

- **CloudTrail Integration**: Check past AWS activity for dynamic principals
- **Configurable Exemptions**: Enable/disable exemption support per check
- **Custom Check Framework**: Easy addition of new checks via plugin system

## Adding New Checks

See [HOW_TO_ADD_A_CHECK.md](../HOW_TO_ADD_A_CHECK.md) for guidance on creating custom checks.

## Check Modules

Generated Terraform uses these modules:
- [SCPs Module](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/scps) - Implements SCP policies
- [RCPs Module](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/rcps) - Implements RCP policies
