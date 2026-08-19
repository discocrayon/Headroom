# Policy Checks Reference

## SCP (Service Control Policy) Checks

### EC2 IMDS v1 Check

**Check Name**: `deny_ec2_imds_v1`

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

### EC2 IMDS Hop Limit Check

**Check Name**: `deny_ec2_imds_hop_limit`

**Purpose**: Identifies EC2 instances whose IMDS hop limit exceeds 1. A hop limit above 1 lets the metadata response cross an extra network hop, which is what allows a container or a downstream proxy on the instance to reach the metadata endpoint.

**How it Works**:
- Scans all AWS regions for EC2 instances
- Reads `MetadataOptions.HttpPutResponseHopLimit`, treating an absent value as the AWS default of 1
- Reads `MetadataOptions.HttpEndpoint` to determine whether IMDS is reachable at all
- Skips terminated instances

**Policy Coverage**: Denies `ec2:RunInstances` when `ec2:MetadataHttpPutResponseHopLimit` is greater than 1.

**Compliance Requirements**:
- An instance at hop limit 1 is compliant
- An instance with `HttpEndpoint` disabled is compliant whatever its hop limit, because there is no reachable IMDS for a hop to cross
- Any other instance with a hop limit above 1 is a violation

**Launch-Time Only**: `ec2:ModifyInstanceMetadataOptions` has no fine-grained condition keys, so this SCP cannot prevent the hop limit being raised after launch. Closing that gap requires denying the action outright or restricting it by `aws:PrincipalArn`, which is a separate policy decision and is not part of this check.

**Container Impact**: Containers add a network hop, so workloads on ECS, EKS, or plain Docker generally need a hop limit of at least 2 to reach IMDS. Expect containerized instances to appear as violations; the placement engine will only recommend enabling the SCP once every account reports full compliance.

**Output**:
- Instance IDs and regions
- Configured hop limit
- Whether the metadata endpoint is enabled
- Compliance percentage

**Example Violation**:
```json
{
  "instance_id": "i-0123456789abcdef0",
  "region": "us-east-1",
  "hop_limit": 2,
  "imds_enabled": true
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

### EC2 AMI Owner Check

**Check Name**: `deny_ec2_ami_owner`

**Purpose**: Identifies EC2 instances using AMIs from untrusted or unapproved owners.

**How it Works**:
- Scans all AWS regions for EC2 instances
- Retrieves AMI information for each instance
- Determines AMI owner for each instance
- Identifies unique AMI owners across all instances

**Policy Coverage**: Denies `ec2:RunInstances` unless the AMI owner is in the approved allowlist (e.g., "amazon", "aws-marketplace", trusted account IDs).

**Allowlist Support**: Generates comprehensive list of unique AMI owners to inform allowlist configuration.

**Output**:
- Instance IDs and regions
- AMI IDs and names
- AMI owners for each instance
- List of all unique AMI owners

**Example Output**:
```json
{
  "instance_id": "i-1234567890abcdef0",
  "region": "us-east-1",
  "ami_id": "ami-0123456789abcdef0",
  "ami_owner": "amazon",
  "ami_name": "amzn2-ami-hvm-2.0.20231218.0-x86_64-gp2"
}
```

---

### EC2 Public IP Check

**Check Name**: `deny_ec2_public_ip`

**Purpose**: Identifies EC2 instances with public IP addresses assigned.

**How it Works**:
- Scans all AWS regions for EC2 instances
- Checks if instances have public IP addresses
- Categorizes instances as violations or compliant

**Policy Coverage**: Denies `ec2:RunInstances` when a public IP address would be assigned (`ec2:AssociatePublicIpAddress` equals "true").

**Output**:
- Instance IDs and ARNs
- Public IP addresses
- Regions
- Compliance percentage

**Example Violation**:
```json
{
  "instance_id": "i-0987654321fedcba0",
  "region": "us-west-2",
  "public_ip_address": "54.123.45.67",
  "has_public_ip": true,
  "instance_arn": "arn:aws:ec2:us-west-2:111111111111:instance/i-0987654321fedcba0"
}
```

---

### IAM SAML Provider Check

**Check Name**: `deny_iam_saml_provider_not_aws_sso`

**Purpose**: Enforces use of AWS IAM Identity Center (AWS SSO) for SAML authentication by identifying non-compliant SAML providers.

**How it Works**:
- Lists all IAM SAML providers in the account
- Checks if provider names start with `AWSSSO_` prefix
- Validates that only zero or one AWS SSO provider exists

**Policy Coverage**: Denies `iam:CreateSAMLProvider` unconditionally once all accounts meet the constraint (zero or one AWS SSO provider only).

**Compliance Requirements**:
- Account is compliant if it has zero SAML providers
- Account is compliant if it has exactly one provider with `AWSSSO_` prefix
- Account is non-compliant if it has multiple providers or any non-AWS SSO provider

**Output**:
- Total SAML provider count
- AWS SSO provider count
- Non-AWS SSO provider count
- Allowed provider ARN (if compliant)
- Violating provider ARNs

**Example Violation**:
```json
{
  "arn": "arn:aws:iam::111111111111:saml-provider/CustomSAML",
  "name": "CustomSAML",
  "create_date": "2024-01-15T10:30:00Z",
  "valid_until": "2025-01-15T10:30:00Z",
  "violation_reason": "provider_prefix_not_awssso"
}
```

---

### Lambda Function URL Authentication Check

**Check Name**: `deny_lambda_auth_type_none`

**Purpose**: Identifies Lambda functions with function URLs using NONE authentication, which allows unauthenticated public access.

**How it Works**:
- Scans all AWS regions for Lambda functions
- Checks for function URLs on each function
- Identifies functions with NONE authentication type

**Policy Coverage**: Denies `lambda:CreateFunctionUrlConfig`, `lambda:UpdateFunctionUrlConfig`, and
`lambda:AddPermission` when `lambda:FunctionUrlAuthType` is set to "NONE". `lambda:AddPermission` is
included because it grants invoke permission on a function URL, which would otherwise leave a path
to unauthenticated access on URLs that already exist.

**Output**:
- Function names and ARNs
- Function URL status
- Authentication type
- Regions
- Compliance percentage

**Example Violation**:
```json
{
  "function_name": "public-api-function",
  "function_arn": "arn:aws:lambda:us-east-1:111111111111:function:public-api-function",
  "region": "us-east-1",
  "has_function_url": true,
  "function_url_auth_type": "NONE"
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

### KMS Third-Party Access Check

**Check Name**: `deny_kms_third_party_access`

**Purpose**: Identifies KMS keys with resource policies allowing external account access.

**How it Works**:
- Scans all AWS regions for KMS keys
- Retrieves key policies for each key
- Parses policies for third-party principals
- Tracks specific KMS actions allowed per account

**Detection**:
- Third-party AWS account IDs from key policies
- Wildcard principals (requiring CloudTrail analysis)
- Specific KMS actions per account and per key

**Actions Tracking**: Records KMS actions like:
- `kms:Decrypt`
- `kms:Encrypt`
- `kms:GenerateDataKey`
- `kms:DescribeKey`
- `kms:CreateGrant`

**Fail-Fast Validation**: Immediately fails if unsupported principal types (e.g., Federated) are detected.

**Output**:
- Total keys analyzed
- Keys with third-party access
- Keys with wildcard principals (violations)
- Third-party account IDs
- KMS actions allowed per account

**Example Output**:
```json
{
  "key_id": "1234abcd-12ab-34cd-56ef-1234567890ab",
  "key_arn": "arn:aws:kms:us-east-1:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
  "region": "us-east-1",
  "third_party_account_ids": ["999999999999"],
  "actions_by_account": {
    "999999999999": ["kms:Decrypt", "kms:DescribeKey"]
  },
  "has_wildcard_principal": false
}
```

---

### Secrets Manager Third-Party Access Check

**Check Name**: `deny_secrets_manager_third_party_access`

**Purpose**: Identifies Secrets Manager secrets with resource policies allowing external account access.

**How it Works**:
- Scans all AWS regions for Secrets Manager secrets
- Retrieves resource policies for each secret
- Parses policies for third-party principals
- Tracks specific Secrets Manager actions allowed per account
- Maps which secrets each third-party account can access

**Detection**:
- Third-party AWS account IDs from secret policies
- Wildcard principals (violations)
- Non-account principals like Federated (violations)
- Specific actions per account

**Actions Tracking**: Records Secrets Manager actions like:
- `secretsmanager:GetSecretValue`
- `secretsmanager:DescribeSecret`
- `secretsmanager:PutSecretValue`

**Fail-Fast Validation**: If any secret policy contains a Federated principal or other unsupported principal types, these are flagged as violations.

**Output**:
- Total secrets analyzed
- Secrets with third-party access
- Secrets with wildcard principals (violations)
- Third-party account IDs
- Actions allowed per third-party account
- Secrets accessible per third-party account

**Example Output**:
```json
{
  "secret_name": "prod/database/password",
  "secret_arn": "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/database/password-AbCdEf",
  "third_party_account_ids": ["888888888888"],
  "has_wildcard_principal": false,
  "has_non_account_principals": false,
  "actions_by_account": {
    "888888888888": ["secretsmanager:GetSecretValue"]
  }
}
```

---

### SQS Third-Party Access Check

**Check Name**: `deny_sqs_third_party_access`

**Purpose**: Identifies SQS queues with resource policies allowing external account access.

**How it Works**:
- Scans all AWS regions for SQS queues
- Retrieves queue policies for each queue
- Parses policies for third-party principals
- Tracks specific SQS actions allowed per account
- Maps which queues each third-party account can access

**Detection**:
- Third-party AWS account IDs from queue policies
- Wildcard principals (violations)
- Non-account principals (violations)
- Specific actions per account

**Actions Tracking**: Records SQS actions like:
- `sqs:SendMessage`
- `sqs:ReceiveMessage`
- `sqs:DeleteMessage`
- `sqs:GetQueueAttributes`

**Fail-Fast Validation**: If any queue policy contains a Federated principal or other unsupported principal types, these are flagged as violations.

**Output**:
- Total queues analyzed
- Queues with third-party access
- Queues with wildcard principals (violations)
- Third-party account IDs
- Actions allowed per third-party account
- Queues accessible per third-party account

**Example Output**:
```json
{
  "queue_url": "https://sqs.us-east-1.amazonaws.com/111111111111/shared-queue",
  "queue_arn": "arn:aws:sqs:us-east-1:111111111111:shared-queue",
  "region": "us-east-1",
  "third_party_account_ids": ["777777777777"],
  "has_wildcard_principal": false,
  "has_non_account_principals": false,
  "actions_by_account": {
    "777777777777": ["sqs:SendMessage", "sqs:ReceiveMessage"]
  }
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
