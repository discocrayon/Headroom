# Policy Checks Reference

## SCP (Service Control Policy) Checks

### EC2 IMDS v1 Check

**Check Name**: `deny_ec2_imds_v1`

**Purpose**: Identifies EC2 instances with Instance Metadata Service (IMDS) v1 enabled, which is a security risk.

**How it Works**:
- Scans all AWS regions for EC2 instances
- Reads `MetadataOptions.HttpTokens`; `optional` means IMDSv1 is permitted
- Reads the instance's `ExemptFromIMDSv2` tag
- Counts every instance permitting IMDSv1 as a violation, unless it is tagged

**Policy Coverage**: One statement.
`DenyRunInstancesMetadataHttpTokensOptional` denies launching an instance that
would answer IMDSv1.

## Scope: the fleet already running is deliberately excluded

**This check governs launches. It does not govern the instances you already
have, and it is not meant to.**

Every instance the scan sees has already launched, so not one of them can be
denied by the statement. An instance answering IMDSv1 is counted as *evidence
about the next launch*: an account still running them is an account whose next
`RunInstances` is likely to be denied, so the SCP is not yet safe to attach
there. The instance itself is not the finding.

The expectation is that such instances get **migrated to IMDSv2**, not carried
indefinitely behind an exemption. The SCP's job is to stop new ones appearing
while that migration happens. Once an account's fleet is clean, the check
reports 100% and the SCP can be attached.

What this scope costs, stated plainly:

| Not covered | Why |
|---|---|
| Instances running with IMDSv1 today | Already launched; the statement only reads `RunInstances` requests. They stay reachable over IMDSv1 until migrated |
| An instance flipped back to `optional` after launch | `ModifyInstanceMetadataOptions` is out of scope for this policy set |
| Credentials already stolen over IMDSv1 | Nothing here denies their *use* |

An earlier revision also generated `DenyRoleDeliveryLessThan2`, which denied
any API call made with credentials fetched over IMDSv1 and so did cover the
running fleet. It was removed rather than split: one variable gating two
statements meant one scan verdict licensing two different kinds of evidence,
and a role-tagged IMDSv1 instance was reported as a clean exemption while this
statement - which reads no role tag - would have denied that account's next
launch.

**Exemption Support**: Tag the **instance** `ExemptFromIMDSv2 = "true"`.

The statement exempts a launch through `aws:RequestTag/ExemptFromIMDSv2`,
which is populated from the `TagSpecifications` of the `RunInstances` call -
and that same entry is what puts the tag on the instance the call creates. So
the tag you can see on a running instance is the trace of the request tag that
exempted its launch, and good evidence its relaunch will carry the same one.

Measured against a live account with `RunInstances --dry-run`, under the
shipped statement:

| Request | Result |
|---|---|
| `HttpTokens=optional`, no tag | **DENY** |
| `HttpTokens=optional`, `ExemptFromIMDSv2=true` | allow |
| `HttpTokens=optional`, `ExemptFromIMDSv2=True` | **DENY** |
| `HttpTokens=required`, no tag | allow |

The key and the value are matched differently, and the scan follows both. IAM
matches condition key names without regard to case, and the tag key after the
slash is part of the name, so `exemptfromimdsv2` exempts too. The value is
compared with `StringNotEquals`, which is case-sensitive, so `True` does not.
An instance carrying the key twice in cases that differ aborts the check: AWS
calls that an unexpected condition failure rather than a match on one of them.

A tag on the instance's **IAM role** exempts nothing. That was
`aws:PrincipalTag`, read by `DenyRoleDeliveryLessThan2`, which this module no
longer generates.

### The proxy is imperfect, and we accept it

The tag on a running instance is not the request tag. It stands in for one:

| When it misleads | What happens |
|---|---|
| Tag applied after launch with `CreateTags` | Instance wears the tag; its relaunch carries none, and the SCP denies it |
| Instance recreated by something that does not declare the tag | Same - Terraform or a launch template that never knew about the tag will not re-supply it |

In both cases this check reports an exemption for a launch enforcement would
deny. **That is a known cost and it is accepted.** An operator who tags an
instance `ExemptFromIMDSv2` is declaring that this workload is meant to keep
IMDSv1; Headroom takes the declaration at face value and does not try to
predict how it will be reapplied. Keeping the tag effective across a
recreation is the operator's job, not the scanner's.

**What a Clean Scan Proves**: That every instance in the account either
requires IMDSv2 or carries the exemption tag, which is the best available
evidence that future launches will pass. It is evidence, not proof - a launch
template the scan never reads can still be denied.

`ec2:MetadataHttpTokens` resolves from the **effective** metadata
configuration, not only from literal request parameters. Dry runs against a
live account show an AMI carrying `imds-support=v2.0` populating it as
`required` even when the request names no `MetadataOptions` at all, so a fleet
on modern Amazon Linux passes the statement without ever specifying the
parameter. On an AMI without that attribute the same request is denied.
Whether an account-level metadata default behaves like the AMI default is
untested - the probe account had none set - but the AMI result makes it
likely.

**The metadata endpoint's state does not enter the verdict.** An instance with
the endpoint disabled and `HttpTokens` optional is a violation, matching
`deny_ec2_imds_hop_limit`, which counts its hop limit the same way. A disabled
endpoint does make IMDSv1 unreachable on the running instance, but the SCP
reads the launch request, where a request turning the endpoint off carries no
`HttpTokens` and so leaves the key absent for `StringNotEquals` to fire on.
Remedying it costs nothing: AWS accepts `HttpTokens=required` alongside a
disabled endpoint - confirmed by dry run, contradicting the EC2 guide - and the
extra parameter changes no behaviour, because nothing is listening.

**Required Permissions**: `ec2:DescribeInstances`. Tags come back with the
instances, so there is nothing else to grant and no IAM call to make.

**Output**:
- List of non-compliant instances (violations)
- List of exempt instances
- List of compliant instances
- Compliance percentage, counting exemptions as compliant

**Example Violation**:
```json
{
  "region": "us-east-1",
  "instance_id": "i-1234567890abcdef0",
  "imdsv1_allowed": true,
  "exemption_tag_present": false
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
- Any instance above hop limit 1 is a violation, **including one with the metadata endpoint disabled**

The endpoint state is reported but does not affect the verdict. A disabled endpoint does make the hop limit inert on the running instance, but the SCP is evaluated against the launch request, and AWS accepts a launch naming both a hop limit and `HttpEndpoint=disabled` - confirmed by dry run, where `MaxImdsHopLimit` denied exactly that request. Excusing those instances would clear an account whose relaunch the SCP denies. Remediation is free: lowering the hop limit on an instance whose endpoint is off changes no behaviour, because nothing reads it.

**Launch-Time Only**: `ec2:ModifyInstanceMetadataOptions` has no fine-grained condition keys, so this SCP cannot prevent the hop limit being raised after launch. Closing that gap requires denying the action outright or restricting it by `aws:PrincipalArn`, which is a separate policy decision and is not part of this check.

**Expect Widespread Violations**: An AMI carrying `imds-support=v2.0`, which includes current Amazon Linux 2023, supplies a hop limit above 1 to launches that name no `MetadataOptions` at all. A dry run against a live account confirms `MaxImdsHopLimit` denies that default launch. So the violations this check reports are not an edge case - on a modern fleet they are the norm, and a default AL2023 instance is a violation before anyone configures anything.

Containers compound it: they add a network hop, so workloads on ECS, EKS, or plain Docker generally need a hop limit of at least 2 to reach IMDS. The placement engine only recommends enabling the SCP once every account reports full compliance, so in practice this check stays unplaced until a fleet explicitly pins hop limit 1 everywhere. Whether a threshold of 1 is the right policy for a fleet on modern AMIs is a decision for the operator, not something this check assumes.

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
- Records, for each instance, the value `ec2:Owner` will hold on a relaunch -
  see **What `ec2:Owner` Holds** below
- Identifies the unique such values across all instances

**Policy Coverage**: Denies the EC2 launch paths - `ec2:RunInstances`,
`ec2:CreateFleet`, `ec2:RequestSpotFleet` and `ec2:RequestSpotInstances` - on
the AMI resource (`arn:aws:ec2:*::image/*`) unless `ec2:Owner` is in the
approved allowlist (e.g., "amazon", "aws-marketplace", trusted account IDs).
The statement is scoped to the image because `ec2:Owner` exists on no other
resource these actions touch. `ec2:ModifyFleet` also supports the key and is
excluded as a deliberate scope decision.

**What `ec2:Owner` Holds**: the AMI's owner *alias* when `DescribeImages`
returns one, and the numeric `OwnerId` only when it does not. `OwnerId` and
`ImageOwnerAlias` are separate fields, and `ImageOwnerAlias` is present only
for Amazon-published and Marketplace images. Measured with
`RunInstances --dry-run` against the statement this repo generates:

| AMI | allowlist | result |
| --- | --- | --- |
| Amazon Linux 2023 (`ImageOwnerAlias: amazon`) | `[numeric OwnerId]` | DENY |
| Amazon Linux 2023 | `["amazon"]` | ALLOW |
| Amazon Linux 2023 | `[numeric OwnerId, "amazon"]` | ALLOW |
| Rocky Linux (no `ImageOwnerAlias`) | `[numeric OwnerId]` | ALLOW |
| Rocky Linux | `["amazon"]` | DENY |

`aws-marketplace` is inferred from the `amazon` rows rather than measured:
every reachable Marketplace AMI required a subscription, and EC2 returns
`OptInRequired` before it evaluates the statement, so a dry run there cannot
tell an allow from a deny.

Recording only the numeric owner - which this check used to do - builds an
allowlist that denies the very AMI a clean scan observed, because
`StringNotEquals` matches whenever the key holds anything other than a listed
value. Both branches are common: Debian and Canonical publish through
Marketplace and carry an alias, while Rocky, AlmaLinux and Fedora/CentOS
publish directly and do not.

Allowlisting an alias is broader than the AMI observed. `ec2:Owner` has no
narrower form for an Amazon or Marketplace image, so `amazon` permits every
Amazon-published AMI and `aws-marketplace` every Marketplace one. The
alternative is not a narrower policy but a broken one.

**Allowlist Support**: The unique values observed across the accounts a
placement covers are unioned into the `ec2_allowed_ami_owners` Terraform
variable. An empty allowlist is never emitted - it would deny every launch
instead of none of them. Two things produce one, and they are handled
differently:

- **No instance in the covered accounts had a resolvable AMI owner.** An
  account running no instances reaches placement as safe and contributes
  nothing. This is a fact about those accounts, so the module leaves
  `deny_ec2_ami_owner = false` with a comment saying why, and generation
  continues for the rest of the organization.
- **A result file predates AMI owner collection.** Its summary has no
  `unique_ami_owners` key at all. Parsing rejects it by path, because once
  parsed it is indistinguishable from the case above and would silently
  borrow whatever the other accounts observed. Re-run the check.

**Unresolvable AMIs**: An instance outlives the visibility of the AMI it was
launched from, so `DescribeImages` does not always return one. The lookup sets
`IncludeDisabled` and `IncludeDeprecated` up front, which resolves the owner of
an AMI turned off with `DisableImage` or hidden past its deprecation date. A
disabled AMI is logged as a warning, since it keeps its owner but can no longer
launch. An AMI that stays unresolvable is recorded as a **violation** with a
null `ami_owner` and an `owner_unknown_reason`:

| `owner_unknown_reason` | Meaning |
|---|---|
| `not_visible` | `DescribeImages` returns nothing even with the include flags. An [Allowed AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/allowed-amis.html) setting filters the AMI, or it was shared and then unshared. |
| `deregistered` | The AMI ID no longer resolves at all (`InvalidAMIID.NotFound` or `InvalidAMIID.Unavailable`), which is what deregistration leaves behind on a long-lived instance. |

Recording these as violations rather than aborting keeps the run going while
ensuring an account whose AMI provenance cannot be attested never counts toward
an org-wide placement of this SCP. An AMI that AWS returns *without* an
`OwnerId` still aborts the run: that is the API breaking its own contract, not a
fact about the account.

**Output**:
- Instance IDs and regions
- AMI IDs and names
- AMI owners for each instance, or the reason the owner is unknown
- List of all unique AMI owners, and a count of instances per unknown reason

**Example Output**:
```json
{
  "instance_id": "i-1234567890abcdef0",
  "region": "us-east-1",
  "ami_id": "ami-0123456789abcdef0",
  "ami_owner": "amazon",
  "ami_name": "amzn2-ami-hvm-2.0.20231218.0-x86_64-gp2",
  "owner_unknown_reason": null
}
```

**Example Violation**:
```json
{
  "instance_id": "i-11111111111111111",
  "region": "us-west-2",
  "ami_id": "ami-11111111111111111",
  "ami_owner": null,
  "ami_name": null,
  "owner_unknown_reason": "not_visible"
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

**Statement Handling**: Every RCP check reads its policy documents through
`headroom.aws.policy_documents.normalize_statements`. A `Statement` that is a
lone object rather than a list is read as a one-element list, as IAM allows.
Anything else raises `MalformedPolicyError` rather than being skipped, which
would report the resource as granting nothing.

**Principal Handling**: An `Allow` naming `NotPrincipal` grants to every
principal except the ones it lists, which is the same reach `Principal: "*"`
has. It sets `has_wildcard_principal` and counts as a violation, so the
resource gets the blocker and the CloudTrail follow-up a literal wildcard
gets. `Deny` with `NotPrincipal` is the form AWS recommends and restricts
rather than grants, so it counts for nothing.

**Condition Handling**: The six third-party access checks read a statement's
`Effect`, `Principal`, and `Action`; they do not evaluate `Condition`. A
wildcard principal narrowed by `aws:PrincipalOrgID` grants nothing outside the
organization, but is still counted as a violation and still blocks that account
from the RCP. A grant narrowed by `s3:prefix` or `aws:SourceVpce` still
contributes its account to the allowlist at full width. Neither can hide a third
party from the scan - a condition only ever narrows a grant - so both cost
coverage rather than safety. `Resource` and `NotResource` are not read either,
with the same widening-only effect: a statement scoped away from the resource
still contributes its principals.

`deny_service_confused_deputy` is the one exception, and a narrow one. It reads
three condition keys - `aws:SourceAccount`, `aws:SourceArn` and
`aws:SourceOrgID` - and only on statements naming a `Service` principal,
because that guard is the whole subject of the check. Everywhere else the
widening-only argument above still holds, and general condition-aware analysis
remains a separate concern.

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

**Action Matching**: A statement counts as granting AssumeRole under the same
rules IAM applies, not by string equality. Matching is case-insensitive, `*`
and `?` expand anywhere in the action name (`sts:*`, `sts:Assume*`,
`sts:*Role`, `sts:AssumeRol?`), and an Allow with `NotAction` grants
AssumeRole unless one of its patterns covers it. A statement naming both
`Action` and `NotAction`, or neither, aborts the run rather than being
guessed at - an unrecognized grant leaves a partner account out of the
allowlist, and the RCP then denies it.

**Principal Forms**: Account IDs are read from any principal ARN regardless of
partition or service, so STS session principals
(`arn:aws:sts::{account}:assumed-role/{role}/{session}`) and GovCloud and
China ARNs all resolve.

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

**Purpose**: Identifies S3 buckets whose policy or ACL allows third-party account access or non-account-based principals.

**How it Works**:
- Lists all S3 buckets
- Retrieves each bucket's ACL and classifies its grantees
- Retrieves bucket policies, where the bucket carries one
- Parses policies for third-party principals
- Detects Federated/CanonicalUser principals

**Detection**:
- Third-party AWS account IDs
- Federated principals (SAML, OIDC)
- CanonicalUser principals
- Wildcard principals
- ACL grants to a canonical user other than the bucket owner, or to an email address
- ACL grants to the `AllUsers` or `AuthenticatedUsers` groups

**Bucket ACLs**: A bucket ACL authorizes principals independently of the bucket
policy, and the RCP denies every principal outside the organization however the
bucket authorized them. Reading only the policy therefore reported an
ACL-shared bucket clean, and the account kept an RCP that broke the grant on
apply. ACL grantees carry canonical user IDs rather than account IDs, and no
API resolves one to the other, so an external grantee cannot be expressed in
`aws:PrincipalAccount` and keeps the account out of the RCP instead. Two
grantees are read as reaching nobody the RCP would deny: the bucket's own
owner, whose grant every bucket carries, and the S3 log delivery group, which
authorizes the same `logging.s3.amazonaws.com` service principal that the
bucket-policy form of the grant names. A grantee type or group the analyzer
cannot classify aborts the run rather than being dropped.

A bucket whose Object Ownership is `BucketOwnerEnforced` has ACLs disabled;
reads still succeed and return the owner's grant alone, so no separate
ownership lookup is needed.

**Object ACLs are not read.** Under `ObjectWriter` ownership an object uploaded
by an external account is owned by that account and can carry its own ACL, as
can log objects delivered under `TargetGrants`. Enumerating those costs one
call per object, so they are out of scope, and an object ACL granting a third
party is not visible to this check.

**Safety**: Prevents RCP deployment for buckets with Federated or CanonicalUser principals (would break access).

**Actions Tracking**: Records which S3 actions are allowed per third-party account and affected buckets.

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

**Purpose**: Identifies ECR resource policies allowing external account access, at either scope - a repository policy or the region's registry policy.

**How it Works**:
- Scans all enabled AWS regions
- Retrieves each region's registry policy
- Retrieves each repository's policy
- Extracts third-party account IDs
- Tracks specific ECR actions allowed

**Detection**:
- Third-party AWS account IDs from repository policies
- Third-party AWS account IDs from registry policies
- Wildcard principals, at either scope
- Specific ECR actions per account

**Registry Policies**: A repository policy governs one repository. A registry
policy governs the whole registry - AWS allows every ECR action in one and
enforces it on every ECR request in the region. A third party named there
reaches repositories whose own policies grant it nothing, so a scan that read
only repository policies would allowlist nobody and the deployed RCP would
break that access.

The commonest registry policy is the cross-account replication grant, which
names the source account and is exercised by the ECR replication
service-linked role. RCPs do not restrict service-linked roles, so that grant
would likely survive the RCP regardless - but the analyzer allowlists the
account anyway rather than inferring a caller identity it never observed. One
redundant allowlist entry is the cheaper error.

Registry findings carry `"scope": "registry"` and no repository name or ARN,
since they belong to no single repository.

**Actions Tracking**: Records ECR actions like:
- `ecr:BatchGetImage`
- `ecr:GetDownloadUrlForLayer`
- `ecr:BatchCheckLayerAvailability`
- `ecr:PutImage`

**Fail-Fast Validation**: Immediately fails if unsupported principal types (e.g., Federated) are detected.

**Output**:
- Policies third parties can reach, at both scopes
- Third-party account IDs
- Allowed ECR actions per account
- Regional distribution

**Example Output**:
```json
{
  "summary": {
    "total_policies_analyzed": 2,
    "policies_third_parties_can_access": 2,
    "policies_with_wildcards": 0,
    "violations": 0,
    "unique_third_party_accounts": ["888888888888", "999999999999"]
  },
  "policies_third_parties_can_access": [
    {
      "scope": "registry",
      "repository_name": null,
      "repository_arn": null,
      "region": "us-east-1",
      "third_party_account_ids": ["999999999999"],
      "actions_by_account": {
        "999999999999": ["ecr:CreateRepository", "ecr:ReplicateImage"]
      },
      "has_wildcard_principal": false
    },
    {
      "scope": "repository",
      "repository_name": "shared-images",
      "repository_arn": "arn:aws:ecr:us-east-1:111111111111:repository/shared-images",
      "region": "us-east-1",
      "third_party_account_ids": ["888888888888"],
      "actions_by_account": {
        "888888888888": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
      },
      "has_wildcard_principal": false
    }
  ]
}
```

---

### KMS Third-Party Access Check

**Check Name**: `deny_kms_third_party_access`

**Purpose**: Identifies KMS keys reachable by external accounts, through either of the two surfaces that authorize access to a key - its resource policy and its grants.

**How it Works**:
- Scans all AWS regions for KMS keys
- Retrieves key policies for each key
- Parses policies for third-party principals
- Lists each key's grants and resolves their principals to accounts
- Tracks specific KMS actions allowed per account

**Detection**:
- Third-party AWS account IDs from key policies
- Third-party AWS account IDs from grants, which no key policy reveals
- External retiring principals, which can call `kms:RetireGrant`
- Wildcard principals (requiring CloudTrail analysis)
- Specific KMS actions per account and per key

**Actions Tracking**: Records KMS actions like:
- `kms:Decrypt`
- `kms:Encrypt`
- `kms:GenerateDataKey`
- `kms:DescribeKey`
- `kms:CreateGrant`

**Grants**: A grant is a second authorization surface, created by `CreateGrant` and separate from the key policy. `GetKeyPolicy` does not report grants, so a key whose policy names nobody outside the organization can still hand `Decrypt` to a vendor. Reading only the policy would leave that vendor out of the allowlist, and the deployed RCP would deny it.

Each grant's `GranteePrincipal` and `RetiringPrincipal` resolve to an account:

| Grant principal | RCP outcome | Recorded as |
|---|---|---|
| IAM ARN in an organization account | Not restricted | Nothing |
| `ec2.us-west-2.amazonaws.com` and other AWS service principals | Exempt - the RCP carries `aws:PrincipalIsAWSService` `false` | Nothing |
| Service-linked role ARN | Exempt - RCPs do not restrict service-linked roles | Nothing |
| IAM ARN outside the organization | Denied | Allowlist entry, plus a `grants` entry |

A grant can only ever widen the allowlist. `CreateGrant` requires a concrete principal, so no grant can be a wildcard, and the wildcard flag is what withholds the RCP from an account.

Encryption context constraints are recorded as a boolean rather than parsed, so `has_constraints` marks a grant whose real access may be narrower than its operations suggest.

**Fail-Fast Validation**: Immediately fails if unsupported principal types (e.g., Federated) are detected in a key policy, or if a grant names a principal that is neither an ARN nor an AWS service principal.

**Output**:
- Total keys analyzed
- Keys with third-party access
- Keys with wildcard principals (violations)
- Keys with grants reaching outside the organization
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
  "has_wildcard_principal": false,
  "grants": [
    {
      "grant_id": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
      "grantee_account_id": "999999999999",
      "retiring_principal_account_id": null,
      "operations": ["kms:Decrypt", "kms:GenerateDataKey"],
      "has_constraints": false
    }
  ]
}
```

A key found only through a grant looks the same, with an empty `actions_by_account` contribution from the policy and `third_party_account_ids` populated entirely from the `grants` list.

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

### Service Confused Deputy Check

**Check Name**: `deny_service_confused_deputy`

**Purpose**: Identifies the out-of-organization accounts that legitimately drive AWS service calls into organization resources, so the `DenyServiceConfusedDeputy` statement can permit them, and the source guards no allowlist can express, so the statement can be withheld from the accounts holding them.

**Why this check exists**: Each of the six statements above ends with `BoolIfExists { "aws:PrincipalIsAWSService" = "false" }`, so its Deny never matches a call an AWS service makes. That exemption is mandatory rather than a convenience: a service-principal request carries no `aws:PrincipalOrgID` and no `aws:PrincipalAccount`, `StringNotEqualsIfExists` on an absent key evaluates true, and without the Bool clause the Deny would match every CloudTrail delivery, access-log write and SSE-KMS call in the organization.

Nothing narrowed that exemption back down. An account outside the organization that configures an AWS service in its own account - a trail, a Config delivery channel, an SNS topic - can have that service reach a bucket, key, queue, secret, repository or role in an organization account while the RCP stands aside. `DenyServiceConfusedDeputy` is the second half of the pair, and this check supplies the allowlist it needs. Severity is bounded by the resource policy: the RCP failing to deny is not the same as access being granted, so this closes a defense-in-depth gap rather than an open door.

**How it Works**:
- Runs the same six analyzers the other RCP checks run - ECR, KMS, S3, Secrets Manager, SQS and IAM role trust policies - reading a field those analyzers now record during the statement walk they already perform
- Reads every `Allow` statement naming a `Service` principal, inside the `Effect` gate each analyzer already applies, and in the IAM analyzer inside its AssumeRole action gate as well - so a trust statement naming a service under some action other than `sts:AssumeRole` is not recorded, which matches the reach of the RCP statement's action list
- Resolves the source guard on that statement: `aws:SourceAccount` directly, `aws:SourceArn` by extracting the account the ARN carries
- Keeps only the sources naming an account outside the organization, or a guard no allowlist can enumerate

Trust policies matter here as much as resource policies. A role that trusts a service principal with no source guard is the canonical confused-deputy vulnerability, and `sts:AssumeRole` is in the statement's action list.

**API cost**: recording the new field costs the other six checks nothing, but this check is not free. Nothing caches an analysis between checks, so registering it issues every RCP read API a second time per account per run - repository, key, bucket, secret, queue and role listings and their policies. Registration alone triggers that second pass; the `deny_service_confused_deputy` Terraform flag gates the rendered statement, not the scan. Caching is deliberately not implemented and is a separate optimization if the duplication proves material, so budget quota and runtime for the RCP pass at double.

**Detection**:
- Out-of-organization accounts pinned by `aws:SourceAccount` or `aws:SourceArn` on a service-principal grant, which become the statement's `aws:SourceAccount` allowlist
- Wildcard sources: `aws:SourceAccount` holding `*` or `?`, or an `aws:SourceArn` that yields no account - a wildcard in the account field, or an S3 bucket ARN, which carries no account at all - with no companion `aws:SourceAccount`. These are violations and withhold the statement from the account
- Condition key names are matched case-insensitively, as IAM matches them, so a policy written `aws:sourceaccount` names the same key
- Guards are read under `StringEquals`, `StringLike`, `ArnEquals`, `ArnLike` and their `IfExists` variants. Any other operator on a source key aborts rather than being read as a guard - a negated operator excludes rather than permits, and reading one as a guard would put the wrong account in the allowlist

**Dispositions**: what one `Allow` statement naming a service principal produces.

| Statement | `source_account_ids` | `has_source_condition` | `has_wildcard_source` | Effect on output |
|---|---|---|---|---|
| `Service` principal, no source key | `[]` | `false` | `false` | Dropped - neither listed nor counted |
| Source names an in-organization account | `[]` | `true` | `false` | Dropped - neither listed nor counted |
| Source names an out-of-organization account | `["999999999999"]` | `true` | `false` | Allowlist entry, recorded as compliant |
| Source is `*`, or an ARN yielding no account, with no companion `aws:SourceAccount` | `[]` | `true` | `true` | Violation - withholds the statement from the account |
| `aws:SourceOrgID` present, or a source key under an operator that does not pin it | - | - | - | Raises `UnknownSourceConditionError` |

Row four is `has_wildcard_principal` in a different costume: an unbounded set of sources that no allowlist can enumerate, handled the same way - withhold the statement from that account and follow up in CloudTrail. An S3 bucket ARN reaches that row honestly rather than by accident. S3 ARNs carry no account field, so `aws:SourceArn` alone never identifies whose bucket drove the call, which is exactly why AWS pairs `aws:SourceArn` with `aws:SourceAccount`. When the companion key is present the pair resolves normally; when it is absent the source is genuinely unidentifiable.

One statement can occupy two rows at once. `aws:SourceAccount` holding `["*", "999999999999"]` resolves the out-of-organization account and sets the wildcard flag, and the check unions the resolved accounts into `unique_third_party_accounts` before it branches on the wildcard - so that statement contributes an allowlist entry and files a violation. The violation governs: any violation withholds the statement from the account regardless of what it contributed.

**The `Null` gate**: The statement carries `Null { "aws:SourceAccount": "false" }`, which reads as "this key is not null", that is, it is present. The Deny therefore applies only to service calls that carry a source account. A call populating only `aws:SourceArn`, or no source keys at all, falls outside the statement entirely. This narrows the service exemption rather than closing it, and is what makes the control deployable without first discovering every service integration in the estate. `StringNotEqualsIfExists` on `aws:SourceOrgID` then catches sources in standalone accounts, which belong to no organization and so carry no organization ID: an attacker cannot escape the control by using an unattached account.

**Unguarded trusts are neither listed nor counted**: A service principal trusted with no source guard produces no output at all - not a finding, not a violation, and not a number in the summary. Two reasons, and the first is the one that matters:

1. The `Null` gate means the statement never fires on a request carrying no source account. An unguarded trust asks nothing of the allowlist and blocks nothing, so reporting it would not change what gets deployed. It is still a real confused-deputy hole - anyone can point their topic at the queue - but it is one this statement does not address, and making it a violation would withhold the statement over a problem the statement does not solve.
2. A count would be wrong rather than merely uninteresting. All six analyzers drop an analysis that found nothing worth reporting, so a tally taken here would see only the unguarded sources that happen to sit on a resource kept for some other reason. That undercount would look like a measurement. A plausible wrong number is worse than no number.

**Fail-Fast Validation**: A source guard that cannot be read aborts the run rather than being dropped. `aws:SourceOrgID` on a service principal raises, because deciding whether it names this organization needs the organization ID, which the analyzers do not receive - guessing would put a foreign organization's sources in the allowlist or leave this one's out. A source key under an unrecognized operator raises for the same reason, as does an `aws:SourceAccount` value that is neither a twelve-digit account ID nor a wildcard. Dropping any of them silently would leave an account out of the allowlist, and the deployed RCP would then deny access that account depended on - the exact failure this analysis exists to prevent.

**Output**:
- Per-finding resource identity: which analyzer found it, the resource, and the region
- The service principal the resource trusts, and the accounts its guard permits
- `unique_third_party_accounts`, which becomes the statement's `aws:SourceAccount` allowlist
- `violations`, which withholds the statement from the account exactly as it does for the other six checks

**Example Output**:
```json
{
  "resource_type": "sqs",
  "resource_identifier": "arn:aws:sqs:us-west-2:111111111111:vendor-events",
  "region": "us-west-2",
  "service_principal": "sns.amazonaws.com",
  "source_account_ids": ["999999999999"],
  "has_source_condition": true,
  "has_wildcard_source": false
}
```

A wildcard finding has the same shape with `source_account_ids` empty and `has_wildcard_source` true, and is written to `violations` rather than `compliant_instances`. `resource_identifier` is `registry` for a finding from a per-region ECR registry policy rather than a repository policy.

`region` is null for three resource types, for two different reasons. S3 buckets and IAM roles are global names, so there is no region to record. Secrets Manager secrets are regional - the analyzer iterates every region, and each secret's ARN encodes its own - but `SecretsPolicyAnalysis` carries no `region` field for the check to read, so the null is a gap in that dataclass rather than a property of the resource. Since the finding identifies a secret by name rather than by ARN, two secrets sharing a name in different regions produce identical findings and an operator cannot tell which region to look in.

---

## Check Features

### All Checks Include

- **Current State Checking**: Scans AWS APIs to check actual resource state
- **Compliance Metrics**: Violation counts and compliance percentages
- **Regional Support**: Multi-region scanning where applicable (SCPs, ECR)
- **Detailed Output**: JSON results with complete resource information

### Some Checks Include

- **Exemption Support**: Tag-based exemptions (EC2 IMDSv1 by the instance's
  own tag, standing in for the launch request's)
- **Allowlist Generation**: Auto-generated allowlists (IAM users, third-party accounts)
- **Safety Mechanisms**: Prevents breaking existing access patterns (S3 Federated principals)
- **Wildcard Detection**: Identifies principals requiring CloudTrail analysis

### Future Enhancements

- **CloudTrail Integration**: Check past AWS activity for dynamic principals
- **Condition-Aware Analysis**: Recognize org-scoping condition keys so a conditioned wildcard is not counted as a blocker
- **Configurable Exemptions**: Enable/disable exemption support per check
- **Custom Check Framework**: Easy addition of new checks via plugin system

## Adding New Checks

See [HOW_TO_ADD_A_CHECK.md](../HOW_TO_ADD_A_CHECK.md) for guidance on creating custom checks.

## Check Modules

Generated Terraform uses these modules:
- [SCPs Module](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/scps) - Implements SCP policies
- [RCPs Module](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/rcps) - Implements RCP policies
