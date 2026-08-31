# Architecture

## Trust Model

```mermaid
graph LR
    subgraph "Trust Configuration"
        SA[Security Analysis Account<br/>111111111111]

        subgraph " "
            MGMT_T[OrgAndAccountInfoReader<br/>in Management Account]
            HR1[Headroom Role<br/>in Prod Account 1]
            HR2[Headroom Role<br/>in Prod Account 2]
            HR3[Headroom Role<br/>in Dev Account 1]
            HR4[Headroom Role<br/>in Dev Account 2]
        end

        SA -->|Trusted Principal| MGMT_T
        SA -->|Trusted Principal| HR1
        SA -->|Trusted Principal| HR2
        SA -->|Trusted Principal| HR3
        SA -->|Trusted Principal| HR4

        style SA fill:#e1f5ff,stroke:#01579b,stroke-width:3px
        style MGMT_T fill:#fff3e0,stroke:#e65100,stroke-width:2px
        style HR1 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
        style HR2 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
        style HR3 fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
        style HR4 fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
    end
```

## Module Structure

```
headroom/
├── aws/           # AWS service integrations
│   ├── ec2.py     # EC2 analysis functions
│   ├── ecr.py     # ECR repository policy analysis
│   ├── eks.py     # EKS analysis functions
│   ├── helpers.py # Shared AWS helpers (region enumeration, per-session memo, pagination)
│   ├── iam/       # IAM analysis package
│   │   ├── roles.py   # RCP-focused IAM role trust policy analysis
│   │   ├── saml_providers.py  # IAM SAML provider analysis
│   │   └── users.py   # SCP-focused IAM user enumeration
│   ├── kms.py     # KMS key policy analysis
│   ├── lambda_functions.py  # Lambda function analysis
│   ├── organization.py  # Organizations API reads and hierarchy traversal
│   ├── organization_snapshot.py  # The run's one Organizations read, as an OrganizationSnapshot
│   ├── policy_documents.py  # Shared resource-policy statement reading
│   ├── rds.py     # RDS analysis functions
│   ├── s3.py      # S3 bucket policy analysis
│   ├── secretsmanager.py  # Secrets Manager policy analysis
│   ├── sessions.py      # Session management utilities
│   └── sqs.py     # SQS queue policy analysis
├── checks/        # Compliance checks (extensible framework)
│   ├── __init__.py      # Imports every check module so @register_check runs
│   ├── base.py    # BaseCheck abstract class (Template Method pattern)
│   ├── registry.py      # Check registration and discovery
│   ├── scps/      # Service Control Policy checks
│   │   ├── deny_ec2_ami_owner.py  # EC2 AMI owner check
│   │   ├── deny_ec2_imds_hop_limit.py  # EC2 IMDS hop limit check
│   │   ├── deny_ec2_imds_v1.py  # EC2 IMDS v1 check
│   │   ├── deny_ec2_public_ip.py  # EC2 public IP check
│   │   ├── deny_eks_create_cluster_without_tag.py  # EKS paved road check
│   │   ├── deny_iam_saml_provider_not_aws_sso.py  # IAM SAML provider check
│   │   ├── deny_iam_user_creation.py  # IAM user creation check
│   │   ├── deny_lambda_auth_type_none.py  # Lambda function URL authentication check
│   │   └── deny_rds_unencrypted.py  # RDS encryption check
│   └── rcps/      # Resource Control Policy checks
│       ├── deny_ecr_third_party_access.py  # ECR third-party access check
│       ├── deny_kms_third_party_access.py  # KMS third-party access check
│       ├── deny_s3_third_party_access.py  # S3 third-party access check
│       ├── deny_secrets_manager_third_party_access.py  # Secrets Manager third-party access check
│       ├── deny_service_confused_deputy.py  # Service confused deputy check
│       ├── deny_sqs_third_party_access.py  # SQS third-party access check
│       └── deny_sts_third_party_assumerole.py  # STS third-party AssumeRole check
├── terraform/     # Terraform generation
│   ├── generate_org_info.py  # Organization data sources
│   ├── generate_scps.py      # SCP configurations
│   ├── generate_rcps.py      # RCP configurations
│   ├── models.py             # Rendered Terraform module/parameter models
│   ├── reconcile.py          # Deletes generated files this run did not render
│   └── utils.py              # Shared Terraform utilities
├── placement/     # Policy placement logic
│   └── hierarchy.py          # OU hierarchy analysis
├── analysis.py    # Security analysis orchestration
├── config.py      # Configuration models (HeadroomConfig, AccountTagLayout)
├── constants.py   # Shared constants
├── enums.py       # CheckType, PlacementLevel and other shared enums
├── log_context.py # Stamps every log record with the account its thread is analyzing
├── main.py        # Application entry point
├── output.py      # Centralized output handling
├── parse_results.py  # Results processing and recommendations
├── types.py       # Shared data models (OrganizationalUnit, AccountOrgPlacement, etc.)
├── usage.py       # CLI argument parsing and config loading
├── utils.py       # Account identifier and Terraform name formatting
└── write_results.py  # JSON results writing
```

## Data Flow

1. **Configuration**: Parse CLI args and YAML config
2. **Organization Discovery**: Establish cross-account sessions, then read AWS Organizations
   exactly once into the run's `OrganizationSnapshot` -- the organization ID, full membership,
   the analyzable accounts, and the OU hierarchy. No later stage reads Organizations again
3. **Analysis**: Execute SCP and RCP compliance checks across accounts
4. **Results Processing**: Analyze compliance and determine SCP/RCP placement
5. **Terraform Generation**: Create deployment configurations with appropriate allowlists

## Execution Flow

```mermaid
sequenceDiagram
    participant Tool as Headroom CLI<br/>(Security Analysis Account)
    participant Mgmt as OrgAndAccountInfoReader<br/>(Management Account)
    participant Prod1 as Headroom Role<br/>(Production Account 1)
    participant ProdN as Headroom Role<br/>(Other Accounts...)

    Note over Tool: Step 1: Organization discovery<br/>(the run's only reads of Organizations)
    Tool->>Mgmt: AssumeRole(OrgAndAccountInfoReader)
    Mgmt-->>Tool: Session Credentials
    Tool->>Mgmt: describe_organization()
    Mgmt-->>Tool: Organization ID
    Tool->>Mgmt: list_accounts() [all pages]
    Mgmt-->>Tool: Every member account, in every lifecycle state
    Tool->>Mgmt: list_roots(), then list_organizational_units_for_parent()<br/>and list_accounts_for_parent() once per parent
    Mgmt-->>Tool: OU Hierarchy
    Tool->>Mgmt: list_tags_for_resource() per analyzable account
    Mgmt-->>Tool: Account Tags
    Note over Tool: OrganizationSnapshot: organization ID, membership,<br/>analyzable accounts, hierarchy
    Note over Tool: Accounts not in ACTIVE state<br/>(CLOSED, SUSPENDED, PENDING_CLOSURE, PENDING_ACTIVATION)<br/>and accounts in skip_account_ids stay in membership and in the<br/>hierarchy, and drop out of the analyzable set only

    Note over Tool: Step 2: Analyze accounts from the snapshot<br/>(max_account_workers at a time, default 16)
    Tool->>Prod1: AssumeRole(Headroom)
    Prod1-->>Tool: Session Credentials
    Tool->>Prod1: describe_instances() [all regions]
    Prod1-->>Tool: EC2 Instance Details
    Tool->>Prod1: Check IMDSv2 Compliance
    Prod1-->>Tool: Compliance Results

    Tool->>ProdN: AssumeRole(Headroom)
    ProdN-->>Tool: Session Credentials
    Tool->>ProdN: describe_instances() [all regions]
    ProdN-->>Tool: EC2 Instance Details
    Tool->>ProdN: Check IMDSv2 Compliance
    ProdN-->>Tool: Compliance Results

    Note over Tool: Step 3: Generate Outputs<br/>(from the snapshot's hierarchy - no further Organizations reads)
    Tool->>Tool: Write JSON Results
    Tool->>Tool: Generate Terraform SCPs
    Tool->>Tool: Generate Org Data Sources
```

## Concurrency model

One worker per account, from a single `ThreadPoolExecutor` sized by
`max_account_workers`. There is no region-level, check-level, or resource-level threading:
at 50-300 accounts the account pool already saturates the available network capacity, so a
second axis would multiply in-flight requests and throttling risk without going faster.

Within an account everything stays serial, which means each account's boto3 session is
touched by exactly one thread. Three caches rely on that: the region list, the projected
EC2 instance list, and the six resource-policy analyses shared between a third-party-access
check and `deny_service_confused_deputy`. All are memoized in `WeakKeyDictionary` instances
keyed on the session object, so entries are released when a worker finishes and nothing
accumulates across a long run. Keying on the session rather than on an account ID is what
keeps one account's data out of another's results.

That premise -- one session per account, on one thread -- is asserted rather than assumed.
`test_the_real_registry_runs_every_check_per_account_across_workers` runs the whole check
registry with four workers and reads back, for every check of every account, which session
it was handed and which thread it ran on. Nothing checks it at runtime, and a
thread-identity check on the memo would not: the pool reuses its worker threads across
accounts, so two accounts sharing one session can be two accounts on one thread.

The third cache exists because `deny_service_confused_deputy` shares six analyzers with
the resource-specific checks: ECR, KMS, S3, Secrets Manager, SQS, and IAM role trust
policies. Which of a pair reads AWS and which is served from memory is registry order, not
design -- it runs fourteenth of sixteen, so the first four are cached by the time it asks
and it reads SQS and IAM role trust policies first. Four of those six sweep every enabled
region, so without the memo each account paid four extra region sweeps -- the same waste as
the four identical EC2 sweeps, arriving by a different route. `memoize_per_session` in `aws/helpers.py` carries it, and refuses a second
call for one session that passes different organization arguments rather than serving the
first call's answer to a different question.

The one genuinely shared object is the security-analysis session, which every worker uses
to assume its target role. Client construction on that session is serialized by a lock in
`aws/sessions.py`; the `AssumeRole` round trip is not, so workers still overlap. The lock is
there because boto3 documents a `Session` as unsafe to share between threads, not because a
particular unguarded mutation was found -- botocore guards the obvious ones itself.

Because accounts interleave in the output, `log_context.py` stamps every record with the
account its thread is working on and every line carries it in brackets. Most log calls under
`headroom/aws/` name only a region or a resource, which is ambiguous the moment two accounts
are in flight; the filter is installed on the root handler rather than on a logger, because
a logger's filters do not see records propagated up from child loggers. Work outside a
worker is stamped `-`.

Two properties of account names are checked before any account is scanned, because both fail
in ways a full run would only reveal at the end. A name that cannot be a filename -- one
containing a path separator, holding a null byte, or too long for the 255-byte component
limit -- would send an account's results outside the directory policy generation reads, or
fail the write partway through. And with
`exclude_account_ids` set, the name alone is the filename, so two accounts sharing one would
interleave their JSON into a single file; names are compared the way a case-insensitive,
normalization-folding filesystem compares them. Both aborts name the offending names and
never the account IDs.

Failure aborts the run. The first worker exception sets an abort `Event` that in-flight
workers check at each check boundary, cancels the queued accounts, joins the workers, and
re-raises. Setting before cancelling is deliberate: an account that starts in the window
between the two finds the Event already set and returns without assuming a role.
Because Python cannot kill a running thread, the Event is what makes the abort prompt.

Only one exception can reach `main`, and a `Future` holding any of the others is collected
without a warning -- unlike an asyncio future, it has no `__del__`. Every failure is
therefore logged by name once the workers are joined, so an operator missing the Headroom
role in forty accounts learns that in one run rather than in forty. The sweep runs outside
the `with` block on purpose: inside it, `__exit__` has not joined the workers yet and the
other futures hold nothing to find. A cancelled account is the one outcome that logs nothing
of its own -- it never ran, and it holds no exception to report -- so a final line counts
them, which is the number that says how much of the organization the results on disk cover.

The checkpoint a worker polls sits below the results-already-on-disk skip, never above it.
A check already on disk is work the account does not owe, so an abort that lands with only
such checks left has stopped nothing; reading the Event first labels a complete account
aborted and sends the operator to a re-run that answers "All results already exist".

An operator's Ctrl-C takes the same path. `shutdown(wait=True)` defaults to
`cancel_futures=False` and puts its sentinel at the back of the work queue, so an interrupt
that only propagated would still wait out every queued account -- hours of it at one worker.
Catching it makes interrupting as prompt as a failure: bounded by the one check each
in-flight worker is already inside.

## Key Architectural Points

1. **Security Analysis Account**: Central hub where Headroom CLI typically executes
2. **Management Account**: Provides organization structure and account metadata via `OrgAndAccountInfoReader` role
3. **Member Accounts**: Each has a `Headroom` role for resource analysis
4. **Trust Relationship**: All roles trust the Security Analysis Account as their principal
5. **Hub-and-Spoke Pattern**: Tool runs from one central account, accesses other accounts via AssumeRole
6. **Flexible Execution**: Can run from either the security analysis account or from the management account (requires `security_analysis_account_id` configuration)
7. **ACTIVE-Only Analysis**: Only accounts in the `ACTIVE` lifecycle state are analyzed. `CLOSED`, `SUSPENDED` and `PENDING_ACTIVATION` accounts reject role assumption, and `PENDING_CLOSURE` accounts are leaving the organization. Read from the `State` field, falling back to the `Status` field that AWS retires on 2026-09-09; an account whose lifecycle state cannot be classified - reporting neither field, or a state AWS added that Headroom does not know - aborts the run rather than being guessed at, and a test asserts the known states still cover the SDK's enum so a new one surfaces in CI. Organization-membership lookups are deliberately **not** filtered, since a closed account stays an organization member and still matches organization-based RCP conditions
8. **Fail-Fast Analysis**: A failure while analyzing any account aborts the entire run; errors are never logged and skipped. A partial run is more dangerous than no run, because the output drives SCP/RCP deployment and an account skipped for a transient error is indistinguishable from one with zero violations. Accounts that genuinely cannot be analyzed are excluded up front by lifecycle state instead
9. **Registry-Driven Policy Wiring**: Every stage between check collection and Terraform generation is driven by the check registry, never by a hardcoded check name. `parse_rcp_result_files` iterates `get_check_names("rcps")` and placement runs once per check, so a registered check cannot be collected and then silently dropped. The one place a new RCP check must be declared by hand is `RCP_TERRAFORM_VARIABLES`, and `test_table_covers_every_registered_rcp_check` fails by name if that entry is missing. This exists because five RCP checks were once collected against every account on every run and rendered as disabled, which is indistinguishable in the output from a check that found nothing
10. **Allowlist Round-Trip**: A check that reports values for an allowlist must carry them the whole way to its Terraform variable - summary key, `SCPCheckResult` field, placement union, module parameter. Break the round trip anywhere and the check still reports 100% compliance and the SCP is still enabled, now with an empty allowlist. For a Deny statement scoped by that allowlist, empty denies everything rather than nothing. `deny_ec2_ami_owner` shipped that way: the module variable and the summary field both existed, nothing joined them. SCP generation now leaves the policy off with a comment rather than rendering an empty `ec2_allowed_ami_owners`, and parsing rejects a result file that predates the collection outright, because an absent summary key and an empty one mean opposite things
11. **Record the Value the Condition Key Holds**: a check that feeds an allowlist must collect what the key will evaluate to at authorization time, not the field of the same name in the describe call. `ec2:Owner` is the AMI's `ImageOwnerAlias` when there is one and its numeric `OwnerId` otherwise; collecting `OwnerId` alone produced an allowlist that denied the exact AMI the scan had just cleared. Tests hid it by asserting API responses AWS cannot return (`OwnerId: "amazon"`), so fixtures for a condition-key check must be shaped like real responses
12. **The Subtree Is the Unit of OU Reasoning**: A policy attached to an OU governs every account in that OU *and* in every OU beneath it, so every question asked about an OU - is it safe to attach here, what must its allowlist hold, which accounts does this recommendation affect - is asked of the whole subtree. Placement walks the hierarchy from the top down and stops at the highest safe OU, whose descendants inherit the policy rather than collecting a redundant second copy; an unsafe OU hands the question to its child OUs. Judging an OU by the accounts parented directly to it once declared a parent policy safe while a violating account two levels down was never examined, and unioned an allowlist that omitted that account's resources. Nothing errored, because the report never mentioned the accounts it had skipped
13. **One Name, One Rule, Both Generators**: Every OU is named for its path down from the root, and both sides of the Terraform contract build that name with the same function - `generate_org_info` declares `local.<path>_ou_id`, `generate_scps` and `generate_rcps` reference it through `ou_id_local_name()`. Colliding or reserved names abort the run rather than overwrite each other. Declaring locals for top-level OUs only, while emitting references for any OU, produced Terraform that failed at plan time on an undeclared local; each module's own tests passed, because one asserted the reference and the other asserted the declaration. `tests/test_nested_ou_hierarchy.py` generates both from one hierarchy and asserts every `local.` a policy reads is one the org info declares
14. **Generation Is Reconciliation, Not Appending**: A run's output is the complete desired state of the Terraform directory, so a target that drops out of the recommendations loses its file. Generation renders every file into a plan before writing any of it, then deletes the generated files the plan omits - which is what makes a failure partway through leave the previous output whole, and what makes two identical runs touch nothing. Ownership is a marker on the file's first line, never a filename pattern or a side manifest: a pattern claims the hand-written `custom_scps.tf` next to ours, and a manifest is separate state that orphans everything it loses and over-deletes whatever it names wrongly. Appending was the original behaviour, and it meant a policy that moved from an OU down to individual accounts kept its OU-wide attachment - still denying the account whose new violation caused the move. Because deleting everything is also how a broken run would present, a run that parses zero result files aborts instead: no evidence is not the same answer as no policies needed
15. **Data Flow**:
   - Management account → Organization metadata
   - Member accounts → Compliance data
   - Tool → Aggregated results + Terraform configs
