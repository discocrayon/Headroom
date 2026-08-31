# Headroom - AWS Multi-Account Security Analysis Tool
## Product Specification

**Version:** 5.0
**Last Updated:** 2025-11-09

---

## Executive Summary

**Headroom** is a Python CLI tool for AWS multi-account security analysis with Service Control Policy (SCP) and Resource Control Policy (RCP) audit capabilities. The tool provides "audit mode" for SCPs/RCPs, enabling security teams to analyze AWS Organizations environments and auto-generate Terraform configurations for policy deployment.

**Core Value Proposition:** Ever want audit mode for SCPs / RCPs? Well now you can.

**Usage Philosophy:** Bare-bones prevention-focused CLI tool. No more getting flooded with thousands of reactive CSPM findings, stop the bleeding where possible.

**Disclaimer:** Don't run this in production / do so at your own risk! :)

**Current State Coverage:** Should always be checked. CloudTrail is only sometimes checked.

---

## Product Capabilities

### 1. Configuration Management
- Hybrid YAML + CLI configuration with CLI override capability
- Pydantic-based validation with strict type checking
- Optional security_analysis_account_id for running from management account vs running directly from security analysis account

### 2. AWS Multi-Account Integration
- Secure cross-account access via IAM role assumption
- AWS Organizations integration for account discovery and metadata
- Tag-based account information extraction (environment/owner default to "unknown", name defaults to account ID)
- Session management with proper credential handling

### 3. SCP Compliance Analysis
- **EC2 IMDS v1 Check:** Multi-region scanning, with exemptions read from the IAM role each instance runs as
- **IAM User Creation Check:** Automatic allowlist generation from discovered users
- **RDS Encryption Check:** Multi-region RDS instance and Aurora cluster encryption analysis
- **SAML Provider Guardrail:** Blocks custom IAM SAML providers so only a single AWS SSO-managed provider exists per account
- Modular check framework with self-registration pattern
- JSON result generation with detailed compliance metrics

#### Check: `deny_iam_saml_provider_not_aws_sso`

- **Objective:** Eliminate custom IAM SAML providers so the companion SCP can unconditionally deny `iam:CreateSAMLProvider`
- **Allowed State:** Zero SAML providers or exactly one AWS SSO-managed provider whose ARN matches `arn:aws:iam::<ACCOUNT_ID>:saml-provider/AWSSSO_<INSTANCE_ID>_<REGION>`
- **Violation States:**
  - More than one SAML provider exists
  - Any provider ARN does not begin with the AWS SSO prefix described above
- **AWS APIs:** `iam:ListSAMLProviders` (read-only; covered by AWS managed `ViewOnlyAccess`)
- **Analysis Output:** Per-provider findings with `arn`, `name`, `create_date`, `valid_until`, and `violation_reason` derived from the rules above
- **Summary Metrics:** `total_saml_providers`, `awssso_provider_count`, `non_awssso_provider_count`, `violating_provider_arns`, `allowed_provider_arn`
- **Terraform Impact:** Generates an SCP statement that denies `iam:CreateSAMLProvider` (no conditions) with explanatory comments; goal placement is organization root because enforcement is universal
- **Why deny everyone?** `AWSServiceRoleForSSO` creates the official provider when accounts join IAM Identity Center and is not affected by SCPs, so a blanket deny only affects custom provider creation attempts
- **Testing Requirements:** Unit tests for AWS enumeration helper, check categorization covering compliant, excess AWSSSO, and non-AWSSSO cases; generator tests confirming Terraform statement, and integration test ensuring placement logic handles new check

### 4. RCP Compliance Analysis
- **STS Third-Party AssumeRole Check:** IAM trust policy analysis across organization
- **S3 Third-Party Access Check:** S3 bucket policy and bucket ACL analysis for third-party access
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated, CanonicalUser)
- Federated and CanonicalUser principal detection to prevent breaking SSO/SAML access
- Action and resource tracking for third-party S3 access patterns
- **ECR Third-Party Access Check:** ECR repository and registry policy analysis across organization
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated) for IAM trust policies
- Organization baseline comparison for external account detection
- Multi-region ECR repository scanning with pagination support
- ECR actions tracking per third-party account
- **KMS Third-Party Access Check:** KMS key policy and key grant analysis across organization
- Third-party account detection from both surfaces, and wildcard principal identification
- Principal type validation (AWS, Service, Federated) for key policies
- Grant principal classification (IAM ARN, AWS service principal) with fail-fast on anything else
- Multi-region KMS key scanning with pagination support for keys and grants
- KMS actions tracking per third-party account
- **Secrets Manager Third-Party Access Check:** Secret resource policy analysis across organization
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated, CanonicalUser) with fail-fast on the last two
- Multi-region secret scanning with pagination support
- Secrets Manager actions tracking per third-party account, and which secrets each one can reach
- **SQS Third-Party Access Check:** Queue resource policy analysis across organization
- Third-party account detection and wildcard principal identification
- Principal type validation (AWS, Service, Federated) with fail-fast on Federated
- Multi-region queue scanning with pagination support
- A queue whose policy cannot be parsed is recorded rather than dropped, so an incomplete read withholds the confused deputy statement instead of vanishing on a log line
- SQS actions tracking per third-party account, and which queues each one can reach
- **Service Confused Deputy Check:** Source-guard analysis on every `Allow` statement naming a `Service` principal, across the six resource types the other RCP checks already analyze - ECR, KMS, S3, Secrets Manager, SQS and IAM role trust policies
- Narrows the AWS service exemption the other six statements must carry, which nothing previously narrowed back down
- Out-of-organization source account detection from `aws:SourceAccount` and `aws:SourceArn`, unioned into the statement's source allowlist
- Wildcard source detection - a source no allowlist can enumerate withholds the statement from that account
- Organization-scoped guards resolved against this organization's own ID, so `aws:SourceOrgID` and `aws:SourceOrgPaths` naming this organization cost no allowlist entry and naming another withhold the statement
- Fail-fast on a source guard that cannot be read (an unrecognized operator, a value that is neither an account ID nor a wildcard)
- No additional AWS API calls in the existing six checks: they record the sources during the statement walk they already perform
- The seventh check calls those same six analyzers, but `memoize_per_session` serves whichever of a pair runs second from memory, so the RCP read APIs are issued once per account per run

### 5. Policy Placement Intelligence
- Organization structure analysis for optimal policy deployment levels
- Greatest common denominator logic for safe SCP deployment
- Union strategy for RCP third-party account allowlists
- Automatic OU and root-level recommendations when safe

### 6. Terraform Auto-Generation
- AWS Organizations data source generation with validation
- SCP Terraform modules with automatic allowlist integration
- RCP Terraform modules with third-party account allowlists
- Multi-level deployment (root, OU, account) based on compliance analysis

---

## Technical Architecture

### Module Organization

```
headroom/
├── __init__.py
├── __main__.py              # Entry point
├── config.py                # Configuration models
├── constants.py             # Check names and type mappings
├── main.py                  # Orchestration
├── usage.py                 # CLI parsing
├── analysis.py              # Check execution
├── parse_results.py         # SCP placement analysis
├── write_results.py         # Result file management
├── output.py                # User-facing output
├── types.py                 # Shared data models
├── enums.py                 # CheckCategory and other shared enums
├── log_context.py           # Stamps each log record with its thread's account
├── utils.py                 # Cross-cutting helpers
├── aws/
│   ├── ec2.py              # EC2 analysis
│   ├── ecr.py              # ECR repository and registry policy analysis
│   ├── eks.py              # EKS cluster analysis
│   ├── helpers.py          # Region enumeration, per-session memoization, pagination
│   ├── kms.py              # KMS key policy and key grant analysis
│   ├── lambda_functions.py # Lambda function URL analysis
│   ├── policy_documents.py # Shared IAM policy grammar - see Shared Policy Grammar
│   ├── rds.py              # RDS analysis
│   ├── s3.py               # S3 bucket policy and ACL analysis
│   ├── secretsmanager.py   # Secret resource policy analysis
│   ├── sqs.py              # Queue resource policy analysis
│   ├── iam/
│   │   ├── roles.py        # Trust policy analysis (RCP)
│   │   ├── saml_providers.py  # SAML provider enumeration (SCP)
│   │   └── users.py        # User enumeration (SCP)
│   ├── organization.py     # Organizations API reads and hierarchy traversal
│   ├── organization_snapshot.py  # The run's one Organizations read - see Organization Integration
│   └── sessions.py         # Session management
├── checks/
│   ├── base.py             # BaseCheck abstract class
│   ├── registry.py         # Check registration system
│   ├── scps/
│   │   ├── deny_ec2_ami_owner.py
│   │   ├── deny_ec2_imds_hop_limit.py
│   │   ├── deny_ec2_imds_v1.py
│   │   ├── deny_ec2_public_ip.py
│   │   ├── deny_eks_create_cluster_without_tag.py
│   │   ├── deny_iam_saml_provider_not_aws_sso.py
│   │   ├── deny_iam_user_creation.py
│   │   ├── deny_lambda_auth_type_none.py
│   │   └── deny_rds_unencrypted.py
│   └── rcps/
│       ├── deny_ecr_third_party_access.py
│       ├── deny_kms_third_party_access.py
│       ├── deny_s3_third_party_access.py
│       ├── deny_secrets_manager_third_party_access.py
│       ├── deny_service_confused_deputy.py
│       ├── deny_sqs_third_party_access.py
│       └── deny_sts_third_party_assumerole.py
├── placement/
│   └── hierarchy.py        # OU hierarchy analysis
└── terraform/
    ├── generate_org_info.py
    ├── generate_scps.py
    ├── generate_rcps.py
    ├── models.py           # Terraform generation data models
    ├── reconcile.py        # Reconciliation against existing Terraform
    └── utils.py
```

### Data Flow

1. **Configuration:** Load YAML → merge with CLI args → validate with Pydantic
2. **AWS Setup:** Assume security analysis role (if specified) → assume OrgAndAccountInfoReader in management account
3. **Organization Discovery:** Read Organizations once into the run's `OrganizationSnapshot` → organization ID, full membership, the OU hierarchy, and account metadata with tags → filter the management account, `skip_account_ids` and every non-ACTIVE account out of the analyzable set only
4. **Analysis:** Filter out accounts whose results all already exist, then analyze the rest
   through a `ThreadPoolExecutor` of `max_account_workers` workers (default 16, maximum 32),
   one worker per account. Each worker:
   - Assumes the Headroom role in its target account
   - Runs all registered SCP checks
   - Runs all registered RCP checks
   - Writes JSON results to `{results_dir}/{check_type}/{check_name}/`

   Within an account the checks stay serial, so each account's boto3 session is touched by
   exactly one thread. The first worker to fail sets an abort `Event` that in-flight workers
   check at each check boundary, then cancels the queued accounts, then re-raises -- setting
   before cancelling, so an account starting in the window between the two finds the Event
   already set. Every other failure is logged by name once the workers are joined, and a
   final line reports how many accounts were cancelled before they started, which is the
   only outcome that otherwise logs nothing. An operator's Ctrl-C takes the same path, so
   interrupting is prompt rather than a wait for the whole queue.

   Because accounts interleave in the output, `log_context.py` stamps every record with
   the account its thread is analyzing and the format carries it in brackets:
   `DEBUG:headroom.aws.sqs:[payments_111111111111] Analyzing SQS queues in eu-west-1`.
   Records emitted outside a worker are stamped `-`, and a record that already carries an
   account -- one passed as `extra={"account": ...}` -- keeps it, because the caller has
   named the account the message is about rather than the one whose worker emitted it.
   The filter is installed on the root handler, not on a logger, because a logger's
   filters never see records propagated up from child loggers. `configure_logging`
   installs it only on handlers it installed itself: a root handler that was already
   there belongs to whoever put it there, and reformatting it would change output
   Headroom does not own.

   Two properties of the account names are checked before the pool starts, since both
   would otherwise surface only at the end of a run that takes roughly sixteen minutes at
   the default sixteen workers. A name that cannot be a filename -- containing a path
   separator, holding a null byte, or too long for the filesystem's 255-byte limit on one
   path component -- would put the account's results outside the directory generation
   reads without failing, or fail the write partway through. A leading dot is allowed:
   `pathlib.Path.glob` matches dotfiles, and the readers take account identity from the
   JSON rather than the filename. And under `exclude_account_ids` the name alone is the
   filename, so two accounts sharing one would interleave their JSON. Both aborts name the
   offending names and never the account IDs. "Account name validation" below gives the
   comparison rule.
5. **Placement:** Parse all result files → match them against the captured hierarchy → determine policy levels
6. **Generation:** Generate `grab_org_info.tf` + SCP Terraform files + RCP Terraform files

---

### Account name validation

Two checks run over the account names before the worker pool starts, and a third runs at
generation. All three failures are otherwise invisible until the end of a run, and two of
them are silent even then.

**A name that cannot be a filename.** A path separator puts the account's results
somewhere other than the check directory that generation reads: the write succeeds, and
the account is missing from the policies with nothing in the log to say so. A null byte
or a name past 237 bytes -- the 255-byte limit on one path component, less the `_`,
twelve-digit account ID and `.json` the resolver adds -- fails the write outright, in a
worker thread, partway through the run. Organizations caps an account name at 50
characters, but `use_account_name_from_tags` reads the name from a tag value, and a tag
value runs to 256. The check is unconditional: the account ID is in the filename under
the default setting too, and it does not make a name with a slash in it safe.

A leading dot is not rejected. `pathlib.Path.glob` matches dotfiles -- `glob.glob` is the
one that skips them, and both readers use `pathlib` -- and neither reader takes account
identity from the filename, reading it out of the JSON `summary` instead. An empty name
is rejected, but for the generation reason below rather than a filename one.

**Two accounts that resolve to one filename.** Only under `exclude_account_ids`, where
the name alone is the filename. Run serially that is a quiet last-writer-wins; run with
a worker per account it is two threads interleaving `json.dump` output into one file,
yielding either corrupt JSON or a valid file holding both accounts' results spliced
together, which then feeds policy generation.

The comparison is the interesting part, because `==` is the wrong test. Development
happens on macOS, where APFS folds two axes by default: case, so `Prod` and `prod` are
one file, and Unicode normal form, so `café` composed and decomposed are one file even
though the two strings hold different code points.

Closing the two axes in sequence does not close their composition, because case folding
can undo the normalization that just ran. `ſ` (U+017F LATIN SMALL LETTER LONG S) followed
by a combining acute has no precomposed form, so NFC returns it unchanged; the fold then
maps `ſ` to `s`, yielding the decomposition of `ś` rather than `ś` itself. Under
`casefold(NFC(x))` the two names key differently while APFS stores them in one inode.
Decomposing first is what closes that: under NFD both spellings reach the fold already
decomposed, and both come out as `s` followed by the combining acute.

Unicode's closed form for this comparison is canonical caseless matching, D145:
`NFD(casefold(NFD(x)))`. That is what Headroom uses. The trailing NFD is there because
D145 specifies it, not because a name has been found that needs it -- against the Unicode
data in the interpreter this was measured on, no single code point changes key when it is
dropped, the example above included. It costs one pass, and it means the guard does not
have to be re-derived when the case-folding data changes.

The guard is deliberately over-eager. On a filesystem that folds neither axis it can
abort a run whose names would not in fact have collided. A loud abort an operator fixes
by renaming an account beats two accounts' JSON interleaved into one file that policy
generation then reads as one account's evidence.

**Two accounts that claim one Terraform identifier.** At generation, not startup.
Everything generated for an account -- its policy file, its module name, the ID local it
targets -- is built from `make_safe_variable_name` of its name, which folds far wider
than the filesystem does: case, spaces, hyphens, and every other non-alphanumeric all
become one underscore, runs of underscores collapse, and leading and trailing underscores
are stripped. `Prod-US`, `Prod US`, `Prod_US`, `prod.us` and `PROD+US` are one identifier.

`make_account_base_names` claims one identifier per account and aborts when two accounts
claim the same one, exactly as `make_ou_base_names` has always done for OUs. Without it
the SCP and RCP plans, which are dictionaries keyed on the destination path, silently
drop the first account's file when the second is rendered -- render-before-mutate never
sees a conflict, because the conflict happened while the plan was being built. The
account locals in `grab_org_info.tf` fail more loudly, declaring the same
`<name>_account_id` twice, but only at `terraform apply`.

The guard reads every account in the organization rather than the analyzed subset,
because `_generate_account_locals` declares a local for every account the hierarchy
holds. A collision between an analyzed account and a skipped one is still a duplicate
local. That is also why it is not one of the two startup guards: those run over
`analyzable_accounts`, which has already dropped the management account,
`skip_account_ids`, and every non-ACTIVE account, so they cannot see this collision at
all. Nothing else keeps it late. The hierarchy it needs is captured before the scan
now, by organization discovery, so an equivalent pre-flight over
`snapshot.hierarchy.accounts` is available; the check stays where the identifiers are
actually claimed, inside `make_account_base_names`, so all three generators inherit it
rather than trusting a separate pre-flight to have run, and the retry after a late
abort is cheap -- resume skips every account already scanned.

The message names the account names and never the account IDs, matching the two startup
guards: `exclude_account_ids` exists so an operator never sees them, and the generated
Terraform looks accounts up by name in any case.

**Two generated files that claim one path.** The claim tables each keep one namespace
free of collisions, and neither can see the other, nor the fixed `root_scps.tf` and
`root_rcps.tf` names. An account named `Root` reduces to `root` and takes the root
policy's file; an account named `Sandbox OU` reduces to `sandbox_ou` and takes the file
belonging to an OU named `Sandbox`. `claim_plan_path` is the check that spans all of
them, because it compares the thing that actually collides -- the destination path -- and
it is the last point at which the collision is still visible. After it the plan is a
dictionary that has already lost an entry.

**Both run before the resume filter, and have to.** They see every account the run
selected, not the subset still needing a scan: `run_checks` drops accounts whose results
already exist, and that filter runs after these. Deferring the duplicate-name check until
after it looks like it would spare a re-run whose colliding accounts had both already
been scanned. It cannot. Under `exclude_account_ids` that pair shares one result file, so
"already scanned" is not a state the results directory can express for either account
separately. One `prod.json` exists, and it cannot name its writer: under this setting the
writer also strips `account_id` from the summary before the file is written, so neither
the filename nor the contents record which account produced it, or whether both
interleaved into it. The resume filter reads that single file and reports
both accounts complete. A check placed after it would therefore skip the collision
silently and let generation attribute one account's evidence to the other; where only one
of the pair is complete, it would let the other overwrite it. The information that would
make the deferred check safe is the account ID that `exclude_account_ids` removed from
the filename and the summary alike.

## Data Models

### Core Configuration Models

```python
# config.py

DEFAULT_RESULTS_DIR = "test_environment/headroom_results"
DEFAULT_SCPS_DIR = "test_environment/scps"
DEFAULT_RCPS_DIR = "test_environment/rcps"
DEFAULT_ACCOUNT_WORKERS = 16   # Accounts analyzed concurrently
MAX_ACCOUNT_WORKERS = 32       # Upper bound; ~1.5 GB resident at 32 workers

class AccountTagLayout(BaseModel):
    environment: str  # Tag key for environment (e.g., "Environment")
    name: str         # Tag key for account name (e.g., "Name")
    owner: str        # Tag key for owner (e.g., "Owner")

class HeadroomConfig(BaseModel):
    management_account_id: Optional[str]                 # Required for org access
    security_analysis_account_id: Optional[str]          # Optional, for cross-account execution
    exclude_account_ids: bool = False                    # Redact IDs in results
    skip_account_ids: List[str] = []                     # Excluded from analysis entirely
    use_account_name_from_tags: bool                     # Use tag vs AWS account name
    account_tag_layout: AccountTagLayout
    results_dir: str = DEFAULT_RESULTS_DIR
    scps_dir: str = DEFAULT_SCPS_DIR
    rcps_dir: str = DEFAULT_RCPS_DIR
    max_account_workers: int = Field(                    # 1 runs accounts serially
        default=DEFAULT_ACCOUNT_WORKERS,
        ge=1,
        le=MAX_ACCOUNT_WORKERS,
    )
```

### Organization Structure Models

```python
# types.py

@dataclass
class OrganizationalUnit:
    ou_id: str
    name: str
    parent_ou_id: Optional[str]       # None for root
    child_ous: List[str]              # Direct child OU IDs
    accounts: List[str]               # Direct child account IDs

@dataclass
class AccountOrgPlacement:
    account_id: str
    account_name: str
    parent_ou_id: str                 # Direct parent OU
    ou_path: List[str]                # Full path from root to account

@dataclass
class OrganizationHierarchy:
    root_id: str
    organizational_units: Dict[str, OrganizationalUnit]   # Keyed by OU ID
    accounts: Dict[str, AccountOrgPlacement]              # Keyed by account ID
```

`AccountInfo` and `OrganizationSnapshot`, the run's whole captured view of the
organization, live in `types.py` too and are described under "Organization
Integration".

### Check Result Models

```python
# types.py

@dataclass
class CheckResult:
    """Base class for all check results."""
    account_id: str
    account_name: str
    check_name: str

@dataclass
class SCPCheckResult(CheckResult):
    """SCP check result with compliance metrics."""
    violations: int
    exemptions: int
    compliant: int
    compliance_percentage: float
    total_instances: Optional[int] = None          # For instance-based checks
    iam_user_arns: Optional[List[str]] = None      # For IAM user checks
    ami_owners: Optional[List[str]] = None         # For the AMI owner check

@dataclass
class RCPCheckResult(CheckResult):
    """RCP check result for third-party access control."""
    third_party_account_ids: List[str]
    blocks_rcp: bool  # True if a principal here defeats any allowlist
```

### Placement Recommendation Models

```python
# types.py

@dataclass
class SCPPlacementRecommendations:
    check_name: str
    recommended_level: str                        # "root", "ou", or "account"
    target_ou_id: Optional[str]                   # None for root/account level
    affected_accounts: List[str]                  # Account IDs covered
    compliance_percentage: float
    reasoning: str
    allowed_iam_user_arns: Optional[List[str]] = None   # For IAM user checks
    ec2_allowed_ami_owners: Optional[List[str]] = None  # For the AMI owner check

@dataclass
class RCPPlacementRecommendations:
    check_name: str
    recommended_level: str                        # "root", "ou", or "account"
    target_ou_id: Optional[str]
    affected_accounts: List[str]
    third_party_account_ids: List[str]            # Unioned third-party IDs
    reasoning: str

@dataclass
class RCPCheckParseResult:
    """Third-party access findings for one RCP check, across every account."""
    check_name: str                               # Which RCP check this is
    account_third_party_map: Dict[str, Set[str]]  # account_id -> third_party_ids
    accounts_with_blockers: Set[str]              # Accounts that cannot take this RCP
```

### Check-Specific Data Models

```python
# aws/ec2.py
@dataclass
class DenyImdsV1Ec2:
    region: str
    instance_id: str
    imdsv1_allowed: bool                # True if IMDSv1 enabled (violation)
    exemption_tag_present: bool         # True if the INSTANCE is tagged

# aws/iam/users.py
@dataclass
class IamUserAnalysis:
    user_name: str
    user_arn: str
    path: str                           # IAM path (e.g., "/", "/admins/")

# aws/rds.py
@dataclass
class DenyRdsUnencrypted:
    db_identifier: str
    db_type: str
    region: str
    engine: str
    encrypted: bool
    db_arn: str

# aws/iam/roles.py
@dataclass
class TrustPolicyAnalysis:
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]   # Non-org account IDs
    has_wildcard_principal: bool        # True if Principal: "*" or NotPrincipal

# aws/ecr.py
PolicyScope = Literal["repository", "registry"]

@dataclass
class ECRPolicyAnalysis:
    scope: PolicyScope                  # Which policy surface this came from
    region: str
    third_party_account_ids: Set[str]   # Non-org account IDs
    repository_name: Optional[str] = None       # None for a registry policy
    repository_arn: Optional[str] = None        # None for a registry policy
    actions_by_account: Dict[str, List[str]] = ...  # Account ID -> allowed actions
    has_wildcard_principal: bool = False        # Principal: "*" or NotPrincipal
```

---

## Configuration System

### Configuration Schema

```yaml
management_account_id: string                # Required for org access
security_analysis_account_id: string         # Optional (omit if running from security account)
exclude_account_ids: boolean                 # Redact account IDs in results
skip_account_ids: list of string             # Never analyzed; each must match a real account
use_account_name_from_tags: boolean          # Use tag for name vs AWS account name
results_dir: string                          # Default: test_environment/headroom_results
scps_dir: string                             # Default: test_environment/scps
rcps_dir: string                             # Default: test_environment/rcps
max_account_workers: integer                 # Accounts analyzed at once, 1-32, default 16
account_tag_layout:
  environment: string                        # Optional tag, fallback: "unknown"
  name: string                               # Optional tag, used when use_account_name_from_tags=true
  owner: string                              # Optional tag, fallback: "unknown"
```

Both models set `extra="forbid"`, so a key outside this schema aborts rather than being
dropped. Pydantic's default is to ignore unknown fields, which makes a misspelling
indistinguishable from a key that was never meant to apply: `max_account_worker: 1`
configured sixteen workers and said nothing about it.

### Configuration Loading Logic

1. Parse CLI arguments (required `--config` flag)
2. Load YAML file with graceful degradation to empty dict
3. Merge YAML with CLI overrides (CLI takes precedence)
4. Validate with Pydantic (raises ValueError/TypeError on failure)
5. Handle missing fields with defaults from config.py constants

### CLI Arguments

```bash
--config CONFIG                            # Required: path to YAML
--results-dir DIR                          # Optional: override results_dir
--scps-dir DIR                             # Optional: override scps_dir
--rcps-dir DIR                             # Optional: override rcps_dir
--management-account-id ID                 # Optional: override management_account_id
--security-analysis-account-id ID          # Optional: override security_analysis_account_id
--exclude-account-ids                      # Optional: flag to redact IDs
--max-account-workers N                    # Optional: override max_account_workers
```

---

## Check Framework

### BaseCheck Abstract Class

     ```python
# checks/base.py

class BaseCheck(ABC, Generic[T]):
    """
    Template Method pattern for all checks.

    Type parameter T: the analysis result type (e.g., DenyImdsV1Ec2)
    """

    # Set by @register_check decorator
    CHECK_NAME: str
    CHECK_TYPE: str

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        exclude_account_ids: bool = False,
        **kwargs: Any,  # RCP checks use org_account_ids and org_id
    ) -> None:
        """Initialize check with common parameters."""

    @abstractmethod
    def analyze(self, session: boto3.Session) -> List[T]:
        """
        Perform AWS API calls to gather data.

        Returns: List of raw analysis results
        """

    @abstractmethod
    def categorize_result(self, result: T) -> tuple[str, Dict[str, Any]]:
        """
        Categorize single result into violation/exemption/compliant.

        Returns: ("violation"|"exemption"|"compliant", result_dict)
        """

    @abstractmethod
    def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
        """
        Build check-specific summary fields.

        Returns: Dict with fields like total_instances, compliance_percentage
        """

    def execute(self, session: boto3.Session) -> None:
        """
        Template method orchestrating check execution:
        1. Call analyze() to get raw results
        2. Categorize each result via categorize_result()
        3. Build summary with base fields + check-specific fields
        4. Write JSON results to disk
        5. Print completion message
    """
```

### CategorizedCheckResult

```python
@dataclass
class CategorizedCheckResult:
    violations: List[Dict[str, Any]]      # Non-compliant resources
    exemptions: List[Dict[str, Any]]      # Exempted resources
    compliant: List[Dict[str, Any]]       # Compliant resources
    summary: Dict[str, Any]               # Summary metadata
```

### Registry Pattern

```python
# checks/registry.py

_CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {}

def register_check(check_type: str, check_name: str) -> Callable:
    """
    Decorator to register check class.

    Usage:
        @register_check("scps", "deny_ec2_imds_v1")
        class DenyImdsV1Ec2Check(BaseCheck[DenyImdsV1Ec2]):
            ...

    Side effects:
    - Stores class in _CHECK_REGISTRY[check_name]
    - Sets class attributes CHECK_NAME and CHECK_TYPE
    - Calls register_check_type() to update constants.CHECK_TYPE_MAP
    """

def get_check_class(check_name: str) -> Type[BaseCheck]:
    """Retrieve check class by name (raises ValueError if unknown)."""

def get_all_check_classes(check_type: Optional[str] = None) -> List[Type[BaseCheck]]:
    """Get all registered checks, optionally filtered by type ("scps" or "rcps")."""

def get_check_names(check_type: str) -> List[str]:
    """Get all check names for a given type."""
```

### Check Discovery

```python
# checks/__init__.py

def _discover_and_register_checks() -> None:
    """
    Automatically discover and import all check modules.

    Walks through scps/ and rcps/ directories and imports all Python files.
    This triggers the @register_check decorator, which registers checks in
    the registry.
    """
    checks_dir = Path(__file__).parent

    for check_type in ["scps", "rcps"]:
        check_type_dir = checks_dir / check_type

        for module_info in pkgutil.iter_modules([str(check_type_dir)]):
            module_name = f"headroom.checks.{check_type}.{module_info.name}"
            importlib.import_module(module_name)


_discover_and_register_checks()
```

**Key Benefits:**
- No manual imports required when adding new checks
- Simply create check file in scps/ or rcps/ directory
- @register_check decorator runs automatically on import
- Zero chance of forgetting to register a new check

---

## SCP Checks

### Deny IMDSv1 (EC2)

**Purpose:** Decide whether an account can take the `deny_ec2_imds_v1` SCP, by
counting the EC2 instances that permit IMDSv1 without carrying the exemption
tag.

**Scope - launches, not the running fleet.** The SCP carries one statement,
`DenyRunInstancesMetadataHttpTokensOptional`, evaluated against a
`RunInstances` request. Every instance the scan sees has already launched, so
none of them can be denied by it. An IMDSv1 instance is counted as evidence
that the *next* launch in that account would be denied, which is what makes
the account not yet ready for the policy. The instances themselves are
expected to be migrated to IMDSv2; the SCP exists to stop new ones appearing
while that happens.

A `DenyRoleDeliveryLessThan2` statement, denying any API call made with
credentials fetched over IMDSv1, previously shared this variable. It was
removed rather than split into its own: one variable gating two statements
meant one scan verdict licensing two kinds of evidence, and a role-tagged
IMDSv1 instance was reported as a clean exemption while the surviving
statement - which reads no role tag - would have denied that account's next
launch. Covering the running fleet again means a new variable with its own
verdict, not a second statement on this one.

**Data Model:**
```python
@dataclass
class DenyImdsV1Ec2:
    region: str
    instance_id: str
    imdsv1_allowed: bool                # True = violation
    exemption_tag_present: bool         # True = exempted
```

**Exemption Dimension:** The statement exempts a launch through
`aws:RequestTag/ExemptFromIMDSv2`. That key is populated from the
`TagSpecifications` of the `RunInstances` call, and the same entry puts the
tag on the instance the call creates - so the scan reads the **instance's**
tag as the observable trace of the request tag, and as evidence that a
relaunch will carry it again.

Measured with `RunInstances --dry-run` under the shipped statement:

```
tokens=optional, no tag                  DENY
tokens=optional, ExemptFromIMDSv2=true   allow
tokens=optional, ExemptFromIMDSv2=True   DENY
tokens=required, no tag                  allow
```

A tag on the instance's IAM **role** exempts nothing. `aws:PrincipalTag`
belonged to `DenyRoleDeliveryLessThan2`, which is no longer generated.

**Tag matching:** the key and the value are matched differently, and the scan
follows both. IAM matches condition key names without regard to case, and the
tag key after the slash is part of the name, so `exemptfromimdsv2` is exempt.
The value is compared with `StringNotEquals`, which is case-sensitive, so
`True` is not exempt and must not be reported exempt. An instance carrying the
key twice in cases that differ raises: AWS documents that as an unexpected
condition failure rather than a match on one of them, so guessing which one
IAM lands on would invent the exemption status of a live workload.

**The proxy is imperfect, and that is accepted.** A tag applied after launch
with `CreateTags`, or an instance whose Terraform never declares the tag,
wears the tag while its relaunch carries none - and the scan then reports an
exemption for a launch enforcement denies. Headroom takes the tag as a
declaration of intent rather than a prediction; keeping it effective across a
recreation is the operator's responsibility.

**Analysis Function:**
```python
# aws/ec2.py
def get_imds_v1_ec2_analysis(session: boto3.Session) -> List[DenyImdsV1Ec2]:
    """
    Scan all regions for EC2 instances.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region, call get_instances(session, region), which reads
       describe_instances at most once per session and region and filters
       out terminated instances
    3. IMDSv1 is allowed when HttpTokens is "optional", whatever HttpEndpoint
       says, because the SCP tests HttpTokens either way
    4. Read the instance's ExemptFromIMDSv2 tag, key matched without regard
       to case and value exactly; raise if the key appears twice in cases
       that differ
    5. Return DenyImdsV1Ec2 for each instance
    """
```

**Categorization Logic:**
```python
def categorize_result(self, result: DenyImdsV1Ec2) -> tuple[str, Dict[str, Any]]:
    result_dict = asdict(result)

    if result.imdsv1_allowed and result.exemption_tag_present:
        return ("exemption", result_dict)
    if result.imdsv1_allowed:
        return ("violation", result_dict)
    return ("compliant", result_dict)
```

**Summary Fields:**
```python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    total = len(violations) + len(exemptions) + len(compliant)
    # An exemption counts as compliant: the SCP spares that launch.
    compliant_count = len(exemptions) + len(compliant)
    compliance_pct = (compliant_count / total * 100) if total > 0 else 100.0

    return {
        "total_instances": total,
        "violations": len(violations),
        "exemptions": len(exemptions),
        "compliant": len(compliant),
        "compliance_percentage": round(compliance_pct, 2)
    }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_ec2_imds_v1",
    "total_instances": 0,
    "violations": 0,
    "exemptions": 0,
    "compliant": 0,
    "compliance_percentage": 100.0
  },
  "violations": [
    {"region": "us-east-1", "instance_id": "i-xxx", "imdsv1_allowed": true, "exemption_tag_present": false}
  ],
  "exemptions": [],
  "compliant_instances": []
}
```

### Deny IAM User Creation

**Purpose:** Discover all IAM users and generate allowlists to prevent creation of unauthorized users.

**Data Model:**
```python
@dataclass
class IamUserAnalysis:
    user_name: str
    user_arn: str
    path: str
```

**Analysis Function:**
```python
# aws/iam/users.py
def get_iam_users_analysis(session: boto3.Session) -> List[IamUserAnalysis]:
    """
    List all IAM users in account.

    Algorithm:
    1. Create IAM client
    2. Use paginator for list_users() (handles pagination)
    3. Extract UserName, Arn, Path for each user
    4. Return IamUserAnalysis for all users

    Note: No filtering - pure enumeration for allowlist generation
    """
```

**Categorization Logic:**
```python
def categorize_result(self, result: IamUserAnalysis) -> tuple[str, Dict[str, Any]]:
    result_dict = {
        "user_name": result.user_name,
        "user_arn": result.user_arn,
        "path": result.path,
    }
    # All users marked as "compliant" (we're listing for allowlist)
    return ("compliant", result_dict)
```

**Summary Fields:**
```python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    return {
        "total_users": len(check_result.compliant),
        "users": [user["user_arn"] for user in check_result.compliant]
    }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_iam_user_creation",
    "total_users": 0,
    "users": [
      "arn:aws:iam::111111111111:user/terraform-user"
    ]
  },
  "violations": [],
  "exemptions": [],
  "compliant_instances": [
    {"user_name": "terraform-user", "user_arn": "arn:aws:iam::111111111111:user/terraform-user", "path": "/"}
  ]
}
```

### Deny RDS Unencrypted

**Purpose:** Identify RDS databases (instances and Aurora clusters) without encryption at rest enabled.

**Data Model:**
```python
@dataclass
class DenyRdsUnencrypted:
    db_identifier: str       # Database identifier (instance or cluster)
    db_type: str             # "instance" or "cluster"
    region: str              # AWS region
    engine: str              # Database engine (mysql, postgres, aurora, etc.)
    encrypted: bool          # True if storage encryption enabled
    db_arn: str              # Full ARN of the database resource
```

**Analysis Function:**
```python
# aws/rds.py
def get_rds_unencrypted_analysis(session: boto3.Session) -> List[DenyRdsUnencrypted]:
    """
    Scan all regions for RDS instances and Aurora clusters.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Analyze RDS instances via describe_db_instances() (paginated)
       b. Analyze Aurora clusters via describe_db_clusters() (paginated)
       c. Check StorageEncrypted field
       d. Create DenyRdsUnencrypted result for each database
    3. Return all results across all regions
    """
```

**Categorization Logic:**
```python
def categorize_result(self, result: DenyRdsUnencrypted) -> tuple[str, Dict[str, Any]]:
    result_dict = {
        "db_identifier": result.db_identifier,
        "db_type": result.db_type,
        "region": result.region,
        "engine": result.engine,
        "encrypted": result.encrypted,
        "db_arn": result.db_arn,
    }

    if not result.encrypted:
        return ("violation", result_dict)
    else:
        return ("compliant", result_dict)
```

**Summary Fields:**
```python
def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
    total = len(check_result.violations) + len(check_result.compliant)
    compliant_count = len(check_result.compliant)
    compliance_pct = (compliant_count / total * 100) if total > 0 else 100.0

    return {
        "total_databases": total,
        "violations": len(check_result.violations),
        "compliant": len(check_result.compliant),
        "compliance_percentage": round(compliance_pct, 2)
    }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_rds_unencrypted",
    "total_databases": 2,
    "violations": 1,
    "compliant": 1,
    "compliance_percentage": 50.0
  },
  "violations": [
    {
      "db_identifier": "unencrypted-db",
      "db_type": "instance",
      "region": "us-east-1",
      "engine": "mysql",
      "encrypted": false,
      "db_arn": "arn:aws:rds:us-east-1:111111111111:db:unencrypted-db"
    }
  ],
  "exemptions": [],
  "compliant_instances": [
    {
      "db_identifier": "encrypted-cluster",
      "db_type": "cluster",
      "region": "us-west-2",
      "engine": "aurora-postgresql",
      "encrypted": true,
      "db_arn": "arn:aws:rds:us-west-2:111111111111:cluster:encrypted-cluster"
    }
  ]
}
```

---

## RCP Checks

### Shared Policy Grammar

Every RCP check reads a policy document, and the parts of IAM's grammar that
vary independently of the service live in `headroom/aws/policy_documents.py`
rather than in each analyzer.

```python
# aws/policy_documents.py
class MalformedPolicyError(Exception): ...
class UnknownSourceConditionError(Exception): ...

@dataclass
class ServicePrincipalSource:
    service_principal: Optional[str]  # e.g. "sns.amazonaws.com", None on a failed read
    source_account_ids: List[str]     # Out-of-org accounts only, sorted
    has_source_condition: bool        # Any source key guards the statement
    has_wildcard_source: bool         # A source no allowlist can enumerate
    read_failure: Optional[str] = None  # Why the read could not be completed

def unreadable_service_principal_source(
    reason: str,
) -> ServicePrincipalSource: ...

def normalize_statements(
    policy: Mapping[str, Any],
    resource_description: str,
) -> List[Any]: ...

def has_not_principal(statement: Mapping[str, Any]) -> bool: ...

def read_service_principal_sources(
    statement: Mapping[str, Any],
    org_account_ids: Set[str],
    org_id: str,
    resource_description: str,
) -> List[ServicePrincipalSource]: ...

def has_actionable_service_principal_source(
    sources: List[ServicePrincipalSource]
) -> bool: ...
```

**Statement shape.** IAM accepts a lone statement object where a one-element
list would do, and each service returns a policy in the shape it was stored.
Iterating that object directly walks its keys as strings, which fails on the
first `statement.get`. A `Statement` that is neither an object nor a list
raises `MalformedPolicyError` naming the resource, because reading it as no
statements would report the policy as granting nothing.

**NotPrincipal.** An `Allow` naming `NotPrincipal` grants to every principal
except the ones it lists, so its reach is everyone outside a short list - the
same reach `Principal: "*"` has. Each analyzer sets `has_wildcard_principal`
for it and moves to the next statement, routing the resource to the blocker
and CloudTrail follow-up a literal wildcard already gets. Reading it any other
way reported the resource clean, left the account eligible for the RCP, and
denied that grant's real audience on apply.

The check runs after the analyzer's own `Effect` gate, and in the STS check
after the AssumeRole action gate as well. `Deny` with `NotPrincipal` is the
form AWS recommends, it restricts rather than grants, and a resource policy's
`Deny` hands access to nobody.

**Service principal sources.** `read_service_principal_sources` is the one
place any analyzer reads a `Condition`, and it reads exactly four keys -
`aws:SourceAccount`, `aws:SourceArn`, `aws:SourceOrgID` and
`aws:SourceOrgPaths` - on statements naming a `Service` principal. Each of the six analyzers calls it inside the
`Effect` gate it already applies - and the IAM analyzer inside its
`_grants_assume_role` gate as well, so a trust statement naming a service under
some action other than `sts:AssumeRole` is never recorded, which matches the
reach of the statement's action list - then stores the result on its analysis
dataclass as `service_principal_sources`. Populating that field costs those six
checks nothing; it happens during the statement walk they already perform. The
seventh check calls the same six analyzer functions again and reads only the
new field. `memoize_per_session` keys their results on the session, so the
second call of each pair costs no API traffic. See Service Confused Deputy
below. One
`Condition` block guards every principal in its statement, so each service the
statement names carries the same guard and gets its own entry.
`has_actionable_service_principal_source` is the predicate each analyzer uses
to decide whether a source alone is reason to keep an analysis it would
otherwise drop; an unguarded source is not, for the reasons in Service
Confused Deputy below. A guard the parser cannot read is, and it comes back as
a `read_failure` entry rather than as a raise: these six analyzers serve six
pre-existing checks that never read a source guard, and raising here would
abort the estate run for all of them over a construct none of them consume.
See that section for the full disposition table and for what the recorded
failure does downstream.

**Not read.** `Resource` and `NotResource` are never consulted. A statement
scoped away from the resource being scanned still contributes its principals,
which widens an allowlist rather than narrowing one. No other `Condition` key
is interpreted anywhere: a wildcard principal narrowed by `aws:PrincipalOrgID`
is still a violation, and a grant narrowed by `s3:prefix` still contributes its
account at full width, both of which cost coverage rather than safety.

### ECR Third-Party Access

**Purpose:** Analyze both ECR resource policy surfaces - repository policies and the per-region registry policy - to identify third-party (non-org) account access and wildcard principals.

**Data Model:**
```python
PolicyScope = Literal["repository", "registry"]

@dataclass
class ECRPolicyAnalysis:
    scope: PolicyScope                        # "repository" or "registry"
    region: str
    third_party_account_ids: Set[str]         # External to organization
    repository_name: Optional[str] = None     # None for a registry policy
    repository_arn: Optional[str] = None      # None for a registry policy
    actions_by_account: Dict[str, List[str]] = field(default_factory=dict)
    has_wildcard_principal: bool = False      # Principal: "*" or NotPrincipal

class PolicyFindings(NamedTuple):
    """What one ECR policy's statements amount to for RCP purposes."""
    third_party_account_ids: Set[str]
    actions_by_account: Dict[str, List[str]]
    has_wildcard_principal: bool
```

**Analysis Function:**
```python
# aws/ecr.py

FAIL_FAST_PRINCIPAL_TYPES = {"Federated"}

def analyze_ecr_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[ECRPolicyAnalysis]:
    """
    Analyze all ECR policies, at both scopes, for third-party access.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Create regional ECR client
       b. Call get_registry_policy for the region's registry policy
       c. Use paginator for describe_repositories
       d. For each repository, call get_repository_policy
       e. Parse JSON policy document
       f. Extract account IDs from Principal field
       g. Track specific ECR actions allowed per account
       h. Detect wildcard principals
       i. Filter to third-party accounts (not in org_account_ids)
    3. Return ECRPolicyAnalysis for policies with third-party or wildcards

    The registry policy is read before the repositories because it is the
    wider surface: it governs every repository the region holds, including
    repositories that carry no policy of their own.

    Multi-Region: Scans all enabled AWS regions
    Pagination: Handles accounts with many ECR repositories

    Raises:
    - UnsupportedPrincipalTypeError: if Federated principal encountered (fail-fast)
    - ClientError: if non-RepositoryPolicyNotFoundException error occurs
    """

def _analyze_registry_policy(
    ecr_client: ECRClient,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> Optional[ECRPolicyAnalysis]:
    """
    Analyze the registry policy for one region.

    AWS allows every ECR action in a registry policy and enforces it on every
    ECR request, so a third party named here reaches the whole registry
    without any repository policy granting it.

    Returns None if the registry carries no policy
    (RegistryPolicyNotFoundException); any other ClientError propagates.
    """

def _analyze_policy_statements(
    policy: JsonDict,
    context: str,
    org_account_ids: Set[str],
    org_id: str
) -> PolicyFindings:
    """
    Read the third-party grants out of one ECR policy document.

    Repository policies and registry policies share a grammar, so they share
    this reader. What differs is reach, which the caller records as scope.
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from principal field.

    Handles:
    - String: "arn:aws:iam::111111111111:..." or "111111111111"
    - List: recursively process each item
    - Dict: process AWS/Service/Federated keys
    - Mixed: {"AWS": [...], "Service": "..."}

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Skip (e.g., ecr.amazonaws.com)
    - Federated: Raise UnsupportedPrincipalTypeError (fail-fast)

    Fail-Fast Validation:
    - Federated principals are unsupported in ECR resource policies
    - Immediately raises exception to prevent unsafe RCP generation
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""

def _normalize_actions(actions: Any) -> List[str]:
    """Normalize actions to list format."""
```

**Custom Exceptions:**
```python
class UnsupportedPrincipalTypeError(Exception):
    """Raised when Federated or other unsupported principal type encountered."""
```

**Check Implementation:**
```python
# checks/rcps/deny_ecr_third_party_access.py

class DenyECRThirdPartyAccessCheck(BaseCheck[ECRPolicyAnalysis]):
    def __init__(self, org_account_ids: Set[str], org_id: str, **kwargs):
        super().__init__(**kwargs)
        self.org_account_ids = org_account_ids
        self.org_id = org_id
        self.all_third_party_accounts: Set[str] = set()
        self.all_actions_by_account: Dict[str, List[str]] = {}

    def analyze(self, session):
        return analyze_ecr_policies(session, self.org_account_ids, self.org_id)

    def categorize_result(self, result):
        # Policies with wildcards are "violations", at either scope
        # Policies with third-party access are "compliant" (expected patterns)
        if result.has_wildcard_principal:
            return ("violation", ...)
        else:
            # Track third-party accounts and actions globally
            self.all_third_party_accounts.update(result.third_party_account_ids)
            for account_id, actions in result.actions_by_account.items():
                if account_id not in self.all_actions_by_account:
                    self.all_actions_by_account[account_id] = []
                self.all_actions_by_account[account_id].extend(actions)
            return ("compliant", ...)

    def build_summary_fields(self, check_result):
        # Aggregate unique third-party account IDs and actions
        # Count policies with wildcards as violations, across both scopes
        actions_by_account_sorted = {
            account_id: sorted(list(set(actions)))
            for account_id, actions in self.all_actions_by_account.items()
        }
        return {
            "total_policies_analyzed": total,
            "policies_third_parties_can_access": len(compliant),
            "policies_with_wildcards": len(violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_account": actions_by_account_sorted,
            "violations": len(violations)
        }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_ecr_third_party_access",
    "total_policies_analyzed": 0,
    "policies_third_parties_can_access": 0,
    "policies_with_wildcards": 0,
    "unique_third_party_accounts": [],
    "third_party_account_count": 0,
    "actions_by_account": {
      "999999999999": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    },
    "violations": 0
  },
  "violations": [
    {
      "scope": "repository",
      "repository_name": "WildcardRepo",
      "repository_arn": "arn:...",
      "region": "us-east-1"
    }
  ],
  "exemptions": [],
  "policies_third_parties_can_access": [
    {
      "scope": "repository",
      "repository_name": "VendorRepo",
      "repository_arn": "arn:...",
      "region": "us-east-1",
      "third_party_account_ids": ["999999999999"],
      "actions_by_account": {
        "999999999999": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
      }
    },
    {
      "scope": "registry",
      "repository_name": null,
      "repository_arn": null,
      "region": "us-east-1",
      "third_party_account_ids": ["888888888888"],
      "actions_by_account": {
        "888888888888": ["ecr:CreateRepository", "ecr:ReplicateImage"]
      }
    }
  ]
}
```

**Registry Policies:**

ECR authorizes access through two policies, not one. A repository policy
governs a single repository. A registry policy governs the registry: AWS
allows every ECR action in one and enforces it on every ECR request in the
region. A third party named in a registry policy therefore reaches
repositories whose own policies grant it nothing.

That makes the registry policy a blind spot with the shape this project keeps
finding: the same invisibility suppresses both the allowlist entry and the
blocker, so the RCP ships looking clean and breaks the access on deployment.

| Registry policy grants | Caller | RCP outcome |
|---|---|---|
| `ecr:ReplicateImage` + `ecr:CreateRepository` (cross-account replication) | ECR replication service-linked role | Exempt - RCPs do not restrict service-linked roles |
| Pull, push, or `ecr:*` to an external account | Ordinary IAM principal | Denied registry-wide |

The analyzer does not distinguish these cases. Deciding a grant is
replication-only means inferring that the caller will be the service-linked
role, which the analyzer never observes; every third-party account found in a
registry policy is allowlisted uniformly. One redundant allowlist entry is
cheaper than one broken integration.

Registry results carry `scope: "registry"` and no repository name or ARN.
Both scopes count toward `violations`, since that is the field that withholds
the RCP from an account - a wildcard registry policy blocks deployment exactly
as a wildcard repository policy does.

### KMS Third-Party Access

**Purpose:** Analyze both surfaces that authorize access to a KMS key - the key policy and the key's grants - to identify third-party (non-org) account access and wildcard principals.

**Data Model:**
```python
@dataclass
class KMSGrantFinding:
    """One grant on a key that reaches outside the organization."""
    grant_id: str
    grantee_account_id: Optional[str]              # None if service principal or in-org
    retiring_principal_account_id: Optional[str]   # None if absent or in-org
    operations: List[str]                          # Prefixed with "kms:"
    has_constraints: bool                          # Encryption context, not parsed

@dataclass
class KMSKeyPolicyAnalysis:
    key_id: str
    key_arn: str
    region: str
    third_party_account_ids: Set[str]         # From both surfaces
    actions_by_account: Dict[str, List[str]] = field(default_factory=dict)
    has_wildcard_principal: bool = False      # Policy only - see Grants below
    grants: List[KMSGrantFinding] = field(default_factory=list)
```

**Analysis Function:**
```python
# aws/kms.py

ALLOWED_PRINCIPAL_TYPES = {"AWS", "Service"}
FAIL_FAST_PRINCIPAL_TYPES = {"Federated"}
AWS_SERVICE_PRINCIPAL_SUFFIX = ".amazonaws.com"
KMS_RETIRE_GRANT_ACTION = "kms:RetireGrant"

def analyze_kms_key_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[KMSKeyPolicyAnalysis]:
    """
    Analyze all KMS keys in an account for third-party access.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all keys via list_keys() (paginated)
       b. Get key policy via get_key_policy(), tolerating a key with none
       c. Parse policy JSON
       d. Extract principals and actions
       e. List the key's grants via list_grants() (paginated)
       f. Resolve each grantee and retiring principal to an account
       g. Identify third-party account IDs (not in org) from both surfaces
       h. Track which actions each third-party account can perform
       i. Detect wildcard principals, which only a policy can carry
    3. Return all results across all regions

    Multi-Region: Scans all enabled AWS regions
    Pagination: list_keys and list_grants are both paginated

    Raises:
    - UnsupportedPrincipalTypeError: if Federated principal encountered (fail-fast)
    - UnknownGranteePrincipalError: if a grant principal cannot be classified
    - ClientError: if AWS API calls fail
    """

def _read_key_policy(
    kms_client: KMSClient,
    key_id: str,
    region: str
) -> Optional[JsonDict]:
    """
    Read a key's policy, or None when the key has no policy.

    A key with no policy is not a key with nothing to find: its grants can
    still reach outside the organization, so the caller keeps going rather
    than treating a missing policy as the end of the analysis.
    """

def _analyze_key_grants(
    kms_client: KMSClient,
    key_id: str,
    region: str,
    org_account_ids: Set[str]
) -> List[KMSGrantFinding]:
    """
    Read a key's grants and return those reaching outside the organization.

    Grants authorize access independently of the key policy and GetKeyPolicy
    does not report them, which makes an unread grant access that breaks on
    apply with nothing in the results to explain why.
    """

def _grant_principal_account_id(principal: str) -> Optional[str]:
    """
    Resolve a grant principal to an account ID.

    Serves both GranteePrincipal and RetiringPrincipal, which take the same
    shapes. Returns None for an AWS service principal, which the RCP exempts.
    Raises UnknownGranteePrincipalError for anything else.
    """

def _external_grant_account(
    principal: Optional[str],
    org_account_ids: Set[str]
) -> Optional[str]:
    """Resolve a grant principal, keeping it only if outside the org."""

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from a key policy principal field.

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Skip (e.g., cloudtrail.amazonaws.com)
    - Federated: Raise UnsupportedPrincipalTypeError (fail-fast)
    - Anything else: Raise UnknownPrincipalTypeError
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""

def _normalize_actions(action: Any) -> List[str]:
    """Normalize actions to list format."""
```

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a key policy."""

class UnsupportedPrincipalTypeError(Exception):
    """Raised when Federated or other unsupported principal type encountered."""

class UnknownGranteePrincipalError(Exception):
    """Raised when a grant names a principal the analyzer cannot classify."""
```

**Check Implementation:**
```python
# checks/rcps/deny_kms_third_party_access.py

class DenyKMSThirdPartyAccessCheck(BaseCheck[KMSKeyPolicyAnalysis]):
    def analyze(self, session):
        return analyze_kms_key_policies(session, self.org_account_ids, self.org_id)

    def categorize_result(self, result):
        # Keys with wildcard principals are "violations"
        # Keys with third-party access are "compliant" (expected patterns)
        # Grants never set has_wildcard_principal, so they never violate
        if result.has_wildcard_principal:
            return ("violation", ...)
        return ("compliant", ...)

    def build_summary_fields(self, check_result):
        all_keys = violations + exemptions + compliant
        return {
            "total_keys_analyzed": len(all_keys),
            "keys_third_parties_can_access": ...,
            "keys_with_wildcards": len(violations),
            "keys_with_third_party_grants": sum(1 for k in all_keys if k["grants"]),
            "violations": len(violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_account": actions_by_account_sorted,
        }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_kms_third_party_access",
    "total_keys_analyzed": 0,
    "keys_third_parties_can_access": 0,
    "keys_with_wildcards": 0,
    "keys_with_third_party_grants": 0,
    "unique_third_party_accounts": [],
    "third_party_account_count": 0,
    "actions_by_account": {
      "999999999999": ["kms:Decrypt", "kms:GenerateDataKey"]
    },
    "violations": 0
  },
  "violations": [],
  "exemptions": [],
  "keys_third_parties_can_access": [
    {
      "key_id": "11111111-1111-1111-1111-111111111111",
      "key_arn": "arn:aws:kms:us-east-1:111111111111:key/11111111-1111-1111-1111-111111111111",
      "region": "us-east-1",
      "third_party_account_ids": ["999999999999"],
      "actions_by_account": {
        "999999999999": ["kms:Decrypt", "kms:GenerateDataKey"]
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
  ]
}
```

**Grants:**

KMS authorizes access through two surfaces, not one. A key policy is a
document `GetKeyPolicy` returns. A grant is a separate object created by
`CreateGrant`, with its own ID, principals, operations, and optional
encryption context constraints. No API returns both, and the console puts
them on different tabs.

That makes grants a blind spot with the shape this project keeps finding: the
same invisibility suppresses both the allowlist entry and the blocker, so the
RCP ships looking clean and breaks the access on deployment. A grant is the
most invisible of the three surfaces found so far, because it is not a policy
document anyone would think to read.

An RCP is a deny filter on requests to the resource. It does not care which
mechanism authorized the call, so a grant's Allow does not survive it.

| Grant principal | Caller | RCP outcome |
|---|---|---|
| IAM ARN in an organization account | Ordinary IAM principal | Not restricted - already in the org |
| `ec2.us-west-2.amazonaws.com` and other AWS service principals | AWS service | Exempt - the RCP carries `aws:PrincipalIsAWSService` `false` |
| Service-linked role ARN | Service-linked role | Exempt - RCPs do not restrict service-linked roles |
| IAM ARN outside the organization | Ordinary IAM principal | Denied |

Only the last row reaches the allowlist. Grant principals are ordinary IAM
ARNs, so unlike an S3 ACL grantee they resolve to an account ID and cost the
account no RCP coverage.

Reading grants can only widen the allowlist, never withhold the RCP.
`CreateGrant` requires a concrete principal, so no grant can be a wildcard,
and `has_wildcard_principal` is the field that sets `blocks_rcp`.

A grant's `RetiringPrincipal` is recorded separately from its
`GranteePrincipal` and contributes only `kms:RetireGrant`, which is the one
thing that principal can do. Attributing the grant's operations to it would
overstate its access.

Grant `Operations` arrive unprefixed from `ListGrants` (`Decrypt`), while a
key policy spells the same permission `kms:Decrypt`. The analyzer prefixes
them so one `actions_by_account` list does not hold two spellings.

Encryption context constraints are recorded as `has_constraints` rather than
parsed. Condition-aware analysis is a separate concern; the boolean keeps the
result honest about what was not read.


### STS Third-Party AssumeRole

**Purpose:** Analyze IAM role trust policies to identify third-party (non-org) account access and wildcard principals.

**Data Model:**
```python
@dataclass
class TrustPolicyAnalysis:
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]    # External to organization
    has_wildcard_principal: bool         # True if Principal: "*" or NotPrincipal
```

**Analysis Function:**
```python
# aws/iam/roles.py

ALLOWED_PRINCIPAL_TYPES = {"AWS", "Service", "Federated"}

def analyze_iam_roles_trust_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[TrustPolicyAnalysis]:
    """
    Analyze all IAM role trust policies for third-party access.

    Algorithm:
    1. List all roles with paginator (list_roles)
    2. For each role, get AssumeRolePolicyDocument
    3. Parse JSON policy document
    4. For each Allow Statement, decide whether it grants sts:AssumeRole
       (see Action Matching below)
    5. Extract account IDs from Principal field
    6. Detect wildcard principals
    7. Filter to third-party accounts (not in org_account_ids)
    8. Return TrustPolicyAnalysis for roles with third-party or wildcards

    Raises:
    - UnknownPrincipalTypeError: if principal type not in ALLOWED_PRINCIPAL_TYPES
    - InvalidFederatedPrincipalError: if Federated principal uses sts:AssumeRole
    - MalformedStatementError: if a statement names both Action and NotAction,
      or neither
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from principal field.

    Handles:
    - String: "arn:aws:iam::111111111111:..." or "111111111111"
    - List: recursively process each item
    - Dict: process AWS/Service/Federated keys
    - Mixed: {"AWS": [...], "Service": "..."}

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Validate but skip (e.g., lambda.amazonaws.com)
    - Federated: Validate action is not sts:AssumeRole, skip
    - Unknown: Raise UnknownPrincipalTypeError

    Validation:
    - Federated principals must use sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity
    - All principal types must be in ALLOWED_PRINCIPAL_TYPES
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""
```

**Action Matching:**

This is the only analyzer that decides anything from a statement's actions;
the S3, SQS, KMS, ECR and Secrets Manager analyzers read every Allow statement
and record actions for reporting only. Because a statement this one fails to
recognize is dropped in silence - no violation, no error, the account merely
absent from the allowlist that keeps it reachable - the match must follow IAM's
own rules rather than compare strings:

- **Case-insensitive.** IAM documents `iam:ListAccessKeys` and
  `IAM:listaccesskeys` as the same action.
- **`*` and `?` expand anywhere in the name**, not just as a whole-action
  wildcard. `sts:*`, `sts:Assume*`, `sts:*Role` and `sts:AssumeRol?` all cover
  `sts:AssumeRole`. Character classes are not IAM syntax and are matched
  literally.
- **`NotAction` inverts the test.** An Allow statement with `NotAction` grants
  every action its patterns do not cover, so it grants `sts:AssumeRole` unless
  one of them matches it.
- **Exactly one of `Action` and `NotAction`.** A statement carrying both, or
  neither, raises `MalformedStatementError`. IAM would not have stored it, and
  either guess misstates who can assume the role.

The `InvalidFederatedPrincipalError` guard deliberately keeps an exact match
instead. A Federated principal paired with `sts:*` is sloppy rather than
wrong - AWS does not let a federated identity call plain `AssumeRole` - and
aborting a run over it would cost more than it catches.

**Principal ARNs:**

Account IDs come from `AWS_ARN_ACCOUNT_ID_PATTERN`, which constrains neither
the partition nor the service segment. A trust policy principal may be an STS
session ARN (`arn:aws:sts::{account}:assumed-role/{role}/{session}` or
`.../federated-user/{name}`) as readily as an IAM one, and GovCloud and China
ARNs carry account IDs that matter just as much. Pinning either segment drops
the account silently.

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when principal type is not in ALLOWED_PRINCIPAL_TYPES."""

class InvalidFederatedPrincipalError(Exception):
    """Raised when Federated principal uses sts:AssumeRole."""
```

**Check Implementation:**
```python
# checks/rcps/deny_sts_third_party_assumerole.py

class ThirdPartyAssumeRoleCheck(BaseCheck[TrustPolicyAnalysis]):
    def __init__(self, org_account_ids: Set[str], org_id: str, **kwargs):
        super().__init__(**kwargs)
        self.org_account_ids = org_account_ids
        self.org_id = org_id

    def analyze(self, session):
        return analyze_iam_roles_trust_policies(session, self.org_account_ids, self.org_id)

    def categorize_result(self, result):
        # Roles with wildcards are "violations"
        # Roles with third-party access are "compliant" (expected patterns)
        if result.has_wildcard_principal:
            return ("violation", ...)
        else:
            return ("compliant", ...)

    def build_summary_fields(self, check_result):
        # Aggregate unique third-party account IDs
        # Count roles with wildcards as violations
        return {
            "total_roles_analyzed": total,
            "roles_third_parties_can_access": len(third_party_roles),
            "roles_with_wildcards": len(violations),
            "unique_third_party_accounts": list(unique_third_parties),
            "violations": len(violations)
        }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_sts_third_party_assumerole",
    "total_roles_analyzed": 0,
    "roles_third_parties_can_access": 0,
    "roles_with_wildcards": 0,
    "unique_third_party_accounts": [],
    "violations": 0
  },
  "violations": [
    {"role_name": "WildcardRole", "role_arn": "arn:..."}
  ],
  "exemptions": [],
  "compliant_instances": [
    {
      "role_name": "CrossAccountRole",
      "role_arn": "arn:...",
      "third_party_account_ids": ["999999999999"]
    }
  ]
}
```

### S3 Third-Party Access

**Purpose:** Analyze the two surfaces that authorize access to an S3 bucket - its policy and its ACL - to identify third-party (non-org) account access, Federated/CanonicalUser principals, and wildcard principals.

**Data Model:**
```python
@dataclass
class S3BucketPolicyAnalysis:
    bucket_name: str
    bucket_arn: str
    third_party_account_ids: Set[str]          # External to organization; policy only
    has_wildcard_principal: bool               # True if Principal: "*", NotPrincipal, or a public ACL group
    has_non_account_principals: bool           # True if Federated, CanonicalUser, or a non-owner ACL grantee
    actions_by_account: Dict[str, Set[str]]    # account_id -> allowed S3 actions; policy only
```

**Analysis Function:**
```python
# aws/s3.py

# S3 supports CanonicalUser in addition to base principal types
ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES | {"CanonicalUser"}

# ACL grantee groups, which name an audience rather than an account
ALL_USERS_GROUP_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_GROUP_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PUBLIC_ACL_GROUP_URIS = frozenset({ALL_USERS_GROUP_URI, AUTHENTICATED_USERS_GROUP_URI})
LOG_DELIVERY_GROUP_URI = "http://acs.amazonaws.com/groups/s3/LogDelivery"


class AclGrantFindings(NamedTuple):
    has_wildcard_grantee: bool                 # ACL grants to a public group
    has_non_account_grantee: bool              # ACL grants to a canonical user or email

def analyze_s3_bucket_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[S3BucketPolicyAnalysis]:
    """
    Analyze all S3 bucket policies and ACLs for third-party access.

    Algorithm:
    1. List all buckets with paginator (list_buckets)
    2. For each bucket, get the bucket ACL (get_bucket_acl) and classify its
       grantees
    3. Get the bucket policy (get_bucket_policy), if the bucket carries one
    4. Parse JSON policy document
    5. For each Allow statement:
       - Check if Principal contains wildcard
       - Check if Principal contains Federated or CanonicalUser types
       - Extract account IDs from Principal field
       - Extract allowed actions
       - Filter to third-party accounts (not in org_account_ids)
       - Track which actions each third-party account can perform
    6. Return S3BucketPolicyAnalysis for buckets with findings

    Raises:
    - UnknownPrincipalTypeError: if principal type not in ALLOWED_PRINCIPAL_TYPES
    - UnsupportedPrincipalTypeError: if Federated/CanonicalUser prevents RCP deployment
    - UnknownGranteeTypeError: if an ACL grantee's type or group is unrecognized
    """

def _analyze_bucket_acl(s3_client: S3Client, bucket_name: str) -> AclGrantFindings:
    """
    Read a bucket's ACL and report what its grants reach.

    The ACL is read before the policy: a bucket that shares only by ACL
    carries no policy at all, so abandoning it for want of one would skip
    the grant most likely to be the only grant on it.
    """

def _read_bucket_policy(s3_client: S3Client, bucket_name: str) -> Optional[JsonDict]:
    """
    Read a bucket's policy, or return None if it carries none.

    A bucket with no policy is not a bucket with nothing to find: its ACL
    can still grant access.
    """

def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from principal field.

    Handles:
    - String: "arn:aws:s3:::bucket" or "111111111111"
    - List: recursively process each item
    - Dict: process AWS/Service/Federated/CanonicalUser keys
    - Mixed: {"AWS": [...], "Federated": "..."}

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Validate but skip (e.g., cloudtrail.amazonaws.com)
    - Federated: Skip (track separately via has_non_account_principals)
    - CanonicalUser: Skip (track separately via has_non_account_principals)
    - Unknown: Raise UnknownPrincipalTypeError
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""

def _has_non_account_principals(principal: Any) -> bool:
    """
    Check if principal contains Federated or CanonicalUser types.

    These principal types cannot be represented as account IDs, so an RCP that
    uses aws:PrincipalAccount for allowlisting would break their access.
    """

def _normalize_actions(action: Any) -> Set[str]:
    """Normalize action field to a set of action strings."""
```

**Bucket ACLs.** A bucket ACL authorizes principals independently of the bucket
policy, and the RCP denies every principal outside the organization however the
bucket authorized them. A surface left unread is therefore a grant that breaks
on apply with nothing in the scan to warn of it: the bucket reports clean, the
account records no violation, and the RCP deploys over access no allowlist
covers.

ACL grantees carry canonical user IDs rather than account IDs, and no API
resolves one to the other, so an external grantee cannot be expressed in
`aws:PrincipalAccount`. It sets `has_non_account_principals` and keeps the
account out of the RCP, which is the answer the check already gives a
`CanonicalUser` principal named in a bucket policy. ACL findings reach those
two booleans and nothing else: a canonical user ID cannot populate
`third_party_account_ids`, and ACL permissions are not IAM actions, so
`actions_by_account` stays a record of the policy alone.

| Grantee | Verdict |
|---------|---------|
| `CanonicalUser` equal to the bucket owner | Ignored - every bucket carries this grant |
| `CanonicalUser` other than the owner | `has_non_account_principals` |
| `AmazonCustomerByEmail` | `has_non_account_principals` |
| `Group` `AllUsers` or `AuthenticatedUsers` | `has_wildcard_principal` |
| `Group` `LogDelivery` | Ignored - see below |
| Any other type or group | `UnknownGranteeTypeError` |

Granting the log delivery group by ACL and granting `logging.s3.amazonaws.com`
by bucket policy authorize the same principal; AWS documents the ACL form as
granting permissions "to the logging service principal by using a bucket ACL".
The RCP spares AWS services through `aws:PrincipalIsAWSService`, so the grant
reaches nobody the RCP would deny.

A bucket whose Object Ownership is `BucketOwnerEnforced` has ACLs disabled.
Reads still succeed and return the owner's grant alone, so that case needs no
separate ownership lookup and costs no extra call.

**Object ACLs are not read.** Under `ObjectWriter` ownership an object uploaded
by an external account is owned by that account and can carry its own ACL, as
can log objects delivered under `TargetGrants`. Enumerating those costs one
call per object and is out of scope, so an object ACL granting a third party is
not visible to this check.

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when principal type is not in ALLOWED_PRINCIPAL_TYPES."""

class UnknownGranteeTypeError(Exception):
    """Raised when an unknown grantee type or group is encountered in a bucket ACL."""

class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a bucket policy contains principal types that can't be handled by RCP.

    Federated and CanonicalUser principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """
```

**Check Implementation:**
```python
# checks/rcps/deny_s3_third_party_access.py

class DenyS3ThirdPartyAccessCheck(BaseCheck[S3BucketPolicyAnalysis]):
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_s3_third_party_access",
    "total_buckets_analyzed": 0,
    "buckets_with_third_party_access": 0,
    "buckets_with_wildcards": 0,
    "buckets_with_non_account_principals": 0,
    "unique_third_party_accounts": [],
    "actions_by_third_party_account": {
      "999999999999": ["s3:GetObject", "s3:PutObject"]
    },
    "buckets_by_third_party_account": {
      "999999999999": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::another-bucket"]
    },
    "violations": 0
  },
  "violations": [
    {
      "bucket_name": "wildcard-bucket",
      "bucket_arn": "arn:aws:s3:::wildcard-bucket",
      "has_wildcard_principal": true,
      "has_non_account_principals": false
    },
    {
      "bucket_name": "federated-bucket",
      "bucket_arn": "arn:aws:s3:::federated-bucket",
      "has_wildcard_principal": false,
      "has_non_account_principals": true
    }
  ],
  "exemptions": [],
  "compliant_instances": [
    {
      "bucket_name": "third-party-bucket",
      "bucket_arn": "arn:aws:s3:::third-party-bucket",
      "third_party_account_ids": ["999999999999"],
      "has_wildcard_principal": false,
      "has_non_account_principals": false,
      "actions_by_account": {
        "999999999999": ["s3:GetObject", "s3:PutObject"]
      }
    }
  ]
}
```

**Principal Type Matrix:**

| Principal Type | Example | Account ID Extraction | RCP Compatible | Categorization |
|----------------|---------|----------------------|----------------|----------------|
| AWS Account | `arn:aws:iam::111111111111:root` | ✅ Extract 111111111111 | ✅ COMPLIANT | Can be allowlisted |
| Wildcard | `"*"` | ❌ None | ❌ VIOLATION | Can't deploy RCP safely |
| Federated (SAML/OIDC) | `arn:aws:iam::111111111111:saml-provider/MyProvider` | ⚠️ Extract 111111111111 but not the accessing principal | ❌ VIOLATION | Would break SSO access |
| CanonicalUser | `79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be` | ❌ None | ❌ VIOLATION | Would break access |
| Service | `cloudtrail.amazonaws.com` | ❌ None (skip) | ✅ EXEMPT | RCP has `aws:PrincipalIsAWSService` check |

**Safety Rationale:**

The RCP uses `aws:PrincipalAccount` condition for allowlisting. This only works for AWS account principals:
- ✅ **AWS Account principals:** Have account IDs → can be allowlisted
- ❌ **Federated principals:** The account ID in the SAML/OIDC provider ARN is NOT the accessing principal (it's the account hosting the provider)
- ❌ **CanonicalUser principals:** S3-specific IDs with no account ID → cannot be allowlisted
- ✅ **Service principals:** Exempt via `aws:PrincipalIsAWSService = "false"` condition

**Deployment Safety:**
- Accounts with wildcard principals → excluded from the S3 RCP
- Buckets with Federated/CanonicalUser principals → marked as violations
- Only buckets with account-based third-party access → used for allowlist generation

### Secrets Manager Third-Party Access

**Purpose:** Analyze Secrets Manager resource policies to identify third-party (non-org) account access and wildcard principals.

**Data Model:**
```python
@dataclass
class SecretsPolicyAnalysis:
    """Analysis of a Secrets Manager secret's resource policy."""
    secret_name: str
    secret_arn: str
    third_party_account_ids: Set[str]         # Accounts outside the organization
    has_wildcard_principal: bool              # Principal "*", or an Allow with NotPrincipal
    has_non_account_principals: bool          # Federated or CanonicalUser - see Fail-Fast below
    actions_by_account: Dict[str, Set[str]]
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)
```

The analysis records no region. The scan is regional, but a secret ARN
carries its own region, so `ServicePrincipalSourceFinding` stamps
`region=None` for a secret and the ARN is the only regional identifier a
consumer needs.

**Analysis Function:**
```python
# aws/secretsmanager.py

ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES

def analyze_secrets_manager_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[SecretsPolicyAnalysis]:
    """
    Analyze all Secrets Manager resource policies for third-party access.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all secrets via the list_secrets paginator
       b. Read each secret's policy via get_resource_policy()
       c. Skip a secret carrying no policy
       d. Parse the policy JSON
       e. For each Allow statement, record its service principal sources,
          then extract its AWS principals
       f. Identify third-party accounts (not in org_account_ids)
       g. Track which actions each third-party account can perform
    3. Return the secrets worth reporting

    Multi-Region: Scans all enabled AWS regions
    Pagination: list_secrets is paginated

    Raises:
    - UnsupportedPrincipalTypeError: Federated or CanonicalUser principal (fail-fast)
    - UnknownPrincipalTypeError: a principal type the analyzer cannot classify
    - MalformedPolicyError: Statement is neither an object nor a list
    - ClientError: any API failure other than a secret having no policy
    """

def _analyze_secrets_in_region(
    session: boto3.Session,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> List[SecretsPolicyAnalysis]:
    """
    Analyze the secrets in one region.

    GetResourcePolicy answers ResourceNotFoundException both for a secret
    that carries no policy and for a secret deleted mid-scan. Neither can
    grant anyone access, so both are skipped. Every other ClientError is
    raised: a region that could not be read is not a region with nothing in
    it, and these results populate an allowlist.
    """

def _analyze_secret_policy(
    secret_name: str,
    secret_arn: str,
    policy: JsonDict,
    org_account_ids: Set[str],
    org_id: str
) -> Optional[SecretsPolicyAnalysis]:
    """
    Analyze a single secret's resource policy.

    Returns None unless the secret carries a third-party account, a wildcard
    principal, a non-account principal, or an actionable service principal
    source. The third of those is unreachable here - see Fail-Fast below.
    The fourth is kept for deny_service_confused_deputy, the only check that
    reads it; deny_secrets_manager_third_party_access filters it back out.
    """

def _extract_account_ids_from_principal(
    principal: Union[str, List[str], Dict[str, Union[str, List[str]]]]
) -> Set[str]:
    """
    Extract AWS account IDs from a resource policy principal field.

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Skip (e.g., lambda.amazonaws.com)
    - Federated, CanonicalUser: Raise UnsupportedPrincipalTypeError (fail-fast)
    - Anything else: Raise UnknownPrincipalTypeError
    """

def _has_wildcard_principal(principal: Any) -> bool:
    """Check if principal contains "*" (wildcard)."""

def _has_non_account_principals(principal: Any) -> bool:
    """Check if principal names a Federated or CanonicalUser identity."""

def _normalize_actions(action: Union[str, List[str]]) -> Set[str]:
    """Normalize actions to set format."""
```

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a resource policy."""

class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a resource policy contains principal types that can't be handled by RCP.

    Federated and CanonicalUser principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """
```

**Check Implementation:**
```python
# checks/rcps/deny_secrets_manager_third_party_access.py

class DenySecretsManagerThirdPartyAccessCheck(BaseCheck[SecretsPolicyAnalysis]):
    # This check spells its parameters out rather than taking **kwargs.
    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        org_account_ids: Set[str],
        org_id: str,
        exclude_account_ids: bool = False,
    ) -> None:
        super().__init__(...)
        self.org_account_ids = org_account_ids
        self.org_id = org_id
        self.all_third_party_accounts: Set[str] = set()
        self.actions_by_account: Dict[str, Set[str]] = {}
        self.secrets_by_account: Dict[str, Set[str]] = {}

    def analyze(self, session):
        # Drops the secrets kept only for a service principal source
        all_results = analyze_secrets_manager_policies(
            session, self.org_account_ids, self.org_id
        )
        return [
            r for r in all_results
            if r.has_wildcard_principal or r.has_non_account_principals or r.third_party_account_ids
        ]

    def categorize_result(self, result):
        # Secrets with wildcard or non-account principals are "violations"
        # Secrets with named third-party access are "compliant"
        if result.has_wildcard_principal or result.has_non_account_principals:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result):
        # NOTE: a violation counts toward secrets_third_parties_can_access only
        # if it also names a third-party account. Every sibling check counts
        # every violation. See Counting below.
        wildcards_with_third_party = sum(
            1 for s in check_result.violations if s.get("third_party_account_ids")
        )
        return {
            "total_secrets_analyzed": len(violations) + len(exemptions) + len(compliant),
            "secrets_third_parties_can_access": wildcards_with_third_party + len(compliant),
            "secrets_with_wildcards": len(check_result.violations),
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_third_party_account": actions_by_account_sorted,
            "secrets_by_third_party_account": secrets_by_account_sorted,
        }

    def _build_results_data(self, check_result):
        # Overrides the base field names
        return {
            "summary": check_result.summary,
            "secrets_third_parties_can_access": check_result.violations + check_result.compliant,
            "secrets_with_wildcards": check_result.violations,
        }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_secrets_manager_third_party_access",
    "total_secrets_analyzed": 0,
    "secrets_third_parties_can_access": 0,
    "secrets_with_wildcards": 0,
    "unique_third_party_accounts": [],
    "third_party_account_count": 0,
    "actions_by_third_party_account": {
      "999999999999": ["secretsmanager:GetSecretValue"]
    },
    "secrets_by_third_party_account": {
      "999999999999": ["arn:aws:secretsmanager:us-east-1:111111111111:secret:shared-secret-AbCdEf"]
    },
    "violations": 0
  },
  "secrets_third_parties_can_access": [
    {
      "secret_name": "shared-secret",
      "secret_arn": "arn:aws:secretsmanager:us-east-1:111111111111:secret:shared-secret-AbCdEf",
      "third_party_account_ids": ["999999999999"],
      "has_wildcard_principal": false,
      "has_non_account_principals": false,
      "actions_by_account": {
        "999999999999": ["secretsmanager:GetSecretValue"]
      }
    }
  ],
  "secrets_with_wildcards": []
}
```

**Fail-Fast:**

`has_non_account_principals` is set and then immediately raised on, so no
analysis this module returns can carry it as `True`. The field and the check
branches that read it are reachable only by constructing the dataclass
directly, which the tests do. S3 is the analyzer where the flag is live: its
ALLOWED_PRINCIPAL_TYPES admits CanonicalUser, so it records the principal and
keeps going, and the flag reaches the check and files the violation. Preserve
the field rather than deriving its absence - the categorization contract is
shared across all
seven, and a Federated principal is a violation wherever it is found.

**Counting:**

`secrets_third_parties_can_access` counts a violation only when that
violation also names a third-party account. Every sibling check counts every
violation, on the reasoning that a wildcard principal means every third party
can reach the resource. Recorded as observed, not endorsed: this
under-reports relative to its siblings, and the metric is descriptive - it
gates nothing. `violations` is what withholds the RCP from the account.

**Allowlist Variable Name:**

The generated Terraform names this check's allowlist
`secrets_manager_third_party_account_ids_allowlist`, with no `_access_`
segment, while its enable flag `deny_secrets_manager_third_party_access`
keeps it. See RCP Terraform Generation - deriving the allowlist name from
the pattern the other checks follow produces a variable `terraform plan`
rejects.


### SQS Third-Party Access

**Purpose:** Analyze SQS queue resource policies to identify third-party (non-org) account access and wildcard principals.

**Data Model:**
```python
@dataclass
class SQSQueuePolicyAnalysis:
    """Analysis of an SQS queue's resource policy."""
    queue_url: str
    queue_arn: str
    region: str
    third_party_account_ids: Set[str]         # Accounts outside the organization
    has_wildcard_principal: bool              # Principal "*", or an Allow with NotPrincipal
    has_non_account_principals: bool          # Federated - see Fail-Fast below
    actions_by_account: Dict[str, Set[str]]
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)
```

`service_principal_sources` carries one further payload here that it carries
nowhere else: a single entry recording that the queue's policy could not be
read at all. See Recording an Unreadable Queue below.

**Analysis Function:**
```python
# aws/sqs.py

ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES

# Error codes meaning a queue no longer exists. A queue deleted between
# list_queues and get_queue_attributes is the only benign reason that read
# fails: the queue is gone, so it holds no policy and can grant nobody
# access. Every other failure is a read Headroom could not complete and must
# not report as an absence of findings.
QUEUE_GONE_ERROR_CODES = frozenset({
    "AWS.SimpleQueueService.NonExistentQueue",
    "QueueDoesNotExist",
})

def analyze_sqs_queue_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze SQS queue policies across all regions.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all queues via the list_queues paginator
       b. Get each queue's Policy and QueueArn attributes
       c. Skip a queue carrying no policy
       d. Parse the policy JSON
       e. For each Allow statement, record its service principal sources,
          then extract its AWS principals
       f. Identify wildcard principals
       g. Identify Federated principals (fail-fast)
       h. Map actions to account IDs
       i. Subtract org_account_ids to leave the third parties
    3. Return every queue that carried a policy

    Multi-Region: Scans all enabled AWS regions
    Pagination: list_queues is paginated

    Raises:
    - UnsupportedPrincipalTypeError: Federated principal found (fail-fast)
    - ClientError: if any region's queues cannot be read
    """

def _analyze_queues_in_region(
    session: boto3.Session,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze the queues in one region.

    A read that fails aborts the run rather than returning an empty list.
    Returning nothing would be indistinguishable from a region that genuinely
    holds no queues with third-party access, and these results populate
    sqs_third_party_access_account_ids_allowlist, so the generated RCP would
    omit every partner whose queues live only in the unreadable region and
    deny them on deploy.

    The two exceptions are a queue deleted mid-scan, which is skipped, and a
    queue whose policy cannot be parsed, which is recorded via
    _unreadable_queue rather than discarded.

    This assumes the Headroom role is exempt from region-allowlist SCPs, which
    makes an AccessDenied here a genuine permissions gap rather than an
    expected regional block. See documentation/SETUP.md.
    """

def _analyze_queue_policy(
    queue_url: str,
    queue_arn: str,
    region: str,
    policy_json: str,
    org_account_ids: Set[str],
    org_id: str
) -> SQSQueuePolicyAnalysis:
    """
    Analyze a single queue's resource policy.

    Returns an analysis for every queue, with no retention filter. The five
    other analyzers drop an analysis that found nothing worth reporting;
    this one does not, so deny_service_confused_deputy sees every queue's
    sources and deny_sqs_third_party_access does the filtering in its own
    analyze(). Adding a has_actionable_service_principal_source gate here
    would change nothing and would suggest a filter that is not there.
    """

def _unreadable_queue(
    queue_url: str,
    queue_arn: str,
    region: str,
    error: Exception,
) -> SQSQueuePolicyAnalysis:
    """
    Record a queue whose policy could not be read.

    Every field deny_sqs_third_party_access reads is left empty, so that
    check's filter drops the queue exactly as the earlier warn-and-skip did.
    The one populated field is service_principal_sources, holding a single
    unreadable_service_principal_source entry, which only
    deny_service_confused_deputy reads and which it files as a violation.
    """

def _extract_account_ids_from_principal(principal: PrincipalType) -> Set[str]:
    """
    Extract AWS account IDs from a queue policy principal field.

    Principal Type Handling:
    - AWS: Extract account IDs from ARNs or plain IDs
    - Service: Skip (e.g., sns.amazonaws.com)
    - Federated: Raise UnsupportedPrincipalTypeError (fail-fast)
    - Anything else: Raise UnknownPrincipalTypeError
    """

def _check_for_wildcard_principal(principal: PrincipalType) -> bool:
    """Check if principal contains "*" (wildcard)."""

def _check_for_non_account_principals(principal: PrincipalType) -> bool:
    """Check if principal names a Federated identity."""

def _normalize_actions(actions: ActionsType) -> Set[str]:
    """Normalize actions to set format."""
```

**Custom Exceptions:**
```python
class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a queue policy."""

class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a queue policy contains principal types that can't be handled by RCP.

    Federated principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """
```

**Check Implementation:**
```python
# checks/rcps/deny_sqs_third_party_access.py

class DenySQSThirdPartyAccessCheck(BaseCheck[SQSQueuePolicyAnalysis]):
    def __init__(self, org_account_ids: Set[str], org_id: str, **kwargs):
        super().__init__(**kwargs)
        self.org_account_ids = org_account_ids
        self.org_id = org_id
        self.all_third_party_accounts: Set[str] = set()
        self.actions_by_account: Dict[str, Set[str]] = {}
        self.queues_by_account: Dict[str, Set[str]] = {}

    def analyze(self, session):
        # This is where every queue with nothing to report is dropped,
        # including the unreadable ones
        all_results = analyze_sqs_queue_policies(
            session, self.org_account_ids, self.org_id
        )
        return [
            r for r in all_results
            if r.has_wildcard_principal or r.has_non_account_principals or r.third_party_account_ids
        ]

    def categorize_result(self, result):
        # Queues with wildcard or non-account principals are "violations"
        # Queues with named third-party access are "compliant"
        if result.has_wildcard_principal or result.has_non_account_principals:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result):
        return {
            "total_queues_analyzed": len(violations) + len(exemptions) + len(compliant),
            "queues_third_parties_can_access": len(violations) + len(compliant),
            "queues_with_wildcards": len(check_result.violations),
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_third_party_account": actions_by_account_sorted,
            "queues_by_third_party_account": queues_by_account_sorted,
        }

    def _build_results_data(self, check_result):
        # Overrides the base field names
        return {
            "summary": check_result.summary,
            "queues_third_parties_can_access": check_result.violations + check_result.compliant,
            "queues_with_wildcards": check_result.violations,
        }
```

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_sqs_third_party_access",
    "total_queues_analyzed": 0,
    "queues_third_parties_can_access": 0,
    "queues_with_wildcards": 0,
    "unique_third_party_accounts": [],
    "third_party_account_count": 0,
    "actions_by_third_party_account": {
      "999999999999": ["sqs:ReceiveMessage", "sqs:SendMessage"]
    },
    "queues_by_third_party_account": {
      "999999999999": ["arn:aws:sqs:us-east-1:111111111111:partner-events"]
    },
    "violations": 0
  },
  "queues_third_parties_can_access": [
    {
      "queue_url": "https://sqs.us-east-1.amazonaws.com/111111111111/partner-events",
      "queue_arn": "arn:aws:sqs:us-east-1:111111111111:partner-events",
      "region": "us-east-1",
      "third_party_account_ids": ["999999999999"],
      "has_wildcard_principal": false,
      "has_non_account_principals": false,
      "actions_by_account": {
        "999999999999": ["sqs:ReceiveMessage", "sqs:SendMessage"]
      }
    }
  ],
  "queues_with_wildcards": []
}
```

**Recording an Unreadable Queue:**

SQS is the only analyzer that records a resource it could not read instead of
logging and moving on. The reason is the shape this project keeps finding: a
resource that vanishes on a `logger.warning` suppresses the allowlist entry
and the blocker together, so the RCP ships looking clean and breaks the
integration on deployment.

The statement walk reads service principal sources before it reaches the
principal types that raise, so a queue can fail partway through with a guard
already read. Recording the queue does not preserve that guard - it dies with
the raise. What it preserves is the knowledge that the read was incomplete,
which is what matters: `deny_service_confused_deputy` turns the entry into a
violation, and the DenyServiceConfusedDeputy statement is withheld from the
account rather than deployed against an allowlist that could not be computed.

`UnsupportedPrincipalTypeError` is re-raised rather than recorded. A Federated
principal is not an unreadable policy - it is a policy read successfully whose
contents make the RCP undeployable, which is a finding the account's operator
must act on.

**Fail-Fast:**

`has_non_account_principals` is set and then immediately raised on, so no
analysis this module returns can carry it as `True`. The field and the check
branches that read it are reachable only by constructing the dataclass
directly, which the tests do. S3 is the analyzer where the flag is live: its
ALLOWED_PRINCIPAL_TYPES admits CanonicalUser, so it records the principal and
keeps going, and the flag reaches the check and files the violation. Preserve
the field rather than deriving its absence - the categorization contract is
shared across all seven.


### Service Confused Deputy

**Purpose:** Narrow the AWS service exemption every other RCP statement must
carry. Identify the out-of-organization accounts that legitimately drive
service-mediated calls into organization resources, so the
`DenyServiceConfusedDeputy` statement can permit them, and the source guards
that no allowlist can express, so the statement can be withheld from the
accounts holding them.

The six statements above each end with
`BoolIfExists { "aws:PrincipalIsAWSService" = "false" }`, so their Deny never
matches a call an AWS service makes. That exemption is mandatory rather than a
convenience: on a service-principal request `aws:PrincipalOrgID` and
`aws:PrincipalAccount` are absent, `StringNotEqualsIfExists` on an absent key
evaluates true, and without the Bool clause the Deny would match every
CloudTrail delivery, access-log write and SSE-KMS call in the organization.
Nothing narrowed the exemption back down, so a principal outside the
organization who configures an AWS service in their own account - a trail, a
Config delivery channel, an SNS topic - could have that service reach a bucket,
key, queue, secret, repository or role in an organization account. Severity is
bounded by the resource policy: the RCP failing to deny is not the same as
access being granted, so this closes a defense-in-depth gap rather than an open
door.

**Data Model:**
```python
# aws/policy_documents.py defines ServicePrincipalSource, which all six
# analyzers record; see Shared Policy Grammar above for its fields.

# checks/rcps/deny_service_confused_deputy.py - one source, plus its resource

@dataclass
class ServicePrincipalSourceFinding:
    resource_type: str                # ecr | kms | s3 | secretsmanager | sqs | iam
    resource_identifier: str          # Name or ARN, whichever the analyzer records
    region: Optional[str]             # None where the analysis records no region - see Region below
    service_principal: str
    source_account_ids: List[str]
    has_source_condition: bool
    has_wildcard_source: bool
```

Each of the six analysis dataclasses - `ECRPolicyAnalysis`,
`KMSKeyPolicyAnalysis`, `S3BucketPolicyAnalysis`, `SecretsPolicyAnalysis`,
`SQSQueuePolicyAnalysis` and `TrustPolicyAnalysis` - gains
`service_principal_sources: List[ServicePrincipalSource]`, populated inside the
statement walk it already performs.

**Analysis Function:**

There is no seventh `aws/` module. The check calls the same six analyzer
functions the other RCP checks call and reads only the new field. Each supplies
the identity of the resource its sources were found on:

| Analyzer | `resource_type` | `resource_identifier` | `region` |
|---|---|---|---|
| `analyze_ecr_policies` | `ecr` | Repository name, or `registry` for a per-region registry policy | Region |
| `analyze_kms_key_policies` | `kms` | Key ID | Region |
| `analyze_s3_bucket_policies` | `s3` | Bucket name | `None` |
| `analyze_secrets_manager_policies` | `secretsmanager` | Secret name | `None` |
| `analyze_sqs_queue_policies` | `sqs` | Queue ARN | Region |
| `analyze_iam_roles_trust_policies` | `iam` | Role name | `None` |

Trust policies matter as much as resource policies here. A role trusting a
service principal with no source guard is the canonical confused-deputy
vulnerability, and `sts:AssumeRole` is in the statement's action list.

**API cost.** Recording `service_principal_sources` costs the existing six
checks nothing, and registering this check does not double the RCP pass.
`memoize_per_session` in `headroom/aws/helpers.py` caches exactly the six
analyses the pair shares, keyed on the session, so whichever of a pair runs
second is served from memory: `ListRepositories` / `GetRepositoryPolicy` /
`GetRegistryPolicy`, `ListKeys` / `GetKeyPolicy` / `ListGrants`, `ListBuckets`
/ `GetBucketPolicy`, `ListSecrets` / `GetResourcePolicy`, `ListQueues` /
`GetQueueAttributes`, and `ListRoles` each run once per account per run.

Registry order decides which check of a pair pays. This one runs fourteenth of
sixteen, so ECR, KMS, S3 and Secrets Manager are already cached when it asks,
while it reads SQS and IAM role trust policies first and
`deny_sqs_third_party_access` and `deny_sts_third_party_assumerole` are then
served from memory. Measured across the whole registry, one account issues 35
API operations with no `(service, region, operation)` triple repeated;
`TestNoCheckRepeatsAnother` in `tests/performance/test_call_counts.py` pins
that. The `deny_service_confused_deputy` Terraform flag gates the rendered
statement, not the scan.

`headroom/aws/` holds three per-session memos, not one: the enabled-region
list and these six analyses in `helpers.py`, and the EC2 instance list in
`ec2.py`. The per-region AMI cache is a fourth, local to one sweep.

**Region.** S3 buckets and IAM roles are global names, so there is no region to
record. A Secrets Manager secret is regional:
`analyze_secrets_manager_policies` iterates `get_all_regions` and analyzes each
region separately, and every `SecretsPolicyAnalysis` carries a `secret_arn`
that encodes the region. The finding's `region` is `None` there because
`SecretsPolicyAnalysis` has no `region` field for the check to read - a gap in
that dataclass rather than a property of the resource. Because the finding's
`resource_identifier` is `secret_name` rather than the ARN, two secrets sharing
a name in different regions produce identical findings and an operator cannot
tell which region to look in. Adding a `region` field to
`SecretsPolicyAnalysis` would close both.

```python
# checks/rcps/deny_service_confused_deputy.py

def _findings_for_resource(
    sources: List[ServicePrincipalSource],
    resource_type: str,
    resource_identifier: str,
    region: Optional[str],
) -> List[ServicePrincipalSourceFinding]:
    """One finding per source, stamped with the resource's identity. No
    filtering here - the filter lives in analyze."""

def analyze(self, session: Session) -> List[ServicePrincipalSourceFinding]:
    """
    Collect service principal sources from every resource type.

    Algorithm:
    1. Call each of the six analyzer functions in turn
    2. Pass each analysis's service_principal_sources through
       _findings_for_resource with that resource's type, identifier and region
    3. Return only the findings with an out-of-organization source account,
       a wildcard source, or a recorded read failure. An unguarded source is
       dropped - see Source Guards
    """
```

**Custom Exceptions:**
```python
class UnknownSourceConditionError(Exception):
    """
    Raised when a source guard on a Service principal cannot be read.

    Internal to policy_documents. read_service_principal_sources catches it
    and returns the message as ServicePrincipalSource.read_failure, so the
    six analyzers that share this parser never propagate it.
    """
```

**Check Implementation:**
```python
# checks/rcps/deny_service_confused_deputy.py

@register_check("rcps", DENY_SERVICE_CONFUSED_DEPUTY)
class DenyServiceConfusedDeputyCheck(BaseCheck[ServicePrincipalSourceFinding]):
    def analyze(self, session):
        # Six analyzers, flattened; unguarded and in-org-only sources dropped
        return [
            f for f in findings
            if f.source_account_ids or f.has_wildcard_source or f.read_failure
        ]

    def categorize_result(self, result):
        # A source no allowlist can express is a "violation" - it withholds
        # the statement from this account, exactly as a wildcard principal does
        # A guard that could not be read is a violation for the same reason:
        # the allowlist cannot be computed, so the statement must be withheld
        # A resolved out-of-org source is "compliant" - it is an allowlist entry
        self.all_third_party_accounts.update(result.source_account_ids)
        if result.has_wildcard_source or result.read_failure is not None:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result):
        return {
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
        }
```

There is deliberately no unguarded-source count in the summary; see Source
Guards below.

**Result JSON Schema:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "deny_service_confused_deputy",
    "violations": 1,
    "unique_third_party_accounts": ["999999999999"],
    "third_party_account_count": 1
  },
  "violations": [
    {
      "resource_type": "s3",
      "resource_identifier": "org-log-archive",
      "region": null,
      "service_principal": "logging.s3.amazonaws.com",
      "source_account_ids": [],
      "has_source_condition": true,
      "has_wildcard_source": true,
      "read_failure": null
    }
  ],
  "exemptions": [],
  "compliant_instances": [
    {
      "resource_type": "sqs",
      "resource_identifier": "arn:aws:sqs:us-west-2:111111111111:vendor-events",
      "region": "us-west-2",
      "service_principal": "sns.amazonaws.com",
      "source_account_ids": ["999999999999"],
      "has_source_condition": true,
      "has_wildcard_source": false,
      "read_failure": null
    }
  ]
}
```

A finding whose source read failed carries the reason in `read_failure`, a
null `service_principal`, and is written to `violations`.

`unique_third_party_accounts` becomes the statement's `aws:SourceAccount`
allowlist, and `violations` withholds the statement from the account, exactly
as they do for the other six checks. The placement logic and the Terraform
renderer treat this check like any other RCP check; nothing in either branches
on its name.

**Source Guards:**

One `Condition` block guards every principal in its statement, so each service
a statement names carries the same guard and produces its own entry. What that
guard resolves to decides everything:

| Statement | `source_account_ids` | `has_source_condition` | `has_wildcard_source` | Effect on output |
|---|---|---|---|---|
| `Service` principal, no source key | `[]` | `False` | `False` | Dropped - neither listed nor counted |
| Source names an in-organization account | `[]` | `True` | `False` | Dropped - neither listed nor counted |
| Source names an out-of-organization account | `["999999999999"]` | `True` | `False` | Allowlist entry, recorded as compliant |
| Source is `"*"`, or an ARN yielding no account, with no companion `aws:SourceAccount` | `[]` | `True` | `True` | Violation - withholds the statement |
| Source is scoped to this organization by `aws:SourceOrgID` or `aws:SourceOrgPaths` | `[]` | `True` | `False` | Dropped - the deployed statement already exempts it |
| Source is scoped to another organization, by either key | `[]` | `True` | `True` | Violation - withholds the statement |
| A source key under an operator that does not pin it | - | - | - | `read_failure` set - violation, withholds the statement |

**The `Null` gate.** The statement carries
`Null { "aws:SourceAccount" = "false" }`, which reads as "this key is not
null", that is, it is present. The Deny therefore applies only to service
calls that carry a source account. A call populating only `aws:SourceArn`, or
no source keys at all, falls outside the statement entirely. This narrows the
service exemption rather than closing it, and it is the clause that makes the
control deployable: without it, shipping the statement would require first
discovering every service integration in the estate. `StringNotEqualsIfExists`
on `aws:SourceOrgID` then catches sources in standalone accounts, which belong
to no organization and so carry no organization ID - an attacker cannot escape
the control by using an unattached account.

**Rows one and two: neither listed nor counted.** An unguarded service
principal, and one guarded to an account already inside the organization,
produce no output at all - no finding, no violation, and no number in the
summary. For row two that is exact: the source is in the organization, so
`aws:SourceOrgID` already exempts it and no allowlist entry is needed.

For row one it is a volume decision. Every log bucket and every service role
carries a service trust with no source guard, so listing them would put every
ordinary service integration in the account into the results and bury the
sources that matter.

Dropping them is not the same as their being safe. `aws:SourceAccount` is
populated by the calling AWS service, from the resource that drove the call;
the `Null` gate tests the request context, not the policy document. An
unguarded policy does not produce an unguarded request - it produces a request
that carries `aws:SourceAccount` and simply is not checked against it. So a
bucket allowing `cloudtrail.amazonaws.com` with no source condition, written
for a partner in out-of-organization account `999999999999`, matches every
clause of the statement once it deploys and the delivery is denied. Discovery
recorded nothing, because the policy names no account for it to record.

Closing that path is precisely what `DenyServiceConfusedDeputy` is for. What
discovery cannot do is enumerate the legitimate drivers of those trusts in
advance - only CloudTrail can, which is what makes the rollout steps below the
safeguard rather than the summary count. This is the check's principal
deployment risk.

An estate-wide count of them was a goal of an earlier draft and was dropped
during implementation. Five of the six analyzers drop an analysis that found
nothing worth reporting - `test_role_with_service_principal` in
`tests/test_aws_iam.py` asserts that a role trusting only a service principal is
not returned - while SQS keeps every queue that carries a policy, since it runs
no retention filter of its own. A tally taken in this check would therefore be
exhaustive for queues and incidental for the other five, seeing only the
unguarded sources that happen to sit on a resource kept for some other reason. A
number complete for one service and arbitrary for five would look like a
measurement. Reversing the contract would flow every service role and every log
bucket in the estate through six shared analyzers to produce one informational
number, and a plausible-looking wrong number is worse than no number.

**Row four: an unenumerable source.** This is `has_wildcard_principal` in a
different costume - an unbounded set of sources - and it gets the same
disposition: withhold the statement from that account and follow up in
CloudTrail. An S3 bucket ARN reaches this row honestly rather than by accident.
S3 ARNs carry no account field (`arn:aws:s3:::a-bucket`), so `aws:SourceArn`
alone never identifies whose bucket drove the call, which is exactly why AWS's
guidance pairs `aws:SourceArn` with `aws:SourceAccount`. When the companion key
is present the pair resolves normally; when it is absent the source is
genuinely unidentifiable and withholding is the conservative answer.

One statement can occupy two rows at once. `aws:SourceAccount` holding
`["*", "999999999999"]` resolves the out-of-organization account *and* sets the
wildcard flag, and `categorize_result` unions the resolved accounts into
`all_third_party_accounts` before it branches on the wildcard - so the
statement contributes an allowlist entry and files a violation. The violation
governs: `blocks_rcp` is `summary["violations"] > 0`, so the account is
withheld from the statement regardless of what it contributed.

**Rows five and six: an organization scope.** `aws:SourceOrgID` names an
organization directly and `aws:SourceOrgPaths` carries it as the first element
of a path such as `o-11111111111/r-1111/ou-1111-11111111/`, so both reduce to
the same comparison against this organization's own ID. That ID is
`snapshot.organization_id`, read once during organization discovery by
`organizations:DescribeOrganization` on the management account session `main`
holds. The deployed statement resolves the same value through
`data.aws_organizations_organization.current.id`, so this is discovery catching
up to what deployment always knew.

A scope naming this organization is a perfect guard. The deployed statement
exempts a source carrying this organization's ID, so the resource needs no
allowlist entry and files no violation - AWS's own recommended service
principal guard costs the account nothing. A scope naming any other
organization sets `has_wildcard_source`, because the allowlist holds account
IDs and another organization's accounts are not knowable from here.

The comparison is exact, with no wildcard expansion. A trailing wildcard on our
own ID, `o-11111111111*`, also matches every organization whose ID extends
that prefix, so reading it as ours would deploy the statement against sources
it does not cover. It falls to the violation side instead, which withholds
rather than over-blocks.

A scope naming this organization suppresses nothing else the guard says. An
accountless `aws:SourceArn` alongside it still reads as a wildcard, even though
the two conditions AND together and the source must therefore be inside this
organization. Acting on that reasoning would turn a withheld statement into a
deployed one, and this analysis errs toward withholding. The same asymmetry
runs the other way: a foreign `aws:SourceAccount` alongside an in-organization
scope is a contradiction that grants nothing, yet the account still reaches the
allowlist. That direction only widens what the statement permits, so it is left
as noise rather than corrected.

**Row seven: an unreadable guard.** A source key under an operator outside
`StringEquals`, `StringLike`, `ArnEquals`, `ArnLike` and their `IfExists`
variants cannot be read as a guard: a negated operator excludes rather than
permits, and reading one as a guard would put the wrong account in the
allowlist. So is an `aws:SourceAccount` value that is neither a twelve-digit
account ID nor a wildcard.

Neither raises out of the parser. `read_service_principal_sources` records the
reason on a `read_failure` entry, and `DenyServiceConfusedDeputyCheck` files
that entry as a violation, which withholds the statement from the account - so
an allowlist we could not compute is never deployed as if it were complete.
Raising was the earlier disposition and it was wrong in one specific way: the
parser sits inside six analyzers that six pre-existing checks share, none of
which reads a source guard, so one unreadable construct anywhere in the estate
aborted the whole run and took those six checks down with it. Recording keeps
the fail-loud guarantee where it matters - the allowlist is never silently
wrong - without the collateral damage.

Reading the organization ID is the one place this check does fail loud. A
`DescribeOrganization` response carrying no ID aborts the run, because every
organization-scoped guard in the estate is classified against that value and
continuing would put a foreign organization's sources in an allowlist, or leave
this one's out, while looking like a healthy run.

**Case-insensitive keys.** IAM matches condition key names without regard to
case, so the analyzer lowercases before comparing: a policy written
`aws:sourceaccount` names the same key as one written `aws:SourceAccount`.

**A resource the analyzer could not read.** An SQS queue whose policy is
unparseable, or names a principal type the analyzer does not recognize, is
recorded as a `read_failure` rather than skipped. The statement walk reads
service principal sources before it reaches the principal types that raise, so
discarding the queue would drop a guard that was read successfully and leave
its account out of the allowlist. The recorded failure withholds the statement
from the account instead. `deny_sqs_third_party_access` is unaffected: the
recorded queue carries no third-party account and no wildcard, so that check's
filter drops it exactly as the earlier warn-and-skip did.

**Residual risk and rollout.** Discovery sees only the sources a resource
policy already pins. An unguarded service trust, and a guard that lives outside
the resource policy, are both invisible to it, and `unique_third_party_accounts`
must not be read as a measurement of the estate's out-of-organization
service-mediated access. Before enabling the statement for a target:

1. Review CloudTrail for calls into that target's accounts where
   `aws:PrincipalIsAWSService` is true and `aws:SourceAccount` falls outside the
   organization. Those are the drivers discovery cannot see. Add the legitimate
   ones to the allowlist, or pin them in the resource policy so the next run
   finds them.
2. Deploy to a test OU with the discovered allowlist and watch for denials
   before going organization-wide.
3. Rolling back is setting `deny_service_confused_deputy` to `false` for the
   affected target, which removes this statement and leaves the other six in
   place.

**Scope.** AWS's reference statement also covers `cognito-identity`,
`cognito-idp`, `logs`, `dynamodb` and `aoss`. Headroom has no checks for those
services, so widening the action list is separate work with its own discovery.
The reference's `aws:ResourceTag/dp:exclude:identity` break-glass is likewise
not implemented: anyone holding the service's tagging permission could set it,
exempting their own resources from the policy that exists to constrain them.
Exemptions go through the allowlist variable, where they stay in Terraform and
stay auditable.

## Results Processing

### Common Parsing Patterns

Both SCP and RCP parsers share these patterns:

**Directory Structure:**
```
{results_dir}/{check_type}/{check_name}/*.json

Examples:
- {results_dir}/scps/deny_ec2_imds_v1/account-name_111111111111.json
- {results_dir}/rcps/deny_sts_third_party_assumerole/account-name_111111111111.json
```

**JSON Parsing:**
```python
try:
    with open(result_file, 'r') as f:
        data = json.load(f)
    # ... processing ...
except (json.JSONDecodeError, KeyError) as e:
    raise RuntimeError(f"Failed to parse result file {result_file}: {e}")
```

**Summary Extraction:**
```python
summary = data.get("summary", {})
account_id = summary.get("account_id", "")
account_name = summary.get("account_name", "")
```

**Account ID Fallback:**
```python
# When account_id missing (exclude_account_ids=True)
if not account_id:
    account_id = lookup_account_id_by_name(
        account_name,
        organization_hierarchy,
        context="result file"
    )
```

**Shared Utility Function:**

Result files are written under the name selected by `use_account_name_from_tags`,
while the hierarchy always holds the AWS Organizations account name. A Name tag
of `management-account` against an account Organizations calls `Management
Account` must still resolve, so the lookup matches exactly first and then retries with
case and separators ignored, using the same canonicalization as Terraform
identifiers (`make_safe_variable_name`).

Organizations enforces uniqueness on account email, not on account name, so
either stage can match more than one account. Resolution requires exactly one
match at a stage; anything else raises rather than attributing results to an
arbitrary account. A name that canonicalizes to the empty string (only
separators) is never canonically matched, since every such name reduces alike.

| Stage | Matches | Behavior |
|-------|---------|----------|
| Exact | 1 | Return the account ID, log at info |
| Exact | >1 | Raise, listing every candidate ID and name |
| Canonical | 1 | Return the account ID, log at warning with both names |
| Canonical | >1 | Raise, listing every candidate ID and name |
| Neither | 0 | Raise `Account name '<name>' from <context> not found in organization hierarchy` |

```python
# aws/organization.py
def lookup_account_id_by_name(
    account_name: str,
    organization_hierarchy: OrganizationHierarchy,
    context: str = "result file"
) -> str:
    """
    Look up account ID by name in organization hierarchy.

    Raises: RuntimeError if the name matches no account or several
    """
    exact_matches = [
        (acc_id, acc_info.account_name)
        for acc_id, acc_info in organization_hierarchy.accounts.items()
        if acc_info.account_name == account_name
    ]
    if len(exact_matches) == 1:
        return exact_matches[0][0]
    if exact_matches:
        raise RuntimeError(f"Account name '{account_name}' from {context} matches ...")

    canonical_name = make_safe_variable_name(account_name)
    canonical_matches: List[Tuple[str, str]] = []
    if canonical_name:
        canonical_matches = [
            (acc_id, acc_info.account_name)
            for acc_id, acc_info in organization_hierarchy.accounts.items()
            if make_safe_variable_name(acc_info.account_name) == canonical_name
        ]
    if len(canonical_matches) == 1:
        logger.warning(f"'{account_name}' resolved by ignoring case and separators")
        return canonical_matches[0][0]
    if canonical_matches:
        raise RuntimeError(f"Account name '{account_name}' from {context} matches ...")

    raise RuntimeError(
        f"Account name '{account_name}' from {context} not found in organization hierarchy"
    )
```

### SCP Results Parsing

```python
# parse_results.py

def parse_scp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPCheckResult]:
    """
    Parse all SCP check result files.

    Results are organized as: {results_dir}/scps/{check_name}/*.json
    RCP results live under rcps/, so there is nothing to filter out here.

    Algorithm:
    1. Look for {results_dir}/scps/ subdirectory
    2. Iterate through all check directories in scps/
    3. Skip non-directory files
    4. For each JSON file in check directory:
       - Parse JSON
       - Extract summary fields
       - Handle missing account_id via lookup
       - Create SCPCheckResult
    5. Return flat list of all results

    Returns: List[SCPCheckResult]
    """
```

**Extracted Fields:**
```python
SCPCheckResult(
    account_id=account_id,
    account_name=summary.get("account_name", ""),
    check_name=summary.get("check", check_name),
    violations=summary.get("violations", 0),
    exemptions=summary.get("exemptions", 0),
    compliant=summary.get("compliant", 0),
    total_instances=summary.get("total_instances", 0),
    compliance_percentage=summary.get("compliance_percentage", 0.0),
    iam_user_arns=summary.get("users", None)  # For deny_iam_user_creation
)
```

### RCP Results Parsing

```python
# terraform/generate_rcps.py

def parse_rcp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPCheckParseResult]:
    """
    Parse result files for every registered RCP check.

    Results are organized as: {results_dir}/rcps/{check_name}/*.json

    Algorithm:
    1. For each check name in sorted(get_check_names("rcps")):
       a. Get check directory using get_results_dir(check_name, results_dir)
       b. If the directory does not exist: record check_name as missing,
          skip to the next check
       c. For each JSON file in the directory:
          - Parse JSON, extract summary
          - Handle missing account_id via lookup
          - Cross-check summary["check"] against check_name (a file with
            no "check" field is presumed to match); raise RuntimeError on
            a mismatch
          - Require summary["violations"] (never defaulted); raise
            RuntimeError if absent
          - blocks_rcp = summary["violations"] > 0
          - If blocks_rcp: add account_id to this check's
            accounts_with_blockers
          - Else: add account_id -> set(unique_third_party_accounts) to
            this check's account_third_party_map
       d. Append an RCPCheckParseResult for this check to the result list
    2. If any registered check's directory was missing: raise a single
       RuntimeError naming every missing check
    3. Return the list of RCPCheckParseResult, one per registered RCP check

    Returns: List[RCPCheckParseResult], one per registered RCP check

    Note: A check directory that exists but is empty is not an error - it
    yields an RCPCheckParseResult with no findings, indistinguishable from
    a check that ran and found nothing. Only an absent directory is an
    error, since that is indistinguishable from a check that was silently
    dropped.
    """
```

---

## Placement Logic

### SCP Placement Algorithm

```python
# parse_results.py

def determine_scp_placement(
    results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Determine optimal SCP placement levels using zero-violation principle.

    Algorithm:
    1. Group results by check_name
    2. For each check:
       a. Filter to 100% compliant accounts (compliance_percentage == 100.0)
       b. If NO compliant accounts: return empty list for this check
       c. Try root level:
          - If ALL org accounts are compliant: recommend root
       d. Try OU level, walking the hierarchy from the top down:
          - An OU is safe when EVERY account in its subtree is compliant -
            the accounts directly in it and the accounts in its child OUs,
            because the policy reaches all of them
          - Recommend OU-level at the highest safe OU and stop descending;
            its child OUs inherit the policy rather than collecting a second
            copy of it
          - An unsafe OU hands the question to its child OUs
       e. Account level:
          - For remaining compliant accounts, recommend account-level
          - compliance_percentage is 100.0, as at every other level: the
            affected accounts are the zero-violation subset. The share of the
            organization those accounts represent goes in `reasoning`, where
            it describes reach rather than gating deployment
       f. For deny_iam_user_creation check:
          - Union all IAM user ARNs from affected accounts, which for an
            OU-level recommendation is the OU's whole subtree
          - Un-redact ARNs (replace "REDACTED" with actual account_id)
          - Attach to allowed_iam_user_arns field
       g. For deny_ec2_ami_owner check:
          - Union all AMI owners from affected accounts
          - Attach to ec2_allowed_ami_owners field
    3. Return List[SCPPlacementRecommendations]

    Safety Principle: Only deploy at levels with 100% compliance (zero violations)
    """
```

**Un-Redaction Logic for IAM User ARNs:**
```python
# When exclude_account_ids=True, ARNs contain "REDACTED"
# Example: "arn:aws:iam::REDACTED:user/terraform-user"

# Un-redaction algorithm:
for arn in iam_user_arns:
    if "REDACTED" in arn:
        # Replace REDACTED with actual account_id
        un_redacted_arn = arn.replace("REDACTED", account_id)
    else:
        un_redacted_arn = arn
```

**Union Logic for IAM User ARNs:**
```python
# For root/OU level SCPs, union all IAM user ARNs from affected accounts

all_user_arns = set()
for account_id in affected_accounts:
    account_result = get_result_for_account(account_id, check_name)
    if account_result.iam_user_arns:
        # Un-redact each ARN
        for arn in account_result.iam_user_arns:
            un_redacted = un_redact_arn(arn, account_id)
            all_user_arns.add(un_redacted)

# Sort for consistent ordering
allowed_iam_user_arns = sorted(all_user_arns)
```

### RCP Placement Algorithm

```python
# terraform/generate_rcps.py

def determine_rcp_placement(
    parse_results: List[RCPCheckParseResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPPlacementRecommendations]:
    """
    Determine optimal RCP placement levels using union strategy.

    Algorithm:
    1. For each RCPCheckParseResult in parse_results (each check runs
       independently, against only its own accounts_with_blockers):
       a. Accounts in this check's accounts_with_blockers were already
          excluded from account_third_party_map by parse_rcp_result_files,
          so they need no further filtering here
       b. If account_third_party_map is empty: no recommendations for this check
       c. Try root level:
          - Check: NO accounts have this check's own blockers (len(accounts_with_blockers) == 0)
          - If safe: union ALL third-party IDs from this check's account_third_party_map
          - Affected accounts: ALL accounts in organization
          - Root-level recommendation is the only recommendation returned for this check
       d. Try OU level (if root not safe), walking from the top down:
          - For each OU:
            - Check: NO account in the OU's SUBTREE - the OU and every OU
              below it - is in this check's accounts_with_blockers
            - If safe: union third-party IDs from this check's
              account_third_party_map for every account in that subtree, and
              stop descending; the child OUs inherit the policy
            - Single-account OUs: Still get OU-level recommendations
       e. Account level:
          - Every account still in this check's account_third_party_map after OU-level coverage gets its own account-level recommendation
    2. Return the recommendations from every check, concatenated

    Union Strategy Rationale:
    - Third-party IDs can be safely combined into single allowlist
    - Account A trusts [111], Account B trusts [222] → allowlist [111, 222]
    - More permissive than requiring identical sets
    - Still safe because RCPs use allowlists (approved principals)

    Critical Safety Rules:
    - Root RCP for a check ONLY if NO accounts have that check's own blockers
    - OU RCP for a check ONLY if NO accounts in that OU have that check's own blockers
    - A blocker is check-specific: an account blocking the S3 RCP can still receive placement for every other check
    - Affected accounts includes ALL accounts at that level (not just eligible ones)

    Returns: List[RCPPlacementRecommendations], concatenated across every registered RCP check
    """
```

---

## Terraform Generation

### Organization Info Generation

```python
# terraform/generate_org_info.py

def generate_terraform_org_info(
    organization_hierarchy: OrganizationHierarchy,
    output_path: str
) -> None:
    """
    Generate grab_org_info.tf with AWS Organizations data sources.

    Algorithm:
    1. Take the hierarchy the run already captured (snapshot.hierarchy). This
       reads no AWS API. It used to run a traversal of its own, the second in a
       single run, so the data sources written here could describe a different
       organization from the one placement had just used
    2. Name every OU for its path down from the root ({ou_path} below), so
       two OUs sharing a name under different parents stay apart. Colliding
       or reserved names abort the run.
    3. Generate data sources:
       - aws_organizations_organization for root
       - aws_organizations_organizational_units for the root's children, and
         one per OU that has child OUs, parented by that OU's own ID local -
         this chain is what resolves an OU at any depth
       - aws_organizations_organizational_unit_child_accounts for each OU that
         holds accounts, parented by that OU's own ID local
    4. Generate locals with validation:
       - validation_check_root: ensure exactly 1 root
       - root_ou_id: data.aws_organizations_organization.org.roots[0].id
       - For each OU, at every depth:
         - validation_check_{ou_path}_ou: ensure exactly 1 match
         - {ou_path}_ou_id: filtered OU ID
       - For each account:
         - validation_check_{account_name}_account: ensure exactly 1 match
         - {account_name}_account_id: filtered account ID, searched in the
           account's OWN parent OU. The child-accounts data source lists an
           OU's immediate children only, so searching the top-level OU above
           a nested account finds nothing.
    5. Write to {scps_dir}/grab_org_info.tf

    Validation Pattern:
    validation_check = (length(filter_result) == 1) ?
        "All good. This is a no-op." :
        error("[Error] Expected exactly 1 X, found ${length(filter_result)}")
    """
```

**Generated Terraform Structure:**
```hcl
# Auto-generated by Headroom

data "aws_organizations_organization" "org" {}

data "aws_organizations_organizational_units" "root_ou" {
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

data "aws_organizations_organizational_unit_child_accounts" "production_accounts" {
  parent_id = local.production_ou_id
}

# Emitted because Production has child OUs; this is what lets a nested OU be
# resolved without hardcoding its ID.
data "aws_organizations_organizational_units" "production_children" {
  parent_id = local.production_ou_id
}

data "aws_organizations_organizational_unit_child_accounts" "production_payments_accounts" {
  parent_id = local.production_payments_ou_id
}

locals {
  # Validation
  validation_check_root = (length(data.aws_organizations_organization.org.roots) == 1) ?
    "All good." : error("[Error] Expected 1 root, found ${length(...)}")

  # Root
  root_ou_id = data.aws_organizations_organization.org.roots[0].id

  # OUs
  validation_check_production_ou = (length([for ou in ... if ou.name == "Production"]) == 1) ?
    "All good." : error("[Error] Expected 1 Production OU")

  production_ou_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "Production"
  ][0]

  # A nested OU is found among its own parent's children
  production_payments_ou_id = [
    for ou in data.aws_organizations_organizational_units.production_children.children :
    ou.id if ou.name == "Payments"
  ][0]

  # Accounts
  validation_check_prod_account_account = ...

  prod_account_account_id = [
    for account in data...production_accounts.accounts :
    account.id if account.name == "prod-account"
  ][0]

  # A nested account is found in its own OU, not the top-level OU above it
  payments_core_account_id = [
    for account in data...production_payments_accounts.accounts :
    account.id if account.name == "payments-core"
  ][0]
}
```

**See:** Test Environment section for complete generated examples in `test_environment/scps/grab_org_info.tf` and `test_environment/rcps/grab_org_info.tf`.

### SCP Terraform Generation

     ```python
# terraform/generate_scps.py

def generate_scp_terraform(
    recommendations: List[SCPPlacementRecommendations],
         organization_hierarchy: OrganizationHierarchy,
    output_dir: str
) -> TerraformPlan:
    """
    Generate SCP Terraform files based on placement recommendations.

    Algorithm:
    1. Group by recommended_level (root/ou/account); a "none" recommendation
       is not a placement and is dropped here
    2. For each group, RENDER a Terraform file into the plan, writing nothing:
       - Root: root_scps.tf
       - OU: {ou_path}_ou_scps.tf
       - Account: {account_name}_scps.tf
    3. For each file:
       - Open with GENERATED_MARKER, the line reconciliation claims it by
       - Generate module call with target_id reference
       - Add boolean flags for each check (organized by category)
       - For deny_iam_user_creation:
         - Transform ARNs: replace account IDs with ${local.X_account_id}
         - Add allowed_iam_users list
       - For deny_ec2_ami_owner:
         - Add ec2_allowed_ami_owners list
         - Leave the policy off if that list is empty (see Allowlist Guard
           below)
    4. Write the completed plan to {scps_dir}/, skipping any file whose
       content already matches
    5. Return the plan, which the caller reconciles the directory against
       (see Reconciliation below)

    An empty recommendation list is a plan for an empty directory, not an
    early return.

    ARN Transformation Algorithm:
    1. Parse ARN: arn:aws:iam::ACCOUNT_ID:user/PATH/NAME
    2. Look up account by ID in organization_hierarchy
    3. Generate safe variable name: account_name_account_id
    4. Replace: arn:aws:iam::${local.account_name_account_id}:user/PATH/NAME
    """
```

**Reconciliation:**

Generation produces the complete desired state of the Terraform directory,
not an increment on top of whatever is already there. Terraform loads every
`.tf` file in a directory, so a file a previous run wrote and this run did not
stays deployed: the run "succeeded" while the organization keeps enforcing a
placement that no longer exists.

The failure has a silent form and a loud one. A renamed or deleted target
takes its `local.<name>_ou_id` declaration out of `grab_org_info.tf` with it,
so its orphaned policy file fails at `terraform plan` on an undeclared local.
A target that still exists but dropped out of the recommendations keeps a
declared local, so its stale file applies cleanly and forever. The worst case
is an OU-level check that moves down to individual accounts because a new
account under that OU started violating it: without reconciliation the OU-wide
attachment survives and keeps denying the very account whose violation forced
the move.

`main()` reconciles once, after both workflows return, over the union of:

| Source | Contributes |
|---|---|
| `handle_scp_workflow` | Every path in the SCP plan |
| `handle_rcp_workflow` | Every path in the RCP plan |
| `generate_terraform_org_info` | `{scps_dir}/grab_org_info.tf` |

Every generated `.tf` in either directory that the union omits is deleted.
Reconciling after both workflows - rather than inside each - is what keeps a
raise anywhere in generation from deleting anything: the previous output stays
whole, complete, and deployable.

**What counts as Headroom's file:** the first line, matched exactly:

```
# Code generated by Headroom. DO NOT EDIT.
```

Rendered unconditionally by `TerraformModule.render()` and by the org-info
header, and checked with `find_managed_files()`. Three alternatives were
rejected:

| Signal | Why not |
|---|---|
| Filename pattern (`*_scps.tf`) | Claims a hand-written `custom_scps.tf` sitting in the same directory |
| Manifest file | Separate state. Lose it and every generated file is an orphan; let it go stale and it names files that were never ours |
| Substring search for "Generated by Headroom" | `scps/README.md` opens with "All of these files are auto-generated by Headroom." and would be deleted |

Symlinks are excluded before the marker is even read: `rcps/grab_org_info.tf`
points at the real file in `scps/`, so following it finds the marker and
deletes a link Headroom is responsible for maintaining. Non-`.tf` files and
subdirectories (`.terraform/`, modules) are never candidates.

**Empty is not the same as unknown:**

Deleting every policy file is the correct response to a run that placed
nothing, and it is also exactly how a broken run would present - wrong
credentials, a mistyped `results_dir`, an analysis that wrote nothing. Reading
zero result files therefore aborts rather than reconciles, because a fail-open
here removes security controls organization-wide on the next `apply`:

| Condition | Response |
|---|---|
| Result files parsed, placement produced no recommendations | Empty plan; managed files deleted |
| `parse_scp_result_files` returned nothing | `RuntimeError` from `analyze_scp_compliance` |
| Every RCP check's directory exists but nothing was read from any of them | `RuntimeError` from `handle_rcp_workflow` |
| An RCP check's directory is missing entirely | `RuntimeError` from `parse_rcp_result_files` |

The RCP discriminator needs both halves of a parse result. An account cleared
for a check lands in `account_third_party_map`; an account blocked from it
lands in `accounts_with_blockers`. Only when both are empty for every check
was nothing read at all - an organization where every account blocks every
check has an empty map too, and that is evidence.

**Allowlist Guard:**

A check whose SCP statement is scoped by an allowlist is only safe to enable
once that allowlist is populated. `deny_ec2_ami_owner` denies
`ec2:RunInstances` unless `ec2:Owner` matches `ec2_allowed_ami_owners`, so an
empty list denies every launch rather than none of them - the exact inversion
of what a check reporting 100% compliance is asserting. Rendering
`ec2_allowed_ami_owners = []` is therefore never correct.

Two things reach that state, and they are not the same condition:

1. **No instance in the affected accounts had a resolvable AMI owner.** An
   account running no instances is safe for the placement and observes
   nothing. The module renders `deny_ec2_ami_owner = false` with a comment
   naming the reason, and the rest of the organization still generates.
   Aborting here would let one empty account stop every unrelated check.
2. **A result file predates AMI owner collection.** Its summary carries no
   `unique_ami_owners` key. Parsing raises, naming the file: after parsing
   this is indistinguishable from case 1, and treating it as case 1 would
   build the allowlist from whatever the other accounts happened to observe.

The value collected for that allowlist is the one `ec2:Owner` will hold - the
AMI's `ImageOwnerAlias` where it has one, its numeric `OwnerId` otherwise.
Collecting `OwnerId` alone yields an allowlist that denies the very AMI the
scan observed; see `documentation/CHECKS.md` for the dry-run measurements.

This exists because the collected owners had no path into the recommendation:
`SCPCheckResult` carried no field for them, so every run enabled the SCP at the
highest compliant level with an empty allowlist. A check that adds an allowlist
variable to `modules/scps` must add the matching field on `SCPCheckResult`,
populate it in `parse_scp_result_files`, and union it in the placement
builders; the module variable alone does nothing.

**Generated SCP Terraform Structure:**
```hcl
# Auto-generated SCP Terraform for root
# Generated by Headroom

module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  # EC2
  deny_ec2_imds_v1 = true

  # IAM
  deny_iam_user_creation = true
  iam_allowed_users = [
    "arn:aws:iam::${local.fort_knox_account_id}:user/terraform-user",
    "arn:aws:iam::${local.security_tooling_account_id}:user/cicd-user"
  ]
}
```

**SCP Module Structure:**
```hcl
# modules/scps/variables.tf

variable "deny_ec2_imds_v1" {
  type = bool
}

variable "deny_iam_user_creation" {
  type = bool
}

variable "iam_allowed_users" {
  type        = list(string)
  default     = []
  description = "IAM user ARNs allowed to be created"
}
```

```hcl
# modules/scps/locals.tf

locals {
  statements = [
    {
      include = var.deny_ec2_imds_v1,
      statement = {
        Action = "ec2:RunInstances"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens"          = "required"
            "aws:RequestTag/ExemptFromIMDSv2" = "true"
          }
        }
      }
    },
    {
      include = var.deny_iam_user_creation,
      statement = {
        Action = "iam:CreateUser"
        NotResource = var.allowed_iam_users
      }
    }
  ]

  # Filter to included statements
  enabled_statements = [for s in local.statements : s.statement if s.include]
}
```

**See:** Test Environment section for complete module documentation and usage examples in `test_environment/modules/scps/`.

### RCP Terraform Generation

```python
# terraform/generate_rcps.py

def generate_rcp_terraform(
    recommendations: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_dir: str
) -> TerraformPlan:
    """
    Generate RCP Terraform files based on placement recommendations.

    Algorithm:
    1. Group by recommended_level (root/ou/account)
    2. For each group, RENDER a Terraform file into the plan, writing nothing:
       - Root: root_rcps.tf
       - OU: {ou_path}_ou_rcps.tf
       - Account: {account_name}_rcps.tf
    3. For each file:
       - Open with GENERATED_MARKER, the line reconciliation claims it by
       - Generate module call with target_id reference
       - For each registered RCP check, in `RCP_TERRAFORM_VARIABLES` order:
         if this target has a recommendation for that check, emit its enable
         flag as true with its third-party allowlist variable; otherwise emit
         the enable flag as false and omit the allowlist
       - Third-party IDs are already unioned by placement logic
    4. Write the completed plan to {rcps_dir}/, skipping any file whose
       content already matches
    5. Return the plan, which the caller reconciles the directory against
       (see Reconciliation under SCP Terraform Generation)

    An empty recommendation list is a plan for an empty directory, not an
    early return.
    """
```

**`RCP_TERRAFORM_VARIABLES`:**

The renderer never branches on a check name. `RCP_TERRAFORM_VARIABLES` maps
each registered RCP check to the three things a module call needs from it: the
section comment, the boolean enable variable, and the list variable holding
its third-party allowlist. `_build_rcp_terraform_module` iterates the table, so
the table's order fixes the order parameters are rendered in - alphabetical by
service: ECR, KMS, S3, Secrets Manager, SQS, STS, then
`deny_service_confused_deputy`, which names no service and so sits after the
alphabetical run rather than inside it - and adding a check requires no edit to
the renderer itself.

The table is the one place a new RCP check must be declared by hand; parsing
and placement are already driven by the check registry. A registered check with
no table entry is collected on every run and then dropped at render time,
emitting no module parameters at all. Because `modules/rcps` declares every
`deny_*` flag without a default, the omission surfaces as a `terraform plan`
failure on a missing required variable rather than as a silently disabled
check. `test_table_covers_every_registered_rcp_check` asserts the table's keys
equal `get_check_names("rcps")` and fails by name in CI, before any Terraform
runs.

**Generated RCP Terraform Structure:**
```hcl
# Auto-generated RCP Terraform configuration for Organization Root
# Generated by Headroom based on third-party account analysis

module "rcps_root" {
  source = "../modules/rcps"
  target_id = local.root_ou_id

  # ECR
  deny_ecr_third_party_access = false

  # KMS
  deny_kms_third_party_access = false

  # S3
  deny_s3_third_party_access = false

  # Secrets Manager
  deny_secrets_manager_third_party_access = false

  # SQS
  deny_sqs_third_party_access = false

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
    "888888888888",
    "999999999999",
  ]

  # Service confused deputy
  deny_service_confused_deputy = false
}
```

**RCP Module Structure:**
```hcl
# modules/rcps/variables.tf

# One enable flag + one allowlist variable per registered RCP check,
# alphabetical by service: ECR, KMS, S3, Secrets Manager, SQS, STS, then
# the service confused deputy check, which names no service and so sits
# after the alphabetical run rather than inside it.
#
# STS is shown below. ECR, KMS, S3 and SQS follow exactly this shape.
# Secrets Manager does not: its allowlist is named
# `secrets_manager_third_party_account_ids_allowlist`, with no `_access_`
# segment, while its enable flag `deny_secrets_manager_third_party_access`
# keeps the segment. Deriving the allowlist name from the pattern produces
# `secrets_manager_third_party_access_account_ids_allowlist`, which
# `terraform plan` rejects with "An argument named ... is not expected here".
# Do not normalize it.
#
# The service confused deputy check is a third shape:
# `service_confused_deputy_source_account_ids_allowlist`, with `source_`
# before `account_ids` because the list holds the accounts a service acted
# for rather than the calling principals. The pattern would predict
# `service_confused_deputy_account_ids_allowlist`. Do not normalize that one
# either.

variable "deny_sts_third_party_assumerole" {
  type        = bool
  description = "Deny STS AssumeRole from third-party accounts except those in the allowlist."
}

variable "sts_third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to assume roles in this target ID."
}
```

```hcl
# modules/rcps/locals.tf

locals {
  # One entry per registered RCP check, each gated by its own boolean. An
  # entry whose `include` is false is dropped from the document; it never
  # permits anything. This is what lets seven checks placed at different
  # levels compose without one weakening another.
  possible_rcp_1_statements = [
    # var.deny_ecr_third_party_access
    # -->
    # Sid: DenyECRThirdPartyAccess
    {
      include = var.deny_ecr_third_party_access,
      statement = {
        "Sid"       = "DenyECRThirdPartyAccess"
        "Principal" = "*"
        "Action" = [
          "ecr:*",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = merge(
            {
              "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
            },
            length(var.ecr_third_party_access_account_ids_allowlist) > 0 ? { "aws:PrincipalAccount" = var.ecr_third_party_access_account_ids_allowlist } : {},
          )
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },

    # KMS, S3, Secrets Manager and SQS entries follow, each with its own
    # include flag, Sid, service action prefix and allowlist variable.

    # var.deny_sts_third_party_assumerole
    # -->
    # Sid: DenySTSThirdPartyAssumeRole
    {
      include = var.deny_sts_third_party_assumerole,
      statement = {
        "Sid"       = "DenySTSThirdPartyAssumeRole"
        "Principal" = "*"
        "Action" = [
          "sts:AssumeRole",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = merge(
            {
              "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
            },
            length(var.sts_third_party_assumerole_account_ids_allowlist) > 0 ? { "aws:PrincipalAccount" = var.sts_third_party_assumerole_account_ids_allowlist } : {},
          )
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },

    # var.deny_service_confused_deputy
    # -->
    # Sid: DenyServiceConfusedDeputy
    #
    # The six statements above exempt AWS service principals. This one
    # narrows that exemption back down. Bool true, not BoolIfExists false:
    # it applies only to service calls. Null on aws:SourceAccount applies it
    # only to the service calls carrying that one key - a call populating
    # only aws:SourceArn, or no source keys at all, falls outside it, which
    # narrows the service exemption rather than closing it.
    {
      include = var.deny_service_confused_deputy,
      statement = {
        "Sid"       = "DenyServiceConfusedDeputy"
        "Principal" = "*"
        "Action" = [
          "ecr:*",
          "kms:*",
          "s3:*",
          "secretsmanager:*",
          "sqs:*",
          "sts:AssumeRole",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = merge(
            {
              "aws:SourceOrgID" = data.aws_organizations_organization.current.id
            },
            length(var.service_confused_deputy_source_account_ids_allowlist) > 0 ? { "aws:SourceAccount" = var.service_confused_deputy_source_account_ids_allowlist } : {},
          )
          "Null" = {
            "aws:SourceAccount" = "false"
          }
          "Bool" = {
            "aws:PrincipalIsAWSService" = "true"
          }
        }
      }
    },
  ]

  # Keep only the statements whose flag is true
  included_rcp_1_deny_statements = [
    for rcp_1_deny_statement in local.possible_rcp_1_statements :
    rcp_1_deny_statement.statement if rcp_1_deny_statement.include
  ]

  # Effect is merged in rather than repeated on every statement
  rcp_1_policy = {
    "Version" = "2012-10-17"
    "Statement" = [
      for statement in local.included_rcp_1_deny_statements :
      merge(statement, { Effect = "Deny" })
    ]
  }

  # jsonencode(jsondecode(...)) minimizes the rendered document
  rcp_1_content = jsonencode(
    jsondecode(data.aws_iam_policy_document.rcp_1.json)
  )

  # Validate the RCP maximum length at plan time rather than apply time
  rcp_length_1 = length(local.rcp_1_content)
  validation_check_1 = (local.rcp_length_1 <= 5120) ? "All good. This is a no-op." : error("[Error] String length exceeds 5120 characters, right now it is ${local.rcp_length_1}")
}

data "aws_iam_policy_document" "rcp_1" {
  source_policy_documents = [jsonencode(local.rcp_1_policy)]
}
```

**RCP Policy Logic:**

Each included statement denies its own service's actions - `ecr:*`, `kms:*`,
`s3:*`, `secretsmanager:*`, `sqs:*`, or `sts:AssumeRole` - EXCEPT when:
1. The principal belongs to the organization (`aws:PrincipalOrgID`)
2. The principal belongs to an allowlisted third-party account
   (`aws:PrincipalAccount`, against that statement's own allowlist variable).
   An empty allowlist omits this key, leaving condition 1 to deny all outsiders.
3. The caller is an AWS service
   (`BoolIfExists { "aws:PrincipalIsAWSService" = "false" }`)

Conditions 1 and 2 share one `StringNotEqualsIfExists` block and condition 3 is
a separate `BoolIfExists`. A `Condition` map ANDs its blocks, so a statement
denies only a principal for which none of the three exceptions hold at once:
outside the organization, absent from that statement's allowlist, and not an
AWS service.

The seventh statement, `DenyServiceConfusedDeputy`, inverts condition 3 rather
than repeating it, and is the one statement covering all six services at once.
It denies when the caller **is** an AWS service (`Bool` `true`) acting for a
source account that is neither in the organization (`aws:SourceOrgID`) nor in
its own allowlist (`aws:SourceAccount`), and only when the request carries a
source account at all - `Null { "aws:SourceAccount" = "false" }` reads as "the
key is present". A service call populating only `aws:SourceArn`, or no source
keys at all, falls outside it, so it narrows the service exemption the other
six must carry rather than closing it. See Service Confused Deputy under RCP
Checks.

**No resource-tag exemption.** An earlier revision carried a fourth exception,
`aws:ResourceTag/dp:exclude:identity = "true"`. Anyone holding the service's
tagging permission can set that tag, so the account an RCP exists to constrain
could exempt its own resources from it. It was inert on S3 regardless: S3 does
not populate `aws:ResourceTag` for ordinary bucket and object access.

A check whose `deny_*` flag is `false` contributes no statement at all, so
checks placed at different levels of the hierarchy never weaken one another.

**Known limitation - one 5,120-character policy per target:**

`modules/rcps/rcps.tf` creates exactly one `aws_organizations_policy`, `rcp_1`,
so every included statement shares a single RCP document. `locals.tf` computes
`rcp_length_1 = length(local.rcp_1_content)`, and `validation_check_1` calls
`error()` at plan time when that exceeds 5120, the AWS maximum length for an
RCP.

Until all six checks were wired through to Terraform, only STS could ever
render `true` in a real run, so at most one statement was included and the
budget was never approached. With seven statements includable simultaneously
the scaffolding alone costs roughly 2,240 of the 5,120 characters, and each
additional twelve-digit account ID costs about 14 more, leaving room for a
couple of hundred allowlist entries across all seven lists combined.
`DenyServiceConfusedDeputy` is 339 of that scaffolding on its own, measured
with an empty allowlist, because it carries six services' actions and three
condition blocks. A large enough organization will hit the plan-time error, now
slightly sooner.

Splitting across a second policy is deliberately not implemented: changes to
`modules/rcps/` are a non-goal for the generator, and a loud failure at plan
time is the correct outcome - the alternative is silently truncating an
allowlist and denying access the organization depends on.

**See:** Test Environment section for complete module documentation and usage examples in `test_environment/modules/rcps/`.

---

## AWS Integration

### Session Management

```python
# aws/sessions.py

def assume_role(
    role_arn: str,
    session_name: str,
    base_session: Optional[boto3.Session] = None
) -> boto3.Session:
    """
    Assume IAM role and return session with temporary credentials.

    Algorithm:
    1. Create STS client from base_session (or new session if None)
    2. Call sts.assume_role(RoleArn, RoleSessionName)
    3. Extract Credentials from response
    4. Create new boto3.Session with temporary credentials
    5. Return new session

    Raises: ClientError if role assumption fails
    """
```

**Role Assumption Pattern:**
```python
# analysis.py

def get_security_analysis_session(config: HeadroomConfig) -> boto3.Session:
    """
    Get session for security analysis account.

    If security_analysis_account_id is specified:
        Assume OrganizationAccountAccessRole in that account
    Else:
        Return default boto3.Session() (running from security account)
    """

def get_management_account_session(
    config: HeadroomConfig,
    session: boto3.Session
) -> boto3.Session:
    """
    Assume OrgAndAccountInfoReader in management account.

    Role ARN: arn:aws:iam::{management_account_id}:role/OrgAndAccountInfoReader
    Session name: HeadroomManagementAccountSession
    """

def get_headroom_session(
    account_id: str,
    config: HeadroomConfig
) -> boto3.Session:
    """
    Assume Headroom role in target account for analysis.

    Role ARN: arn:aws:iam::{account_id}:role/Headroom
    Session name: Headroom-{account_id}
    Base session: security_analysis_session
    """
```

### Organization Integration

```python
# aws/organization_snapshot.py

def discover_organization(
    config: HeadroomConfig,
    org_client: OrganizationsClient
) -> OrganizationSnapshot:
    """
    Read the organization once and return the run's whole view of it.

    Algorithm:
    1. Read this organization's ID via describe_organization(). A response
       carrying no ID aborts rather than falling back
    2. List every member account via list_accounts(), all pages. Deliberately
       unfiltered: the management account, accounts named in skip_account_ids,
       and accounts in every non-ACTIVE lifecycle state are all members
    3. Abort if list_accounts reported one account ID more than once, or
       reported an account carrying no name
    4. Abort if a skip_account_ids entry matched no member. Checked against
       full membership before any filtering, so a mistyped entry reports itself
       rather than losing the race to a lifecycle abort it may have caused
    5. Narrow membership to the analyzable accounts, in this order: drop the
       management account, then skip_account_ids, then every account not in the
       ACTIVE lifecycle state (see "Account Lifecycle State Filtering" below).
       Configured skips are consulted before the lifecycle check so an account
       whose state cannot be classified can be excluded by configuration
       instead of aborting every other account's analysis
    6. Find the organization's single root via list_roots(), all pages, then
       walk the tree breadth-first from it, reading each parent's children
       exactly once: one list_organizational_units_for_parent() and one
       list_accounts_for_parent() per parent, building the OrganizationalUnit
       entries and, for every account, an AccountOrgPlacement carrying its
       parent_ou_id (None directly under the root) and its ou_path. Every
       account is retained whatever its lifecycle state and whether or not
       configuration skips it
    7. Cross-check the two views: they must hold the same account IDs under the
       same names, or the run aborts
    8. For each analyzable account, get tags via list_tags_for_resource(), all
       pages, and build AccountInfo:
       - environment from the layout's environment tag (default "unknown")
       - owner from the layout's owner tag (default "unknown")
       - name: if use_account_name_from_tags, the layout's name tag (default
         account_id); otherwise account.Name from the API, which step 3 has
         already required rather than defaulted
    9. Verify those names can become result filenames, and under
       exclude_account_ids that they are unique (see "Account name
       validation"), then return the frozen OrganizationSnapshot

    Returns: OrganizationSnapshot

    Raises: RuntimeError on any of the aborts above, on an account under
            more than one parent or an OU reached twice during the traversal,
            and on a failed Organizations read: describe_organization,
            list_accounts, list_roots and the two per-parent listings all
            wrap ClientError and BotoCoreError, so a refusal or a connection
            failure is reported against the discovery phase rather than as
            an unlabelled traceback
    """
```

```python
# types.py

@dataclass(frozen=True)
class AccountInfo:
    account_id: str
    environment: str       # From tags, default "unknown"
    name: str             # The name tag (default account_id), or the API name
    owner: str            # From tags, default "unknown"

@dataclass(frozen=True)
class OrganizationSnapshot:
    organization_id: str                          # This organization, e.g. o-11111111111
    member_account_ids: frozenset[str]            # Every member, unfiltered
    analyzable_accounts: tuple[AccountInfo, ...]  # What the scan runs against
    hierarchy: OrganizationHierarchy              # Every OU and every account
```

#### One captured view, read once

`discover_organization` is the only place a run reads AWS Organizations. The scan,
SCP generation, RCP generation and `grab_org_info.tf` all consume the
`OrganizationSnapshot` it returns. Before it existed, four independent reads could each
observe a different organization -- placement could be computed against one hierarchy
and the Terraform data sources rendered from another -- and nothing detected the
disagreement.

Each Organizations operation therefore runs exactly once per run, in this order:
`describe_organization`, `list_accounts` (paginated), `list_roots`, then
`list_organizational_units_for_parent` and `list_accounts_for_parent` once per parent,
then `list_tags_for_resource` once per analyzable account. The management role is
assumed once, before the scan, and never again.

**Two views, cross-checked.** `list_accounts` is canonical for membership and lifecycle
state; the OU traversal is canonical for placement. The cross-check is unconditional,
and it is `list_accounts_for_parent` that makes an unconditional check safe: it returns
accounts in **every** lifecycle state, CLOSED and SUSPENDED included, so a quiescent
organization presents the same accounts on both sides no matter what state they are in.
A cross-check written against a view that dropped closed accounts would have had to
tolerate a set difference, and would then have tolerated a real one.

The names must agree as well as the IDs, because the two views feed different consumers.
`AccountOrgPlacement.account_name` comes from the traversal and is what
`lookup_account_id_by_name` matches result files against; `AccountInfo.name` comes from
the global view plus tags and is what names those result files. The
canonicalization fallback in `lookup_account_id_by_name` bridges the two, and it can
only do that if the raw Organizations names are identical on both sides.

**Six disagreements abort discovery.** Each is a case where what the run found
contradicts what it was told, or contradicts itself, and none has a safe reading:

| Guard | Aborts when | Why not resolve it |
|-------|-------------|--------------------|
| Duplicate account IDs | `list_accounts` reports one account ID more than once | Two `AccountInfo` for one account become two workers, therefore two threads writing one result file. Nothing downstream would notice on its own: `member_account_ids` is a frozenset, so the repeat dedupes there, and the cross-check keys accounts by ID, so the duplicate collapses before it can be seen |
| Account with no name | `list_accounts` reports an account carrying no `Name` | The cross-check compares the two views' raw names and the result filename is built from one of them, so substituting the account ID would report the two views agreeing on a name neither of them holds |
| Unmatched `skip_account_ids` | A configured entry matches no organization member | A typo, a wrong digit count, and an account that has left the organization all look identical to a correct entry, and the account the operator meant to exclude keeps being analyzed with nothing in the output saying so |
| Views disagree | An account is in one view only, or the two views name it differently | Result filenames come from one view and placement matching from the other, so proceeding attributes results to the wrong account or to none |
| Name unusable as a filename | An analyzable account's name is empty, holds a null byte, reads as a path, or runs past 237 bytes | See "Account name validation": a path separator writes the account's results where generation does not look, without failing |
| Duplicate names under `exclude_account_ids` | Two analyzable accounts share a name under canonical caseless matching | The account ID is not in the filename, so both accounts resolve to one path and interleave their JSON into it |

The traversal enforces two more of its own, for the same reason: an account appearing
under more than one parent, and an OU reached twice. `find_organization_root` and
`_read_organization_id` add the structural aborts -- no root, several roots, no
organization ID.

**Concurrent organization mutation aborts the run.** This captures a view; it is not
transaction isolation. Organizations offers no consistent snapshot across calls, so an
account created, closed, renamed or moved between two of the reads above can make them
disagree. Two of the six guards -- duplicate IDs and the cross-check -- exist to catch
exactly that, as do the traversal's two invariants, and all four say the same thing: the
organization was modified during discovery, re-run Headroom. The remedy is a retry, not
reconciliation. Proceeding on two disagreeing views would produce placement
and Terraform describing an organization that never existed, and discovery is the
cheapest part of a run to repeat -- it happens before any account is scanned.

#### Account Lifecycle State Filtering

Only accounts in the `ACTIVE` lifecycle state are analyzed. AWS Organizations
reports an account's lifecycle position through two fields on the `Account`
object:

| Field | Values | Status |
|-------|--------|--------|
| `State` | `PENDING_ACTIVATION`, `ACTIVE`, `SUSPENDED`, `PENDING_CLOSURE`, `CLOSED` | Current |
| `Status` | `ACTIVE`, `SUSPENDED`, `PENDING_CLOSURE` | Retired 2026-09-09 |

`State` is authoritative; `Status` is a fallback for SDKs released before
2025-09-09, which do not model `State` (botocore drops unmodeled fields from
responses). Because the retiring `Status` value `SUSPENDED` covers both of the
`State` values `SUSPENDED` and `CLOSED`, allowlisting `ACTIVE` skips exactly the
same accounts under either field, which makes the retirement a non-event.

| State | Analyzed | Reason |
|-------|----------|--------|
| `ACTIVE` | Yes | Fully operational |
| `CLOSED` | No | Role assumption is impossible; AWS removes the account from the organization 90 days after closure |
| `SUSPENDED` | No | AWS has restricted access, so API calls fail |
| `PENDING_ACTIVATION` | No | Sign-up was never completed, so the account is unusable |
| `PENDING_CLOSURE` | No | Still functional, but leaving the organization, so it must not hold back an organization-wide recommendation |

Without this filtering a single closed account aborts an entire run, because
`run_checks()` does not catch the `ClientError` that `assume_role` raises,
losing the results of every account later in the list.

**An indeterminate state aborts the run.** An account reporting neither field
raises `RuntimeError` naming the remediation. That cause is environment-wide
rather than per-account: an SDK too old to model `State` once `Status` has been
retired makes every account report nothing. Continuing would attempt every closed
account and then fail inside `assume_role` with an `AccessDenied` that names none
of the real cause, so the failure belongs at the point the information is
actually missing.

**An unrecognized state also aborts the run.** A `State` value absent from both
`ACTIVE` and the skip set means AWS has added a lifecycle state, and neither
guess is safe: analyzing an account that turns out to be unusable burns the run
on a downstream error that explains nothing, while skipping one that is usable
drops it from the compliance picture that gates policy deployment. The error
names the offending value and the constant to update.

The governing principle is therefore uniform - **never guess at an account's
lifecycle state.** A state that is known and analyzable is analyzed, a state that
is known and unusable is skipped, and anything else stops the run.

The cost of that uniformity is that a state AWS adds would break runs, so
`test_every_state_aws_defines_is_classified` asserts that `ACTIVE` plus the skip
set exactly covers `AccountStateType`, the SDK's own enumeration of the field.
A new AWS state therefore surfaces as a CI failure naming the state when
`boto3-stubs` is upgraded, rather than as a failed run in production.

**Scope.** This filtering produces one of the snapshot's four fields,
`analyzable_accounts`, which is the account list that drives per-account checks.
It deliberately does **not** reach the other three:

- `member_account_ids` is the organization-membership oracle for the third-party
  RCP checks, and is unfiltered. A closed account remains an organization member
  until AWS removes it, and organization-based RCP conditions still match it, so
  filtering here would reclassify a recently-closed sibling account as a third
  party and produce false positive findings.
- `organization_id` is this organization's own ID, read from
  `organizations:DescribeOrganization`. It names the organization, not its
  members, so no account filtering applies.
- `hierarchy` retains every account, because it is what resolves account names
  read back from result files on disk. A result file written before an account
  closed must still resolve, and placement is driven by the results that exist,
  which leaves an account with no results already inert.

### Region Discovery

Every regional check resolves its region list through one helper,
`aws/helpers.get_all_regions()`, which calls `ec2:DescribeRegions` with no
arguments.

Calling it with no arguments is the entire contract. The default response
contains only the regions **enabled for the account** and omits every
`not-opted-in` region:

| `OptInStatus` | Meaning | Returned by default |
|---------------|---------|---------------------|
| `opt-in-not-required` | Enabled for every account | Yes |
| `opted-in` | Opt-in region the account has enabled | Yes |
| `not-opted-in` | Opt-in region the account has not enabled | No |

**Never pass `AllRegions=True`.** Per the EC2 API it "indicates whether to
display all Regions, including Regions that are disabled for your account".
Because every caller builds a per-region client from this list, each disabled
region added would become a doomed API call against a region that cannot hold
resources. Headroom has no interest in analyzing a disabled region, so the
cheapest correct behaviour is to never learn about one.
`test_only_enabled_regions_are_requested` asserts the exact call signature, so
adding the argument fails the suite rather than the run.

An enabled region is not a guarantee that a given service is available there.
Handling a missing regional endpoint is the caller's concern. Note that an
absent endpoint raises `EndpointConnectionError`, which is not a `ClientError`
subclass, so an `except ClientError` never catches it.

#### Credentials in Opt-In Regions

Reaching an enabled region also needs credentials AWS will honour there. Session
tokens issued by the **global** STS endpoint, `sts.amazonaws.com`, are valid only
in regions that are enabled by default, so an opt-in region rejects them:

```
An error occurred (AuthFailure) when calling the DescribeInstances operation:
AWS was not able to validate the provided access credentials
```

botocore reaches that endpoint by default. Its `sts_regional_endpoints` setting
defaults to `legacy`, which rewrites the STS endpoint whenever the session's
region is one of botocore's `LEGACY_GLOBAL_STS_REGIONS` -- the regions that
predate opt-in regions, `us-east-1` and `us-west-2` among them. An operator
running Headroom from `us-west-2` therefore mints unusable credentials without
having configured anything wrong.

Headroom does not depend on the operator's configuration for this.
`aws/sessions.new_session()` is the only place in the package that constructs a
boto3 `Session`, and it sets `sts_regional_endpoints = regional` on every one.
`assume_role()` builds its STS client in an explicit region and stamps that
region onto the session it returns, so a chained assumption -- base account to
security analysis account to member account -- stays regional at every hop. When
no region resolves, `assume_role()` raises instead of picking one, on the same
grounds as every other guess Headroom refuses to make.

`test_only_the_sessions_module_constructs_a_session` fails the suite if any
module builds a `Session` directly. A direct construction silently reinherits the
`legacy` default, and nothing in a mocked test suite notices; the break surfaces
only once a scan reaches an opt-in region.

#### Retry Configuration

`new_session()` also sets `retry_mode = standard` and `max_attempts = 5` on the
botocore session, so every client built from it inherits them without a
per-call-site `Config`. A client reports the resolved pair as
`{"total_max_attempts": 5, "mode": "standard"}`.

Five is parity rather than headroom. botocore's default mode is `legacy`, whose
`__default__` policy already allows five attempts, while `standard` allows three
-- so setting the mode alone would have lowered the ceiling at the point where
many accounts started being analyzed at once. What `standard` changes is which
failures are retried: legacy keyed several rules on HTTP status alone, 429 and
509 among them, while standard retries 500, 502, 503 and 504 on status and
otherwise matches the parsed error code, which is how it picks up the throttling
family.

`adaptive` is deliberately not used. It adds client-side rate limiting that
throttles unpredictably, and workers are spread across separate accounts, which
are separate rate-limit buckets.

#### Unreadable Regions

**A region that cannot be read aborts the run.** Every regional analysis raises
on a `ClientError` rather than contributing an empty result, because an empty
result is exactly what a genuinely empty region produces. Nothing downstream can
distinguish "this region holds no findings" from "this region was never read",
and both feed generated policy:

| Check type | Consequence of a silently unread region |
|------------|------------------------------------------|
| RCP third-party access | The allowlist omits partners whose resources live only in that region, so deploying the RCP denies them |
| SCP compliance | The region contributes no violations, so an OU looks clean and a policy is recommended on incomplete evidence |

The single exception is a resource that has been **deleted between listing it and
reading it**. That is the one benign read failure: the resource is gone, so it
holds no policy and can grant nobody access. Those error codes are named
explicitly - `QUEUE_GONE_ERROR_CODES` in `aws/sqs.py` and
`FUNCTION_GONE_ERROR_CODE` in `aws/lambda_functions.py` - and every other code
propagates.

This requires the `Headroom` role to be **exempt from region-allowlist SCPs**.
Region enablement is independent of SCPs, so a region denied by
`aws:RequestedRegion` is still enabled, still returned by `DescribeRegions`, and
still scanned. Without the exemption every run would abort in the denied
regions. With it, an `AccessDenied` unambiguously means a missing permission.
See `documentation/SETUP.md`.

Recovery is cheap because the abort is not a rollback. `run_checks_for_type()`
consults `results_exist()` per check per account, so every result already written
to disk is kept and skipped on the next run: fix the permission, re-run, and the
scan resumes where it stopped.

Routing all callers through the single helper is required by `AP-006: Not Using
Existing Helpers` in `HOW_TO_ADD_A_CHECK.md`, which names duplicated region
discovery as the anti-pattern. It keeps the enabled-regions guarantee in one
place instead of restating it at each call site.

**The answer is memoized per session.** Eleven functions call `get_all_regions()`,
so an account resolved the same list eleven times; the enabled-region set cannot
change within a run, and the other ten calls were pure latency. The memo is a
`WeakKeyDictionary` keyed on the session object -- never on an account ID or
name, which is what keeps one account's region list out of another account's
results -- so an entry is released as soon as its worker drops the session and a
300-account run accumulates nothing.

Two further memos follow the same shape and the same reasoning:
`aws/ec2.get_instances()` for one region's instances, and
`aws/helpers.memoize_per_session()` for the six resource-policy analyses
`deny_service_confused_deputy` shares with the resource-specific checks, where
whichever of a pair runs second is served from memory. Registry order decides
which one pays, not design: the check runs fourteenth of sixteen, so ECR, KMS,
S3 and Secrets Manager are cached before it asks, while it reads SQS and IAM
role trust policies first. That last memo also refuses a second call
for one session carrying different organization arguments, since the session
alone is a sufficient key only while those are fixed for the run.

Each holds its lock only around the dictionary, never across the AWS call, so one
account's sweep cannot serialize every other worker behind it.

### EC2 Integration

```python
# aws/ec2.py

def get_imds_v1_ec2_analysis(
    session: boto3.Session
) -> List[DenyImdsV1Ec2]:
    """
    Scan all regions for EC2 instances with IMDSv1.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region, call get_instances(session, region)
    3. For each instance:
       - IMDSv1 is allowed when MetadataOptions.HttpTokens is "optional",
         whatever MetadataOptions.HttpEndpoint says
       - Record the instance profile ARN, if any
    4. Resolve each distinct instance profile to its role, once per account,
       and exempt on that role's ExemptFromIMDSv2 tag
    5. Return all results
    """
```

`get_instances()` is the single reader of `describe_instances`. Four checks --
IMDSv1, AMI owner, public IP, and IMDS hop limit -- each need every instance in
every region, and each used to sweep independently: four identical passes per
region, 51 of the 68 calls a 17-region account made. It paginates, drops
terminated instances, projects each entry to the fields the checks read, and
memoizes the result per session and region.

**The instance ARN carries the owning account.** `instance_arn` is built from
the reservation's `OwnerId`, which lives on the reservation and not on the
instance entry inside it. Reading it off the instance produced an empty account
segment on every instance ever scanned. A results directory that spans the
change therefore holds both shapes, and resuming into one is expected: the
account segment is not read back by anything, and the fix is not worth
re-scanning accounts already on disk for.

`ReservationTypeDef` declares `OwnerId` optional, so a reservation arriving
without one raises a `RuntimeError` naming the region and the instances that
reservation covered. It is not inferred from the calling identity: the owning
account is what makes the ARN resolvable, and a wrong one is worse than a
stopped run.

### IAM Integration

```python
# aws/iam/users.py

def get_iam_users_analysis(
    session: boto3.Session
) -> List[IamUserAnalysis]:
    """
    List all IAM users in account.

    Algorithm:
    1. Create IAM client
    2. Use paginator for list_users()
    3. For each user, extract UserName, Arn, Path
    4. Return List[IamUserAnalysis]

    Pagination: Handles accounts with many users
    """

# aws/iam/roles.py

def analyze_iam_roles_trust_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[TrustPolicyAnalysis]:
    """
    Analyze IAM role trust policies for third-party access.

    (See detailed algorithm in RCP Checks section above)

    Pagination: Handles accounts with many roles
    Exception Handling: Specific exceptions only (ClientError, json.JSONDecodeError)
    Fail-Loud: All exceptions logged with context and re-raised
    """
```

### SAML Provider Integration

```python
# aws/iam/saml_providers.py

@dataclass
class SamlProviderAnalysis:
    arn: str
    name: str
    create_date: datetime.datetime | None
    valid_until: datetime.datetime | None

def get_saml_providers_analysis(
    session: boto3.Session,
) -> List[SamlProviderAnalysis]:
    """
    Enumerate IAM SAML providers.

    Algorithm:
    1. Create IAM client
    2. Call list_saml_providers()
    3. For each entry:
       - Record ARN
       - Derive provider name from ARN suffix
       - Capture CreateDate and ValidUntil if present
    4. Return List[SamlProviderAnalysis]

    Pagination: API does not paginate (single response)
    """
```

---

## Check Execution Flow

### Generic Check Execution

```python
# analysis.py

def run_checks_for_type(
    check_type: str,
    headroom_session: boto3.Session,
    account_info: AccountInfo,
    config: HeadroomConfig,
    org_account_ids: Set[str],
    org_id: str,
    abort: threading.Event
) -> bool:
    """
    Execute all checks of a given type for single account.

    Algorithm:
    1. Get all check classes for type via registry.get_all_check_classes(check_type)
    2. For each check class:
       a. Get check_name from class.CHECK_NAME
       b. Check if results already exist via results_exist()
       c. If exists: skip, before the abort is consulted. A check on disk is
          work this account does not owe, so an abort that lands with only
          such checks left has stopped nothing, and reporting otherwise
          labels a complete account aborted
       d. Return False if the abort Event is set, so a worker whose run has
          been aborted stops at a check boundary rather than at the end
       e. Instantiate check with common parameters + org_account_ids + org_id
       f. Call check.execute(headroom_session)
    3. Return True, having reached the end without a checkpoint stopping it

    Check instantiation uses **kwargs pattern:
    - SCP checks ignore org_account_ids and org_id
    - RCP checks use org_account_ids; all seven take org_id, which only the
      source guard readers consult
    """

def run_checks(
    security_session: boto3.Session,
    relevant_account_infos: Sequence[AccountInfo],
    config: HeadroomConfig,
    org_account_ids: AbstractSet[str],
    org_id: str
) -> None:
    """
    Run all checks across all accounts.

    Algorithm:
    1. Receive org_account_ids and org_id. perform_analysis() gathers neither:
       it is handed the run's OrganizationSnapshot and passes down two of its
       fields, member_account_ids and organization_id, both read during
       organization discovery before the scan began. org_id is what classifies
       aws:SourceOrgID and aws:SourceOrgPaths guards on service principals
    2. Serially, for each account, drop it from the work list when both
       all_check_results_exist("scps", ...) and all_check_results_exist("rcps", ...)
       report every result already on disk
    3. Submit the remaining accounts to a ThreadPoolExecutor sized by
       config.max_account_workers, one account per worker. Each worker:
       a. Registers its account with set_account() so its log records name it,
          and clears it in a finally, because the pool reuses the thread and
          the next records off it would otherwise carry the finished account
       b. Logs and returns immediately if the abort Event is already set
       c. Gets a Headroom session via get_headroom_session()
       d. Runs SCP checks via run_checks_for_type("scps", ..., org_id, abort)
       e. Runs RCP checks via run_checks_for_type("rcps", ..., org_id, abort)
    4. Consume the futures with as_completed(). The first one carrying an
       exception sets the abort Event, cancels the outstanding futures, and
       re-raises
    5. A KeyboardInterrupt out of that loop does the same before re-raising,
       so Ctrl-C is as prompt as a failure
    6. Once the executor has joined its workers, _log_every_failure() reports
       every account that failed, not only the one that propagated. Only one
       exception can reach main(), and concurrent.futures.Future has no
       __del__, so the others would otherwise be collected without even an
       "exception was never retrieved" warning
    7. _log_the_accounts_that_never_ran() then reports how many accounts were
       cancelled before starting. Every other outcome announces itself; a
       cancelled account never ran and holds no exception, so without this the
       operator had to reach that number by subtraction -- and it is the number
       that says how much of the organization the results on disk cover

    Error handling is deliberately absent: the first failure aborts the entire
    run rather than being logged and skipped. A partial run is more dangerous
    than no run, because this output drives SCP and RCP deployment and an
    account skipped for a transient error is indistinguishable in the results
    from an account with zero violations, so swallowing the error could
    green-light a policy that breaks it. Accounts that genuinely cannot be
    analyzed are excluded earlier, by lifecycle state in
    `discover_organization`, and never reach the pool.

    Aborting takes two mechanisms because Python cannot kill a running thread.
    Future.cancel clears the queue but does nothing to accounts already in
    flight; the abort Event stops those at their next check boundary.

    An operator's Ctrl-C takes the same path. shutdown(wait=True) defaults to
    cancel_futures=False and puts its sentinel at the back of the work queue,
    so an interrupt that only propagated would still wait out every queued
    account. Catching it makes interrupting prompt and bounded by the one
    check each in-flight worker is already inside, the same as a failure.
    """
```

### Results Skip Logic

```python
# write_results.py

def results_exist(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False
) -> bool:
    """
    Check if results file exists for check + account.

    Algorithm:
    1. Get expected path via get_results_path()
    2. Check if file exists
    3. Also check alternate format (with/without account_id)
    4. Return True if either format exists

    Backward Compatibility: Checks both filename formats
    """

def get_results_path(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False
) -> Path:
    """
    Get path for results file.

    Format:
    - With IDs: {results_dir}/{check_type}/{check_name}/{account_name}_{account_id}.json
    - Without IDs: {results_dir}/{check_type}/{check_name}/{account_name}.json
    """

def get_results_dir(
    check_name: str,
    results_base_dir: str
) -> str:
    """
    Get directory for check results.

    Format: {results_base_dir}/{check_type}/{check_name}

    check_type determined via CHECK_TYPE_MAP from constants.py
    """
```

---

## Constants and Registration

### Constants Module

```python
# constants.py

# SCP Checks (alphabetical by service)
DENY_EC2_AMI_OWNER = "deny_ec2_ami_owner"
DENY_EC2_IMDS_HOP_LIMIT = "deny_ec2_imds_hop_limit"
DENY_EC2_IMDS_V1 = "deny_ec2_imds_v1"
DENY_EC2_PUBLIC_IP = "deny_ec2_public_ip"
DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG = "deny_eks_create_cluster_without_tag"
DENY_IAM_USER_CREATION = "deny_iam_user_creation"
DENY_IAM_SAML_PROVIDER_NOT_AWS_SSO = "deny_iam_saml_provider_not_aws_sso"
DENY_LAMBDA_AUTH_TYPE_NONE = "deny_lambda_auth_type_none"
DENY_RDS_UNENCRYPTED = "deny_rds_unencrypted"

# RCP Checks (alphabetical by service)
DENY_ECR_THIRD_PARTY_ACCESS = "deny_ecr_third_party_access"
DENY_KMS_THIRD_PARTY_ACCESS = "deny_kms_third_party_access"
DENY_S3_THIRD_PARTY_ACCESS = "deny_s3_third_party_access"
DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS = "deny_secrets_manager_third_party_access"
DENY_SERVICE_CONFUSED_DEPUTY = "deny_service_confused_deputy"
DENY_SQS_THIRD_PARTY_ACCESS = "deny_sqs_third_party_access"
DENY_STS_THIRD_PARTY_ASSUMEROLE = "deny_sts_third_party_assumerole"

_CHECK_TYPE_MAP: Dict[str, str] = {}

def register_check_type(check_name: str, check_type: str) -> None:
    """
    Register check type in CHECK_TYPE_MAP.

    Called by @register_check decorator.
    """
    _CHECK_TYPE_MAP[check_name] = check_type

def get_check_type_map() -> Dict[str, str]:
    """
    Get CHECK_TYPE_MAP (lazily loads checks if needed).

    Ensures all checks are registered before returning map.
    """
    if not _CHECK_TYPE_MAP:
        import headroom.checks  # noqa: F401
    return _CHECK_TYPE_MAP

# No static SCP/RCP name sets exist. get_check_type_map() is the single
# source of truth for which type a check belongs to, populated by
# @register_check at import time.
```

### Dynamic Registration Flow

1. `checks/__init__.py` imports all check modules
2. Module imports trigger class definitions
3. Class definitions have `@register_check` decorators
4. Decorators execute immediately upon class definition
5. Decorator calls `register_check_type()` to update `_CHECK_TYPE_MAP`
6. Decorator stores class in `_CHECK_REGISTRY`
7. Later, `get_all_check_classes()` retrieves registered checks

---

## Output System

### OutputHandler Class

```python
# output.py

class OutputHandler:
    """Centralized handler for user-facing output."""

    @staticmethod
    def check_completed(
        check_name: str,
        account_identifier: str,
        data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Print check completion with statistics."""
        print(f"✅ Completed {check_name} for account {account_identifier}")
        if data:
        violations = data.get("violations", 0)
        exemptions = data.get("exemptions", 0)
        compliant = data.get("compliant", 0)
        print(f"   Violations: {violations}, Exemptions: {exemptions}, Compliant: {compliant}")

    @staticmethod
    def error(title: str, error: Exception) -> None:
        """Print error message."""
        print(f"\n🚨 {title}:\n{error}\n")

    @staticmethod
    def success(title: str, data: Any) -> None:
        """Print success message."""
        print(f"\n✅ {title}:")
        print(data)

    @staticmethod
    def section_header(title: str) -> None:
        """Print section header."""
        print(f"\n{'='*80}")
        print(f"{title}")
        print(f"{'='*80}\n")
```

---

## Safety Principles

### SCP Deployment Safety

**Zero-Violation Principle:**
- Only deploy SCPs at levels where ALL accounts have 100% compliance
- Ensures policies won't break existing compliant resources
- Accounts with violations receive account-specific recommendations
- Compliance is measured as: (compliant + exemptions) / total * 100

**Placement Hierarchy:**
1. **Root Level:** Recommended when ALL accounts in org are 100% compliant
2. **OU Level:** Recommended when ALL accounts in specific OU are 100% compliant
3. **Account Level:** Recommended for individual compliant accounts, and
   enabled in those accounts' files. A recommendation reaching a module is
   itself the signal to enable the policy, because `affected_accounts` is the
   zero-violation subset at every level

### RCP Deployment Safety

**Blocker Exclusion:**
- An account is excluded from a check's RCP generation whenever that check's own violations count is nonzero; each check defines what counts as a violation for its own resource type (see `documentation/CHECKS.md`)
- Static analysis cannot always determine the actual principals a resource policy would grant access to
  - Conditions are not evaluated: a `Principal: "*"` scoped by `aws:PrincipalOrgID` is counted as a violation and blocks the account, and a grant scoped by `s3:prefix` or a lapsed `DateLessThan` still contributes its account to the allowlist. A condition can only narrow a grant, so neither can hide a third party from the scan; both cost coverage rather than safety.
- Placement runs once per check, each against only that check's own blocked accounts, so a blocker for one RCP (e.g. S3) never suppresses placement for another (e.g. STS)
- Avoids OU-level RCP for a check if ANY account beneath that OU is blocked for that check, including accounts inside its child OUs, because the policy reaches them too
- Avoids root-level RCP for a check if ANY account in the organization is blocked for that check

**Union Strategy:**
- Third-party account IDs combined (unioned) at each level
- More permissive than requiring identical sets across accounts
- Still safe because RCPs use allowlists (approved principals)
- Example: Account A trusts [111], Account B trusts [222] → RCP allowlist [111, 222]

**Placement Hierarchy:**
1. **Root Level:** Only if NO accounts have that check's own blockers; unions ALL third-party IDs
2. **OU Level:** Only if NO accounts in OU have that check's own blockers; unions OU third-party IDs
3. **Account Level:** Blocked accounts excluded; no RCP generated for them

---

## Quality Standards

### Testing Requirements
- **Coverage:** 100% (432 tests covering all code paths)
- **Test Categories:**
  - Unit tests for individual functions
  - Integration tests for end-to-end workflows
  - Error path testing for exception handling
  - Mock integration for AWS services
- **Test Organization:** Centralized fixtures with `autouse=True` for mock dependencies
- **Test Naming:** Descriptive BDD-style names (`test_<action>_when_<condition>`)

### Type Safety
- **Mypy:** Strict mode with no untyped definitions
- **Type Annotations:** All functions, methods, and variables annotated
- **Generics:** Used in BaseCheck for type-safe check implementations
- **Type Aliases:** `PolicyRecommendation`, `AccountThirdPartyMap`, etc.

### Code Standards
- **Python Version:** 3.13
- **Pre-commit Hooks:**
  - flake8: Linting
  - autopep8: Auto-formatting
  - autoflake: Remove unused imports
  - trailing-whitespace: Remove trailing whitespace
  - end-of-file-fixer: Ensure files end with newline
- **Import Organization:** All imports at top level (no dynamic imports)
- **Function Structure:** No nested functions (minimize indentation)
- **Continuation:** Use parentheses for multi-line statements (no backslash-newline)

### Error Handling
- **Specific Exceptions:** Always catch specific types (ClientError, json.JSONDecodeError, etc.)
- **Fail-Loud Philosophy:** Never silence errors; all exceptions logged with context and re-raised
- **No Generic Catches:** Never `except Exception:` - always specify what can fail
- **No Silent Fallbacks:** Avoid defensive programming that hides configuration/permission issues

---

## Usage

### Installation

```bash
pip install -r requirements.txt
```

### Running Analysis

```bash
# Basic usage
python -m headroom --config config.yaml

# With custom directories
python -m headroom --config config.yaml \
  --results-dir ./my_results \
  --scps-dir ./my_scps \
  --rcps-dir ./my_rcps

# Excluding account IDs from results
python -m headroom --config config.yaml --exclude-account-ids

# Override account IDs via CLI
python -m headroom --config config.yaml \
  --management-account-id 222222222222 \
  --security-analysis-account-id 111111111111
```

### Running Tests

```bash
# Run all tests with coverage
tox

# Run specific test file
pytest tests/test_analysis.py -v

# Type checking
mypy headroom/ tests/
```

---

## Test Environment & Live Integration

### Overview

The `test_environment/` directory contains a complete, reproducible AWS Organizations environment for live integration testing. Unlike unit tests in `tests/`, this is real infrastructure deployed to AWS that demonstrates Headroom's end-to-end functionality.

**Purpose:**
- Live integration testing against actual AWS resources
- Reproducible demo environment deployable by anyone with an AWS Organizations setup
- Source of truth for example outputs in `test_environment/headroom_results/`
- Documentation-by-example showing complete workflow: infrastructure → analysis → generated Terraform

**Key Characteristics:**
- Real AWS Organizations with multiple accounts and OUs
- Intentionally created violations, exemptions, and compliant resources
- Test scenarios covering all SCP and RCP checks
- Generated Terraform demonstrating placement recommendations

### Directory Structure

```
test_environment/
├── accounts.tf                          # AWS Organizations accounts
├── organizational_units.tf              # OU hierarchy
├── providers.tf                         # Provider configuration with account aliases
├── data.tf                              # Organization data sources
├── variables.tf                         # Input variables
├── terraform.tfvars.example             # Example variable values
├── org_and_account_info_reader.tf       # Management account IAM role
├── headroom_roles.tf                    # Headroom roles in all accounts
├── test_deny_iam_user_creation.tf       # IAM users for testing
├── test_deny_deny_sts_third_party_assumerole.tf  # IAM roles with trust policies
├── account_scps.tf                      # Account-level SCP attachments (if any)
├── modules/
│   ├── headroom_role/                   # Reusable Headroom role module
│   ├── scps/                            # Production SCP module
│   └── rcps/                            # Production RCP module
├── scps/                                # Generated SCP Terraform
│   ├── grab_org_info.tf                 # Auto-generated org data sources
│   ├── root_scps.tf                     # Root-level SCPs
│   ├── {ou_path}_ou_scps.tf            # OU-level SCPs, named for the OU's
│   │                                   # path from the root (production,
│   │                                   # production_payments, ...)
│   └── {account_name}_scps.tf          # Account-level SCPs
├── rcps/                                # Generated RCP Terraform
│   ├── grab_org_info.tf                 # Auto-generated org data sources
│   ├── {ou_path}_ou_rcps.tf            # OU-level RCPs
│   └── {account_name}_rcps.tf          # Account-level RCPs
├── headroom_results/                    # JSON analysis results
│   ├── scps/
│   │   ├── deny_ec2_imds_v1/
│   │   │   └── {account_name}.json
│   │   ├── deny_iam_user_creation/
│   │   │   └── {account_name}.json
│   │   └── deny_rds_unencrypted/
│   │       └── {account_name}.json
│   └── rcps/
│       └── deny_sts_third_party_assumerole/
│           └── {account_name}.json
├── test_deny_ec2_imds_v1/               # EC2 instances (expensive, separate directory)
│   ├── README.md                        # Cost warnings and usage
│   ├── providers.tf                     # Cross-account providers
│   ├── data.tf                          # AMI data sources
│   └── ec2_instances.tf                 # Test EC2 instances
└── test_deny_rds_unencrypted/           # RDS instances/clusters (expensive, separate directory)
    ├── README.md                        # Cost warnings and usage
    ├── providers.tf                     # Cross-account providers
    ├── data.tf                          # Organization data sources
    └── rds_resources.tf                 # Test RDS databases
```

### Organization Structure

The test environment creates the following AWS Organizations hierarchy:

```
AWS Organization (Management Account: 222222222222)
│
├── Root OU (r-xxxx)
│   │
│   ├── High Value Assets OU (ou-xxxx-xxxxxxxx)
│   │   ├── fort-knox (Production Account)
│   │   │   - Environment: production
│   │   │   - Owner: Cloud Architecture
│   │   │   - Category: high_value_assets
│   │   │   - IAM Users: 1 (github-actions with /service/ path)
│   │   │   - IAM Roles: 1 (WildcardRole - violation)
│   │   │   - EC2 Instances: 0-1 (test-imdsv1-exempt when testing)
│   │   │
│   │   └── security-tooling (Security Analysis Account: 111111111111)
│   │       - Environment: production
│   │       - Owner: Security
│   │       - Category: high_value_assets
│   │       - IAM Users: 1 (cicd-deployer with /automation/ path)
│   │       - IAM Roles: 0 (service principals only)
│   │       - EC2 Instances: 0
│   │       - Note: This is where Headroom executes from
│   │
│   ├── Shared Services OU (ou-xxxx-xxxxxxxx)
│   │   └── shared-foo-bar (Shared Services Account)
│   │       - Environment: production
│   │       - Owner: Traffic
│   │       - Category: shared_services
│   │       - IAM Users: 1 (legacy-developer with / path)
│   │       - IAM Roles: 15 (extensive third-party trust policy testing)
│   │       - EC2 Instances: 0-1 (test-imdsv1-enabled when testing)
│   │       - Third-Party Accounts: 11 unique external accounts
│   │       - Wildcards: 1 role (WildcardRole)
│   │
│   └── Acme Acquisition OU (ou-xxxx-xxxxxxxx)
│       └── acme-co (Acquired Company Account)
│           - Environment: production
│           - Owner: SRE
│           - Category: acme_acquisition
│           - IAM Users: 2 (terraform-user, temp-contractor with /contractors/ path)
│           - IAM Roles: 1 (ThirdPartyVendorA)
│           - EC2 Instances: 0-1 (test-imdsv2-only when testing)
│           - Third-Party Accounts: 1 (CrowdStrike: 999911114444)
```

**Account ID Mapping:**
- Management Account: 222222222222
- Security Tooling: 111111111111
- Fort Knox: (dynamically created)
- Shared Foo Bar: (dynamically created)
- Acme Co: (dynamically created)

### Infrastructure Components

#### Root-Level Terraform Files

**`accounts.tf`**
```hcl
# Creates AWS Organizations accounts with tags
resource "aws_organizations_account" "fort_knox" {
  name      = "fort-knox"
  email     = "user+fort-knox@example.com"
  parent_id = aws_organizations_organizational_unit.high_value_assets.id

  tags = {
    Environment = "production"
    Owner       = "Cloud Architecture"
    Category    = "high_value_assets"
  }
}
# ... similar for security_tooling, shared_foo_bar, acme_co
```

**Purpose:** Creates member accounts and assigns them to OUs. Tags provide metadata for account information extraction.

**`organizational_units.tf`**
```hcl
# Creates OUs under organization root
resource "aws_organizations_organizational_unit" "high_value_assets" {
  name      = "high_value_assets"
  parent_id = data.aws_organizations_organization.current.roots[0].id
}
# ... similar for shared_services, acme_acquisition
```

**Purpose:** Establishes OU hierarchy for testing placement recommendations.

**`providers.tf`**
```hcl
# Provider aliases for cross-account resource creation
provider "aws" {
  alias  = "fort_knox"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.fort_knox.id}:role/OrganizationAccountAccessRole"
  }
}
# ... similar for security_tooling, shared_foo_bar, acme_co
```

**Purpose:** Enables Terraform to create resources in member accounts by assuming `OrganizationAccountAccessRole`.

**`data.tf`**
```hcl
data "aws_organizations_organization" "current" {}
data "aws_caller_identity" "current" {}
```

**Purpose:** Retrieves organization root ID and management account information.

**`variables.tf`**
```hcl
variable "base_email" {
  type        = string
  description = "Email for AWS accounts"
}
```

**Purpose:** Base email for account creation (uses + addressing: `user+account-name@domain.com`).

**`org_and_account_info_reader.tf`**

Role in management account that Headroom uses to query AWS Organizations API.

**Permissions:**
- `organizations:DescribeAccount`
- `organizations:DescribeOrganization`
- `organizations:DescribeOrganizationalUnit`
- `organizations:ListAccounts`
- `organizations:ListAccountsForParent`
- `organizations:ListChildren`
- `organizations:ListOrganizationalUnitsForParent`
- `organizations:ListParents`
- `organizations:ListRoots`
- `organizations:ListTagsForResource`

**Trust Policy:** Trusts security-tooling account (111111111111).

**`headroom_roles.tf`**

Deploys `Headroom` role to all member accounts using the `modules/headroom_role` module.

```hcl
module "headroom_role_fort_knox" {
  source = "./modules/headroom_role"
  providers = {
    aws = aws.fort_knox
  }
  account_id_to_trust = aws_organizations_account.security_tooling.id
}
# ... similar for other accounts
```

### Test Scenario Files

#### IAM User Creation Test (`test_deny_iam_user_creation.tf`)

Creates IAM users across accounts to test `deny_iam_user_creation` SCP check and allowlist generation.

**Test Users:**

| Account | User Name | Path | Purpose |
|---------|-----------|------|---------|
| acme-co | terraform-user | `/` | Standard automation user |
| acme-co | temp-contractor | `/contractors/` | Non-root path testing |
| fort-knox | github-actions | `/service/` | Service account pattern |
| shared-foo-bar | legacy-developer | `/` | Human user pattern |
| security-tooling | cicd-deployer | `/automation/` | CI/CD automation |

**Expected Behavior:**
- All users discovered by IAM user analysis
- ARNs collected into allowlist
- Root-level SCP generated with `allowed_iam_users` parameter
- ARN transformation: account IDs replaced with `${local.X_account_id}` references

**Example Generated Allowlist:**
```hcl
iam_allowed_users = [
  "arn:aws:iam::${local.acme_co_account_id}:user/contractors/temp-contractor",
  "arn:aws:iam::${local.acme_co_account_id}:user/terraform-user",
  "arn:aws:iam::${local.fort_knox_account_id}:user/service/github-actions",
  "arn:aws:iam::${local.security_tooling_account_id}:user/automation/cicd-deployer",
  "arn:aws:iam::${local.shared_foo_bar_account_id}:user/legacy-developer",
]
```

#### STS Third-Party AssumeRole Test (`test_deny_sts_third_party_assumerole.tf`)

Creates IAM roles with diverse trust policy patterns to test RCP third-party detection.

**Test Roles (15 total in shared-foo-bar, 1 in acme-co, 1 in fort-knox):**

| Role Name | Account | Trust Policy | Third-Party IDs | Purpose |
|-----------|---------|--------------|-----------------|---------|
| ThirdPartyVendorA | acme-co | CrowdStrike | 999911114444 | Simple third-party |
| ThirdPartyVendorB | shared-foo-bar | Barracuda + Check Point | 999911116666, 999911110000 | Multiple third-parties |
| WildcardRole | fort-knox | `Principal: "*"` | N/A (wildcard) | Wildcard detection |
| LambdaExecutionRole | shared-foo-bar | `Service: lambda.amazonaws.com` | N/A (service) | Service principal skip |
| MultiServiceRole | shared-foo-bar | Multiple services | N/A (services) | Service array handling |
| MixedPrincipalsRole | shared-foo-bar | CyberArk + EC2 service | 999900007777 | Mixed AWS + Service |
| SAMLFederationRole | shared-foo-bar | SAML provider | N/A (federated) | Federated SAML |
| OIDCFederationRole | shared-foo-bar | GitHub OIDC | N/A (federated) | Federated OIDC |
| OrgAccountCrossAccess | shared-foo-bar | Duckbill Group | 999900004444 | Org-external account |
| ComplexMultiStatementRole | shared-foo-bar | Forcepoint + Lambda | 999900001111 | Multi-statement |
| ThirdPartyUserRole | shared-foo-bar | Sophos w/ ExternalId | 999911117777 | ExternalId condition |
| PlainAccountIdRole | shared-foo-bar | Vectra (plain ID) | 999900002222 | Plain account ID format |
| MixedFormatsRole | shared-foo-bar | Ermetic + Zesty | 999911112222, 999900005555 | ARN + plain ID mix |
| ConditionalThirdPartyRole | shared-foo-bar | Duckbill w/ ExternalId | 999900004444 | Conditional trust |
| UltraComplexRole | shared-foo-bar | Check Point + CrowdStrike + ECS + SAML | 999900006666, 999911114444 | Complex multi-statement |

**Third-Party Account IDs (Real Vendors):**
- 999911114444: CrowdStrike
- 999911116666: Barracuda
- 999911110000: Check Point
- 999900007777: CyberArk
- 999900001111: Forcepoint
- 999911117777: Sophos
- 999900002222: Vectra
- 999911112222: Ermetic
- 999900005555: Zesty
- 999900004444: Duckbill Group
- 999900006666: Check Point (additional account)

**All Roles Attached Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*"
  }]
}
```

**Rationale:** Roles are intentionally "useless" (deny-all policy) and exist solely for trust policy analysis.

**Expected Behavior:**
- Wildcard role (fort-knox) flagged as a violation of
  `deny_sts_third_party_assumerole`
- Fort-knox excluded from that one check's RCP placement. The wildcard sits in
  an IAM role trust policy, which says nothing about the account's ECR, KMS,
  S3, Secrets Manager or SQS resource policies, so fort-knox still receives
  recommendations for those five checks
- Shared-foo-bar: 11 unique third-party accounts detected
- Acme-co: 1 third-party account (CrowdStrike)
- OU-level STS RCP not possible while fort-knox is in the OU; the OU stays
  eligible for the other five checks
- Account-level RCPs generated for accounts with no blocker for the check
  being placed

#### EC2 IMDSv1 Test (`test_deny_ec2_imds_v1/`)

**⚠️ Cost Warning:** This directory is **separate** because EC2 instances incur ongoing costs. Instances should only be created during active testing.

**Cost:** ~$0.029/hour (~$20.90/month) for 5 t2.nano instances.

**Test Instances:**

| Instance | Account | IMDS Config | Exemption tag | Expected Result |
|----------|---------|-------------|---------------|-----------------|
| test-imdsv1-enabled | shared-foo-bar | `http_tokens = "optional"` | none | **Violation** |
| test-imdsv2-only | acme-co | `http_tokens = "required"` | none | Compliant |
| test-imdsv1-exempt | fort-knox | `http_tokens = "optional"` | on its IAM **role** | **Exemption** |
| test-imdsv1-instance-tagged-only | shared-foo-bar | `http_tokens = "optional"` | on the **instance** | **Violation** |
| test-imds-disabled-tokens-optional | acme-co | `http_endpoint = "disabled"`, `http_tokens = "optional"` | none | **Violation** |

The last two are the regression cases. An instance tag exempts nothing, because
no statement in the policy reads instance tags. An instance with the metadata
endpoint disabled is still a violation while its tokens are optional, matching
how `deny_ec2_imds_hop_limit` counts its hop limit. The SCP reads the launch
request, where turning the endpoint off leaves `HttpTokens` unnamed and
`ec2:MetadataHttpTokens` absent for `StringNotEquals` to fire on - confirmed
denied by dry run against a live account. The remedy is to name
`HttpTokens=required` anyway, which AWS accepts alongside a disabled endpoint
and which changes no behaviour.

**Separate Directory Structure:**
```
test_deny_ec2_imds_v1/
├── README.md         # Cost warnings and usage instructions
├── providers.tf      # Cross-account providers (reuses org account IDs)
├── data.tf          # AMI data source (Amazon Linux 2023)
└── ec2_instances.tf # Instance definitions
```

**Usage Pattern:**
```bash
# Only when testing
cd test_deny_ec2_imds_v1/
terraform init
terraform apply

# Run Headroom analysis
cd ..
python -m headroom --config config.yaml

# Destroy immediately after testing
cd test_deny_ec2_imds_v1/
terraform destroy
```

**AMI Selection:** Uses latest Amazon Linux 2023 (free tier eligible, HVM, EBS).

### Modules

#### `modules/headroom_role/`

Reusable module for deploying Headroom IAM role across accounts.

**Files:**
- `main.tf`: Role resource and policy attachments
- `variables.tf`: `account_id_to_trust` input
- `outputs.tf`: Role ARN and name
- `versions.tf`: Terraform version constraints

**Permissions:**
- `ViewOnlyAccess` (AWS managed policy): Read-only access to most services
- `SecurityAudit` (AWS managed policy): Security-focused read permissions

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Action": "sts:AssumeRole",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::{account_id_to_trust}:root"
    }
  }]
}
```

**Rationale:** Security tooling accounts commonly have broad read access across organization.

#### `modules/scps/`

Production-ready SCP module used by generated Terraform files.

**Files:**
- `scps.tf`: Policy resource and attachments
- `locals.tf`: Statement filtering logic
- `variables.tf`: Boolean flags and allowlists
- `README.md`: Usage documentation

**Key Variables:**
```hcl
variable "target_id" {
  type        = string
  description = "OU ID or account ID to attach SCP"
}

variable "deny_ec2_imds_v1" {
  type    = bool
  default = false
}

variable "deny_iam_user_creation" {
  type    = bool
  default = false
}

variable "iam_allowed_users" {
  type        = list(string)
  default     = []
  description = "IAM user ARNs allowed to be created"
}
```

**Statement Filtering Logic:**
```hcl
locals {
  statements = [
    {
      include = var.deny_ec2_imds_v1,
      statement = {
        Action = "ec2:RunInstances"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      }
    },
    {
      include = var.deny_iam_user_creation,
      statement = {
        Action = "iam:CreateUser"
        NotResource = var.allowed_iam_users
      }
    }
  ]

  enabled_statements = [for s in local.statements : s.statement if s.include]
}
```

**See:** [modules/scps/README.md](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/scps#scps-module)

#### `modules/rcps/`

Production-ready RCP module used by generated Terraform files.

**Files:**
- `rcps.tf`: Policy resource and attachments
- `locals.tf`: RCP policy document
- `data.tf`: Organization data source
- `variables.tf`: Allowlist configuration
- `README.md`: Usage documentation

**Key Variables:**
```hcl
variable "target_id" {
  type        = string
  description = "Organization account, root, or unit."
}

# One enable flag + one allowlist variable per registered RCP check,
# alphabetical by service: ECR, KMS, S3, Secrets Manager, SQS, STS, then
# the service confused deputy check, which names no service and so sits
# after the alphabetical run rather than inside it.
#
# STS is shown below. ECR, KMS, S3 and SQS follow exactly this shape.
# Secrets Manager does not: its allowlist is named
# `secrets_manager_third_party_account_ids_allowlist`, with no `_access_`
# segment, while its enable flag `deny_secrets_manager_third_party_access`
# keeps the segment. Deriving the allowlist name from the pattern produces
# `secrets_manager_third_party_access_account_ids_allowlist`, which
# `terraform plan` rejects with "An argument named ... is not expected here".
# Do not normalize it.
#
# The service confused deputy check is a third shape:
# `service_confused_deputy_source_account_ids_allowlist`, with `source_`
# before `account_ids` because the list holds the accounts a service acted
# for rather than the calling principals. The pattern would predict
# `service_confused_deputy_account_ids_allowlist`. Do not normalize that one
# either.

variable "deny_sts_third_party_assumerole" {
  type        = bool
  description = "Deny STS AssumeRole from third-party accounts except those in the allowlist."
}

variable "sts_third_party_assumerole_account_ids_allowlist" {
  type        = list(string)
  default     = []
  description = "Allowlist of third-party AWS account IDs that are permitted to assume roles in this target ID."
}
```

**RCP Policy Logic:**

Each included statement denies its own service's actions - `ecr:*`, `kms:*`,
`s3:*`, `secretsmanager:*`, `sqs:*`, or `sts:AssumeRole` - EXCEPT when:
1. The principal belongs to the organization (`aws:PrincipalOrgID`)
2. The principal belongs to an allowlisted third-party account
   (`aws:PrincipalAccount`, against that statement's own allowlist variable).
   An empty allowlist omits this key, leaving condition 1 to deny all outsiders.
3. The caller is an AWS service
   (`BoolIfExists { "aws:PrincipalIsAWSService" = "false" }`)

Conditions 1 and 2 share one `StringNotEqualsIfExists` block and condition 3 is
a separate `BoolIfExists`. A `Condition` map ANDs its blocks, so a statement
denies only a principal for which none of the three exceptions hold at once:
outside the organization, absent from that statement's allowlist, and not an
AWS service.

The seventh statement, `DenyServiceConfusedDeputy`, inverts condition 3 rather
than repeating it, and is the one statement covering all six services at once.
It denies when the caller **is** an AWS service (`Bool` `true`) acting for a
source account that is neither in the organization (`aws:SourceOrgID`) nor in
its own allowlist (`aws:SourceAccount`), and only when the request carries a
source account at all - `Null { "aws:SourceAccount" = "false" }` reads as "the
key is present". A service call populating only `aws:SourceArn`, or no source
keys at all, falls outside it, so it narrows the service exemption the other
six must carry rather than closing it. See Service Confused Deputy under RCP
Checks.

**No resource-tag exemption.** An earlier revision carried a fourth exception,
`aws:ResourceTag/dp:exclude:identity = "true"`. Anyone holding the service's
tagging permission can set that tag, so the account an RCP exists to constrain
could exempt its own resources from it. It was inert on S3 regardless: S3 does
not populate `aws:ResourceTag` for ordinary bucket and object access.

A check whose `deny_*` flag is `false` contributes no statement at all, so
checks placed at different levels of the hierarchy never weaken one another.

**See:** [modules/rcps/README.md](https://github.com/discocrayon/Headroom/tree/main/test_environment/modules/rcps#rcps-module)

### Generated Outputs

#### `scps/` Directory (Generated by Headroom)

**`grab_org_info.tf`**

Auto-generated Organization data sources with validation logic.

```hcl
# Auto-generated by Headroom

data "aws_organizations_organization" "org" {}

data "aws_organizations_organizational_units" "root_ou" {
  parent_id = data.aws_organizations_organization.org.roots[0].id
}

data "aws_organizations_organizational_unit_child_accounts" "high_value_assets_accounts" {
  parent_id = local.high_value_assets_ou_id
}

locals {
  # Root validation
  validation_check_root = (length(data.aws_organizations_organization.org.roots) == 1) ?
    "All good. This is a no-op." :
    error("[Error] Expected exactly 1 root, found ${length(data.aws_organizations_organization.org.roots)}")

  root_ou_id = data.aws_organizations_organization.org.roots[0].id

  # OU validation
  validation_check_high_value_assets_ou = (length([
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "high_value_assets"
  ]) == 1) ? "All good." : error("[Error] Expected 1 high_value_assets OU")

  high_value_assets_ou_id = [
    for ou in data.aws_organizations_organizational_units.root_ou.children :
    ou.id if ou.name == "high_value_assets"
  ][0]

  # Account validation
  validation_check_fort_knox_account = (length([
    for account in data.aws_organizations_organizational_unit_child_accounts.high_value_assets_accounts.accounts :
    account.id if account.name == "fort-knox"
  ]) == 1) ? "All good." : error("[Error] Expected 1 fort-knox account")

  fort_knox_account_id = [
    for account in data.aws_organizations_organizational_unit_child_accounts.high_value_assets_accounts.accounts :
    account.id if account.name == "fort-knox"
  ][0]
}
```

**Purpose:** Provides locals for SCP Terraform files to reference; validates organization structure at plan time.

**`root_scps.tf`**

Example of root-level SCP deployment (generated when all accounts 100% compliant).

```hcl
# Auto-generated SCP Terraform configuration for Organization Root
# Generated by Headroom based on compliance analysis

module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  # EC2
  deny_ec2_imds_v1 = false

  # IAM
  deny_iam_user_creation = true
  iam_allowed_users = [
    "arn:aws:iam::${local.fort_knox_account_id}:user/service/github-actions",
    "arn:aws:iam::${local.security_tooling_account_id}:user/automation/cicd-deployer",
    "arn:aws:iam::${local.acme_co_account_id}:user/contractors/temp-contractor",
    "arn:aws:iam::${local.acme_co_account_id}:user/terraform-user",
    "arn:aws:iam::${local.shared_foo_bar_account_id}:user/legacy-developer",
  ]
}
```

**Note:** `deny_ec2_imds_v1 = false` because EC2 test instances create violations. In real environment with 100% compliance, this would be `true`.

**`{ou_path}_ou_scps.tf`**

Example of OU-level SCP deployment.

```hcl
# Auto-generated SCP Terraform configuration for high_value_assets OU
# Generated by Headroom based on compliance analysis

module "scps_high_value_assets_ou" {
  source = "../modules/scps"
  target_id = local.high_value_assets_ou_id

  # EC2
  deny_ec2_imds_v1 = true

  # IAM
  deny_iam_user_creation = false
}
```

**`{account_name}_scps.tf`**

Example of account-level SCP deployment.

```hcl
# Auto-generated SCP Terraform configuration for fort-knox
# Generated by Headroom based on compliance analysis

module "scps_fort_knox" {
  source = "../modules/scps"
  target_id = local.fort_knox_account_id

  # EC2
  deny_ec2_imds_v1 = true

  # IAM
  deny_iam_user_creation = false
}
```

#### `rcps/` Directory (Generated by Headroom)

**`grab_org_info.tf`**

Identical structure to `scps/grab_org_info.tf` (Organization data sources with validation).

**`{ou_path}_ou_rcps.tf`**

Example of OU-level RCP deployment (union of third-party accounts).

```hcl
# Auto-generated RCP Terraform configuration for acme_acquisition OU
# Generated by Headroom based on third-party account analysis

module "rcps_acme_acquisition_ou" {
  source = "../modules/rcps"
  target_id = local.acme_acquisition_ou_id

  # ECR
  deny_ecr_third_party_access = false

  # KMS
  deny_kms_third_party_access = false

  # S3
  deny_s3_third_party_access = false

  # Secrets Manager
  deny_secrets_manager_third_party_access = false

  # SQS
  deny_sqs_third_party_access = false

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
    "999911114444",
  ]

  # Service confused deputy
  deny_service_confused_deputy = false
}
```

**Note:** Only contains CrowdStrike (999911114444) because acme-co is the only account in this OU and it only trusts CrowdStrike.

**`{account_name}_rcps.tf`**

Example of account-level RCP deployment.

```hcl
# Auto-generated RCP Terraform configuration for shared-foo-bar
# Generated by Headroom based on third-party account analysis

module "rcps_shared_foo_bar" {
  source = "../modules/rcps"
  target_id = local.shared_foo_bar_account_id

  # ECR
  deny_ecr_third_party_access = false

  # KMS
  deny_kms_third_party_access = false

  # S3
  deny_s3_third_party_access = false

  # Secrets Manager
  deny_secrets_manager_third_party_access = false

  # SQS
  deny_sqs_third_party_access = false

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
    "999900001111",
    "999900002222",
    "999900004444",
    "999900005555",
    "999900006666",
    "999900007777",
    "999911110000",
    "999911112222",
    "999911114444",
    "999911116666",
    "999911117777",
  ]

  # Service confused deputy
  deny_service_confused_deputy = false
}
```

**Note:** Contains all 11 third-party accounts detected in shared-foo-bar's IAM roles.

#### `headroom_results/` Directory (Generated by Headroom)

**Directory Structure:**
```
headroom_results/
├── scps/
│   ├── deny_ec2_imds_v1/
│   │   ├── acme-co.json
│   │   ├── fort-knox.json
│   │   ├── security-tooling.json
│   │   └── shared-foo-bar.json
│   └── deny_iam_user_creation/
│       ├── acme-co.json
│       ├── fort-knox.json
│       ├── security-tooling.json
│       └── shared-foo-bar.json
└── rcps/
    └── deny_sts_third_party_assumerole/
        ├── acme-co.json
        ├── fort-knox.json
        ├── security-tooling.json
        └── shared-foo-bar.json
```

**Example: `scps/deny_ec2_imds_v1/acme-co.json`**
```json
{
  "summary": {
    "account_name": "acme-co",
    "check": "deny_ec2_imds_v1",
    "total_instances": 1,
    "violations": 0,
    "exemptions": 0,
    "compliant": 1,
    "compliance_percentage": 100.0
  },
  "violations": [],
  "exemptions": [],
  "compliant_instances": [
    {
      "region": "us-east-1",
      "instance_id": "i-fake0acmeco000001",
      "imdsv1_allowed": false,
      "exemption_tag_present": false
    }
  ]
}
```

**Example: `scps/deny_iam_user_creation/acme-co.json`**
```json
{
  "summary": {
    "account_name": "acme-co",
    "check": "deny_iam_user_creation",
    "total_users": 2,
    "users": [
      "arn:aws:iam::REDACTED:user/contractors/temp-contractor",
      "arn:aws:iam::REDACTED:user/terraform-user"
    ]
  },
  "violations": [],
  "exemptions": [],
  "compliant_instances": [
    {
      "user_name": "temp-contractor",
      "user_arn": "arn:aws:iam::REDACTED:user/contractors/temp-contractor",
      "path": "/contractors/"
    },
    {
      "user_name": "terraform-user",
      "user_arn": "arn:aws:iam::REDACTED:user/terraform-user",
      "path": "/"
    }
  ]
}
```

**Note:** ARNs show `REDACTED` because example results were generated with `exclude_account_ids: true` in config.

**Example: `rcps/deny_sts_third_party_assumerole/shared-foo-bar.json`**
```json
{
  "summary": {
    "account_name": "shared-foo-bar",
    "check": "deny_sts_third_party_assumerole",
    "total_roles_analyzed": 11,
    "roles_third_parties_can_access": 10,
    "roles_with_wildcards": 1,
    "violations": 1,
    "unique_third_party_accounts": [
      "999900001111",
      "999900002222",
      "999900004444",
      "999900005555",
      "999900006666",
      "999900007777",
      "999911110000",
      "999911112222",
      "999911114444",
      "999911116666",
      "999911117777"
    ],
    "third_party_account_count": 11
  },
  "roles_third_parties_can_access": [
    {
      "role_name": "ThirdPartyVendorA",
      "role_arn": "arn:aws:iam::REDACTED:role/ThirdPartyVendorA",
      "third_party_account_ids": ["999911114444"],
      "has_wildcard_principal": false
    }
  ],
  "roles_with_wildcards": [
    {
      "role_name": "WildcardRole",
      "role_arn": "arn:aws:iam::REDACTED:role/WildcardRole",
      "third_party_account_ids": [],
      "has_wildcard_principal": true
    }
  ]
}
```

### Reproducibility Guide

#### Prerequisites

1. AWS Organizations with management account access
2. Terraform installed (v1.0+)
3. AWS CLI configured with management account credentials
4. Python 3.13+ with requirements installed
5. Headroom configuration file

#### Initial Setup

**Step 1: Configure Variables**

```bash
cd test_environment/
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:
```hcl
base_email = "your-email+aws@example.com"
```

**Note:** Uses email + addressing to create unique emails per account.

**Step 2: Deploy Core Infrastructure**

```bash
terraform init
terraform plan
terraform apply
```

This creates:
- 3 organizational units
- 4 member accounts
- OrgAndAccountInfoReader role in management account
- Headroom roles in all member accounts
- Test IAM users
- Test IAM roles with trust policies

**Expected Time:** 10-15 minutes (account creation is slow).

**Step 3: Configure Headroom**

Create `my_config.yaml` in repo root:
```yaml
management_account_id: '222222222222'  # Your management account ID
exclude_account_ids: false
use_account_name_from_tags: false

account_tag_layout:
  environment: 'Environment'
  name: 'Name'
  owner: 'Owner'
```

**Note:** Omit `security_analysis_account_id` if running from security-tooling account.

#### Running Headroom Analysis

**Step 1: Execute Headroom**

```bash
# From repo root
python -m headroom --config my_config.yaml
```

**Expected Output:**
```
================================================================================
SCP/RCP PLACEMENT RECOMMENDATIONS
================================================================================

Check: deny_iam_user_creation
Recommended Level: ROOT
Affected Accounts: 4
Compliance: 100.0%
Reasoning: All accounts in organization have zero violations - safe to deploy at root level
----------------------------------------

Check: deny_sts_third_party_assumerole
Recommended Level: OU
Affected Target: acme_acquisition (ou-xxxx-xxxxxxxx)
Affected Accounts: 1
Third-Party Accounts: 1
Reasoning: All accounts under this OU allow the same third-party accounts with no violations - safe for OU-level RCP
----------------------------------------
```

**Step 2: Verify Generated Files**

Check that files were created:
```bash
ls test_environment/scps/
# grab_org_info.tf
# root_scps.tf
# high_value_assets_ou_scps.tf  (if applicable)

ls test_environment/rcps/
# grab_org_info.tf
# acme_acquisition_ou_rcps.tf
# security_tooling_rcps.tf

ls test_environment/headroom_results/scps/deny_iam_user_creation/
# acme-co.json
# fort-knox.json
# security-tooling.json
# shared-foo-bar.json
```

**Step 3: Review Results**

Compare generated files with examples in repository:
- `test_environment/scps/root_scps.tf`
- `test_environment/rcps/acme_acquisition_ou_rcps.tf`
- `test_environment/headroom_results/scps/deny_iam_user_creation/acme-co.json`

#### Testing EC2 IMDSv1 Check (Optional)

**⚠️ Warning:** Creates billable EC2 instances (~$12.54/month if left running).

```bash
cd test_environment/test_deny_ec2_imds_v1/
terraform init
terraform apply

# Run Headroom again
cd ../..
python -m headroom --config my_config.yaml

# Check updated results
cat test_environment/headroom_results/scps/deny_ec2_imds_v1/acme-co.json

# Destroy instances immediately
cd test_environment/test_deny_ec2_imds_v1/
terraform destroy
```

**Expected Results:**
- `acme-co`: 1 compliant instance (IMDSv2 required)
- `fort-knox`: 1 exemption (IMDSv1 allowed but tagged)
- `shared-foo-bar`: 1 violation (IMDSv1 allowed, no exemption)

#### Cleanup

**Destroy Member Account Resources:**
```bash
cd test_environment/test_deny_ec2_imds_v1/
terraform destroy  # If EC2 instances exist

cd ..
terraform destroy -target=aws_iam_user.terraform_user
terraform destroy -target=aws_iam_user.github_actions
terraform destroy -target=aws_iam_user.legacy_developer
terraform destroy -target=aws_iam_user.cicd_deployer
terraform destroy -target=aws_iam_user.temp_contractor
terraform destroy -target=aws_iam_role.third_party_vendor_a
terraform destroy -target=aws_iam_role.wildcard_role
# ... repeat for all IAM roles
```

**Note:** AWS Organizations accounts cannot be deleted via Terraform or API. Must be deleted manually via AWS Console:
1. Remove all resources from accounts
2. Close accounts via AWS Organizations console
3. Wait 90 days for account closure to complete

### Expected Test Scenarios & Results

#### Scenario 1: All Accounts Compliant (IAM Users)

**Initial State:** 5 IAM users across 4 accounts, no violations.

**Expected Results:**
- Root-level SCP recommended
- All 5 user ARNs in allowlist
- ARNs transformed with `${local.X_account_id}` references
- Compliance: 100%

**Generated File:** `scps/root_scps.tf`

#### Scenario 2: Third-Party Access without Wildcards (acme-co)

**Initial State:** 1 role trusting CrowdStrike, no wildcards.

**Expected Results:**
- OU-level RCP recommended (if other accounts in OU also compliant)
- Third-party allowlist: `["999911114444"]`
- Compliance: 100%

**Generated File:** `rcps/acme_acquisition_ou_rcps.tf`

#### Scenario 3: Wildcard Principal Detection (fort-knox)

**Initial State:** 1 role with `Principal: "*"` wildcard.

**Expected Results:**
- Violation flagged in the `deny_sts_third_party_assumerole` results JSON
- Account excluded from that check's RCP placement at every level. Placement
  runs once per check against only that check's blocked accounts, and a
  trust-policy wildcard blocks STS alone
- OU-level STS RCP not possible if fort-knox is in the OU; the OU remains
  eligible for the other five checks
- The other five checks write a result file for fort-knox like any other
  account and place it normally
- CloudTrail analysis recommended (future feature)

**Generated File:** Whichever file covers fort-knox for the five checks it does
not block - the root file, its OU file, or `rcps/fort_knox_rcps.tf` at account
level, depending on where each check places. Only the STS statement is switched
off for it; one wildcard no longer excludes the account from every RCP.

#### Scenario 4: EC2 IMDSv1 with Exemptions (fort-knox)

**Initial State:** 1 EC2 instance with IMDSv1 enabled + `ExemptFromIMDSv2` tag.

**Expected Results:**
- Instance categorized as "exemption"
- Account compliance: 100%
- Compliance calculation: (exemptions + compliant) / total
- Eligible for OU or root-level SCP

**Generated File:** `scps/high_value_assets_ou_scps.tf` (if all accounts in OU compliant).

#### Scenario 5: Multiple Third-Party Accounts (shared-foo-bar)

**Initial State:** 15 roles trusting 11 unique third-party accounts + 1 wildcard.

**Expected Results:**
- Wildcard violation flagged for `deny_sts_third_party_assumerole`
- Account excluded from STS RCP placement at every level, account level
  included: a blocked account is kept out of that check's
  `account_third_party_map` entirely, so none of its 11 trust-policy
  third-party IDs reach an STS allowlist
- The wildcard is in a trust policy, so it blocks STS only. The ECR, KMS, S3,
  Secrets Manager and SQS checks place shared-foo-bar normally, and the
  third-party IDs those checks find do reach their allowlists

**Generated File:** Whichever file covers shared-foo-bar for the five checks it
does not block. No file carries an STS statement for this account.

### Integration with Development Workflow

#### Unit Tests vs Live Integration

| Aspect | Unit Tests (`tests/`) | Live Integration (`test_environment/`) |
|--------|----------------------|----------------------------------------|
| Execution | Mocked AWS API calls | Real AWS API calls |
| Speed | Fast (~10 seconds) | Slow (~5 minutes) |
| Cost | Free | ~$0 (without EC2) or ~$12/month (with EC2) |
| Coverage | Function-level | End-to-end workflow |
| Purpose | Verify code correctness | Verify AWS integration |
| CI/CD | Runs on every commit | Manual execution |

#### When to Update Test Environment

1. **New Check Added:** Add test scenarios in `test_deny_{check_name}.tf`
2. **Policy Changes:** Update `modules/scps/` or `modules/rcps/` and regenerate
3. **Organization Structure Changes:** Modify `organizational_units.tf` and `accounts.tf`
4. **Breaking Changes:** Rebuild from scratch to verify reproducibility
5. **Documentation Updates:** Regenerate example outputs for README.md

#### Committing Generated Files

**Philosophy:** Generated files are committed to demonstrate tool output and provide documentation.

**What to Commit:**
- `scps/*.tf` (generated SCP Terraform)
- `rcps/*.tf` (generated RCP Terraform)
- `headroom_results/**/*.json` (JSON analysis results)

**What NOT to Commit:**
- `terraform.tfstate` (contains sensitive account IDs)
- `terraform.tfvars` (contains personal email)
- `test_deny_ec2_imds_v1/terraform.tfstate` (EC2 instance IDs)

**Gitignore Pattern:**
```
test_environment/terraform.tfstate*
test_environment/test_deny_ec2_imds_v1/terraform.tfstate*
test_environment/terraform.tfvars
```

#### Documentation-by-Example

The test environment serves as executable documentation:

1. **README.md Examples:** Code blocks reference actual generated files
2. **Module READMEs:** Point to test environment usage patterns
3. **Specification:** References test environment for concrete examples
4. **Onboarding:** New contributors deploy test environment to understand workflow

### Cost Considerations

#### Ongoing Costs (Without EC2)

- **AWS Organizations:** Free
- **IAM Roles:** Free
- **IAM Users:** Free
- **Data Sources:** Free (query costs negligible)

**Total: $0/month**

#### Ongoing Costs (With EC2 Instances)

- **3x t2.nano instances:** ~$12.54/month
- **Data Transfer:** Negligible (no network traffic)
- **EBS Volumes:** Included with t2.nano

**Total: ~$12.54/month** (if instances left running)

**Recommendation:** Keep EC2 instances destroyed except during active testing.

#### One-Time Costs

- **AWS Account Creation:** Free
- **Terraform State Storage:** Free (local state)
- **API Calls:** Negligible (covered by free tier)

#### Cost Optimization Tips

1. Destroy EC2 instances immediately after testing
2. Use `terraform.tfstate` locally (no S3 costs)
3. Run Headroom infrequently (API calls are cheap but not free)
4. Close unused member accounts after testing (90-day process)

---

## IAM Role Requirements

### OrganizationAccountAccessRole
- **Location:** Security analysis account
- **Required:** Only if running from management account
- **Not Required:** If running directly from security analysis account
- **Trusted By:** Management account (or wherever you run Headroom from)
- **Purpose:** Initial role assumption to enter security analysis account

### OrgAndAccountInfoReader
- **Location:** Management account
- **Required:** Always
- **Trusted By:** Security analysis account
- **Permissions:**
  - `organizations:DescribeAccount`
  - `organizations:DescribeOrganization`
  - `organizations:DescribeOrganizationalUnit`
  - `organizations:ListAccounts`
  - `organizations:ListAccountsForParent`
  - `organizations:ListChildren`
  - `organizations:ListOrganizationalUnitsForParent`
  - `organizations:ListParents`
  - `organizations:ListRoots`
  - `organizations:ListTagsForResource`
- **Purpose:** Query Organizations API for account discovery and hierarchy analysis
- **Reference Implementation:** See `test_environment/org_and_account_info_reader.tf`

### Headroom
- **Location:** All accounts (including management, excluding security analysis if running from there)
- **Required:** Always
- **Trusted By:** Security analysis account
- **Permissions:**
  - **EC2:** `ec2:DescribeRegions`, `ec2:DescribeInstances`
  - **IAM:** `iam:ListUsers`, `iam:ListRoles` (both covered by AWS managed `SecurityAudit`, which grants `iam:Get*` and `iam:List*`)
- **Purpose:** Execute compliance checks in each account
- **Reference Implementation:** See `test_environment/modules/headroom_role/` and `test_environment/headroom_roles.tf`

---

## Result Structure

### Directory Layout

```
{results_dir}/
├── scps/
│   ├── deny_ec2_imds_v1/
│   │   ├── account-name_111111111111.json
│   │   ├── another-account_222222222222.json
│   │   └── ...
│   └── deny_iam_user_creation/
│       ├── account-name_111111111111.json
│       └── ...
└── rcps/
    └── deny_sts_third_party_assumerole/
        ├── account-name_111111111111.json
        └── ...
```

### Result File Format

**Common Structure:**
```json
{
  "summary": {
    "account_name": "string",
    "account_id": "string",
    "check": "string",
    ...check-specific fields...
  },
  "violations": [...],
  "exemptions": [...],
  "compliant_instances": [...]
}
```

**See:** Test Environment section for complete example result files in `test_environment/headroom_results/`.

---

## Future Roadmap

- Additional SCP checks (S3, VPC, CloudFormation, etc.)
- CloudTrail historical analysis for wildcard principal resolution
- Condition-aware RCP analysis: treat a wildcard principal confined by `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, or `aws:PrincipalAccount` as scoped rather than as a blocker
- OU-based account filtering (filter by OU, environment, owner)
- Metrics-based decision making for policy deployment
- GitHub Actions integration for CI/CD pipelines
- Advanced SCP deployment strategies (phased rollout, canary deployments)

---

*This specification describes the complete Headroom product as of version 5.0.*
