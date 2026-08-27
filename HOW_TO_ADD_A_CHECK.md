# How to Add a New Check to Headroom

```yaml
# LLM Metadata
document_type: implementation_guide
target_audience: [ai_assistant, experienced_developer]
context_dependencies:
  - headroom/checks/base.py
  - headroom/checks/registry.py
  - documentation/POLICY_TAXONOMY.md
version: 2.0
last_updated: 2025-11-17
optimization: llm_first
```

---

## 🤖 Quick Start Decision Tree

```json
{
  "step_1_check_type": {
    "question": "What are you analyzing?",
    "options": {
      "AWS_Resources": {
        "check_type": "SCP",
        "directory": "headroom/checks/scps/",
        "examples": ["Unencrypted RDS", "EC2 with IMDSv1"],
        "focus": "Resource compliance violations"
      },
      "IAM_Trust_Policies": {
        "check_type": "RCP",
        "directory": "headroom/checks/rcps/",
        "examples": ["Third-party access", "Cross-account"],
        "focus": "Who can access what"
      }
    }
  },
  "step_2_pattern": {
    "reference": "documentation/POLICY_TAXONOMY.md",
    "common_patterns": {
      "Pattern_1": "Absolute Deny (no conditions)",
      "Pattern_2": "Conditional Deny (most common for SCPs)",
      "Pattern_4": "Exception Tag Allow (exemptions)",
      "Pattern_5a": "Account Allowlist (RCPs)",
      "Pattern_5b": "Resource ARN Allowlist (SCPs)"
    }
  }
}
```

---

## 📋 Implementation Checklist

```yaml
execution_order:
  phase_1_constants:
    file: headroom/constants.py
    action: add_constant
    format: "DENY_{SERVICE}_{DESCRIPTOR}"

  phase_2_aws_analysis:
    file: headroom/aws/{service}.py
    create:
      - dataclass model
      - analysis function with multi-region support
      - helper functions
    use_template: "aws_analysis_multiregion"

  phase_3_check_class:
    file: headroom/checks/{scps|rcps}/{check_name}.py
    create:
      - class inheriting BaseCheck[T]
      - @register_check decorator
      - analyze() method
      - categorize_result() method
      - build_summary_fields() method
    use_template: "check_class_scp" or "check_class_rcp"

  phase_4_terraform_module:
    files:
      - test_environment/modules/{scps|rcps}/variables.tf
      - test_environment/modules/{scps|rcps}/locals.tf
    add:
      - boolean variable
      - policy statement
    naming: "deny_{service}_{descriptor}"
    ordering: "alphabetical by service"

  phase_5_terraform_generation:
    file: headroom/terraform/generate_{scps|rcps}.py
    scp: "add parameter generation logic to _build_scp_terraform_module"
    rcp: |
      Add one RCP_TERRAFORM_VARIABLES entry naming the check's comment,
      enable variable, and allowlist variable. The renderer loops the table,
      so no branch needs editing. Parsing and placement are already driven by
      the registry and need no change.
    enforced_by: |
      test_table_covers_every_registered_rcp_check fails by name if a
      registered RCP check has no table entry. Do not silence it by removing
      the check from the registry.
    ordering: "alphabetical by service"

  phase_6_tests:
    files:
      - tests/test_aws_{service}.py
      - tests/test_checks_{check_name}.py
    min_coverage: 100
    scenarios: [mixed, all_compliant, all_violations, empty, edge_cases]

  phase_7_validation:
    commands:
      - "mypy headroom/ tests/"
      - "pytest tests/ --cov=headroom"
      - "tox"
    all_must_pass: true
```

---

## 🎯 File Templates

### Template: SCP Check Class (Pattern 2 - Conditional Deny)

```python
# FILE: headroom/checks/scps/{check_name}.py
# TEMPLATE: SCP_PATTERN_2
# USAGE: Copy entire file, replace {variables}

"""Check for {DESCRIPTION}."""

from typing import List

import boto3

from ...aws.{service} import {DataModel}, get_{check_name}_analysis
from ...constants import {CHECK_CONSTANT}
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", {CHECK_CONSTANT})
class {CheckClass}(BaseCheck[{DataModel}]):
    """Check for {DESCRIPTION}."""

    def analyze(self, session: boto3.Session) -> List[{DataModel}]:
        """Analyze {RESOURCE_TYPE} for {PURPOSE}."""
        return get_{check_name}_analysis(session)

    def categorize_result(
        self,
        result: {DataModel}
    ) -> tuple[str, JsonDict]:
        """Categorize single result."""
        result_dict = {
            # Map all dataclass fields:
            # "field_name": result.field_name,
        }

        if {VIOLATION_CONDITION}:
            return ("violation", result_dict)
        return ("compliant", result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> JsonDict:
        """Build summary statistics."""
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_{resources}": total,
            "violations": len(check_result.violations),
            "compliant": compliant_count,
            "compliance_percentage": compliance_pct,
        }
```

**Variables:**
- `{check_name}`: `deny_rds_unencrypted`
- `{CheckClass}`: `DenyRdsUnencryptedCheck`
- `{service}`: `rds`
- `{DataModel}`: `DenyRdsUnencrypted`
- `{CHECK_CONSTANT}`: `DENY_RDS_UNENCRYPTED`
- `{DESCRIPTION}`: `RDS databases without encryption`
- `{RESOURCE_TYPE}`: `databases`
- `{PURPOSE}`: `encryption configuration`
- `{VIOLATION_CONDITION}`: `not result.encrypted`
- `{resources}`: `databases`

---

### Template: SCP Check Class (Pattern 4 - With Exemptions)

```python
# FILE: headroom/checks/scps/{check_name}.py
# TEMPLATE: SCP_PATTERN_4
# DIFFERENCE: Adds exemption handling

def categorize_result(self, result: {DataModel}) -> tuple[str, JsonDict]:
    """Categorize with exemption support."""
    result_dict = {
        "field": result.field,
        "exemption_tag": result.exemption_tag_value,
    }

    # Check exemption FIRST
    if result.has_exemption_tag:
        return ("exemption", result_dict)

    # Then check violation
    if {VIOLATION_CONDITION}:
        return ("violation", result_dict)

    return ("compliant", result_dict)

def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
    """Build summary including exemptions in compliant count."""
    total = (
        len(check_result.violations) +
        len(check_result.exemptions) +
        len(check_result.compliant)
    )

    # CRITICAL: Include exemptions in compliant count
    compliant_count = len(check_result.compliant) + len(check_result.exemptions)
    compliance_pct = (compliant_count / total * 100) if total else 100

    return {
        "total_{resources}": total,
        "violations": len(check_result.violations),
        "exemptions": len(check_result.exemptions),
        "compliant": len(check_result.compliant),
        "compliance_percentage": compliance_pct,
    }
```

---

### Template: AWS Analysis Function (Multi-Region)

```python
# FILE: headroom/aws/{service}.py
# TEMPLATE: AWS_MULTIREGION_ANALYSIS
# USAGE: Copy entire file, replace {variables}

"""AWS {service} analysis functions for Headroom checks."""

from dataclasses import dataclass
from typing import List
import boto3
import logging
from botocore.exceptions import ClientError

from .helpers import get_all_regions

logger = logging.getLogger(__name__)


@dataclass
class {DataModel}:
    """
    Data model for {RESOURCE_TYPE} analysis.

    Attributes:
        field_name: str  # Description
    """
    # Define all fields with types


def get_{check_name}_analysis(
    session: boto3.Session
) -> List[{DataModel}]:
    """
    Analyze {RESOURCE_TYPE} across all regions.

    Algorithm:
    1. Get all regions via get_all_regions()
    2. For each region: analyze resources via paginator
    3. Return aggregated results

    Args:
        session: boto3.Session for target account

    Returns:
        List of {DataModel} results
    """
    all_results = []
    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing {resource} in {region}")
        regional_results = _analyze_{resource}_in_region(session, region)
        all_results.extend(regional_results)

    logger.info(f"Analyzed {len(all_results)} {resource} across {len(regions)} regions")
    return all_results


def _analyze_{resource}_in_region(
    session: boto3.Session,
    region: str
) -> List[{DataModel}]:
    """Analyze {resource} in specific region with pagination."""
    client = session.client("{service}", region_name=region)
    results = []

    # Separate try/except for paginator setup
    try:
        paginator = client.get_paginator("{operation}")
    except ClientError as e:
        logger.warning(f"Failed to get paginator in {region}: {e}")
        return []

    # Process pages
    for page in paginator.paginate():
        items = page.get("{ItemsKey}", [])

        for item in items:
            # Separate try/except for per-item processing
            try:
                result = _analyze_single_item(item, region)
                results.append(result)
            except ClientError as e:
                logger.warning(f"Failed to analyze item in {region}: {e}")
                continue

    return results


def _analyze_single_item(
    item: dict,
    region: str
) -> {DataModel}:
    """Extract data from single item."""
    return {DataModel}(
        # Map fields from item dict
    )
```

**Variables:**
- `{service}`: `rds`
- `{DataModel}`: `DenyRdsUnencrypted`
- `{check_name}`: `deny_rds_unencrypted`
- `{resource}`: `databases`
- `{RESOURCE_TYPE}`: `RDS instances and clusters`
- `{operation}`: `describe_db_instances`
- `{ItemsKey}`: `DBInstances`

---

### Template: RCP Check (Third-Party Access)

```python
# FILE: headroom/checks/rcps/{check_name}.py
# TEMPLATE: RCP_THIRD_PARTY_ACCESS
# USAGE: For RCP checks analyzing IAM policies

"""Check for {DESCRIPTION}."""

from typing import Any, List, Set

import boto3

from ...aws.{service} import {DataModel}, analyze_{service}_{resource}_policies
from ...constants import {CHECK_CONSTANT}
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("rcps", {CHECK_CONSTANT})
class {CheckClass}(BaseCheck[{DataModel}]):
    """Check for third-party access in {RESOURCE_TYPE}."""

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        org_account_ids: Set[str],  # RCP-specific
        **kwargs: Any
    ) -> None:
        """Initialize with organization account IDs."""
        super().__init__(check_name, account_name, account_id, results_dir, **kwargs)
        self.org_account_ids = org_account_ids

    def analyze(self, session: boto3.Session) -> List[{DataModel}]:
        """Analyze {RESOURCE_TYPE} policies."""
        return analyze_{service}_{resource}_policies(
            session,
            self.org_account_ids
        )

    def categorize_result(
        self,
        result: {DataModel}
    ) -> tuple[str, JsonDict]:
        """Categorize based on third-party access."""
        result_dict = {
            "resource_arn": result.resource_arn,
            "third_party_account_ids": sorted(result.third_party_account_ids),
        }

        if result.third_party_account_ids:
            return ("violation", result_dict)
        return ("compliant", result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> JsonDict:
        """Build summary with third-party allowlist."""
        all_third_party_ids: Set[str] = set()
        for violation in check_result.violations:
            third_party_ids = violation.get("third_party_account_ids", [])
            all_third_party_ids.update(third_party_ids)

        return {
            "total_{resources}": len(check_result.violations) + len(check_result.compliant),
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "third_party_account_ids_allowlist": sorted(all_third_party_ids),
        }
```

---

### Template: RCP AWS Analysis (Policy Extraction)

```python
# FILE: headroom/aws/{service}.py
# TEMPLATE: RCP_POLICY_ANALYSIS

"""AWS {service} policy analysis for third-party access detection."""

from dataclasses import dataclass
from typing import List, Set
import boto3
import json
import logging
import re
from botocore.exceptions import ClientError

from .helpers import get_all_regions
from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN

logger = logging.getLogger(__name__)


@dataclass
class {DataModel}:
    """Policy analysis result."""
    resource_arn: str
    all_account_ids: Set[str]
    third_party_account_ids: Set[str]
    region: str


def analyze_{service}_{resource}_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[{DataModel}]:
    """
    Analyze {resource} policies for third-party access.

    Args:
        session: boto3 session
        org_account_ids: Set of organization account IDs

    Returns:
        List of policy analysis results
    """
    all_results = []
    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing {resource} policies in {region}")
        regional_results = _analyze_policies_in_region(
            session,
            region,
            org_account_ids
        )
        all_results.extend(regional_results)

    logger.info(f"Analyzed {len(all_results)} {resource} across {len(regions)} regions")
    return all_results


def _analyze_policies_in_region(
    session: boto3.Session,
    region: str,
    org_account_ids: Set[str]
) -> List[{DataModel}]:
    """Analyze policies in specific region."""
    client = session.client("{service}", region_name=region)
    results = []

    # Get resources with policies
    try:
        paginator = client.get_paginator("{list_operation}")
    except ClientError as e:
        logger.warning(f"Failed to list {resource} in {region}: {e}")
        return []

    for page in paginator.paginate():
        resources = page.get("{ResourceKey}", [])

        for resource in resources:
            try:
                # Get policy for this resource
                policy_response = client.{get_policy_operation}(
                    {ResourceIdParam}=resource["{ResourceIdKey}"]
                )
                policy_str = policy_response.get("{PolicyKey}", "{}")
                policy = json.loads(policy_str)

                # Extract account IDs from policy
                all_account_ids = _extract_account_ids_from_policy(policy)

                # Identify third-party (non-org) accounts
                third_party_ids = all_account_ids - org_account_ids

                result = {DataModel}(
                    resource_arn=resource["{ArnKey}"],
                    all_account_ids=all_account_ids,
                    third_party_account_ids=third_party_ids,
                    region=region,
                )
                results.append(result)

            except ClientError as e:
                logger.warning(f"Failed to get policy for resource: {e}")
                continue

    return results


def _extract_account_ids_from_policy(policy: dict) -> Set[str]:
    """
    Extract all AWS account IDs from IAM policy.

    Handles various principal formats:
    - String: "arn:aws:iam::111111111111:root"
    - Dict: {"AWS": "arn:aws:iam::111111111111:root"}
    - List: {"AWS": ["arn:aws:iam::111111111111:root"]}
    """
    account_ids = set()

    for statement in policy.get("Statement", []):
        principal = statement.get("Principal", {})

        if isinstance(principal, str):
            account_ids.update(_extract_from_string(principal))
        elif isinstance(principal, dict):
            for key, value in principal.items():
                if isinstance(value, str):
                    account_ids.update(_extract_from_string(value))
                elif isinstance(value, list):
                    for item in value:
                        account_ids.update(_extract_from_string(item))

    return account_ids


def _extract_from_string(principal: str) -> Set[str]:
    """Extract account ID from principal string."""
    account_ids = set()

    # Match ARN format
    arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
    if arn_match:
        account_ids.add(arn_match.group(1))

    # Match raw account ID (12 digits)
    elif re.match(r'^\d{12}$', principal):
        account_ids.add(principal)

    return account_ids
```

**Variables:**
- `{service}`: `sqs`
- `{resource}`: `queues`
- `{DataModel}`: `SQSQueuePolicyAnalysis`
- `{list_operation}`: `list_queues`
- `{ResourceKey}`: `QueueUrls`
- `{get_policy_operation}`: `get_queue_attributes`
- `{ResourceIdParam}`: `QueueUrl`
- `{ResourceIdKey}`: URL or ARN key
- `{PolicyKey}`: `Policy`
- `{ArnKey}`: `QueueArn`

---

## ⚠️ Critical Code Standards

```yaml
type_annotations:
  rule: ALL functions must have complete type annotations
  no_any: Use JsonDict instead of Dict[str, Any]
  exception: "Only **kwargs: Any when matching base class"
  verify: "mypy headroom/ tests/"

imports:
  rule: ALL imports at top of file
  never:
    - imports inside functions
    - dynamic imports
  verify: "grep -r 'def.*:' -A 10 headroom/ | grep 'import '"

exceptions:
  rule: ONLY catch specific exceptions
  never:
    - "except Exception:"
    - "except:"
  pattern: Separate exception handlers by operation
  anti_pattern: Nested handlers for same exception type
  verify: "grep -r 'except Exception\\|except:' headroom/"

fail_fast:
  rule: Never silently return empty on unexpected data
  anti_pattern: "if isinstance(...) ... else: return []"
  principle: Let code crash on bad data with clear errors

test_coverage:
  requirement: 100%
  verify: "pytest --cov=headroom --cov-report=term-missing"
  scenarios:
    - mixed_compliance
    - all_compliant
    - all_violations
    - empty_results
    - edge_cases
```

---

## 🔧 Validation Commands

```bash
# Phase 1: Type checking (must pass)
mypy headroom/ tests/

# Phase 2: Unit tests (must pass, 100% coverage)
pytest tests/test_checks_{check_name}.py tests/test_aws_{service}.py -v --cov

# Phase 3: Integration tests (must pass)
pytest tests/ -v

# Phase 4: All quality checks (must pass)
tox

# Phase 5: Verify registration
python -c "from headroom.checks.registry import get_check_names; assert '{check_name}' in get_check_names()"
```

---

## 🚫 Anti-Patterns (DO NOT DO)

### AP-001: Using Any Type

```python
# ❌ BAD
def categorize_result(self, result: T) -> tuple[str, Dict[str, Any]]:
    pass

# ✅ GOOD
from ...types import JsonDict
def categorize_result(self, result: T) -> tuple[str, JsonDict]:
    pass
```

### AP-002: Imports Inside Functions

```python
# ❌ BAD
def analyze():
    from .helpers import get_regions  # WRONG

# ✅ GOOD
from .helpers import get_regions

def analyze():
    pass
```

### AP-003: Nested Exception Handlers

```python
# ❌ BAD - Confusing flow
try:
    paginator = client.get_paginator("list")
    for page in paginator.paginate():
        try:
            process(page)
        except ClientError:  # Nested same type
            pass
except ClientError:  # Outer same type
    pass

# ✅ GOOD - Separate by operation
try:
    paginator = client.get_paginator("list")
except ClientError as e:
    logger.error(f"Failed to get paginator: {e}")
    return []

for page in paginator.paginate():
    try:
        process(page)
    except ClientError as e:
        logger.warning(f"Failed to process page: {e}")
        continue
```

### AP-004: Defensive Empty Returns

```python
# ❌ BAD - Hides bugs
def normalize(actions):
    if isinstance(actions, str):
        return {actions}
    if isinstance(actions, list):
        return set(actions)
    return set()  # Silently returns empty on bad data!

# ✅ GOOD - Fails fast
def normalize(actions):
    if isinstance(actions, str):
        return {actions}
    return set(actions)  # Raises TypeError on bad data - good!
```

### AP-005: Wrong Variable Naming

```python
# ❌ BAD - Doesn't start with service
variable "allowed_ami_owners" {}

# ✅ GOOD - Starts with service name
variable "ec2_allowed_ami_owners" {}

# ❌ BAD - Service at end
DENY_IMDS_V1_EC2 = "deny_imds_v1_ec2"

# ✅ GOOD - Service after action
DENY_EC2_IMDS_V1 = "deny_ec2_imds_v1"
```

### AP-006: Not Using Existing Helpers

```python
# ❌ BAD - Duplicating region discovery
ec2_client = session.client("ec2")
regions_response = ec2_client.describe_regions()
regions = [r["RegionName"] for r in regions_response["Regions"]]

# ✅ GOOD - Use existing helper
from .helpers import get_all_regions
regions = get_all_regions(session)
```

### AP-007: Hardcoded Patterns

```python
# ❌ BAD - Duplicated regex across files
arn_match = re.match(r'^arn:aws:[^:]+:[^:]*:(\d{12}):', principal)

# ✅ GOOD - Use constant
from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN
arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
```

The copies drift, and they drift narrower. `roles.py`, `kms.py` and `ecr.py`
each carried `r'^arn:aws:iam::(\d{12}):'` while `s3.py`, `sqs.py` and
`secretsmanager.py` used the constant. The three copies silently dropped every
STS session principal and every non-commercial partition, so the accounts
never reached the allowlist and the RCP denied them.

---

### AP-008: String-Comparing IAM Policy Actions

```python
# ❌ BAD - misses sts:*, sts:Assume*, STS:AssumeRole, NotAction
has_assume_role = "sts:AssumeRole" in action or "*" in action

# ✅ GOOD - match the way IAM matches
if _grants_assume_role(statement, role_name):
```

IAM compares action names case-insensitively and expands `*` and `?` anywhere
in the name, and an `Allow` with `NotAction` grants everything its patterns do
not cover. A statement your analyzer fails to recognize is dropped in
silence - no violation, no error, just an account missing from an allowlist -
so the comparison has to follow IAM's rules, not Python's.

Prefer not gating on actions at all. Only the STS trust policy analyzer does;
the other five read every `Allow` statement and keep actions for reporting.
If you must gate, a statement naming both `Action` and `NotAction`, or
neither, should raise rather than be guessed at.

### AP-009: Scanning a Different Dimension Than the Policy Enforces

```python
# ❌ BAD - the SCP exempts by role tag; this reads the instance's tags
for tag in instance.get('Tags', []):
    if tag['Key'] == 'ExemptFromIMDSv2' and tag['Value'].lower() == 'true':
        exemption_tag_present = True

# ✅ GOOD - read the dimension the condition key reads
resolved = resolve_instance_profile_role(iam_client, profile_arn)
role_exemption_tag_present = (
    resolved.tags.get(IMDS_EXEMPTION_TAG_KEY) == IMDS_EXEMPTION_TAG_VALUE
)
```

*Both halves of this example are historical, and the verdict was
statement-specific.* The role tag was right for `DenyRoleDeliveryLessThan2`,
which exempts on `aws:PrincipalTag`. That statement was later removed (AP-011),
leaving only the launch-time one, which exempts on `aws:RequestTag` - and for
*that* statement the instance's own tag is the correct thing to read, because
`TagSpecifications` populates the request key and tags the instance in one
act. The check reads instance tags again today.

So do not read this entry as "instance tags are always wrong". Read it as: the
dimension is a property of the statement, and it changes when the statement
does. Re-derive it every time the policy moves.

A check decides whether a policy is safe to attach. That answer is only as
good as the match between what the scanner measures and what the policy
evaluates. Three ways they drift apart, all observed in this repo:

1. **Wrong dimension.** `aws:PrincipalTag/X`, `aws:RequestTag/X` and a tag on
   the resource are three different things wearing the same tag name. The
   `deny_ec2_imds_v1` scanner read instance tags for a policy that exempts by
   role tag, so accounts reported zero violations while enforcement would deny
   every API call those instances made - the scan named the instances that
   would break as its evidence the SCP was safe.
2. **Wrong case sensitivity - in both directions at once.** A tag condition
   key has two halves that match by opposite rules. IAM matches condition key
   *names* without regard to case, and the tag key in
   `aws:PrincipalTag/ExemptFromIMDSv2` is part of the name, so
   `exemptfromimdsv2` matches. `StringNotEquals` compares the *value*
   case-sensitively, so `True` does not match `true`. The original scanner had
   both backwards: exact on the key, `.lower()` on the value. Check each half
   against its own rule, and note that `StringEqualsIgnoreCase` exists when you
   want the other comparison. Where a principal could carry the key twice in
   cases that differ, AWS calls the result an unexpected condition failure -
   raise rather than pick one.
3. **Request state vs. resource state.** A condition key on a create action is
   evaluated against the request, not against the object that results, so a
   scan of running resources is not automatically a scan of what enforcement
   will see. Be careful about the inverse mistake too: "the request" is not the
   same as "the literal parameters the caller typed".
   `ec2:MetadataHttpTokens` was measured resolving from the effective
   configuration - an AMI with `imds-support=v2.0` populates it as `required`
   for a request that names no `MetadataOptions` - so the naive reading
   overstated the gap. Where a scan genuinely cannot observe the enforced
   dimension, say so in the check's docstring instead of implying the clean
   scan covers it.

   **A docstring was not enough.** That remedy was applied here and the defect
   survived it: the docstring said the clean scan did not cover the launch-time
   statement, while the tool went on printing `100.0% - safe to deploy at root
   level` for a fleet made entirely of IMDSv1 instances. Prose in a file the
   operator is not reading does not correct a number the operator is reading.
   A gap the scan cannot close has to change the verdict, or stop being part
   of what the verdict licenses. See AP-011.

   **And check whether the gap is real before designing around it.** "The scan
   cannot observe a request in flight" was true and led straight to a wrong
   conclusion, because an observable thing stood in for it: the request's tags
   land on the resource it creates. A key you cannot read directly may still
   have a proxy. Name the proxy, argue for it, measure it - AP-011 habit 3.

   None of this is settleable from documentation. AWS's own guide says
   `HttpTokens` requires `HttpEndpoint=enabled`; `RunInstances` accepts the
   combination anyway. When a condition key's behaviour is load-bearing for a
   generated policy, prove it with `run-instances --dry-run` under a throwaway
   role carrying the statement, with a control request that must be denied so a
   broken probe cannot pass as a clean result.
4. **One key read two ways.** Every condition key a statement adds is a key
   the scanner has to mirror, and a second key is where the two drift. Both
   IMDS statements were briefly built around a `ec2:MetadataHttpEndpoint`
   clause, on the theory that a launch disabling IMDS must stay possible; the
   hop-limit statement never carried it, so the pair disagreed about the same
   fleet. Dropping it left one key, `HttpTokens`, deciding in both the policy
   and the check. Prefer the narrower statement whose extra permission the
   operator can buy back for free - here, naming `HttpTokens=required` on a
   launch with no metadata service, which changes no behaviour.

Before writing the analyzer, read the statement and list every condition key
in it. For each one, name what the scanner will read to model it. A key with
no answer is a gap to document, not to approximate.

---

### AP-010: Judging a Target by Part of What It Governs

```python
# BAD - "the OU's accounts" read as the accounts parented directly to it
ou_accounts = [
    acc_id for acc_id, acc in organization_hierarchy.accounts.items()
    if acc.parent_ou_id == ou_id
]

# GOOD - the OU's accounts are everything the attachment reaches
ou_accounts = accounts_under_ou(ou_id, organization_hierarchy)
```

A policy attached to an OU applies to every account in that OU **and in every
OU below it**. Placement used to decide one level at a time: an OU counted as
safe when the accounts sharing its level were safe, and the allowlist it
carried was unioned over those same accounts. In an organization nesting more
than one level deep that shipped a policy declared safe for accounts it had
never examined, carrying an allowlist that omitted their resources. Nothing
errored - the report simply did not mention them.

Two habits keep this from recurring:

1. **Name the blast radius, then measure exactly it.** Write down what an
   attachment reaches before writing the query that gathers it. Root reaches
   every account. An OU reaches its subtree. An account reaches one account.
   Anything narrower than the blast radius is a set of accounts being
   declared safe without being looked at.
2. **Test generators against each other, not only alone.** The same defect had
   a second half: `generate_scps` emitted `local.<ou>_ou_id` for OUs that
   `generate_org_info` declared only at depth one. Both modules' tests passed -
   one asserted the reference was written, the other asserted the declaration
   was written - and the mismatch surfaced only at `terraform plan`.
   `tests/test_nested_ou_hierarchy.py` now generates both from one hierarchy
   and asserts every `local.` a policy reads is one the org info declares.
   Where two modules must agree on a name, put the rule in one function they
   both call - here `ou_id_local_name()` - and test the pair together.

---

### AP-011: One Verdict Gating Two Statements

```hcl
# BAD - one variable, two statements, two different kinds of evidence
{ include = var.deny_ec2_imds_v1, statement = { ... ec2:RoleDelivery ... } },
{ include = var.deny_ec2_imds_v1, statement = { ... ec2:MetadataHttpTokens ... } },

# GOOD - one variable, one statement, and a check that measures exactly it
{ include = var.deny_ec2_imds_v1, statement = { ... ec2:MetadataHttpTokens ... } },
```

A check produces one number and the generator turns it into one boolean. If
that boolean gates two statements, the check is licensing something it never
measured.

`deny_ec2_imds_v1` did this. Its two statements were evaluated at different
times and exempted on different condition keys:
`DenyRoleDeliveryLessThan2` at runtime, exempting by
`aws:PrincipalTag/ExemptFromIMDSv2` on the calling role, and
`DenyRunInstancesMetadataHttpTokensOptional` at launch, exempting by
`aws:RequestTag/ExemptFromIMDSv2` on the request. The scanner read role tags,
which was right for the first statement and meaningless for the second. So a
role-tagged IMDSv1 instance was recorded as an *exemption*, the account came
out at zero violations, and placement offered the combined policy at the
organization root - for a fleet on which every single instance answered
IMDSv1.

Note the direction of the error. It is not that the evidence for the second
statement was missing; it pointed the *other way*. The exempted instances did
match that statement's condition, and the account most likely to be broken was
the one that had configured the exemption on purpose, because it had a legacy
IMDSv1 workload. The scan named the launches that would break as its evidence
the policy was safe.

Three habits keep this from recurring:

1. **Count the statements a variable gates.** One is the number. When it is
   two, either split the variable so each half carries its own verdict, or
   remove a statement. `deny_ec2_imds_v1` was resolved by removing one: the
   running fleet is now explicitly out of scope, documented as a scope
   decision rather than a caveat, on the grounds that an IMDSv1 instance is
   either migrated or tagged for exemption.
2. **Remove the old variable name; do not quietly narrow it.** Keeping
   `deny_ec2_imds_v1` while adding a second variable would leave every
   committed `deny_ec2_imds_v1 = true` valid, applying cleanly, silently
   enforcing less than the operator believed. Terraform rejects an argument a
   module no longer declares - `Error: Unsupported argument`, raised at
   `init` - and that error is the point. A name whose meaning changes without
   a signal is the same defect wearing a fix.
3. **A key you cannot read may still have a proxy - name it and measure it.**
   `aws:RequestTag/ExemptFromIMDSv2` lives on a request in flight, which no
   scan sees. It does not follow that the check must report no exemptions:
   `TagSpecifications` populates that key *and* tags the instance it creates,
   so the instance's tag is the trace of the request tag and evidence its
   relaunch carries one. That proxy is now what the check reads.

   The discipline is what separates a proxy from AP-009's mistake. A proxy is
   named, argued from the mechanism that links it to the real key, measured
   against enforcement, and has its failure modes written down and accepted -
   here, a tag applied by `CreateTags` after launch, or a recreator that never
   declares it. Reaching for a same-named tag on an unrelated condition key,
   with no such argument, is not a proxy; that is how `aws:PrincipalTag` got
   read for a statement that never mentioned it.

---

## 📝 Naming Conventions

```yaml
check_name:
  format: "deny_{service}_{descriptor}"
  examples:
    - deny_rds_unencrypted
    - deny_ec2_imds_v1
    - deny_s3_third_party_access
    - deny_sts_third_party_assumerole
  rule: Service name comes immediately after action

constant_name:
  format: "DENY_{SERVICE}_{DESCRIPTOR}"
  derive_from: check_name.upper()

class_name:
  format: "{CheckName}Check"
  examples:
    - DenyRdsUnencryptedCheck
    - DenyEc2ImdsV1Check

dataclass_name:
  format: "{CheckName}"
  examples:
    - DenyRdsUnencrypted
    - SQSQueuePolicyAnalysis

file_names:
  check: "headroom/checks/{scps|rcps}/{check_name}.py"
  aws: "headroom/aws/{service}.py"
  test_check: "tests/test_checks_{check_name}.py"
  test_aws: "tests/test_aws_{service}.py"

terraform_variables:
  boolean: "deny_{service}_{descriptor}"
  allowlist: "{service}_{descriptor}_allowlist"
  ordering: "alphabetical by service, boolean before allowlist"
```

---

## 🗂️ File Modification Checklist

```yaml
must_create:
  - path: headroom/checks/{type}/{check_name}.py
    contains: ["@register_check", "class.*Check", "def analyze", "def categorize_result", "def build_summary_fields"]
    template: check_class_scp or check_class_rcp

  - path: headroom/aws/{service}.py
    contains: ["@dataclass", "def get_{check_name}_analysis", "get_all_regions"]
    template: aws_multiregion_analysis

  - path: tests/test_checks_{check_name}.py
    min_tests: 5
    must_test: [mixed, all_compliant, all_violations, empty, categorization]

  - path: tests/test_aws_{service}.py
    min_tests: 3
    must_test: [success, empty, pagination]

must_modify:
  - path: headroom/constants.py
    add_line: "{CHECK_CONSTANT} = \"{check_name}\""
    location: "alphabetical order by service"

  - path: test_environment/modules/{type}/variables.tf
    add_block: |
      variable "{check_name}" {
        type        = bool
        description = "..."
      }
    location: "alphabetical by service"

  - path: test_environment/modules/{type}/locals.tf
    add_to: "possible_{type}_denies list"
    add_block: |
      {
        include = var.{check_name},
        statement = {
          Action = [...]
          Resource = "*"
          Condition = {...}
        }
      },

  - path: headroom/terraform/generate_{type}.py
    function: "_build_{type}_terraform_module"
    add_lines: |
      {check_name} = "{check_name}" in enabled_policies
      terraform_content += f"  {check_name} = {{str({check_name}).lower()}}\n"
    location: "alphabetical by service"

# A check whose SCP statement is scoped by an allowlist needs EVERY step
# below. Stop short anywhere and the check still reports 100% compliance,
# the SCP is still enabled, and the allowlist renders empty - which for a
# Deny statement denies everything rather than nothing. deny_ec2_ami_owner
# shipped with the first and last steps only.
if_check_has_allowlist:
  - path: headroom/checks/{type}/{check_name}.py
    function: "build_summary_fields"
    add_line: "\"unique_{thing}s\": sorted(list({thing}s))"

  - path: headroom/types.py
    dataclass: "SCPCheckResult"
    add_line: "{thing}s: Optional[List[str]] = None"

  - path: headroom/parse_results.py
    function: "_parse_single_scp_result_file"
    add_line: "{thing}s=summary.get(\"unique_{thing}s\")"

  - path: headroom/parse_results.py
    add_function: "_build_{thing}s_for_recommendation"
    call_from: ["_build_root_recommendation", "_build_ou_recommendation", "_build_account_recommendation"]
    purpose: "Union the values across the accounts a placement covers"

  - path: headroom/types.py
    dataclass: "SCPPlacementRecommendations"
    add_line: "{service}_allowed_{thing}s: Optional[List[str]] = None"

  - path: headroom/terraform/generate_scps.py
    function: "_build_{service}_terraform_parameters"
    add_lines: |
      Emit the list parameter, and raise RuntimeError naming the module
      if it is empty. Never render an empty allowlist.

  - path: tests/test_parse_results.py
    must_test: [summary_field_carried, union_across_accounts, other_checks_unaffected]

  - path: tests/test_generate_scps.py
    must_test: [renders_populated_allowlist, aborts_on_empty_allowlist]

if_check_has_exemptions:
  - path: test_environment/modules/scps/locals.tf
    read_first: |
      List every condition key in the statement, including the ones that
      express the exemption. For each, name what the scanner will read to
      model it. See AP-009.

  - path: headroom/aws/{service}.py
    must_read: |
      The dimension the condition key reads, not a same-named tag on a
      convenient object. aws:PrincipalTag reads the calling role's tags;
      aws:RequestTag reads the create request's; neither reads the resource's.

  - path: headroom/constants.py
    add_lines: |
      The exemption tag key and value as constants, with a comment on the
      operator that compares them. StringNotEquals is case-sensitive, so the
      scanner must not lowercase what enforcement will not.

  - path: headroom/checks/{type}/{check_name}.py
    docstring: |
      State which statements a clean scan clears and which it cannot. An
      exemption the scan cannot observe - a launch-request tag, say - belongs
      in the docstring, not in an implied guarantee.

  - path: tests/test_aws_{service}.py
    must_test: [right_dimension_exempts, wrong_dimension_does_not, value_case_is_exact]

optional_modify:
  - path: test_environment/test_{check_name}.tf
    purpose: "Test infrastructure (if needed for E2E)"

  - path: test_environment/test_{check_name}/README.md
    purpose: "Document test scenarios and costs"
```

---

## 🎯 Implementation Patterns

### Pattern: Multi-Region Analysis

```python
# USE: When analyzing resources in multiple regions
# COPY: This exact pattern

from .helpers import get_all_regions

def get_analysis(session: boto3.Session) -> List[Model]:
    all_results = []
    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing in {region}")
        results = _analyze_region(session, region)
        all_results.extend(results)

    return all_results
```

### Pattern: Pagination with Error Handling

```python
# USE: For paginated AWS API calls
# COPY: This exact pattern

# Setup paginator (separate try/except)
try:
    paginator = client.get_paginator("operation")
except ClientError as e:
    logger.warning(f"Failed to get paginator: {e}")
    return []

# Process pages
for page in paginator.paginate():
    items = page.get("Items", [])

    for item in items:
        # Per-item processing (separate try/except)
        try:
            result = process(item)
            results.append(result)
        except ClientError as e:
            logger.warning(f"Failed to process item: {e}")
            continue  # Skip item, continue with others
```

### Pattern: Exemption Categorization

```python
# USE: For Pattern 4 checks with exemption tags
# COPY: This exact pattern

def categorize_result(self, result: Model) -> tuple[str, JsonDict]:
    result_dict = {
        "id": result.id,
        "exemption_tag": result.exemption_tag,
    }

    # Check exemption FIRST (before violation)
    if result.has_exemption:
        return ("exemption", result_dict)

    # Then check violation
    if result.violates_policy:
        return ("violation", result_dict)

    # Everything else compliant
    return ("compliant", result_dict)

def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
    total = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

    # CRITICAL: Include exemptions in compliant count
    compliant_count = len(check_result.compliant) + len(check_result.exemptions)
    compliance_pct = (compliant_count / total * 100) if total else 100

    return {
        "total": total,
        "violations": len(check_result.violations),
        "exemptions": len(check_result.exemptions),
        "compliant": len(check_result.compliant),
        "compliance_percentage": compliance_pct,
    }
```

### Pattern: RCP Third-Party Analysis

```python
# USE: For RCP checks analyzing IAM policies
# COPY: This exact pattern

def analyze_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[Result]:
    all_results = []
    regions = get_all_regions(session)

    for region in regions:
        client = session.client("service", region_name=region)

        # Get resources with policies
        for resource in _get_resources(client, region):
            policy = _get_policy(client, resource)

            # Extract account IDs from principals
            all_account_ids = _extract_account_ids(policy)

            # Identify third-party (non-org) accounts
            third_party_ids = all_account_ids - org_account_ids

            result = Result(
                resource_arn=resource["Arn"],
                all_account_ids=all_account_ids,
                third_party_account_ids=third_party_ids,
                region=region,
            )
            all_results.append(result)

    return all_results
```

---

## 🐛 Common Errors & Fixes

```yaml
error_check_not_registered:
  symptom: "RuntimeError: Unknown check type"
  causes:
    - "@register_check decorator missing"
    - "Decorator has wrong parameters"
    - "Check file not in scps/ or rcps/ directory"
  fix: "Verify @register_check('scps'|'rcps', CHECK_CONSTANT)"
  verify: "python -c 'from headroom.checks.registry import get_check_names; print(get_check_names())'"

error_type_checking_fails:
  symptom: "mypy errors"
  causes:
    - "Missing type annotations"
    - "Using Dict[str, Any] instead of JsonDict"
    - "Using Any inappropriately"
  fix:
    - "Add type hints to ALL functions"
    - "from ...types import JsonDict"
    - "Only use Any in **kwargs"

error_tests_fail:
  symptom: "pytest failures"
  causes:
    - "Missing test scenarios"
    - "Using DEFAULT_RESULTS_DIR in tests"
    - "Not mocking AWS calls"
  fix:
    - "Use temp_results_dir fixture"
    - "Mock all boto3 calls"
    - "Test all scenarios: mixed, all_compliant, all_violations, empty"

error_coverage_below_100:
  symptom: "pytest --cov shows <100%"
  causes:
    - "Missing edge case tests"
    - "Untested error paths"
    - "Missing categorization tests"
  fix:
    - "Run pytest --cov-report=term-missing to see untested lines"
    - "Add tests for all code paths"

error_terraform_validation_fails:
  symptom: "terraform validate fails"
  causes:
    - "Variable not added to module"
    - "Variable name mismatch"
    - "Policy syntax error"
  fix:
    - "Add variable to test_environment/modules/{type}/variables.tf"
    - "Verify variable name matches check_name"
    - "Validate policy JSON syntax"

error_generated_terraform_missing_check:
  symptom: "Generated .tf files don't include new check"
  causes:
    - "Not added to generate_{type}.py"
    - "Check not in enabled_policies set"
  fix:
    - "Add boolean generation in _build_{type}_terraform_module"
    - "Verify check_name matches constant"
```

---

## 📊 Test Requirements

```yaml
test_scenarios_mandatory:
  mixed_compliance:
    violations: ">0"
    compliant: ">0"
    verify: "Both categories populated"

  all_compliant:
    violations: "0"
    compliant: ">0"
    compliance_percentage: "100.0"

  all_violations:
    violations: ">0"
    compliant: "0"
    compliance_percentage: "0.0"

  empty_results:
    violations: "0"
    compliant: "0"
    total: "0"
    compliance_percentage: "100.0"  # Default when empty

  categorization_paths:
    test: "Each categorization return path"
    verify: "violation, compliant, (exemption if Pattern 4)"

test_data_standards:
  principle: |
    Every identifier in a test, fixture, docstring, or doc example must be
    impossible to mistake for one from a real account. Correct prefix, correct
    length, one repeated digit for the body. An identifier that arrives from a
    bug report, console screenshot, API response, or error message gets rewritten
    to its placeholder before it enters the repo -- including in the commit
    message.
  applies_to: ["tests/", "documentation/", "docstrings", "sample_config.yaml", "commit messages", "PR descriptions"]
  not_sensitive: ["region names", "service names", "AWS-owned owner aliases: amazon, aws-marketplace"]

  fake_account_ids:
    rule: "Blocks of four repeated digits: AAAABBBBCCCC"
    pattern: '^(\d)\1{3}(\d)\2{3}(\d)\3{3}$'  # 1000 available values
    primary: "111111111111"    # A == B == C reads clearest, so exhaust these first
    secondary: "222222222222"
    tertiary: "333333333333"
    beyond_ten: ["111122223333", "444455556666", "000011112222"]
    never_use: "123456789012"  # Old AWS convention
    never_use_style: "Sequential runs such as 234567890123 or 987654321098"

  fake_resource_ids:
    rule: "Real prefix, real length, body is one repeated digit"
    ec2_instance: "i-11111111111111111"                      # i- plus 17 hex
    ec2_ami: "ami-11111111111111111"                         # ami- plus 17 hex
    kms_key: "11111111-1111-1111-1111-111111111111"          # UUID
    organizations_root: "r-1111"
    organizations_ou: "ou-1111-11111111"                     # ou-<root>-<suffix>
    organizations_org: "o-11111111111"
    iam_access_key: "AKIAIOSFODNN7EXAMPLE"                   # AWS's own example key
    never_use: "AWS doc-style bodies such as i-1234567890abcdef0 or ami-0abcdef1234567890"
    reason: "A plausible-looking body cannot be told from a real one on review"

  resource_naming:
    format: "descriptive-purpose"
    examples: ["encrypted-db", "unencrypted-violation", "exempted-instance"]
    never_use: "a name copied from a real account"

  arn_format:
    pattern: "arn:aws:service:region:111111111111:resource-type/resource-name"
    rule: "Account field uses a fake_account_ids value; resource field uses fake_resource_ids or resource_naming"

test_fixtures:
  temp_results_dir:
    always_use: true
    never_use: "DEFAULT_RESULTS_DIR"
    never_use: "test_environment/headroom_results/"
    reason: "Prevents pollution of actual results directory"

test_mocking:
  mock_all_aws_calls: true
  use_patches:
    - "headroom.checks.{type}.{check}.get_{check}_analysis"
    - "headroom.checks.base.write_check_results"
  verify_calls:
    - "mock_analysis.return_value = test_data"
    - "assert mock_write.called"
```

---

## 🚀 Quick Implementation Steps

```yaml
step_1_gather_requirements:
  collect:
    - check_name: "deny_{service}_{descriptor}"
    - check_type: "SCP or RCP"
    - aws_service: "ec2, rds, s3, iam, etc."
    - pattern: "1-6 from POLICY_TAXONOMY.md"
    - api_calls: ["list operation", "describe operation"]
    - condition_keys: "From AWS Service Authorization Reference"

step_2_create_python:
  sequence:
    - Add constant to headroom/constants.py
    - Create headroom/aws/{service}.py using template
    - Create headroom/checks/{type}/{check_name}.py using template
    - Verify: "python -c 'from headroom.checks.registry import get_check_names; print(get_check_names())'"

step_3_create_tests:
  sequence:
    - Create tests/test_aws_{service}.py
    - Create tests/test_checks_{check_name}.py
    - Run: "pytest tests/test_checks_{check_name}.py tests/test_aws_{service}.py -v --cov"
    - Verify: "100% coverage"

step_4_update_terraform:
  sequence:
    - Add variable to test_environment/modules/{type}/variables.tf
    - Add policy to test_environment/modules/{type}/locals.tf
    - Add generation to headroom/terraform/generate_{type}.py
    - Run: "terraform validate" in test_environment/

step_5_validate:
  sequence:
    - Run: "mypy headroom/ tests/"
    - Run: "pytest tests/ --cov=headroom"
    - Run: "tox"
    - All must pass with no errors

step_6_e2e_optional:
  if_needed:
    - Create test_environment/test_{check_name}.tf
    - Document in test_environment/test_{check_name}/README.md
    - Run: "python -m headroom --config test_config.yaml"
    - Verify generated results and Terraform
```

---

## 🔍 AWS Service Authorization Reference

**CRITICAL:** Always verify condition keys in official AWS documentation

```yaml
verification_process:
  step_0_machine_readable:
    index: "https://servicereference.us-east-1.amazonaws.com/"
    url: "https://servicereference.us-east-1.amazonaws.com/v1/{service}/{service}.json"
    why: "Same data as the HTML reference below, as JSON. The HTML page renders
      client-side, so it cannot be fetched or grepped - use this instead and
      cite it in the policy comment."
    shape: "Actions[].Resources[].ConditionKeys[] - the condition keys a given
      action supports ON a given resource type"
    example_query: "list every action whose image resource carries ec2:Owner"

  step_1:
    url: "https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html"
    action: "Find your service (e.g., Amazon RDS, Amazon EC2)"

  step_2:
    action: "Look up each action in the Actions table"
    verify: "Condition keys column lists ALL supported keys"

  step_3:
    rule: "If condition key is NOT listed for an action, it CANNOT be used"
    do_not: "Assume support based on logic or web searches"

  step_3b_resource_scope:
    rule: "A resource-level condition key exists on ONE resource type. Scope the
      statement's Resource to that type, not to whatever the action creates."
    why: "An action is authorized against every resource it touches. On a
      resource that does not carry the key, the key is absent - and a negated
      operator (StringNotEquals, ArnNotLike, Bool with a false test) on an
      absent key evaluates TRUE, so the Deny matches everything."
    example: "ec2:Owner lives on the image resource. deny_ec2_ami_owner scoped
      to arn:aws:ec2:*:*:instance/* denied every RunInstances call; scoped to
      arn:aws:ec2:*::image/* it denies only untrusted AMI owners."
    counterpart: "Use ...IfExists only where an absent key should mean allow.
      In a Deny, that is usually the wrong direction - see BoolIfExists on
      aws:PrincipalIsAWSService in modules/rcps/locals.tf, where it is right."
    converse: "The same lookup decides which actions belong in the statement.
      An action that lists no such resource type can never match a statement
      scoped to it, so adding it reads as coverage while denying nothing -
      ec2:RunScheduledInstances against arn:aws:ec2:*::image/*, for example."

  step_4_undocumented:
    if: "You want to include undocumented action"
    requirements:
      - Manually test the SCP actually blocks the action
      - Document as "special exception" in policy comments
      - Mark with "✅ MANUALLY TESTED"
      - Accept AWS could remove support without notice

examples:
  rds_storage_encrypted:
    documented_actions:
      - "rds:CreateDBCluster"
      - "rds:RestoreDBClusterFromS3"
      - "rds:CreateBlueGreenDeployment"
    undocumented_but_tested:
      - "rds:CreateDBInstance"  # Works despite not being documented
    not_supported:
      - "rds:RestoreDBInstanceFromDBSnapshot"
      - "rds:RestoreDBClusterFromSnapshot"
```

---

## 📖 Reference Files

```yaml
base_class:
  file: headroom/checks/base.py
  class: BaseCheck[T]
  methods:
    - analyze(session) -> List[T]
    - categorize_result(result: T) -> tuple[str, JsonDict]
    - build_summary_fields(result) -> JsonDict
  template_method: execute()  # Calls your methods

registry:
  file: headroom/checks/registry.py
  decorator: "@register_check(type, name)"
  discovery: "Automatic from scps/ and rcps/ directories"

type_aliases:
  file: headroom/types.py
  use:
    - JsonDict: "Instead of Dict[str, Any]"
    - CheckCategory: "For categorization return values"
    - PrincipalType: "For IAM principal parsing"

helpers:
  file: headroom/aws/helpers.py
  functions:
    - get_all_regions(session): "Get all AWS regions"
    - paginate(client, operation, **kwargs): "Generic pagination"

constants:
  file: headroom/constants.py
  add: "CHECK_NAME constants"
  add: "Regex patterns used across files"
  format: "UPPER_SNAKE_CASE"

policy_patterns:
  file: documentation/POLICY_TAXONOMY.md
  use: "Determine which pattern (1-6) applies"
  examples: "See existing checks as pattern examples"
```

---

## ✅ Final Checklist

```yaml
before_completion:
  code_quality:
    - mypy_passes: "mypy headroom/ tests/"
    - tests_pass: "pytest tests/ -v"
    - coverage_100: "pytest --cov=headroom"
    - tox_passes: "tox"

  files_created:
    - headroom/constants.py: "Added constant"
    - headroom/aws/{service}.py: "Created or updated"
    - headroom/checks/{type}/{check_name}.py: "Created with @register_check"
    - tests/test_aws_{service}.py: "Created"
    - tests/test_checks_{check_name}.py: "Created"

  files_modified:
    - test_environment/modules/{type}/variables.tf: "Added variable"
    - test_environment/modules/{type}/locals.tf: "Added policy"
    - headroom/terraform/generate_{type}.py: "Added generation logic"

  verification:
    - check_registered: "Appears in get_check_names()"
    - terraform_validates: "terraform validate passes"
    - no_lint_errors: "No flake8 errors"
    - no_type_errors: "No mypy errors"

  optional:
    - test_infrastructure: "test_environment/test_{check_name}.tf"
    - documentation: "test_{check_name}/README.md"
    - e2e_tested: "Ran against test environment"
```

---

**END OF GUIDE**

For questions, reference:
- Existing checks in `headroom/checks/scps/` and `headroom/checks/rcps/`
- `documentation/POLICY_TAXONOMY.md` for policy patterns
- `headroom/checks/base.py` for BaseCheck interface
- Test files in `tests/` for test examples
