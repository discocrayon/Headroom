# How to Add a New Check to Headroom

```yaml
# LLM Metadata
document_type: implementation_guide
target_audience: [ai_assistant, experienced_developer]
context_dependencies:
  - spec/README.md
  - spec/invariants.md
  - spec/contracts/policy-model.md
  - headroom/checks/base.py
  - headroom/checks/registry.py
normative_authority: spec/
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
    "reference": "spec/contracts/policy-model.md",
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
  phase_0_specification:
    file: spec/checks/{scps|rcps}/{check_name}.md
    action: write_first
    why: |
      The specification is the deliverable; the implementation expresses it.
      Deciding the enforced statement, the decision table, and the accepted
      limitations before writing code is what stops the scanner and the policy
      from measuring different things.
    contract: spec/checks/index.md
    enforced_by: |
      tests/test_spec_corpus.py fails if a registered check has no
      specification, if its frontmatter is incomplete, or if it cites an
      invariant that does not exist.

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
    file: headroom/checks/{scps|rcps}/{check_name}.py
    action: |
      Nothing outside the check module. @register_check takes
      terraform_section=TerraformSection.<SERVICE> and, where the statement
      is scoped by an allowlist, allowlist=Allowlist(summary_key=...,
      terraform_variable=...). Both generators render every registered
      definition from the registry (INV-13).
    new_service: |
      Add one member to TerraformSection in headroom/enums.py, in
      alphabetical position. Declaration order is render order.
    enforced_by: |
      test_every_registered_scp_check_is_rendered and
      test_every_registered_rcp_check_is_rendered fail by name if a
      registered check does not reach its module;
      test_every_registered_check_is_declared_by_its_module fails by name
      if test_environment/modules/{type}/variables.tf does not declare the
      check's boolean or its allowlist variable;
      test_every_registered_check_is_read_by_a_statement fails by name if
      no statement in test_environment/modules/{type}/locals.tf is gated by
      the check's boolean or reads its allowlist variable;
      test_generic_pipeline_modules_name_no_check fails if a generic
      module names a check.

  phase_6_tests:
    files:
      - tests/test_aws_{service}.py
      - tests/test_checks_{check_name}.py
    min_coverage: 100
    scenarios: [mixed, all_compliant, all_violations, empty, edge_cases]

  phase_7_validation:
    commands:
      - "pytest tests/test_spec_corpus.py"
      - "mypy headroom/ tests/"
      - "coverage run --source=headroom,tests -m pytest tests/"
      - "coverage report --include=headroom/* --show-missing --fail-under=100"
      - "tox"
    all_must_pass: true
```

---

## 🎯 File Templates

Every template below obeys one rule about failure: a read that did not complete
is never recorded as an absence of findings. Tolerate one benign condition
whose meaning you know - "this resource carries no policy", "this resource was
deleted between the list call and the read" - and re-raise everything else. One
condition is not always one error code: AWS spells the deleted-queue case two
ways, so `QUEUE_GONE_ERROR_CODES` in `headroom/aws/sqs.py:36-39` holds both.
Match a frozenset of codes, not a single string, and put every code in it that
means the same thing. Logging a warning and returning `[]`, or stepping over
the failure with `continue`, reports an account as clean on the strength of
resources nobody read. That is INV-01, absence of evidence is not evidence of
safety, and INV-02, a run fails whole and never partially, both in
[`spec/invariants.md`](spec/invariants.md).

The shape to copy is `headroom/aws/s3.py`. `_read_bucket_policy` (`:175-203`)
is the smallest function that makes the call: it returns `None` for
`NoSuchBucketPolicy` and re-raises every other `ClientError`. Its caller
materialises the bucket listing into a list first (`:247-254`, with a comment
saying why) so that a listing failure is raised where it happened, outside the
loop, instead of reaching the per-bucket handler and being reported as the
wrong thing.

The shape *not* to copy is the rest of `headroom/aws/sqs.py`. Its narrow
handler is right about which codes to tolerate, but it sits inline at
`:215-228`, lexically inside the region-wide `try:` at `:208` whose
`except ClientError` is at `:246` - two handlers for one exception type, nested,
which is what AP-003 warns about. It does not swallow, so nothing is unsafe; a
per-queue failure is simply reported as a region-listing failure.

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
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", {CHECK_CONSTANT}, terraform_section=TerraformSection.{SERVICE})
class {CheckClass}(BaseCheck[{DataModel}]):
    """Check for {DESCRIPTION}."""

    def analyze(self, session: boto3.Session) -> List[{DataModel}]:
        """Analyze {RESOURCE_TYPE} for {PURPOSE}."""
        return get_{check_name}_analysis(session)

    def categorize_result(
        self,
        result: {DataModel}
    ) -> tuple[CheckCategory, JsonDict]:
        """Categorize single result."""
        result_dict: JsonDict = {
            # Map all dataclass fields:
            # "field_name": result.field_name,
        }

        if {VIOLATION_CONDITION}:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

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

def categorize_result(self, result: {DataModel}) -> tuple[CheckCategory, JsonDict]:
    """Categorize with exemption support."""
    result_dict = {
        "field": result.field,
        "exemption_tag": result.exemption_tag_value,
    }

    # Check exemption FIRST
    if result.has_exemption_tag:
        return (CheckCategory.EXEMPTION, result_dict)

    # Then check violation
    if {VIOLATION_CONDITION}:
        return (CheckCategory.VIOLATION, result_dict)

    return (CheckCategory.COMPLIANT, result_dict)

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
from mypy_boto3_{service}.type_defs import {ItemTypeDef}

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

    # Materialized rather than streamed, so a failure here is raised as the
    # listing failure it is, and never mistaken for a per-item one. Re-raise:
    # returning [] would report the region as holding nothing.
    try:
        pages = list(client.get_paginator("{operation}").paginate())
    except ClientError as e:
        logger.error(f"Failed to list {resource} in {region}: {e}")
        raise

    for item in [item for page in pages for item in page.get("{ItemsKey}", [])]:
        results.append(_analyze_single_item(item, region))

    return results


def _analyze_single_item(
    item: {ItemTypeDef},
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
- `{ItemTypeDef}`: `DBInstanceTypeDef`, from `mypy_boto3_rds.type_defs`. Take it
  from the stubs rather than writing `dict`: a boto3 page item is a `TypedDict`,
  and `mypy` rejects passing one where a bare `dict` is declared.

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
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import Allowlist, register_check


@register_check(
    "rcps",
    {CHECK_CONSTANT},
    terraform_section=TerraformSection.{SERVICE},
    allowlist=Allowlist(
        summary_key="unique_third_party_accounts",
        terraform_variable="{allowlist_var}",
    ),
)
class {CheckClass}(BaseCheck[{DataModel}]):
    """Check for third-party access in {RESOURCE_TYPE}."""

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        org_account_ids: Set[str],  # RCP-specific
        org_id: str,                # RCP-specific
        exclude_account_ids: bool = False,
        **kwargs: Any
    ) -> None:
        """Initialize with the organization's account IDs and its own ID."""
        super().__init__(
            check_name=check_name,
            account_name=account_name,
            account_id=account_id,
            results_dir=results_dir,
            exclude_account_ids=exclude_account_ids,
            **kwargs,
        )
        self.org_account_ids = org_account_ids
        self.org_id = org_id
        self.all_third_party_accounts: Set[str] = set()

    def analyze(self, session: boto3.Session) -> List[{DataModel}]:
        """Analyze {RESOURCE_TYPE} policies, keeping only those with a finding."""
        all_results = analyze_{service}_{resource}_policies(
            session,
            self.org_account_ids,
            self.org_id
        )
        # Filter here, as five of the six shipped RCP checks do
        # (deny_s3_third_party_access.py:84-88). A resource with none of the
        # three is nothing the RCP would change, and counting it inflates
        # total_{resources} and compliant with resources no check reports.
        # deny_sts_third_party_assumerole.py:82-85 tests two of the three
        # because TrustPolicyAnalysis carries no has_non_account_principals
        # field; a data model carrying all three has no such excuse.
        return [
            result for result in all_results
            if result.has_wildcard_principal
            or result.has_non_account_principals
            or result.third_party_account_ids
        ]

    def categorize_result(
        self,
        result: {DataModel}
    ) -> tuple[CheckCategory, JsonDict]:
        """Categorize on what no allowlist can express, not on third parties."""
        result_dict = {
            "resource_arn": result.resource_arn,
            "third_party_account_ids": sorted(result.third_party_account_ids),
            "has_wildcard_principal": result.has_wildcard_principal,
            "has_non_account_principals": result.has_non_account_principals,
        }

        # Accumulate before the branch, so the allowlist spans the compliant
        # resources too. Third-party access is not itself a blocker; it is the
        # thing the allowlist is built from - see the "RCP placement" section
        # of spec/contracts/placement.md.
        self.all_third_party_accounts.update(result.third_party_account_ids)

        if result.has_wildcard_principal or result.has_non_account_principals:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> JsonDict:
        """Build summary with the third-party allowlist Terraform reads."""
        return {
            "total_{resources}": len(check_result.violations) + len(check_result.compliant),
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "unique_third_party_accounts": sorted(self.all_third_party_accounts),
            "third_party_account_count": len(self.all_third_party_accounts),
        }
```

`unique_third_party_accounts` is the key, and it is not optional: the shared
reader `parse_results._read_declared_allowlist`, which
`headroom/terraform/generate_rcps.py` reads every RCP result through, raises on a
summary that omits it rather than generating an empty allowlist, because an
empty allowlist denies every third party. `violations` is the other key
`_parse_single_rcp_result_file` requires, and a non-zero count is what marks
the account as one the RCP cannot be deployed to.

---

### Template: RCP AWS Analysis (Policy Extraction)

```python
# FILE: headroom/aws/{service}.py
# TEMPLATE: RCP_POLICY_ANALYSIS

"""AWS {service} policy analysis for third-party access detection."""

from dataclasses import dataclass, field
from typing import List, Optional, Set
import boto3
import json
import logging
from botocore.exceptions import ClientError
from mypy_boto3_{service}.client import {ServiceClient}

from .helpers import get_all_regions
from .policy_documents import (
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_principal,
    read_service_principal_sources,
)
from ..types import JsonDict

logger = logging.getLogger(__name__)

# The codes that mean there is nothing to read on this resource. One benign
# condition, which a service may spell more than one way - so a frozenset,
# never a single string. Every other ClientError is a read that did not
# complete.
NOTHING_TO_READ_ERROR_CODES = frozenset({"{BenignErrorCode}"})


@dataclass
class {DataModel}:
    """Policy analysis result."""
    resource_arn: str
    all_account_ids: Set[str]
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    region: str
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)


def analyze_{service}_{resource}_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[{DataModel}]:
    """
    Analyze {resource} policies for third-party access.

    Args:
        session: boto3 session
        org_account_ids: Set of organization account IDs
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of policy analysis results
    """
    all_results = []
    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing {resource} policies in {region}")
        all_results.extend(_analyze_policies_in_region(
            session,
            region,
            org_account_ids,
            org_id
        ))

    logger.info(
        f"Analyzed {len(all_results)} {resource} with third-party access "
        f"across {len(regions)} regions"
    )
    return all_results


def _read_policy(
    client: {ServiceClient},
    resource_id: str
) -> Optional[JsonDict]:
    """
    Return the resource's policy document, or None if there is nothing to read.

    Raises:
        ClientError: If the policy cannot be read for any other reason
    """
    try:
        policy_response = client.{get_policy_operation}(
            {ResourceIdParam}=resource_id
        )
    except ClientError as e:
        # Matched by code, because there is nothing here to find. Every other
        # ClientError is a read that did not complete, and returning None for
        # it would clear the account on the strength of a resource nobody read
        # (INV-01).
        if e.response["Error"]["Code"] in NOTHING_TO_READ_ERROR_CODES:
            logger.debug(f"No policy to read on {resource_id}")
            return None
        raise

    policy: JsonDict = json.loads(policy_response["{PolicyKey}"])
    return policy


def _analyze_policies_in_region(
    session: boto3.Session,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> List[{DataModel}]:
    """Analyze policies in specific region."""
    client: {ServiceClient} = session.client("{service}", region_name=region)
    results: List[{DataModel}] = []

    # Materialized rather than streamed, so that a listing failure is raised
    # here and reported as the listing failure it is. Left inside the loop it
    # would reach _read_policy's caller as a per-resource failure and be
    # logged as the wrong thing - and either way a region nobody listed must
    # never pass for a region holding nothing.
    try:
        pages = list(client.get_paginator("{list_operation}").paginate())
    except ClientError as e:
        logger.error(f"Failed to list {resource} in {region}: {e}")
        raise

    for item in [item for page in pages for item in page.get("{ResourceKey}", [])]:
        policy = _read_policy(client, item["{ResourceIdKey}"])
        if policy is None:
            continue

        analysis = _analyze_policy(
            policy=policy,
            resource_arn=item["{ArnKey}"],
            region=region,
            org_account_ids=org_account_ids,
            org_id=org_id,
        )

        # Drop a resource with no finding before returning it. The service
        # principal source is one of the findings: deny_service_confused_deputy
        # reads it off this same analysis, so a resource whose only finding is
        # a source guard must survive.
        has_service_source = has_actionable_service_principal_source(analysis.service_principal_sources)
        if analysis.third_party_account_ids or analysis.has_wildcard_principal or analysis.has_non_account_principals or has_service_source:
            results.append(analysis)

    return results


def _analyze_policy(
    policy: JsonDict,
    resource_arn: str,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> {DataModel}:
    """Read one policy document. Makes no AWS call, so it handles no ClientError."""
    resource_description = f"policy on {resource_arn}"
    all_account_ids: Set[str] = set()
    has_wildcard = False
    has_non_account_principals = False
    sources: List[ServicePrincipalSource] = []

    # Read every Allow statement's Principal through the one shared reader.
    # Do not write your own: see AP-007.
    for statement in normalize_statements(policy, resource_description):
        if statement.get("Effect") != "Allow":
            continue
        if has_not_principal(statement):
            has_wildcard = True
            continue
        principal = statement.get("Principal")
        if not principal:
            continue

        sources.extend(read_service_principal_sources(
            statement, org_account_ids, org_id, resource_description
        ))

        reading = read_principal(
            principal, RESOURCE_POLICY_PRINCIPAL_TYPES, resource_description
        )
        all_account_ids.update(reading.account_ids)
        has_wildcard = has_wildcard or reading.has_wildcard
        has_non_account_principals = (
            has_non_account_principals or reading.has_non_account_principals
        )

    return {DataModel}(
        resource_arn=resource_arn,
        all_account_ids=all_account_ids,
        # Identify third-party (non-org) accounts
        third_party_account_ids=all_account_ids - org_account_ids,
        has_wildcard_principal=has_wildcard,
        has_non_account_principals=has_non_account_principals,
        region=region,
        service_principal_sources=sources,
    )
```

`has_wildcard_principal` and `has_non_account_principals` are two ways of saying
the same thing, and the check must categorize either as a `VIOLATION`: an
allowlist keyed on `aws:PrincipalAccount` can carry neither, so the RCP would
deny a grant that exists today.

The same facts are filtered on twice, and the templates do it in both places.
Five of the six shipped analyzers drop a resource with no finding before
returning it: `_grants_third_party_access` in `headroom/aws/ecr.py` names the
predicate and `analyze_ecr_policies` applies it once per surface - registry
and repository - and `analyze_kms_key_policies` in `kms.py`,
`analyze_s3_bucket_policies` in `s3.py`, `_analyze_secret_policy` in
`secretsmanager.py` and `analyze_iam_roles_trust_policies` in `iam/roles.py`
inline the same test.
`analyze_sqs_queue_policies` is the sixth and appends every queue carrying a
policy, which
[`spec/checks/rcps/deny_sqs_third_party_access.md`](spec/checks/rcps/deny_sqs_third_party_access.md)
records as that check's own accepted limitation rather than as the pattern to
copy.

The check's `analyze` filters again, and that is the filter that decides what
gets counted: a resource whose only finding is one of the three - both flags
and `third_party_account_ids` - is discarded before it is counted unless all
three are tested. Five of the six shipped checks test all three
(`deny_s3_third_party_access.py:84-88`).
`deny_sts_third_party_assumerole.py:82-85` tests two, because
`TrustPolicyAnalysis` (`headroom/aws/iam/roles.py:62-66`) carries no
`has_non_account_principals` field at all;
[`spec/checks/rcps/deny_sts_third_party_assumerole.md`](spec/checks/rcps/deny_sts_third_party_assumerole.md)
owns why that principal is tolerated there and nowhere else.

Let `UnknownPrincipalTypeError` propagate. All six analyzers abort the run on a
principal key AWS does not document, because catching it and moving on clears
the account on the strength of a resource nobody read. `aws/sqs.py` once caught
it and recorded the queue as a read failure with every field its own check
reads left empty, which cleared the account exactly that way; the catch is
gone. A new analyzer propagates.
See [`spec/contracts/policy-model.md`](spec/contracts/policy-model.md) and
[`spec/checks/rcps/deny_sqs_third_party_access.md`](spec/checks/rcps/deny_sqs_third_party_access.md).

`org_id` is the third argument every one of the six analyzers takes, and it is
what `read_service_principal_sources` classifies an `aws:SourceOrgID` or
`aws:SourceOrgPaths` guard against: a guard naming this organization needs no
allowlist entry, and one naming any other organization names accounts no
allowlist can carry. `deny_service_confused_deputy` is the check that reads the
`service_principal_sources` the six analyzers record; the other six RCP checks
ignore the field, and none of them has to thread anything of its own to get it.

**Variables**, worked through Secrets Manager. Substituting these and running
`mypy headroom/` on the result is the check that the template still holds; it
is how the SQS worked example that stood here before was found to be broken.

- `{service}`: `secretsmanager`
- `{resource}`: `secrets`
- `{DataModel}`: `SecretsPolicyAnalysis`
- `{ServiceClient}`: `SecretsManagerClient`, from `mypy_boto3_secretsmanager.client`
- `{list_operation}`: `list_secrets`
- `{ResourceKey}`: `SecretList`
- `{get_policy_operation}`: `get_resource_policy`
- `{ResourceIdParam}`: `SecretId`
- `{ResourceIdKey}`: `ARN`
- `{PolicyKey}`: `ResourcePolicy`
- `{ArnKey}`: `ARN`
- `{BenignErrorCode}`: `ResourceNotFoundException`

Two things the choice of service decides, and both bite:

- **Whether the page items are objects.** `list_secrets` pages carry
  `SecretList`, a list of objects with `ARN` and `Name`, so
  `item["{ResourceIdKey}"]` reads. `list_queues` pages carry `QueueUrls`, a list
  of **strings**, so the same line is a `str` subscript - `TypeError` at
  runtime, `Invalid index type "str" for "str"` under `mypy`. For a service like
  that, the item *is* the id, and `{ResourceIdKey}` and `{ArnKey}` do not apply.
- **Whether the policy sits at the top of the response.**
  `get_resource_policy` returns `ResourcePolicy` directly.
  `get_queue_attributes` nests it, so the read there is
  `policy_response["Attributes"]["Policy"]`.

`{BenignErrorCode}` is the code that means there is nothing to read, and
`NOTHING_TO_READ_ERROR_CODES` is a frozenset because one condition can have
more than one code. Per service, from the tree:

| Read | Codes |
|---|---|
| `secretsmanager.get_resource_policy` | `ResourceNotFoundException` (`_analyze_secrets_in_region` in `secretsmanager.py`) |
| `s3.get_bucket_policy` | `NoSuchBucketPolicy` (`_read_bucket_policy` in `s3.py`) |
| `kms.get_key_policy` | `NotFoundException` (`_read_key_policy` in `kms.py`) |
| `ecr.get_repository_policy` | `RepositoryPolicyNotFoundException` (`_analyze_repository_in_region` in `ecr.py`) |
| `ecr.get_registry_policy` | `RegistryPolicyNotFoundException` (`_analyze_registry_policy` in `ecr.py`) |
| `sqs.get_queue_attributes` | `AWS.SimpleQueueService.NonExistentQueue` **and** `QueueDoesNotExist` - one condition, two spellings (`sqs.py:36-39`) |

If you cannot name the codes and say what they mean, catch nothing.

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
  verify: "coverage run --source=headroom,tests -m pytest tests/ && coverage report --include=headroom/* --show-missing --fail-under=100"
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
pytest tests/test_checks_{check_name}.py tests/test_aws_{service}.py -v

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
def categorize_result(self, result: T) -> tuple[CheckCategory, Dict[str, Any]]:
    pass

# ✅ GOOD
from ...types import JsonDict
def categorize_result(self, result: T) -> tuple[CheckCategory, JsonDict]:
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

# ✅ GOOD - Separate by operation, and neither branch swallows

# The per-resource read lives in its own function. It tolerates the codes for
# one benign condition and re-raises the rest.
def _read_policy(client: ServiceClient, resource_id: str) -> Optional[JsonDict]:
    try:
        response = client.get_policy(ResourceId=resource_id)
    except ClientError as e:
        if e.response["Error"]["Code"] in NOTHING_TO_READ_ERROR_CODES:
            logger.debug(f"No policy to read on {resource_id}")
            return None
        raise

    policy: JsonDict = json.loads(response["Policy"])
    return policy


# The listing is materialized so that a listing failure is raised here and
# reported as the listing failure it is. Re-raise: returning [] reports "no
# findings" for resources nobody looked at, which is INV-01 exactly backwards.
try:
    pages = list(client.get_paginator("list").paginate())
except ClientError as e:
    logger.error(f"Failed to list: {e}")
    raise

# The loop runs outside that try, so the two handlers never nest - not
# lexically and not at runtime. A failure inside _read_policy that is not one
# of the tolerated codes propagates from where it happened, rather than being
# caught here and logged as a listing failure.
for page in pages:
    process(page)
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

If your check reads a resource type another check already reads, call that
check's analyzer rather than writing a second sweep, and decorate the analyzer
with `memoize_per_session` from `aws/helpers.py` if it does not carry it yet.
An account's session belongs to one worker, so the second caller is served
from memory and pays nothing. Without it a shared analyzer that sweeps regions
costs the account a full extra sweep -- the mistake `deny_service_confused_deputy`
made for six analyzers, and the one
`tests/performance/test_call_counts.py::TestCallCounts::test_the_shared_analyzers_read_an_account_once_for_both_callers`
now pins.

### AP-007: Hardcoded Patterns

```python
# ❌ BAD - Duplicated regex across files
arn_match = re.match(r'^arn:aws:[^:]+:[^:]*:(\d{12}):', principal)

# ❌ STILL BAD - your own walk over the Principal element
if isinstance(principal, dict) and "AWS" in principal:
    ...

# ✅ GOOD - one reader, for every analyzer
from .policy_documents import RESOURCE_POLICY_PRINCIPAL_TYPES, read_principal
reading = read_principal(principal, RESOURCE_POLICY_PRINCIPAL_TYPES, description)
```

The copies drift, and they drift narrower. `roles.py`, `kms.py` and `ecr.py`
each carried `r'^arn:aws:iam::(\d{12}):'` while `s3.py`, `sqs.py` and
`secretsmanager.py` used the constant. The three copies silently dropped every
STS session principal and every non-commercial partition, so the accounts
never reached the allowlist and the RCP denied them.

The regex was the first half of that lesson and the whole `Principal` walk was
the second. Six analyzers each carried their own, and they diverged on more than
a pattern: which principal types they permitted, whether an unreadable one
aborted the run or was skipped, and whether one carrying no account ID was a
finding at all. Four answers to one question. `read_principal` in
`headroom/aws/policy_documents.py` is now the only place a
`Principal` element is interpreted; call it rather than writing the walk again.

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

[INV-09](spec/invariants.md#inv-09--scan-the-dimension-the-policy-enforces) is
the rule: read the dimension your statement conditions on, or declare the
substitution and what it costs. This entry is the authoring habit behind it.

A check decides whether a policy is safe to attach. That answer is only as good
as the match between what the scanner measures and what the policy evaluates.
Four ways they drift apart, all observed in this repo:

1. **Wrong dimension.** `aws:PrincipalTag/X`, `aws:RequestTag/X` and a tag on
   the resource are three different things wearing the same tag name. The
   `deny_ec2_imds_v1` scanner once read instance tags for a statement that
   exempted by *role* tag, so accounts reported zero violations while
   enforcement would deny every API call those instances made - the scan named
   the instances that would break as its evidence the SCP was safe. The role
   tag was right for that statement. It is not right for the launch-time
   statement that replaced it, which exempts on `aws:RequestTag`, and for which
   the instance's own tag is a defensible proxy because `TagSpecifications`
   populates the request key and tags the instance in one act. The dimension is
   a property of the statement and changes when the statement does. Re-derive
   it every time the policy moves; do not read this entry as "instance tags are
   always wrong".

2. **Wrong case sensitivity - in both directions at once.** A tag condition key
   has two halves that match by opposite rules. IAM matches condition key
   *names* without regard to case, and the tag key in
   `aws:PrincipalTag/ExemptFromIMDSv2` is part of the name, so
   `exemptfromimdsv2` matches. `StringNotEquals` compares the *value*
   case-sensitively, so `True` does not match `true`. The original scanner had
   both backwards: exact on the key, `.lower()` on the value. Check each half
   against its own rule, and note that `StringEqualsIgnoreCase` exists when you
   want the other comparison. Where a principal could carry the key twice in
   cases that differ, AWS calls the result an unexpected condition failure -
   raise rather than pick one. All three rules live in
   `find_tag_value_as_iam_matches` in `headroom/aws/helpers.py`; call it rather
   than writing the comparison again. Two checks reading the same kind of tag
   by two different rules is a bug this repository has had once.

3. **Request state vs. resource state.** A condition key on a create action is
   evaluated against the request, not against the object that results, so a
   scan of running resources is not automatically a scan of what enforcement
   will see. The inverse mistake is just as easy: "the request" is not "the
   literal parameters the caller typed". `ec2:MetadataHttpTokens` resolves from
   the effective configuration - an AMI with `imds-support=v2.0` populates it
   as `required` for a request naming no `MetadataOptions` - so the naive
   reading overstated the gap.

   Two follow-ons, both learned the hard way here:

   - **A docstring is not a remedy.** The docstring said the clean scan did not
     cover the launch-time statement while the tool went on printing
     `100.0% - safe to deploy at root level` for a fleet made entirely of
     IMDSv1 instances. Prose in a file the operator is not reading does not
     correct a number the operator is reading. A gap the scan cannot close has
     to change the verdict, or stop being part of what the verdict licenses.
     See AP-011 and
     [INV-10](spec/invariants.md#inv-10--one-verdict-gates-one-statement).
   - **Check whether the gap is real before designing around it.** "The scan
     cannot observe a request in flight" was true and led straight to a wrong
     conclusion, because an observable thing stood in for it: the request's
     tags land on the resource it creates. A key you cannot read directly may
     still have a proxy. Name the proxy, argue for it in the check's
     specification, measure it - AP-011 habit 3.

   None of this is settleable from documentation. AWS's own guide says
   `HttpTokens` requires `HttpEndpoint=enabled`; `RunInstances` accepts the
   combination anyway. When a condition key's behaviour is load-bearing for a
   generated policy, prove it with `run-instances --dry-run` under a throwaway
   role carrying the statement, with a control request that must be denied so a
   broken probe cannot pass as a clean result.

4. **One key read two ways.** Every condition key a statement adds is a key the
   scanner has to mirror, and a second key is where the two drift. Both IMDS
   statements were briefly built around an `ec2:MetadataHttpEndpoint` clause,
   on the theory that a launch disabling IMDS must stay possible; the hop-limit
   statement never carried it, so the pair disagreed about the same fleet.
   Dropping it left one key, `HttpTokens`, deciding in both the policy and the
   check. Prefer the narrower statement whose extra permission the operator can
   buy back for free - here, naming `HttpTokens=required` on a launch with no
   metadata service, which changes no behaviour.

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

  - path: headroom/checks/{type}/{check_name}.py
    decorator: "@register_check"
    add_kwarg: "terraform_section=TerraformSection.<SERVICE>,"
    do_not: "Edit generate_scps.py or generate_rcps.py. Both render from the registry; a hand-written branch is what INV-13 forbids."
    enforced_by: "test_generic_pipeline_modules_name_no_check fails if a generic module names a check."

# A check whose SCP statement is scoped by an allowlist needs EVERY step
# below. Stop short anywhere and the check still reports 100% compliance,
# the SCP is still enabled, and the allowlist renders empty - which for a
# Deny statement denies everything rather than nothing. deny_ec2_ami_owner
# shipped with the value collected and the module variable declared, and
# nothing carrying one to the other.
#
# Collect the value the CONDITION KEY will hold, not the field of the same
# name in the describe call. They can differ: ec2:Owner is an AMI's
# ImageOwnerAlias when it has one and its numeric OwnerId otherwise, so
# deny_ec2_ami_owner's allowlist of OwnerIds denied every Amazon and
# Marketplace AMI the scan had just cleared. Measure it with a --dry-run
# probe before believing either field, and shape the fixtures like real API
# responses - an unrealistic one (OwnerId: "amazon") hid this for a release.
if_check_has_allowlist:
  - path: headroom/checks/{type}/{check_name}.py
    function: "build_summary_fields"
    add_line: "\"unique_{thing}s\": sorted(list({thing}s))"

  - path: headroom/checks/{type}/{check_name}.py
    decorator: "@register_check"
    add_kwarg: |
      allowlist=Allowlist(
          summary_key="unique_{thing}s",
          terraform_variable="{service}_allowed_{thing}s",
          restores_account_ids=<True when the values are ARNs>,
          empty_allowlist_comment="{check_name} stays off here: <why the covered accounts observed nothing, and what an empty list would do>",
      )
    purpose: |
      Parsing reads summary_key and aborts when it is absent - an absent key
      and an empty list mean opposite things. Placement unions the values
      across the accounts a placement covers. Rendering emits
      terraform_variable only when the check is enabled and, when the union
      is empty and a comment is declared, leaves the policy off with that
      comment (INV-06). No Python file outside the check module changes; the
      Terraform module still declares the variable, below.

  - path: test_environment/modules/{type}/variables.tf
    add_block: |
      variable "{service}_allowed_{thing}s" {
        type        = list(string)
        default     = []
        description = "..."
      }
    location: "alphabetical by service"
    purpose: "The statement in locals.tf reads it as var.{service}_allowed_{thing}s. Without the declaration the rendered module does not plan; without default = [] every module call where the check is off stops planning, because the renderer emits the allowlist only for an enabled check."

  - path: tests/test_checks_{check_name}.py
    must_test: [summary_key_carries_the_observed_values, summary_key_present_when_nothing_observed]
    purpose: |
      Parsing, placement, and rendering of an allowlist are generic and
      already pinned: an absent summary_key aborts, an empty list is an
      observation, values union across the accounts a placement covers, and
      an empty union leaves the policy off with its comment. Those tests
      live in tests/test_parse_results.py, tests/test_terraform_parameters.py,
      and tests/test_committed_terraform_examples.py and need no new case.
      The check's own test is the one place its summary_key is proven to
      hold the values the statement's condition key will compare against,
      and to be present, as [], when the account holds nothing.

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
      aws:RequestTag reads the create request's. Neither is the resource's own
      tag. Substituting one is allowed only where you can argue the proxy is
      exact and write that argument into the check's specification, as
      spec/checks/scps/deny_ec2_imds_v1.md does. See INV-09.

  - path: headroom/constants.py
    add_lines: |
      The exemption tag key and value as constants, with a comment on the
      operator that compares them. StringNotEquals is case-sensitive, so the
      scanner must not lowercase what enforcement will not.

  - path: spec/checks/{type}/{check_name}.md
    must_state: |
      Which statements a clean scan clears and which it cannot, in the
      accepted-limitations section. A gap the scan cannot close changes the
      verdict or leaves the statement ungenerated; it is never carried by
      prose alone. See AP-009 habit 3.

  - path: tests/test_aws_{service}.py
    must_test: [right_dimension_exempts, wrong_dimension_does_not, value_case_is_exact, key_case_is_ignored, key_twice_in_differing_cases_raises]

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

# The per-item read, in its own function. The codes for one benign condition
# are tolerated; everything else propagates.
def _read_item(client: ServiceClient, item_id: str) -> Optional[JsonDict]:
    try:
        return client.get_item(ItemId=item_id)
    except ClientError as e:
        if e.response["Error"]["Code"] in NOTHING_TO_READ_ERROR_CODES:
            logger.debug(f"{item_id} is gone, skipping")
            return None
        raise


# The listing, materialized and on its own: a failure here is a set of items
# nobody read, so it aborts the run rather than shortening the results
# (INV-01, INV-02).
try:
    pages = list(client.get_paginator("operation").paginate())
except ClientError as e:
    logger.error(f"Failed to list items: {e}")
    raise

# The walk runs outside that try, so a per-item failure is never caught by the
# listing handler and mis-reported as a listing failure.
for item in [item for page in pages for item in page.get("Items", [])]:
    read = _read_item(client, item["Id"])
    if read is None:
        continue
    results.append(process(read))
```

### Pattern: Exemption Categorization

```python
# USE: For Pattern 4 checks with exemption tags
# COPY: This exact pattern

def categorize_result(self, result: Model) -> tuple[CheckCategory, JsonDict]:
    result_dict = {
        "id": result.id,
        "exemption_tag": result.exemption_tag,
    }

    # Check exemption FIRST (before violation)
    if result.has_exemption:
        return (CheckCategory.EXEMPTION, result_dict)

    # Then check violation
    if result.violates_policy:
        return (CheckCategory.VIOLATION, result_dict)

    # Everything else compliant
    return (CheckCategory.COMPLIANT, result_dict)

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
# _read_policy and _analyze_policy are the two helpers from
# "Template: RCP AWS Analysis (Policy Extraction)" above. _analyze_policy is
# where read_principal does the work - never write your own walk (AP-007).

def analyze_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[Result]:
    all_results = []

    for region in get_all_regions(session):
        client: ServiceClient = session.client("service", region_name=region)

        # The listing on its own: a failure enumerating a region is a region
        # nobody read, so it aborts the run.
        try:
            resources = list(_get_resources(client, region))
        except ClientError as e:
            logger.error(f"Failed to list resources in {region}: {e}")
            raise

        # Outside that try, so a per-resource failure propagates from where it
        # happened instead of being logged as a listing failure. The codes for
        # one benign condition are tolerated inside _read_policy.
        for resource in resources:
            policy = _read_policy(client, resource["Id"])
            if policy is None:
                continue

            all_results.append(_analyze_policy(
                policy=policy,
                resource_arn=resource["Arn"],
                region=region,
                org_account_ids=org_account_ids,
                org_id=org_id,
            ))

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
  fix: "Verify @register_check('scps'|'rcps', CHECK_CONSTANT, terraform_section=TerraformSection.<SERVICE>)"
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
  symptom: "coverage report shows <100%"
  causes:
    - "Missing edge case tests"
    - "Untested error paths"
    - "Missing categorization tests"
  fix:
    - "Run coverage report --include=headroom/* --show-missing to see untested lines"
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
    length, one repeated digit for the body -- except iam_unique_id, whose body
    is the one repeated letter A, for the reason iam_unique_id_reason gives.
    An identifier that arrives from a bug report, console screenshot, API
    response, or error message gets rewritten to its placeholder before it
    enters the repo -- including in the commit message.
  applies_to: ["headroom/", "spec/", "tests/", "test_environment/", "documentation/", "docstrings", "sample_config.yaml", "commit messages", "PR descriptions"]
  not_sensitive: ["region names", "service names", "AWS-owned owner aliases: amazon, aws-marketplace"]

  fake_account_ids:
    rule: "Blocks of four repeated digits: AAAABBBBCCCC"
    pattern: '^(\d)\1{3}(\d)\2{3}(\d)\3{3}$'  # 1000 available values
    primary: "111111111111"    # A == B == C reads clearest, so exhaust these first
    secondary: "222222222222"
    tertiary: "333333333333"
    beyond_ten: ["111122223333", "444455556666", "000011112222"]
    third_party: "9999BBBBCCCC"  # Out-of-organization accounts: 999900001111, 999911110000, ...
    third_party_reason: "The org-vs-third-party distinction is what the RCP checks turn on, so it should be visible in the fixture"
    never_use: "123456789012"  # Old AWS convention
    never_use_style: "Sequential runs such as 234567890123 or 987654321098"
    never_use_real: "A vendor's published account ID is still a real one. INV-15 in spec/invariants.md grants every standing exception, scopes it, and says what it buys; a new one is argued there and not here. This line named the set once and went stale when the set grew, so it names the invariant instead."

  fake_resource_ids:
    rule: "Real prefix, real length, body is one repeated digit - except iam_unique_id, whose alphabet omits 0, 1, 8, and 9"
    ec2_instance: "i-11111111111111111"                      # i- plus 17 hex
    ec2_ami: "ami-11111111111111111"                         # ami- plus 17 hex
    kms_key: "11111111-1111-1111-1111-111111111111"          # UUID
    organizations_root: "r-1111"
    organizations_ou: "ou-1111-11111111"                     # ou-<root>-<suffix>
    organizations_org: "o-11111111111"
    iam_access_key: "AKIAIOSFODNN7EXAMPLE"                   # AWS's own example key
    iam_unique_id: "AROAAAAAAAAAAAAAAAAAA"                   # AROA/AIDA plus 17, body one repeated LETTER
    iam_unique_id_user: "AIDAAAAAAAAAAAAAAAAAA"
    iam_unique_id_decodable: "AROA6RVFFB77QAAAAAAAA"         # Decodes to 999999999999
    iam_unique_id_reason: |
      The one body that is not a repeated digit. A repeated A resolves to no
      account, and AROA11111111111111111 is not a value AWS could have issued
      at all, so it aborts the run before the fixture reaches its path. Copy
      the literal above rather than picking your own letter: repeated Q
      through Z decode to a plausible account, and only A through P do not.
      Use iam_unique_id_decodable where the grantee has to resolve to an
      account, built by inverting headroom/aws/iam_unique_ids.py onto a
      placeholder one. INV-15 in spec/invariants.md owns both forms and which
      repeated bodies decode.
    ipv4_address: "111.111.111.111"                          # every octet one repeated digit
    ipv4_second: "222.222.222.222"                           # when a test needs a second host
    never_use_style: "AWS documentation's own hex bodies - the 1234567890abcdef0 and 0abcdef1234567890 its EC2 examples print"
    never_use_ip: "52.x and 54.x above all, which are live AWS EC2 ranges and read as a real instance's public IP"
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
    - aws_service: "the service the check reads. headroom/aws/ holds an
        adapter for ec2, ecr, eks, iam, kms, lambda, rds, s3, secretsmanager
        and sqs today; anything else is a new module"
    - pattern: "1-6 from spec/contracts/policy-model.md"
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
    - Run: "pytest tests/test_checks_{check_name}.py tests/test_aws_{service}.py -v"
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
    - Run: "coverage run --source=headroom,tests -m pytest tests/"
    - Run: "coverage report --include=headroom/* --show-missing --fail-under=100"
    - Run: "tox"
    - All must pass with no errors

step_6_e2e_optional:
  if_needed:
    - Create test_environment/test_{check_name}.tf
    - Document in test_environment/test_{check_name}/README.md
    - Run: "python -m headroom --config config.yaml"
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
    - categorize_result(result: T) -> tuple[CheckCategory, JsonDict]
    - build_summary_fields(check_result: CategorizedCheckResult) -> JsonDict
  template_method: execute()  # Calls your methods

registry:
  file: headroom/checks/registry.py
  decorator: "@register_check(type, name, terraform_section=..., allowlist=...)"
  discovery: "Automatic from scps/ and rcps/ directories"

type_aliases:
  file: headroom/types.py
  use:
    - JsonDict: "Instead of Dict[str, Any]"
    - AccountThirdPartyMap: "Account ID to the third-party accounts it reaches"

enums:
  file: headroom/enums.py
  use:
    - CheckCategory: "For categorization return values"
    - CheckType: "SCPS or RCPS"
    - PlacementLevel: "ROOT, OU, ACCOUNT or NONE"

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
  file: spec/contracts/policy-model.md
  use: "Determine which pattern (1-6) applies"
  examples: "See existing checks as pattern examples"

specification:
  manifest: spec/README.md
  invariants: spec/invariants.md
  per_check: "spec/checks/scps/{check_name}.md or spec/checks/rcps/{check_name}.md"
  enforced_by: tests/test_spec_corpus.py
```

---

## ✅ Final Checklist

```yaml
before_completion:
  code_quality:
    - mypy_passes: "mypy headroom/ tests/"
    - tests_pass: "pytest tests/ -v"
    - coverage_100: "coverage run --source=headroom,tests -m pytest tests/ && coverage report --include=headroom/* --show-missing --fail-under=100"
    - tox_passes: "tox"

  files_created:
    - spec/checks/{type}/{check_name}.md: "Written first, before any code"
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
    - specification_valid: "pytest tests/test_spec_corpus.py"
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
- `spec/contracts/policy-model.md` for policy patterns, and `spec/README.md` for which specification owns what
- `headroom/checks/base.py` for BaseCheck interface
- Test files in `tests/` for test examples
