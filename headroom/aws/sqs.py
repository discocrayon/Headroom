"""
AWS SQS queue policy analysis.

This module contains functions for analyzing SQS queues and their resource policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Union

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_sqs.client import SQSClient

from .helpers import get_all_regions, memoize_per_session
from .policy_documents import (
    normalize_actions,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    ServicePrincipalSource,
    UnknownPrincipalTypeError,
    has_not_principal,
    normalize_statements,
    read_principal,
    read_service_principal_sources,
    unreadable_service_principal_source,
)

logger = logging.getLogger(__name__)

# Error codes meaning a queue no longer exists.
#
# A queue deleted between `list_queues` and `get_queue_attributes` is the only
# benign reason that read fails: the queue is gone, so it holds no policy and can
# grant nobody access. Every other failure is a read Headroom could not complete
# and must not report as an absence of findings.
QUEUE_GONE_ERROR_CODES = frozenset({
    "AWS.SimpleQueueService.NonExistentQueue",
    "QueueDoesNotExist",
})


ActionsType = Union[str, List[str]]


@dataclass
class SQSQueuePolicyAnalysis:
    """
    Analysis of an SQS queue's resource policy.

    Attributes:
        queue_url: URL of the SQS queue
        queue_arn: ARN of the SQS queue
        region: AWS region where queue exists
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name
        has_non_account_principals: True if the policy grants to a principal
            type carrying no account ID, which no allowlist can preserve
        actions_by_account: Dict mapping account IDs to sets of allowed actions
        service_principal_sources: Service principals this policy trusts,
            with the cross-service source guard on each, or a single entry
            recording that the queue's policy could not be read at all.
            Read by the deny_service_confused_deputy check; contributes
            nothing to this analysis's own third-party accounts or wildcard
            flag, so a queue kept only for one of these entries stays
            invisible to the deny_sqs_third_party_access check.
    """
    queue_url: str
    queue_arn: str
    region: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)


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

    Args:
        queue_url: Queue URL
        queue_arn: Queue ARN
        region: AWS region
        policy_json: Policy JSON string
        org_account_ids: Set of organization account IDs to exclude
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        SQSQueuePolicyAnalysis result

    Raises:
        json.JSONDecodeError: If the policy is not valid JSON
        UnknownPrincipalTypeError: If a statement names a principal key AWS
            does not document
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
    """
    policy = json.loads(policy_json)
    third_party_account_ids: Set[str] = set()
    actions_by_account: Dict[str, Set[str]] = {}
    has_wildcard_principal = False
    has_non_account_principals = False
    sources: List[ServicePrincipalSource] = []

    statements = normalize_statements(policy, f"Queue {queue_arn} in {region}")

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        # An Allow with NotPrincipal reaches everyone it does not name,
        # which is what the wildcard flag records
        if has_not_principal(statement):
            has_wildcard_principal = True
            continue

        principal = statement.get("Principal")
        if not principal:
            continue

        sources.extend(
            read_service_principal_sources(statement, org_account_ids, org_id, f"Queue {queue_arn}")
        )

        reading = read_principal(
            principal, RESOURCE_POLICY_PRINCIPAL_TYPES, f"Queue {queue_arn} in {region}"
        )

        if reading.has_non_account_principals:
            has_non_account_principals = True

        has_wildcard_principal = has_wildcard_principal or reading.has_wildcard

        actions = normalize_actions(statement.get("Action", []))

        for account_id in reading.account_ids:
            if account_id in org_account_ids:
                continue
            third_party_account_ids.add(account_id)
            if account_id not in actions_by_account:
                actions_by_account[account_id] = set()
            actions_by_account[account_id].update(actions)

    return SQSQueuePolicyAnalysis(
        queue_url=queue_url,
        queue_arn=queue_arn,
        region=region,
        third_party_account_ids=third_party_account_ids,
        has_wildcard_principal=has_wildcard_principal,
        has_non_account_principals=has_non_account_principals,
        actions_by_account=actions_by_account,
        service_principal_sources=sources,
    )


def _unreadable_queue(
    queue_url: str,
    queue_arn: str,
    region: str,
    error: Exception,
) -> SQSQueuePolicyAnalysis:
    """
    Record a queue whose policy could not be read.

    The statement walk reads service principal sources before it reaches
    the principal types that raise, so a queue can fail partway through with
    a guard already read. Recording the queue does not preserve that guard -
    it dies with the raise. What it preserves is the knowledge that the read
    was incomplete, which is what matters: without it the queue vanished on
    a logger.warning, its source account never reached the
    DenyServiceConfusedDeputy allowlist, and the deployed RCP broke that
    integration. The failure entry withholds the statement instead.

    Every field the deny_sqs_third_party_access check reads is left empty,
    so that check's filter drops this queue exactly as the earlier
    warn-and-skip did. Only deny_service_confused_deputy sees the entry,
    and it files it as a violation, which withholds the statement from the
    account.

    Args:
        queue_url: URL of the queue that could not be read
        queue_arn: ARN of the queue, empty if the attributes never arrived
        region: AWS region the queue lives in
        error: Why the policy could not be read

    Returns:
        An analysis carrying only the read failure
    """
    return SQSQueuePolicyAnalysis(
        queue_url=queue_url,
        queue_arn=queue_arn,
        region=region,
        third_party_account_ids=set(),
        has_wildcard_principal=False,
        has_non_account_principals=False,
        actions_by_account={},
        service_principal_sources=[unreadable_service_principal_source(
            f"Queue {queue_url} in {region} could not be analyzed: {error}"
        )],
    )


def _analyze_queues_in_region(
    session: Session,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze SQS queues in a specific region.

    A read that fails aborts the run rather than returning an empty list.
    Returning nothing would be indistinguishable from a region that genuinely
    holds no queues with third-party access, and these results populate
    `sqs_third_party_access_account_ids_allowlist`, so the generated RCP would
    omit every partner whose queues live only in the unreadable region and deny
    them on deploy.

    This assumes the `Headroom` role is exempt from region-allowlist SCPs, which
    makes an `AccessDenied` here a genuine permissions gap rather than an
    expected regional block. See documentation/SETUP.md.

    A queue whose policy is unparseable, or names a principal type the
    analyzer does not recognize, is recorded rather than discarded - see
    `_unreadable_queue`.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze
        org_account_ids: Set of organization account IDs to exclude
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of SQSQueuePolicyAnalysis results for queues with policies

    Raises:
        ClientError: If listing queues, or reading a queue's attributes for any
            reason other than the queue having been deleted mid-scan, fails
    """
    sqs_client: SQSClient = session.client("sqs", region_name=region)
    results: List[SQSQueuePolicyAnalysis] = []

    try:
        paginator = sqs_client.get_paginator("list_queues")

        for page in paginator.paginate():
            queue_urls = page.get("QueueUrls", [])

            for queue_url in queue_urls:
                try:
                    attrs = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=["Policy", "QueueArn"]
                    )
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code in QUEUE_GONE_ERROR_CODES:
                        logger.debug(
                            f"Queue {queue_url} in {region} was deleted during the "
                            "scan, skipping"
                        )
                        continue
                    raise

                attributes = attrs.get("Attributes", {})
                policy_json = attributes.get("Policy")
                queue_arn = attributes.get("QueueArn", "")

                if not policy_json:
                    continue

                try:
                    result = _analyze_queue_policy(
                        queue_url=queue_url,
                        queue_arn=queue_arn,
                        region=region,
                        policy_json=policy_json,
                        org_account_ids=org_account_ids,
                        org_id=org_id
                    )
                    results.append(result)
                except (json.JSONDecodeError, UnknownPrincipalTypeError) as e:
                    logger.warning(f"Failed to analyze queue {queue_url} in {region}: {e}")
                    results.append(_unreadable_queue(queue_url, queue_arn, region, e))

    except ClientError as e:
        logger.error(f"Failed to analyze SQS queues in region {region}: {e}")
        raise

    return results


@memoize_per_session
def analyze_sqs_queue_policies(
    session: Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze SQS queue policies across all regions.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all SQS queues
       b. Get queue attributes (Policy, QueueArn)
       c. Skip queues without policies
       d. Parse policy JSON
       e. Extract principal account IDs
       f. Identify wildcard principals
       g. Identify principals carrying no account ID, which no allowlist can
          preserve and which therefore block the account
       h. Record third-party accounts (not in org) and the actions each may
          take, admitting an account to both in one step so the two cannot
          disagree
    3. Return all results with third-party access or wildcards

    Args:
        session: boto3.Session for the target account
        org_account_ids: Set of organization account IDs to exclude from results
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of SQSQueuePolicyAnalysis results

    Raises:
        ClientError: If any region's queues cannot be read
    """
    all_results: List[SQSQueuePolicyAnalysis] = []
    regions = get_all_regions(session)

    for region in regions:
        logger.debug(f"Analyzing SQS queues in {region}")
        regional_results = _analyze_queues_in_region(session, region, org_account_ids, org_id)
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} SQS queues with policies "
        f"across {len(regions)} regions"
    )
    return all_results
