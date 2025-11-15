"""
AWS OpenSearch Serverless (AOSS) analysis placeholder.

Headroom skips evaluating AOSS data access policies because the
`deny_aoss_third_party_access` RCP cannot break policies, so this module always
returns zero violations.
"""

import logging
from dataclasses import dataclass
from typing import List, Set

import boto3

logger = logging.getLogger(__name__)


@dataclass
class AossResourcePolicyAnalysis:
    """
    Container describing the fields the previous AOSS analysis emitted.
    """

    resource_name: str
    resource_type: str
    resource_arn: str
    policy_name: str
    third_party_account_ids: Set[str]
    allowed_actions: List[str]


def analyze_aoss_resource_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
) -> List[AossResourcePolicyAnalysis]:
    """
    Return no violations for OpenSearch Serverless access policies.

    Args:
        session: boto3 session for the target account (unused).
        org_account_ids: Set of organization account IDs (unused).

    Returns:
        Empty list to indicate no violations.
    """

    logger.info(
        "Skipping OpenSearch Serverless analysis because no policy violations "
        "can be caused by the deny_aoss_third_party_access RCP"
    )
    return []
