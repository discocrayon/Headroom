"""
AWS IAM SAML provider enumeration utilities.

This module provides helper functions and data models used by SCP checks that
need to analyze IAM SAML providers within an account.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError
from mypy_boto3_iam.client import IAMClient
from mypy_boto3_iam.type_defs import ListSAMLProvidersResponseTypeDef

logger = logging.getLogger(__name__)


@dataclass
class SamlProviderAnalysis:
    """
    Analysis record describing an IAM SAML provider.

    Attributes:
        arn: Full ARN of the SAML provider.
        name: Provider name derived from ARN suffix.
        create_date: Creation timestamp, if reported by AWS.
        valid_until: Expiration timestamp, if reported by AWS.
    """

    arn: str
    name: str
    create_date: Optional[datetime]
    valid_until: Optional[datetime]


def get_saml_providers_analysis(session: boto3.Session) -> List[SamlProviderAnalysis]:
    """
    Enumerate IAM SAML providers for the target account.

    Args:
        session: boto3 Session scoped to the target account.

    Returns:
        List of SamlProviderAnalysis entries discovered in the account.
    """
    iam_client: IAMClient = session.client("iam")
    results: List[SamlProviderAnalysis] = []

    try:
        response: ListSAMLProvidersResponseTypeDef = iam_client.list_saml_providers()
    except ClientError as exc:
        logger.error("Failed to list IAM SAML providers from AWS API: %s", exc)
        raise

    for entry in response.get("SAMLProviderList", []):
        arn = entry["Arn"]
        name = arn.split("/", 1)[1] if "/" in arn else arn
        create_date: Optional[datetime] = entry.get("CreateDate")
        valid_until: Optional[datetime] = entry.get("ValidUntil")

        results.append(
            SamlProviderAnalysis(
                arn=arn,
                name=name,
                create_date=create_date,
                valid_until=valid_until,
            )
        )

    return results
