"""
AWS IAM user enumeration.

This module contains functions for listing IAM users in an account,
specifically for IAM user creation SCP checks.
"""

import logging
from dataclasses import dataclass
from typing import List

import boto3
from botocore.exceptions import ClientError
from mypy_boto3_iam.client import IAMClient

# Set up logging
logger = logging.getLogger(__name__)


@dataclass
class IamUserAnalysis:
    """
    Analysis of an IAM user.

    Attributes:
        user_name: Name of the IAM user
        user_arn: ARN of the IAM user
        path: Path of the IAM user
    """
    user_name: str
    user_arn: str
    path: str


def get_iam_users_analysis(session: boto3.Session) -> List[IamUserAnalysis]:
    """
    Get all IAM users in an account.

    Args:
        session: boto3 Session for the target account

    Returns:
        List of IamUserAnalysis for all IAM users
    """
    iam_client: IAMClient = session.client("iam")
    results: List[IamUserAnalysis] = []

    paginator = iam_client.get_paginator("list_users")
    try:
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                user_arn = user["Arn"]
                path = user["Path"]

                results.append(IamUserAnalysis(
                    user_name=user_name,
                    user_arn=user_arn,
                    path=path
                ))
    except ClientError as e:
        logger.error(f"Failed to list IAM users from AWS API: {e}")
        raise

    return results
