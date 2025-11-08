"""AWS session management utilities."""

import boto3
from botocore.exceptions import ClientError
from typing import Optional


def assume_role(
    role_arn: str,
    session_name: str,
    base_session: Optional[boto3.Session] = None
) -> boto3.Session:
    """
    Assume an IAM role and return a session with temporary credentials.

    Args:
        role_arn: ARN of the role to assume
        session_name: Name for the role session
        base_session: Session to use for assuming role (defaults to boto3.Session())

    Returns:
        boto3 Session with assumed role credentials

    Raises:
        RuntimeError: If role assumption fails
    """
    if base_session is None:
        base_session = boto3.Session()

    sts = base_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
    except ClientError as e:
        raise RuntimeError(f"Failed to assume role {role_arn}: {e}")

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

