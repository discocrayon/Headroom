"""AWS session management utilities."""

from typing import Optional

from boto3.session import Session
from mypy_boto3_sts.client import STSClient
from mypy_boto3_sts.type_defs import AssumeRoleResponseTypeDef, CredentialsTypeDef


def assume_role(
    role_arn: str,
    session_name: str,
    base_session: Optional[Session] = None
) -> Session:
    """
    Assume an IAM role and return a session with temporary credentials.

    Args:
        role_arn: ARN of the role to assume
        session_name: Name for the role session
        base_session: Session to use for assuming role (defaults to boto3.Session())

    Returns:
        boto3 Session with assumed role credentials

    Raises:
        ClientError: If role assumption fails (AccessDenied, InvalidParameterValue, etc.)
    """
    if base_session is None:
        base_session = Session()

    sts: STSClient = base_session.client("sts")
    resp: AssumeRoleResponseTypeDef = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )

    creds: CredentialsTypeDef = resp["Credentials"]
    return Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )
