"""AWS session management utilities."""

from typing import Optional

import botocore.session
from boto3.session import Session
from mypy_boto3_sts.client import STSClient
from mypy_boto3_sts.type_defs import AssumeRoleResponseTypeDef, CredentialsTypeDef

__all__ = ["assume_role", "new_session"]


def new_session(
    region_name: Optional[str] = None,
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
) -> Session:
    """
    Build a boto3 Session that reaches STS at a regional endpoint.

    botocore defaults `sts_regional_endpoints` to `legacy`, which rewrites the
    STS endpoint to the global `sts.amazonaws.com` whenever the session's region
    is one of botocore's `LEGACY_GLOBAL_STS_REGIONS` -- the regions that predate
    opt-in regions, `us-east-1` and `us-west-2` among them. Session tokens the
    global endpoint issues are valid only in regions that are enabled by
    default, so an assumed-role credential minted there fails with `AuthFailure`
    the moment Headroom reads an opt-in region.

    Headroom scans every enabled region of every account, so opt-in regions are
    the normal case rather than the exception, and it cannot depend on the
    operator having set `sts_regional_endpoints = regional` themselves. Every
    session in the package is therefore built here;
    `test_only_the_sessions_module_constructs_a_session` pins that.
    """
    botocore_session = botocore.session.get_session()
    botocore_session.set_config_variable("sts_regional_endpoints", "regional")
    return Session(
        botocore_session=botocore_session,
        region_name=region_name,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
    )


def assume_role(
    role_arn: str,
    session_name: str,
    base_session: Optional[Session] = None
) -> Session:
    """
    Assume an IAM role and return a session with temporary credentials.

    The returned session carries the region the role was assumed from, so a
    chained assumption -- base account to security account to member account --
    keeps minting credentials regionally at every hop. See `new_session` for why
    that matters.

    Args:
        role_arn: ARN of the role to assume
        session_name: Name for the role session
        base_session: Session to use for assuming role (defaults to new_session())

    Returns:
        boto3 Session with assumed role credentials

    Raises:
        ClientError: If role assumption fails (AccessDenied, InvalidParameterValue, etc.)
        RuntimeError: If no region is configured to call STS in
    """
    if base_session is None:
        base_session = new_session()

    region = base_session.region_name
    if not region:
        raise RuntimeError(
            f"Cannot assume {role_arn}: no AWS region is configured. Headroom "
            f"calls STS at a regional endpoint so the credentials it mints stay "
            f"valid in opt-in regions, and it will not guess which region that "
            f"should be. Set AWS_REGION, AWS_DEFAULT_REGION, or a region on the "
            f"AWS profile."
        )

    sts: STSClient = base_session.client("sts", region_name=region)
    resp: AssumeRoleResponseTypeDef = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )

    creds: CredentialsTypeDef = resp["Credentials"]
    return new_session(
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )
