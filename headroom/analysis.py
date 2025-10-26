import logging
import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore
from typing import List
from dataclasses import dataclass
from .config import HeadroomConfig, AccountTagLayout
from .checks.deny_imds_v1_ec2 import check_deny_imds_v1_ec2
from .write_results import results_exist

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AccountInfo:
    account_id: str
    environment: str
    name: str
    owner: str


def get_security_analysis_session(config: HeadroomConfig) -> boto3.Session:
    """Assume OrganizationAccountAccessRole in the security analysis account and return a boto3 session."""
    account_id = config.security_analysis_account_id
    if not account_id:
        logger.debug("No security_analysis_account_id provided, assuming already in security analysis account")
        return boto3.Session()
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
    sts = boto3.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HeadroomSecurityAnalysisSession"
        )
    except ClientError as e:
        raise RuntimeError(f"Failed to assume role: {e}")
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


def get_subaccount_information(config: HeadroomConfig, session: boto3.Session) -> List[AccountInfo]:
    """
    Assume OrgAndAccountInfoReader role in the management account using the provided session.
    Return subaccount info with tags, skipping the management account itself.
    """
    if not config.management_account_id:
        raise ValueError("management_account_id must be set in config")
    role_arn = f"arn:aws:iam::{config.management_account_id}:role/OrgAndAccountInfoReader"
    sts = session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HeadroomOrgAndAccountInfoReaderSession"
        )
    except ClientError as e:
        raise RuntimeError(f"Failed to assume OrgAndAccountInfoReader role: {e}")
    creds = resp["Credentials"]
    mgmt_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )
    org_client = mgmt_session.client("organizations")
    paginator = org_client.get_paginator("list_accounts")
    accounts = []
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            account_id = acct["Id"]
            # Note: It is useful to have results for the management account, too
            # However, that is not what I want to focus on now
            if account_id == config.management_account_id:
                continue  # Skip the management account itself
            # Get tags for the account
            try:
                tags_resp = org_client.list_tags_for_resource(ResourceId=account_id)
                tags = {tag["Key"]: tag["Value"] for tag in tags_resp.get("Tags", [])}
            except ClientError as e:
                logger.warning(f"Could not fetch tags for account {account_id}: {e}")
                tags = {}
            layout: AccountTagLayout = config.account_tag_layout
            environment = tags.get(layout.environment) or "unknown"
            # Determine name source
            if config.use_account_name_from_tags:
                name = tags.get(layout.name) or account_id
            else:
                name = acct.get("Name") or account_id
            owner = tags.get(layout.owner) or "unknown"
            accounts.append(AccountInfo(
                account_id=account_id,
                environment=environment,
                name=name,
                owner=owner
            ))
    return accounts


def get_relevant_subaccounts(account_infos: List[AccountInfo]) -> List[AccountInfo]:
    """
    Filter account_infos based on CLI and configuration arguments.

    For now, returns all accounts. Future implementation will support filtering by:
    - All accounts
    - Specific OU
    - Specific owner
    - Specific environment
    """
    return account_infos


def get_headroom_session(config: HeadroomConfig, security_session: boto3.Session, account_id: str) -> boto3.Session:
    """Assume Headroom role in the target account and return a boto3 session."""
    role_arn = f"arn:aws:iam::{account_id}:role/Headroom"
    sts = security_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HeadroomAnalysisSession"
        )
    except ClientError as e:
        raise RuntimeError(f"Failed to assume Headroom role in account {account_id}: {e}")
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


def run_checks(security_session: boto3.Session, relevant_account_infos: List[AccountInfo], config: HeadroomConfig) -> None:
    """
    Run security checks against all relevant accounts.

    For each account:
    1. Checks if results already exist and skips if they do
    2. Assumes the Headroom role in that account
    3. Runs all configured SCP checks
    4. Writes results to headroom_results folder
    """
    for account_info in relevant_account_infos:
        account_identifier = f"{account_info.name}_{account_info.account_id}"

        # Check if results already exist for this account
        if results_exist(
            check_name="deny_imds_v1_ec2",
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_base_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
        ):
            logger.info(f"Results already exist for account {account_identifier}, skipping checks")
            continue

        logger.info(f"Running checks for account: {account_identifier}")

        try:
            headroom_session = get_headroom_session(config, security_session, account_info.account_id)

            # Run SCP checks
            # TODO: Make this configurable based on which SCPs are enabled
            check_deny_imds_v1_ec2(
                headroom_session,
                account_info.name,
                account_info.account_id,
                config.results_dir,
                config.exclude_account_ids,
            )

            logger.info(f"Checks completed for account: {account_identifier}")

        except RuntimeError as e:
            logger.error(f"Failed to run checks for account {account_identifier}: {e}")
            continue


def perform_analysis(config: HeadroomConfig) -> None:
    """Perform security analysis using the security analysis account session.

    `get_subaccount_information` excludes the management account because it is not
    affected by SCPs/RCPs.
    """
    logger.info("Starting security analysis")
    security_session = get_security_analysis_session(config)
    logger.info("Successfully obtained security analysis session")
    account_infos = get_subaccount_information(config, security_session)
    logger.info(f"Fetched subaccount information: {account_infos}")

    relevant_account_infos = get_relevant_subaccounts(account_infos)
    logger.info(f"Filtered to {len(relevant_account_infos)} relevant accounts for analysis")

    run_checks(security_session, relevant_account_infos, config)
    logger.info("Security analysis completed")
