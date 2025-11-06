import logging
import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore
from typing import List, Set
from dataclasses import dataclass
from .config import HeadroomConfig, AccountTagLayout
from .checks.scps.deny_imds_v1_ec2 import check_deny_imds_v1_ec2
from .checks.rcps.check_third_party_assumerole import check_third_party_assumerole
from .write_results import results_exist
from .constants import DENY_IMDS_V1_EC2, THIRD_PARTY_ASSUMEROLE

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
            account_name = acct.get("Name", account_id)
            # Note: It is useful to have results for the management account, too
            # However, that is not what I want to focus on now
            if account_id == config.management_account_id:
                continue  # Skip the management account itself
            # Get tags for the account
            try:
                tags_resp = org_client.list_tags_for_resource(ResourceId=account_id)
                tags = {tag["Key"]: tag["Value"] for tag in tags_resp.get("Tags", [])}
            except ClientError as e:
                logger.warning(f"Could not fetch tags for account {account_name} ({account_id}): {e}")
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


def get_all_organization_account_ids(config: HeadroomConfig, session: boto3.Session) -> Set[str]:
    """
    Get all account IDs in the organization (including management account).

    Args:
        config: Headroom configuration
        session: boto3 Session with access to security analysis account

    Returns:
        Set of all account IDs in the organization
    """
    if not config.management_account_id:
        raise ValueError("management_account_id must be set in config")

    role_arn = f"arn:aws:iam::{config.management_account_id}:role/OrgAndAccountInfoReader"
    sts = session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HeadroomOrgAccountListSession"
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

    account_ids: Set[str] = set()
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            account_ids.add(acct["Id"])

    return account_ids


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


def all_scp_results_exist(account_info: AccountInfo, config: HeadroomConfig) -> bool:
    """
    Check if all SCP check results exist for an account.

    Args:
        account_info: Account information
        config: Headroom configuration

    Returns:
        True if all SCP results exist, False otherwise
    """
    return results_exist(
        check_name=DENY_IMDS_V1_EC2,
        account_name=account_info.name,
        account_id=account_info.account_id,
        results_base_dir=config.results_dir,
        exclude_account_ids=config.exclude_account_ids,
    )


def all_rcp_results_exist(account_info: AccountInfo, config: HeadroomConfig) -> bool:
    """
    Check if all RCP check results exist for an account.

    Args:
        account_info: Account information
        config: Headroom configuration

    Returns:
        True if all RCP results exist, False otherwise
    """
    return results_exist(
        check_name=THIRD_PARTY_ASSUMEROLE,
        account_name=account_info.name,
        account_id=account_info.account_id,
        results_base_dir=config.results_dir,
        exclude_account_ids=config.exclude_account_ids,
    )


def run_scp_checks(
    headroom_session: boto3.Session,
    account_info: AccountInfo,
    config: HeadroomConfig
) -> None:
    """
    Run all SCP compliance checks for a single account.

    Args:
        headroom_session: boto3 Session with Headroom role assumed
        account_info: Account information
        config: Headroom configuration
    """
    # Check deny_imds_v1_ec2
    if not results_exist(
        check_name=DENY_IMDS_V1_EC2,
        account_name=account_info.name,
        account_id=account_info.account_id,
        results_base_dir=config.results_dir,
        exclude_account_ids=config.exclude_account_ids,
    ):
        check_deny_imds_v1_ec2(
            headroom_session,
            account_info.name,
            account_info.account_id,
            config.results_dir,
            config.exclude_account_ids,
        )


def run_rcp_checks(
    headroom_session: boto3.Session,
    account_info: AccountInfo,
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """
    Run all RCP compliance checks for a single account.

    Args:
        headroom_session: boto3 Session with Headroom role assumed
        account_info: Account information
        config: Headroom configuration
        org_account_ids: Set of all account IDs in the organization
    """
    # Check third_party_assumerole
    if not results_exist(
        check_name=THIRD_PARTY_ASSUMEROLE,
        account_name=account_info.name,
        account_id=account_info.account_id,
        results_base_dir=config.results_dir,
        exclude_account_ids=config.exclude_account_ids,
    ):
        check_third_party_assumerole(
            headroom_session,
            account_info.name,
            account_info.account_id,
            config.results_dir,
            org_account_ids,
            config.exclude_account_ids,
        )


def run_checks(
    security_session: boto3.Session,
    relevant_account_infos: List[AccountInfo],
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """
    Run security checks against all relevant accounts.

    For each account:
    1. Checks if results already exist and skips if they do
    2. Assumes the Headroom role in that account
    3. Runs all configured SCP/RCP checks
    4. Writes results to headroom_results folder

    Args:
        security_session: boto3 Session for security analysis account
        relevant_account_infos: List of accounts to check
        config: Headroom configuration
        org_account_ids: Set of all account IDs in the organization
    """
    for account_info in relevant_account_infos:
        account_identifier = f"{account_info.name}_{account_info.account_id}"

        # Check if all results already exist
        scp_exist = all_scp_results_exist(account_info, config)
        rcp_exist = all_rcp_results_exist(account_info, config)

        if scp_exist and rcp_exist:
            logger.info(f"All results already exist for account {account_identifier}, skipping checks")
            continue

        logger.info(f"Running checks for account: {account_identifier}")

        try:
            headroom_session = get_headroom_session(config, security_session, account_info.account_id)

            # Run SCP checks
            if not scp_exist:
                run_scp_checks(headroom_session, account_info, config)

            # Run RCP checks
            if not rcp_exist:
                run_rcp_checks(headroom_session, account_info, config, org_account_ids)

            logger.info(f"Checks completed for account: {account_identifier}")

        except RuntimeError as e:
            raise RuntimeError(f"Failed to run checks for account {account_identifier}: {e}")


def perform_analysis(config: HeadroomConfig) -> None:
    """
    Perform security analysis using the security analysis account session.

    `get_subaccount_information` excludes the management account because it is not
    affected by SCPs/RCPs.
    """
    logger.info("Starting security analysis")
    security_session = get_security_analysis_session(config)
    logger.info("Successfully obtained security analysis session")

    # Get all organization account IDs (including management account)
    # This is needed for RCP checks to identify third-party accounts
    logger.info("Fetching all organization account IDs")
    org_account_ids = get_all_organization_account_ids(config, security_session)
    logger.info(f"Found {len(org_account_ids)} accounts in organization")

    account_infos = get_subaccount_information(config, security_session)
    logger.info(f"Fetched subaccount information: {account_infos}")

    relevant_account_infos = get_relevant_subaccounts(account_infos)
    logger.info(f"Filtered to {len(relevant_account_infos)} relevant accounts for analysis")

    run_checks(security_session, relevant_account_infos, config, org_account_ids)
    logger.info("Security analysis completed")
