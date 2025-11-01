"""
SCP/RCP Compliance Results Analysis Module

Analyzes headroom_results JSON files and determines optimal SCP/RCP placement
levels (root, OU, account) based on violation patterns and organization structure.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore

from .analysis import get_security_analysis_session
from .config import HeadroomConfig
from .terraform.generate_org_info import generate_terraform_org_info
from .aws.organization import analyze_organization_structure
from .types import (
    OrganizationalUnit, AccountOrgPlacement, OrganizationHierarchy,
    CheckResult, SCPPlacementRecommendations
)

# Set up logging
logger = logging.getLogger(__name__)


def parse_result_files(results_dir: str) -> List[CheckResult]:
    """
    Parse all JSON result files from headroom_results directory.

    Returns list of CheckResult objects.
    """
    results_path = Path(results_dir)
    if not results_path.exists():
        raise RuntimeError(f"Results directory {results_dir} does not exist")

    check_results: List[CheckResult] = []

    # Iterate through check directories
    for check_dir in results_path.iterdir():
        if not check_dir.is_dir():
            continue

        check_name = check_dir.name
        logger.info(f"Processing check: {check_name}")

        # Process each account result file
        for result_file in check_dir.glob("*.json"):
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)

                summary = data.get("summary", {})

                # Extract account_id - try from JSON first, then from filename
                account_id = summary.get("account_id", "")
                if not account_id:
                    # Try to extract from filename (format: name_id.json or name.json)
                    filename_stem = result_file.stem
                    if "_" in filename_stem:
                        # Old format: account_name_account_id
                        parts = filename_stem.rsplit("_", 1)
                        if len(parts) == 2 and parts[1].isdigit():
                            account_id = parts[1]

                check_results.append(CheckResult(
                    account_id=account_id,
                    account_name=summary.get("account_name", ""),
                    check_name=summary.get("check", check_name),
                    violations=summary.get("violations", 0),
                    exemptions=summary.get("exemptions", 0),
                    compliant=summary.get("compliant", 0),
                    total_instances=summary.get("total_instances", 0),
                    compliance_percentage=summary.get("compliance_percentage", 0.0)
                ))

            except (json.JSONDecodeError, KeyError) as e:
                raise RuntimeError(f"Failed to parse result file {result_file}: {e}")

    return check_results


def determine_scp_placement(
    results_data: List[CheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Analyze compliance results to determine optimal SCP/RCP placement level.

    Finds the highest organizational level where ALL accounts have zero violations.
    Ensures safe deployment without breaking existing violations that would cause operational issues.
    """
    recommendations: List[SCPPlacementRecommendations] = []

    # Group results by check name
    check_groups: Dict[str, List[CheckResult]] = {}
    for result in results_data:
        if result.check_name not in check_groups:
            check_groups[result.check_name] = []
        check_groups[result.check_name].append(result)

    for check_name, check_results in check_groups.items():
        logger.info(f"Analyzing placement for check: {check_name}")

        # Check if ALL accounts have zero violations (root level)
        all_accounts_zero_violations = all(
            result.violations == 0 for result in check_results
        )

        if all_accounts_zero_violations:
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="root",
                target_ou_id=None,
                affected_accounts=[result.account_id for result in check_results],
                compliance_percentage=100.0,
                reasoning="All accounts in organization have zero violations - safe to deploy at root level"
            ))
            continue

        # Check OU level - find OUs where ALL accounts have zero violations
        ou_violation_status: Dict[str, Dict[str, int]] = {}

        for result in check_results:
            account_info = organization_hierarchy.accounts.get(result.account_id)
            if not account_info:
                raise RuntimeError(f"Account {result.account_name} ({result.account_id}) not found in organization hierarchy")

            parent_ou_id = account_info.parent_ou_id
            if parent_ou_id not in ou_violation_status:
                ou_violation_status[parent_ou_id] = {"total_accounts": 0, "zero_violation_accounts": 0}

            ou_violation_status[parent_ou_id]["total_accounts"] += 1
            if result.violations == 0:
                ou_violation_status[parent_ou_id]["zero_violation_accounts"] += 1

        # Find OUs where all accounts have zero violations
        safe_ous: List[str] = []
        for ou_id, status in ou_violation_status.items():
            if status["zero_violation_accounts"] == status["total_accounts"] and status["total_accounts"] > 0:
                safe_ous.append(ou_id)

        if safe_ous:
            # Recommend OU level deployment for the largest safe OU
            largest_ou = max(safe_ous, key=lambda ou_id: ou_violation_status[ou_id]["total_accounts"])
            ou_name = organization_hierarchy.organizational_units.get(largest_ou, OrganizationalUnit("", "", None, [], [])).name

            affected_accounts = [
                result.account_id for result in check_results
                if organization_hierarchy.accounts.get(result.account_id, AccountOrgPlacement("", "", "", [])).parent_ou_id == largest_ou
            ]

            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="ou",
                target_ou_id=largest_ou,
                affected_accounts=affected_accounts,
                compliance_percentage=100.0,
                reasoning=f"All accounts in OU '{ou_name}' have zero violations - safe to deploy at OU level"
            ))
            continue

        # Check account level - individual accounts with zero violations
        safe_accounts = [
            result for result in check_results if result.violations == 0
        ]

        if safe_accounts:
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=[result.account_id for result in safe_accounts],
                compliance_percentage=len(safe_accounts) / len(check_results) * 100.0,
                reasoning=f"Only {len(safe_accounts)} out of {len(check_results)} accounts have zero violations - deploy at individual account level"
            ))
        else:
            # No safe deployment possible
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="none",
                target_ou_id=None,
                affected_accounts=[],
                compliance_percentage=0.0,
                reasoning="No accounts have zero violations - SCP deployment would break existing violations"
            ))

    return recommendations


def parse_results(config: HeadroomConfig) -> List[SCPPlacementRecommendations]:
    """
    Main function to parse results and determine SCP placement recommendations.

    Called from main.py after SCP analysis completion.

    Returns:
        List of SCP placement recommendations for each check.
    """
    logger.info("Starting SCP placement analysis")

    # Get security analysis session
    security_session = get_security_analysis_session(config)

    # Get management account session for Organizations API
    if not config.management_account_id:
        logger.error("management_account_id must be set for SCP placement analysis")
        return []

    role_arn = f"arn:aws:iam::{config.management_account_id}:role/OrgAndAccountInfoReader"
    sts = security_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HeadroomSCPPlacementAnalysisSession"
        )
    except ClientError as e:
        logger.error(f"Failed to assume OrgAndAccountInfoReader role: {e}")
        return []

    creds = resp["Credentials"]
    mgmt_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

    # Generate Terraform organization info file
    logger.info("Generating Terraform organization info file")
    generate_terraform_org_info(mgmt_session, f"{config.scps_dir}/grab_org_info.tf")

    # Analyze organization structure
    logger.info("Analyzing organization structure")
    try:
        organization_hierarchy = analyze_organization_structure(mgmt_session)
        logger.info(f"Found {len(organization_hierarchy.organizational_units)} OUs and {len(organization_hierarchy.accounts)} accounts")
    except RuntimeError as e:
        logger.error(f"Failed to analyze organization structure: {e}")
        return []

    # Parse result files
    results_dir = config.results_dir
    logger.info(f"Parsing result files from {results_dir}")
    results_data = parse_result_files(results_dir)

    if not results_data:
        logger.warning("No result files found to analyze")
        return []

    logger.info(f"Parsed {len(results_data)} result entries")

    # Determine SCP placement recommendations
    logger.info("Determining SCP placement recommendations")
    recommendations = determine_scp_placement(results_data, organization_hierarchy)

    # Output recommendations
    print("\n" + "=" * 80)
    print("SCP/RCP PLACEMENT RECOMMENDATIONS")
    print("=" * 80)

    for rec in recommendations:
        print(f"\nCheck: {rec.check_name}")
        print(f"Recommended Level: {rec.recommended_level.upper()}")
        if rec.target_ou_id:
            ou_name = organization_hierarchy.organizational_units.get(rec.target_ou_id, OrganizationalUnit("", "", None, [], [])).name
            print(f"Target OU: {ou_name} ({rec.target_ou_id})")
        print(f"Affected Accounts: {len(rec.affected_accounts)}")
        print(f"Compliance: {rec.compliance_percentage:.1f}%")
        print(f"Reasoning: {rec.reasoning}")
        print("-" * 40)

    logger.info("SCP placement analysis completed")
    return recommendations
