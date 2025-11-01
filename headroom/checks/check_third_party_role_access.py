"""
Check for IAM roles that allow third-party account access.

This check identifies IAM roles with trust policies that allow principals
from accounts outside the organization to assume them.
"""

import boto3  # type: ignore
from typing import Set
from ..aws.iam import analyze_iam_roles_trust_policies
from ..write_results import write_check_results


def check_third_party_role_access(
    headroom_session: boto3.Session,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    org_account_ids: Set[str],
    exclude_account_ids: bool = False,
) -> Set[str]:
    """
    Check for IAM roles that allow third-party account access.

    This check identifies:
    - IAM roles with trust policies allowing accounts outside the organization
    - IAM roles with wildcard principals in trust policies
    - All unique third-party account IDs found

    Args:
        headroom_session: boto3.Session for the target account
        account_name: Account name
        account_id: Account ID
        results_base_dir: Base directory for results
        org_account_ids: Set of all account IDs in the organization
        exclude_account_ids: If True, exclude account ID from results

    Returns:
        Set of third-party account IDs found in this account
    """
    # Get IAM role trust policy analysis
    trust_policy_results = analyze_iam_roles_trust_policies(
        headroom_session,
        org_account_ids
    )

    # Process results
    roles_with_third_party_access = []
    roles_with_wildcards = []
    all_third_party_accounts: Set[str] = set()

    for result in trust_policy_results:
        result_dict = {
            "role_name": result.role_name,
            "role_arn": result.role_arn,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "has_wildcard_principal": result.has_wildcard_principal
        }

        # Track all third-party accounts
        all_third_party_accounts.update(result.third_party_account_ids)

        if result.has_wildcard_principal:
            roles_with_wildcards.append(result_dict)
        if result.third_party_account_ids:
            roles_with_third_party_access.append(result_dict)

    # Create summary
    summary = {
        "account_name": account_name,
        "account_id": account_id,
        "check": "third_party_role_access",
        "total_roles_analyzed": len(trust_policy_results),
        "roles_with_third_party_access": len(roles_with_third_party_access),
        "roles_with_wildcards": len(roles_with_wildcards),
        "unique_third_party_accounts": sorted(list(all_third_party_accounts)),
        "third_party_account_count": len(all_third_party_accounts)
    }

    # Prepare full results
    results = {
        "summary": summary,
        "roles_with_third_party_access": roles_with_third_party_access,
        "roles_with_wildcards": roles_with_wildcards
    }

    # Write results to JSON file
    write_check_results(
        check_name="third_party_role_access",
        account_name=account_name,
        account_id=account_id,
        results_data=results,
        results_base_dir=results_base_dir,
        exclude_account_ids=exclude_account_ids,
    )

    account_identifier = f"{account_name}_{account_id}"
    print(f"Third-party role access check completed for {account_identifier}: "
          f"{len(roles_with_third_party_access)} roles with third-party access, "
          f"{len(roles_with_wildcards)} roles with wildcards, "
          f"{len(all_third_party_accounts)} unique third-party accounts")

    return all_third_party_accounts
