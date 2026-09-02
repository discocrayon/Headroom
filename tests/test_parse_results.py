"""
Tests for parse_results.py module.

Tests SCP/RCP compliance results analysis and placement recommendations.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, patch

import pytest

from headroom.parse_results import (
    _build_ou_recommendation,
    parse_scp_result_files,
    determine_scp_placement,
    analyze_scp_compliance,
    print_policy_recommendations,
)
from headroom.terraform.generate_scps import render_scp_terraform
from headroom.types import (
    OrganizationHierarchy,
    OrganizationalUnit,
    AccountOrgPlacement,
    SCPCheckResult,
    SCPPlacementRecommendations,
    RCPPlacementRecommendations,
)
from headroom.config import HeadroomConfig, AccountTagLayout


def make_test_org_hierarchy() -> OrganizationHierarchy:
    """Create a simple test organization hierarchy."""
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="test-account",
                parent_ou_id="r-1111",
                ou_path=["Root"]
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="test-account-2",
                parent_ou_id="r-1111",
                ou_path=["Root"]
            ),
        }
    )


def make_hierarchy_with_production_ou(ou_account_ids: List[str]) -> OrganizationHierarchy:
    """
    Build a hierarchy with one OU and one account parented to the root.

    Args:
        ou_account_ids: Accounts under the Production OU

    Returns:
        A hierarchy holding 111111111111 at the root and those accounts
        under ou-1234
    """
    accounts = {
        "111111111111": AccountOrgPlacement(
            "111111111111", "account-111111111111", "r-1111", ["Root"]
        )
    }
    for account_id in ou_account_ids:
        accounts[account_id] = AccountOrgPlacement(
            account_id, f"account-{account_id}", "ou-1234", ["Production"]
        )
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={
            "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ou_account_ids)
        },
        accounts=accounts
    )


def make_scp_result(
    account_id: str,
    check_name: str,
    allowlist_values: Optional[List[str]],
    violations: int = 0
) -> SCPCheckResult:
    """
    Build one account's SCP check result carrying the values it observed.

    Args:
        account_id: Account the result belongs to
        check_name: Check the result belongs to
        allowlist_values: Values the check observed in that account
        violations: Findings the policy would have denied

    Returns:
        One parsed-shaped result
    """
    return SCPCheckResult(
        account_id=account_id,
        account_name="",
        check_name=check_name,
        violations=violations,
        exemptions=0,
        compliant=2,
        compliance_percentage=100.0 if violations == 0 else 50.0,
        total_instances=2,
        allowlist_values=allowlist_values
    )


class TestResultFileParsing:
    """Test result file parsing functionality."""

    def test_parse_scp_result_files_success(self) -> None:
        """Test successful parsing of result files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)

            # Create test directory structure
            check_dir = results_path / "scps" / "deny_ec2_imds_v1"
            check_dir.mkdir(parents=True)

            # Create test result files
            test_data = [
                {
                    "summary": {
                        "account_name": "test-account-1",
                        "account_id": "111111111111",
                        "check": "deny_ec2_imds_v1",
                        "total_instances": 5,
                        "violations": 2,
                        "exemptions": 1,
                        "compliant": 2,
                        "compliance_percentage": 60.0
                    },
                    "violations": [],
                    "exemptions": [],
                    "compliant_instances": []
                },
                {
                    "summary": {
                        "account_name": "test-account-2",
                        "account_id": "222222222222",
                        "check": "deny_ec2_imds_v1",
                        "total_instances": 3,
                        "violations": 0,
                        "exemptions": 0,
                        "compliant": 3,
                        "compliance_percentage": 100.0
                    },
                    "violations": [],
                    "exemptions": [],
                    "compliant_instances": []
                }
            ]

            # Write test files with correct account IDs
            with open(check_dir / "test-account-1_111111111111.json", 'w') as f:
                json.dump(test_data[0], f)
            with open(check_dir / "test-account-2_222222222222.json", 'w') as f:
                json.dump(test_data[1], f)

            org_hierarchy = make_test_org_hierarchy()
            result = parse_scp_result_files(temp_dir, org_hierarchy)

            assert len(result) == 2
            # Sort by account_id for consistent ordering
            result.sort(key=lambda x: x.account_id)
            assert result[0].account_id == "111111111111"
            assert result[0].violations == 2
            assert result[1].account_id == "222222222222"
            assert result[1].violations == 0

    def test_parse_scp_result_files_missing_directory(self) -> None:
        """Test handling of missing results directory."""
        org_hierarchy = make_test_org_hierarchy()
        with pytest.raises(RuntimeError, match="Results directory /nonexistent/directory does not exist"):
            parse_scp_result_files("/nonexistent/directory", org_hierarchy)

    def test_parse_scp_result_files_missing_scps_subdirectory(self) -> None:
        """Test handling when results directory exists but scps/ subdirectory doesn't."""
        with tempfile.TemporaryDirectory() as temp_dir:
            org_hierarchy = make_test_org_hierarchy()
            # Directory exists but has no scps/ subdirectory
            result = parse_scp_result_files(temp_dir, org_hierarchy)
            assert result == []

    def test_parse_scp_result_files_invalid_json(self) -> None:
        """Test handling of invalid JSON files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            check_dir = results_path / "scps" / "deny_ec2_imds_v1"
            check_dir.mkdir(parents=True)

            # Create invalid JSON file
            with open(check_dir / "invalid.json", 'w') as f:
                f.write("invalid json content")

            org_hierarchy = make_test_org_hierarchy()
            # Should raise exception on invalid JSON
            with pytest.raises(RuntimeError, match="Failed to parse result file .*/invalid.json"):
                parse_scp_result_files(temp_dir, org_hierarchy)

    def test_parse_scp_result_files_non_directory_files(self) -> None:
        """Test handling of non-directory files in scps directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            scps_path = results_path / "scps"
            scps_path.mkdir()

            # Create a file instead of directory in scps/
            with open(scps_path / "not_a_directory.txt", 'w') as f:
                f.write("This is not a directory")

            org_hierarchy = make_test_org_hierarchy()
            result = parse_scp_result_files(temp_dir, org_hierarchy)
            assert result == []

    def test_parse_scp_result_files_without_account_id_in_json(self) -> None:
        """Test parsing files where account_id is missing from JSON but in filename."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            check_dir = results_path / "scps" / "deny_ec2_imds_v1"
            check_dir.mkdir(parents=True)

            test_data = {
                "summary": {
                    "account_name": "test-account",
                    "check": "deny_ec2_imds_v1",
                    "total_instances": 5,
                    "violations": 0,
                    "exemptions": 0,
                    "compliant": 5,
                    "compliance_percentage": 100.0
                },
                "violations": [],
                "exemptions": [],
                "compliant_instances": []
            }

            # Write file with account_id in filename but not in JSON
            with open(check_dir / "test-account_111111111111.json", 'w') as f:
                json.dump(test_data, f)

            org_hierarchy = make_test_org_hierarchy()
            result = parse_scp_result_files(temp_dir, org_hierarchy)

            assert len(result) == 1
            assert result[0].account_id == "111111111111"
            assert result[0].account_name == "test-account"
            assert result[0].violations == 0

    def test_parse_scp_result_files_filename_without_account_id(self) -> None:
        """Test parsing files raises error when account_id missing and name not in org hierarchy."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            check_dir = results_path / "scps" / "deny_ec2_imds_v1"
            check_dir.mkdir(parents=True)

            test_data = {
                "summary": {
                    "account_name": "unknown-account",
                    "check": "deny_ec2_imds_v1",
                    "total_instances": 5,
                    "violations": 0,
                    "exemptions": 0,
                    "compliant": 5,
                    "compliance_percentage": 100.0
                },
                "violations": [],
                "exemptions": [],
                "compliant_instances": []
            }

            # Write file with account name not in org hierarchy
            with open(check_dir / "unknown-account.json", 'w') as f:
                json.dump(test_data, f)

            org_hierarchy = make_test_org_hierarchy()
            # Should raise error when account name lookup fails
            with pytest.raises(RuntimeError, match="Account name 'unknown-account' .* not found in organization hierarchy"):
                parse_scp_result_files(temp_dir, org_hierarchy)

    def test_parse_scp_result_files_restores_redacted_account_ids(self) -> None:
        """Test un-redaction of IAM user ARNs in deny_iam_user_creation results."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            check_dir = results_path / "scps" / "deny_iam_user_creation"
            check_dir.mkdir(parents=True)

            test_data = {
                "summary": {
                    "account_name": "test-account-1",
                    "account_id": "111111111111",
                    "check": "deny_iam_user_creation",
                    "total_users": 2,
                    "users": [
                        "arn:aws:iam::REDACTED:user/terraform-user",
                        "arn:aws:iam::REDACTED:user/service/github-actions"
                    ],
                    "violations": 0,
                    "exemptions": 0,
                    "compliant": 2,
                    "compliance_percentage": 100.0
                },
                "violations": [],
                "exemptions": [],
                "compliant_instances": []
            }

            with open(check_dir / "test-account-1_111111111111.json", 'w') as f:
                json.dump(test_data, f)

            org_hierarchy = make_test_org_hierarchy()
            result = parse_scp_result_files(temp_dir, org_hierarchy)

            assert len(result) == 1
            assert result[0].allowlist_values is not None
            assert len(result[0].allowlist_values) == 2
            # Check that REDACTED was replaced with actual account ID
            assert "arn:aws:iam::111111111111:user/terraform-user" in result[0].allowlist_values
            assert "arn:aws:iam::111111111111:user/service/github-actions" in result[0].allowlist_values


class TestSCPPlacementDetermination:
    """Test SCP placement determination logic."""

    def test_determine_scp_placement_root_level(self) -> None:
        """Test recommendation for root level deployment."""
        # All accounts have zero violations
        results_data = [
            SCPCheckResult("111111111111", "account-1", "deny_ec2_imds_v1", 0, 0, 5, 100.0, 5),
            SCPCheckResult("222222222222", "account-2", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "ou-1234", ["Production"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "root"
        assert result[0].target_ou_id is None
        assert result[0].compliance_percentage == 100.0
        assert "All accounts in organization have zero violations" in result[0].reasoning

    def test_determine_scp_placement_ou_level(self) -> None:
        """Test recommendation for OU level deployment."""
        # Only accounts in one OU have zero violations
        results_data = [
            SCPCheckResult("111111111111", "account-1", "deny_ec2_imds_v1", 2, 0, 3, 60.0, 5),
            SCPCheckResult("222222222222", "account-2", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "ou-1234", ["Production"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "ou"
        assert result[0].target_ou_id == "ou-1234"
        assert result[0].compliance_percentage == 100.0
        assert "under OU 'Production'" in result[0].reasoning
        assert "including those in its child OUs" in result[0].reasoning

    def test_determine_scp_placement_account_level(self) -> None:
        """Test recommendation for account level deployment."""
        # Only some individual accounts have zero violations
        results_data = [
            SCPCheckResult("111111111111", "account-1", "deny_ec2_imds_v1", 2, 0, 3, 60.0, 5),
            SCPCheckResult("222222222222", "account-2", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),
            SCPCheckResult("333333333333", "account-3", "deny_ec2_imds_v1", 1, 0, 2, 66.7, 3),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222", "333333333333"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "ou-1234", ["Production"]),
                "333333333333": AccountOrgPlacement("333333333333", "account-3", "ou-1234", ["Production"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "account"
        assert result[0].target_ou_id is None
        # Every account this recommendation targets has zero violations, the
        # same thing root and OU recommendations report. The 1-of-3 coverage
        # is org-wide reach, and lives in the reasoning.
        assert result[0].compliance_percentage == 100.0
        assert "Only 1 out of 3 accounts have zero violations" in result[0].reasoning
        assert "222222222222" in result[0].affected_accounts

    def test_determine_scp_placement_no_safe_deployment(self) -> None:
        """Test recommendation when no safe deployment is possible."""
        # All accounts have violations
        results_data = [
            SCPCheckResult("111111111111", "account-1", "deny_ec2_imds_v1", 2, 0, 3, 60.0, 5),
            SCPCheckResult("222222222222", "account-2", "deny_ec2_imds_v1", 1, 0, 2, 66.7, 3),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "r-1111", ["Root"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "none"
        assert result[0].target_ou_id is None
        assert result[0].compliance_percentage == 0.0
        assert "No accounts have zero violations" in result[0].reasoning
        assert result[0].affected_accounts == []

    def test_determine_scp_placement_unions_allowlist_values(self) -> None:
        """Test that IAM user ARNs are unioned for deny_iam_user_creation check."""
        # All accounts have zero violations with different IAM users
        results_data = [
            SCPCheckResult(
                account_id="111111111111",
                account_name="account-1",
                check_name="deny_iam_user_creation",
                violations=0,
                exemptions=0,
                compliant=2,
                compliance_percentage=100.0,
                total_instances=2,
                allowlist_values=[
                    "arn:aws:iam::111111111111:user/terraform-user",
                    "arn:aws:iam::111111111111:user/github-actions"
                ]
            ),
            SCPCheckResult(
                account_id="222222222222",
                account_name="account-2",
                check_name="deny_iam_user_creation",
                violations=0,
                exemptions=0,
                compliant=1,
                compliance_percentage=100.0,
                total_instances=1,
                allowlist_values=[
                    "arn:aws:iam::222222222222:user/cicd-deployer"
                ]
            ),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "r-1111", ["Root"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "root"
        assert result[0].allowlist_values is not None
        assert len(result[0].allowlist_values) == 3
        # Check all ARNs are present and sorted
        assert result[0].allowlist_values == [
            "arn:aws:iam::111111111111:user/github-actions",
            "arn:aws:iam::111111111111:user/terraform-user",
            "arn:aws:iam::222222222222:user/cicd-deployer"
        ]

    def test_determine_scp_placement_missing_account_in_hierarchy(self) -> None:
        """Test handling when account is not found in organization hierarchy."""
        # Create scenario that forces OU level check (not all accounts have zero violations)
        results_data = [
            SCPCheckResult("111111111111", "known-account", "deny_ec2_imds_v1", 2, 0, 3, 60.0, 5),  # Has violations
            SCPCheckResult("999999999999", "unknown-account", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),  # No violations but not in hierarchy
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["111111111111"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "known-account", "ou-1234", ["Production"])
            }
        )

        # Should raise exception for account not in hierarchy
        with pytest.raises(RuntimeError, match="Account \\(999999999999\\) not found in organization hierarchy"):
            determine_scp_placement(results_data, mock_hierarchy)

    def test_determine_scp_placement_missing_account_id_lookup_by_name(self) -> None:
        """Test handling when account_id is missing but account_name can be found in hierarchy."""
        results_data = [
            SCPCheckResult("", "known-account", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),
            SCPCheckResult("222222222222", "another-account", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),
            SCPCheckResult("333333333333", "third-account", "deny_ec2_imds_v1", 2, 0, 1, 33.3, 3),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["111111111111", "222222222222"]),
                "ou-5678": OrganizationalUnit("ou-5678", "Development", None, [], ["333333333333"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "known-account", "ou-1234", ["Production"]),
                "222222222222": AccountOrgPlacement("222222222222", "another-account", "ou-1234", ["Production"]),
                "333333333333": AccountOrgPlacement("333333333333", "third-account", "ou-5678", ["Development"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].check_name == "deny_ec2_imds_v1"
        assert result[0].recommended_level == "ou"
        assert result[0].target_ou_id == "ou-1234"
        assert set(result[0].affected_accounts) == {"111111111111", "222222222222"}

    def test_determine_scp_placement_missing_account_id_not_found_by_name(self) -> None:
        """Test handling when account_id is missing and account_name is not in hierarchy."""
        results_data = [
            SCPCheckResult("111111111111", "known-account", "deny_ec2_imds_v1", 2, 0, 3, 60.0, 5),
            SCPCheckResult("", "unknown-account", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["111111111111"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "known-account", "ou-1234", ["Production"])
            }
        )

        with pytest.raises(RuntimeError, match="Account name 'unknown-account' from SCP check result not found in organization hierarchy"):
            determine_scp_placement(results_data, mock_hierarchy)


class TestParseResultsIntegration:
    """Test integration of analyze_scp_compliance function."""

    def test_parse_scp_results_success(self) -> None:
        """Test successful analyze_scp_compliance execution."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id="222222222222"
        )

        # Mock organization hierarchy (now passed as parameter)
        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "test-account", "r-1111", ["Root"])
            }
        )

        parsed = [
            SCPCheckResult(
                account_id="111111111111",
                account_name="test-account",
                check_name="deny_ec2_imds_v1",
                violations=0,
                exemptions=0,
                compliant=3,
                total_instances=3,
                compliance_percentage=100.0,
            )
        ]

        with patch('headroom.parse_results.parse_scp_result_files', return_value=parsed):
            recommendations = analyze_scp_compliance(config, mock_hierarchy)

        assert [rec.check_name for rec in recommendations] == ["deny_ec2_imds_v1"]

    def test_parse_scp_results_missing_management_account_id(self) -> None:
        """Test that analyze_scp_compliance works with minimal organization hierarchy."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id=None
        )

        # Organization hierarchy is now passed by caller
        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={}
        )

        parsed = [
            SCPCheckResult(
                account_id="111111111111",
                account_name="test-account",
                check_name="deny_ec2_imds_v1",
                violations=0,
                exemptions=0,
                compliant=1,
                total_instances=1,
                compliance_percentage=100.0,
            )
        ]

        with patch('headroom.parse_results.parse_scp_result_files', return_value=parsed):
            assert analyze_scp_compliance(config, mock_hierarchy)

    def test_parse_scp_results_no_result_files(self) -> None:
        """Test that no result files stops the run rather than emptying the directory."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id="222222222222"
        )

        mock_security_session = Mock()
        mock_sts = Mock()
        mock_security_session.client.return_value = mock_sts

        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "test-key",
                "SecretAccessKey": "test-secret",
                "SessionToken": "test-token"
            }
        }

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={}
        )

        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            with pytest.raises(RuntimeError, match="No SCP result files"):
                analyze_scp_compliance(config, mock_hierarchy)

    def test_parse_scp_results_assume_role_failure(self) -> None:
        """Test that analyze_scp_compliance refuses to proceed on no evidence."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id="222222222222"
        )

        # Organization hierarchy is now passed by caller (role assumption happens before this)
        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={}
        )

        # Zero parsed results is the absence of evidence, not the evidence of
        # absence. Returning [] would reconcile the SCP directory to empty and
        # detach every policy in the organization on the next apply.
        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            with pytest.raises(RuntimeError, match="No SCP result files"):
                analyze_scp_compliance(config, mock_hierarchy)

    def test_parse_scp_results_organization_analysis_failure(self) -> None:
        """Test that analyze_scp_compliance works with minimal hierarchy data."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id="222222222222"
        )

        # Organization hierarchy is now passed by caller (analysis happens before this)
        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={}
        )

        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            with pytest.raises(RuntimeError, match="No SCP result files"):
                analyze_scp_compliance(config, mock_hierarchy)

    def test_parse_scp_results_with_recommendations_output(self) -> None:
        """Test analyze_scp_compliance returns recommendations without printing."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id="222222222222"
        )

        mock_security_session = Mock()
        mock_sts = Mock()
        mock_security_session.client.return_value = mock_sts

        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "test-key",
                "SecretAccessKey": "test-secret",
                "SessionToken": "test-token"
            }
        }

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "test-account", "r-1111", ["Root"])
            }
        )

        mock_results = [
            SCPCheckResult("111111111111", "test-account", "deny_ec2_imds_v1", 0, 0, 5, 100.0, 5)
        ]

        with patch('headroom.parse_results.parse_scp_result_files', return_value=mock_results):
            recommendations = analyze_scp_compliance(config, mock_hierarchy)

            # Verify recommendations were returned
            assert len(recommendations) == 1
            assert recommendations[0].check_name == "deny_ec2_imds_v1"
            assert recommendations[0].recommended_level == "root"

    def test_parse_scp_results_with_ou_recommendation_output(self) -> None:
        """Test analyze_scp_compliance with OU-level recommendation output."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id="222222222222"
        )

        mock_security_session = Mock()
        mock_sts = Mock()
        mock_security_session.client.return_value = mock_sts

        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "test-key",
                "SecretAccessKey": "test-secret",
                "SessionToken": "test-token"
            }
        }

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "test-account", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "prod-account", "ou-1234", ["Production"])
            }
        )

        # Create results that will trigger OU-level recommendation
        mock_results = [
            SCPCheckResult("111111111111", "test-account", "deny_ec2_imds_v1", 2, 0, 3, 60.0, 5),  # Has violations
            SCPCheckResult("222222222222", "prod-account", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),  # No violations
        ]

        with patch('headroom.parse_results.parse_scp_result_files', return_value=mock_results), \
             patch('builtins.print'):

            recommendations = analyze_scp_compliance(config, mock_hierarchy)

            # Verify that recommendations were returned
            assert isinstance(recommendations, list)
            assert len(recommendations) > 0


class TestGenerateSCPTerraform:
    """Test SCP Terraform generation functionality."""

    def test_render_scp_terraform_account_level(self) -> None:
        """Test generating Terraform files for account-level SCP recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            hierarchy = OrganizationHierarchy(
                root_id="r-1111",
                organizational_units={},
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "ou-1234", ["Production"]),
                    "111111111111": AccountOrgPlacement("111111111111", "prod-account", "ou-1234", ["Production"])
                }
            )

            # Create mock recommendations
            recommendations = [
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="account",
                    target_ou_id=None,
                    affected_accounts=["222222222222", "111111111111"],
                    compliance_percentage=100.0,
                    reasoning="All accounts have zero violations"
                )
            ]

            # Render Terraform files
            rendered = render_scp_terraform(recommendations, hierarchy, Path(temp_dir))

            # Check that files were rendered
            output_path = Path(temp_dir)
            fort_knox_file = output_path / "fort_knox_scps.tf"
            prod_account_file = output_path / "prod_account_scps.tf"

            assert fort_knox_file in rendered
            assert prod_account_file in rendered

            # Check content of fort-knox file
            content = rendered[fort_knox_file]
            assert "fort-knox" in content
            assert "deny_ec2_imds_v1" in content
            assert "deny_ec2_imds_v1 = true" in content
            assert "local.fort_knox_account_id" in content

    def test_render_scp_terraform_account_level_enables_the_policy(self) -> None:
        """
        Each safe account's file enables the policy the recommendation names.

        An account-level recommendation exists only for accounts with zero
        violations, and only when some other account has some - so the tier's
        org-wide coverage never reaches 100%. Generation used to gate on that
        fraction, so every per-account file it wrote had every policy false
        and protected nothing.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            hierarchy = OrganizationHierarchy(
                root_id="r-1111",
                organizational_units={},
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "ou-1234", ["Production"]),
                    "111111111111": AccountOrgPlacement("111111111111", "prod-account", "ou-1234", ["Production"])
                }
            )

            recommendations = [
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="account",
                    target_ou_id=None,
                    affected_accounts=["222222222222", "111111111111"],
                    compliance_percentage=100.0,
                    reasoning="Only 2 out of 5 accounts have zero violations - deploy at individual account level"
                )
            ]

            rendered = render_scp_terraform(recommendations, hierarchy, Path(temp_dir))

            output_path = Path(temp_dir)
            fort_knox_file = output_path / "fort_knox_scps.tf"

            assert fort_knox_file in rendered

            content = rendered[fort_knox_file]
            assert "fort-knox" in content
            assert "deny_ec2_imds_v1 = true" in content
            # A check with no recommendation for this account stays off.
            assert "deny_rds_unencrypted = false" in content

    def test_render_scp_terraform_ou_level(self) -> None:
        """Test generating Terraform files for OU-level SCP recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            hierarchy = OrganizationHierarchy(
                root_id="r-1111",
                organizational_units={
                    "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
                },
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "ou-1234", ["Production"])
                }
            )

            # Create mock OU-level recommendations
            recommendations = [
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="ou",
                    target_ou_id="ou-1234",
                    affected_accounts=["222222222222"],
                    compliance_percentage=100.0,
                    reasoning="All accounts in OU have zero violations"
                )
            ]

            # Render Terraform files
            rendered = render_scp_terraform(recommendations, hierarchy, Path(temp_dir))

            # Check that the OU file was rendered
            output_path = Path(temp_dir)
            production_ou_file = output_path / "production_ou_scps.tf"

            assert production_ou_file in rendered

            # Check content of production OU file
            content = rendered[production_ou_file]
            assert "Production" in content
            assert "deny_ec2_imds_v1" in content
            assert "deny_ec2_imds_v1 = true" in content
            assert "local.production_ou_id" in content

    def test_render_scp_terraform_root_level(self) -> None:
        """Test generating Terraform files for root-level SCP recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            # Note: r-1111 is the org root ID, not an account. Accounts are placed under it.
            hierarchy = OrganizationHierarchy(
                root_id="r-1111",
                organizational_units={},
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "r-1111", ["Root"])
                }
            )

            # Create mock root-level recommendations
            recommendations = [
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="root",
                    target_ou_id=None,
                    affected_accounts=["222222222222"],
                    compliance_percentage=100.0,
                    reasoning="All accounts in organization have zero violations"
                )
            ]

            # Render Terraform files
            rendered = render_scp_terraform(recommendations, hierarchy, Path(temp_dir))

            # Check that the root file was rendered
            output_path = Path(temp_dir)
            root_file = output_path / "root_scps.tf"

            assert root_file in rendered

            # Check content of root file
            content = rendered[root_file]
            assert "Organization Root" in content
            assert "deny_ec2_imds_v1" in content
            assert "deny_ec2_imds_v1 = true" in content
            assert "local.root_ou_id" in content

    def test_render_scp_terraform_mixed_levels(self) -> None:
        """Test generating Terraform files for mixed account, OU, and root level recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            # Note: r-1111 is the org root ID. Accounts can be placed under it or under OUs.
            hierarchy = OrganizationHierarchy(
                root_id="r-1111",
                organizational_units={
                    "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
                },
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "ou-1234", ["Production"]),
                    "111111111111": AccountOrgPlacement("111111111111", "prod-account", "r-1111", ["Root"])
                }
            )

            # Create mock mixed-level recommendations
            recommendations = [
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="account",
                    target_ou_id=None,
                    affected_accounts=["222222222222"],
                    compliance_percentage=100.0,
                    reasoning="Account has zero violations"
                ),
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="ou",
                    target_ou_id="ou-1234",
                    affected_accounts=["222222222222"],
                    compliance_percentage=100.0,
                    reasoning="All accounts in OU have zero violations"
                ),
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="root",
                    target_ou_id=None,
                    affected_accounts=["222222222222", "111111111111"],
                    compliance_percentage=100.0,
                    reasoning="All accounts in organization have zero violations"
                )
            ]

            # Render Terraform files
            rendered = render_scp_terraform(recommendations, hierarchy, Path(temp_dir))

            # Check that all files were rendered
            output_path = Path(temp_dir)
            fort_knox_file = output_path / "fort_knox_scps.tf"
            production_ou_file = output_path / "production_ou_scps.tf"
            root_file = output_path / "root_scps.tf"

            assert fort_knox_file in rendered
            assert production_ou_file in rendered
            assert root_file in rendered

            # Check that all files contain the SCP flag
            for file_path in [fort_knox_file, production_ou_file, root_file]:
                assert "deny_ec2_imds_v1 = true" in rendered[file_path]


class TestPrintPolicyRecommendations:
    """Test print_policy_recommendations function."""

    def test_print_policy_recommendations_with_empty_list(self) -> None:
        """Test that empty recommendations list returns early without printing."""
        org_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={}
        )

        with patch('builtins.print') as mock_print:
            print_policy_recommendations([], org_hierarchy, "Test Title")

        mock_print.assert_not_called()

    def test_print_policy_recommendations_with_scp_recommendations(self) -> None:
        """Test printing SCP recommendations shows compliance percentage."""
        org_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-123": OrganizationalUnit(
                    ou_id="ou-123",
                    name="Production",
                    parent_ou_id="r-1111",
                    child_ous=[],
                    accounts=["111111111111"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="prod-account",
                    parent_ou_id="ou-123",
                    ou_path=["r-1111", "ou-123"]
                )
            }
        )

        recommendations = [
            SCPPlacementRecommendations(
                check_name="deny_ec2_imds_v1",
                recommended_level="ou",
                target_ou_id="ou-123",
                affected_accounts=["111111111111"],
                compliance_percentage=75.5,
                reasoning="Test reasoning"
            )
        ]

        with patch('builtins.print') as mock_print:
            print_policy_recommendations(recommendations, org_hierarchy, "SCP RECOMMENDATIONS")

        printed_calls = [str(call) for call in mock_print.call_args_list]

        assert any("SCP RECOMMENDATIONS" in str(call) for call in printed_calls)
        assert any("deny_ec2_imds_v1" in str(call) for call in printed_calls)
        assert any("75.5%" in str(call) for call in printed_calls)
        assert any("Compliance (affected accounts):" in str(call) for call in printed_calls)

    def test_print_policy_recommendations_with_rcp_recommendations(self) -> None:
        """Test printing RCP recommendations shows third-party accounts."""
        org_hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="test-account",
                    parent_ou_id="r-1111",
                    ou_path=["r-1111"]
                )
            }
        )

        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=["111111111111"],
                third_party_account_ids=["999999999999", "888888888888"],
                reasoning="Test reasoning for RCP"
            )
        ]

        with patch('builtins.print') as mock_print:
            print_policy_recommendations(recommendations, org_hierarchy, "RCP RECOMMENDATIONS")

        printed_calls = [str(call) for call in mock_print.call_args_list]

        assert any("RCP RECOMMENDATIONS" in str(call) for call in printed_calls)
        assert any("deny_sts_third_party_assumerole" in str(call) for call in printed_calls)
        assert any("Third-Party Accounts: 2" in str(call) for call in printed_calls)


class TestRootParentedAccountPlacement:
    """
    Tests for accounts attached directly to the organization root.

    Such an account has no parent OU, so it can only be targeted by an SCP
    attached to the account itself. Treating the root ID as an OU used to
    raise "OU r-... not found in organization hierarchy" during Terraform
    generation.
    """
    ROOT_ID = "r-aabb"
    WORKLOADS_OU_ID = "ou-aabb-workloads"
    LEGACY_OU_ID = "ou-aabb-legacy"

    def make_hierarchy(self) -> OrganizationHierarchy:
        """
        Build an org with a safe OU, an unsafe OU, and a root-parented account.

        This is the shape that reaches OU grouping: the org is not safe at root,
        one OU is fully compliant, and one account hangs off the root.
        """
        return OrganizationHierarchy(
            root_id=self.ROOT_ID,
            organizational_units={
                self.WORKLOADS_OU_ID: OrganizationalUnit(
                    ou_id=self.WORKLOADS_OU_ID,
                    name="Workloads",
                    parent_ou_id=None,
                    child_ous=[],
                    accounts=["222222222222"]
                ),
                self.LEGACY_OU_ID: OrganizationalUnit(
                    ou_id=self.LEGACY_OU_ID,
                    name="Legacy",
                    parent_ou_id=None,
                    child_ous=[],
                    accounts=["333333333333"]
                ),
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="sandbox",
                    parent_ou_id=None,
                    ou_path=["Root"]
                ),
                "222222222222": AccountOrgPlacement(
                    account_id="222222222222",
                    account_name="prod",
                    parent_ou_id=self.WORKLOADS_OU_ID,
                    ou_path=["Workloads"]
                ),
                "333333333333": AccountOrgPlacement(
                    account_id="333333333333",
                    account_name="legacy-app",
                    parent_ou_id=self.LEGACY_OU_ID,
                    ou_path=["Legacy"]
                ),
            }
        )

    def make_results(self) -> list[SCPCheckResult]:
        """Build check results where only the Legacy OU account has violations."""
        return [
            SCPCheckResult(
                account_id="111111111111",
                account_name="sandbox",
                check_name="deny_ec2_imds_v1",
                violations=0,
                exemptions=0,
                compliant=3,
                compliance_percentage=100.0
            ),
            SCPCheckResult(
                account_id="222222222222",
                account_name="prod",
                check_name="deny_ec2_imds_v1",
                violations=0,
                exemptions=0,
                compliant=5,
                compliance_percentage=100.0
            ),
            SCPCheckResult(
                account_id="333333333333",
                account_name="legacy-app",
                check_name="deny_ec2_imds_v1",
                violations=7,
                exemptions=0,
                compliant=1,
                compliance_percentage=12.5
            ),
        ]

    def test_root_parented_account_is_placed_at_account_level(self) -> None:
        """The root-parented account gets its own account-level recommendation."""
        recommendations = determine_scp_placement(
            self.make_results(),
            self.make_hierarchy()
        )

        account_recs = [
            r for r in recommendations if r.recommended_level == "account"
        ]
        assert len(account_recs) == 1
        assert account_recs[0].affected_accounts == ["111111111111"]

    def test_safe_ou_still_gets_an_ou_recommendation(self) -> None:
        """Adding account-level coverage does not displace the OU recommendation."""
        recommendations = determine_scp_placement(
            self.make_results(),
            self.make_hierarchy()
        )

        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        assert len(ou_recs) == 1
        assert ou_recs[0].target_ou_id == self.WORKLOADS_OU_ID

    def test_no_recommendation_targets_the_root_id_as_an_ou(self) -> None:
        """Regression: the root ID must never appear as target_ou_id."""
        recommendations = determine_scp_placement(
            self.make_results(),
            self.make_hierarchy()
        )

        assert all(r.target_ou_id != self.ROOT_ID for r in recommendations)

    def test_render_scp_terraform_does_not_raise_for_root_parented_account(
        self
    ) -> None:
        """
        Regression: rendering Terraform used to raise RuntimeError.

        The root ID reached _generate_ou_scp_terraform, which looked it up in
        organizational_units and failed.
        """
        hierarchy = self.make_hierarchy()
        recommendations = determine_scp_placement(self.make_results(), hierarchy)

        with tempfile.TemporaryDirectory() as tmp_dir:
            rendered = render_scp_terraform(recommendations, hierarchy, Path(tmp_dir))

            generated = {path.name for path in rendered}
            assert generated == {"workloads_ou_scps.tf", "sandbox_scps.tf"}


class TestOURecommendationValidation:
    """Tests that a missing OU is reported rather than silently defaulted."""

    def test_build_ou_recommendation_raises_for_unknown_ou(self) -> None:
        """An OU absent from the hierarchy is an invariant violation."""
        hierarchy = OrganizationHierarchy(
            root_id="r-aabb",
            organizational_units={},
            accounts={}
        )

        with pytest.raises(RuntimeError, match=r"OU ou-aabb-missing not found"):
            _build_ou_recommendation(
                check_name="deny_ec2_imds_v1",
                target_ou_id="ou-aabb-missing",
                affected_accounts=["111111111111"],
                check_results=[],
                organization_hierarchy=hierarchy
            )


class TestCoverageIsIndependentOfOtherOUs:
    """
    Tests that placement for one account does not depend on unrelated OUs.

    Placement used to return OU-level candidates exclusively, so a compliant
    account sharing an OU with a violating one was recommended only while no
    other OU qualified. Remediating an unrelated OU silently withdrew it.
    """
    WORKLOADS_OU_ID = "ou-aabb-workloads"
    LEGACY_OU_ID = "ou-aabb-legacy"
    CLEAN_SIBLING = "333333333333"

    def make_hierarchy(self) -> OrganizationHierarchy:
        """Build two OUs of two accounts each."""
        return OrganizationHierarchy(
            root_id="r-aabb",
            organizational_units={
                self.WORKLOADS_OU_ID: OrganizationalUnit(
                    self.WORKLOADS_OU_ID, "Workloads", None, [],
                    ["111111111111", "222222222222"]
                ),
                self.LEGACY_OU_ID: OrganizationalUnit(
                    self.LEGACY_OU_ID, "Legacy", None, [],
                    [self.CLEAN_SIBLING, "444444444444"]
                ),
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    "111111111111", "prod", self.WORKLOADS_OU_ID, ["Workloads"]
                ),
                "222222222222": AccountOrgPlacement(
                    "222222222222", "staging", self.WORKLOADS_OU_ID, ["Workloads"]
                ),
                self.CLEAN_SIBLING: AccountOrgPlacement(
                    self.CLEAN_SIBLING, "legacy-a", self.LEGACY_OU_ID, ["Legacy"]
                ),
                "444444444444": AccountOrgPlacement(
                    "444444444444", "legacy-b", self.LEGACY_OU_ID, ["Legacy"]
                ),
            }
        )

    def make_results(self, staging_violations: int) -> list[SCPCheckResult]:
        """
        Build results where legacy-a is always compliant and legacy-b never is.

        staging_violations controls whether the unrelated Workloads OU qualifies.
        """
        counts = {
            "111111111111": ("prod", 0),
            "222222222222": ("staging", staging_violations),
            self.CLEAN_SIBLING: ("legacy-a", 0),
            "444444444444": ("legacy-b", 9),
        }
        return [
            SCPCheckResult(
                account_id=account_id,
                account_name=name,
                check_name="deny_ec2_imds_v1",
                violations=violations,
                exemptions=0,
                compliant=5,
                compliance_percentage=100.0
            )
            for account_id, (name, violations) in counts.items()
        ]

    def covered_accounts(self, staging_violations: int) -> set[str]:
        """Return every account named by any recommendation."""
        recommendations = determine_scp_placement(
            self.make_results(staging_violations),
            self.make_hierarchy()
        )
        return {
            account
            for rec in recommendations
            for account in rec.affected_accounts
        }

    def test_clean_account_covered_when_another_ou_qualifies(self) -> None:
        """A compliant account is recommended even though its own OU cannot be."""
        assert self.CLEAN_SIBLING in self.covered_accounts(staging_violations=0)

    def test_clean_account_covered_when_no_other_ou_qualifies(self) -> None:
        """The same account is recommended when no OU qualifies at all."""
        assert self.CLEAN_SIBLING in self.covered_accounts(staging_violations=4)

    def test_remediating_an_unrelated_ou_never_reduces_coverage(self) -> None:
        """
        Coverage is monotonic: fixing one OU cannot drop accounts elsewhere.

        The only difference between these runs is whether staging violates.
        """
        before_remediation = self.covered_accounts(staging_violations=4)
        after_remediation = self.covered_accounts(staging_violations=0)

        assert before_remediation <= after_remediation

    def test_violating_account_is_never_recommended(self) -> None:
        """Widening coverage must not recommend an account that has violations."""
        assert "444444444444" not in self.covered_accounts(staging_violations=0)


class TestAmiOwnerValuesAreParsed:
    """
    The parser carries deny_ec2_ami_owner's summary values into a result.

    `unique_ami_owners` reaches `SCPCheckResult.allowlist_values` unchanged:
    a populated list, an empty list (the check ran and observed nothing),
    and an absent key (a stale result, rejected rather than read as empty).
    """
    OBSERVED_OWNERS = ["amazon", "aws-marketplace"]

    def test_parse_carries_unique_ami_owners_from_summary(self) -> None:
        """The summary's unique_ami_owners survives into the check result."""
        with tempfile.TemporaryDirectory() as temp_dir:
            check_dir = Path(temp_dir) / "scps" / "deny_ec2_ami_owner"
            check_dir.mkdir(parents=True)

            test_data = {
                "summary": {
                    "account_name": "test-account-1",
                    "account_id": "111111111111",
                    "check": "deny_ec2_ami_owner",
                    "total_instances": 2,
                    "violations": 0,
                    "exemptions": 0,
                    "compliant": 2,
                    "compliance_percentage": 100.0,
                    "unique_ami_owners": self.OBSERVED_OWNERS,
                    "unknown_ami_owners": {}
                },
                "violations": [],
                "exemptions": [],
                "compliant_instances": []
            }

            with open(check_dir / "test-account-1_111111111111.json", 'w') as f:
                json.dump(test_data, f)

            result = parse_scp_result_files(temp_dir, make_test_org_hierarchy())

            assert len(result) == 1
            assert result[0].allowlist_values == self.OBSERVED_OWNERS

    def test_parse_rejects_a_result_file_predating_ami_owner_collection(self) -> None:
        """
        A deny_ec2_ami_owner result with no unique_ami_owners key aborts.

        Once parsed, a file written before the check collected owners is
        indistinguishable from an account that ran no instances - both yield
        an empty allowlist. They need opposite handling, so the distinction is
        drawn while the file is still in hand: a missing key is a stale
        artifact to re-run, an empty list is a fact about the account.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            check_dir = Path(temp_dir) / "scps" / "deny_ec2_ami_owner"
            check_dir.mkdir(parents=True)

            stale = {
                "summary": {
                    "account_name": "test-account-1",
                    "account_id": "111111111111",
                    "check": "deny_ec2_ami_owner",
                    "total_instances": 2,
                    "violations": 0,
                    "exemptions": 0,
                    "compliant": 2,
                    "compliance_percentage": 100.0,
                },
                "violations": [],
                "exemptions": [],
                "compliant_instances": []
            }

            with open(check_dir / "test-account-1_111111111111.json", 'w') as f:
                json.dump(stale, f)

            with pytest.raises(RuntimeError, match="has no unique_ami_owners in its summary"):
                parse_scp_result_files(temp_dir, make_test_org_hierarchy())

    def test_parse_accepts_an_account_that_observed_no_ami_owners(self) -> None:
        """
        An account with no instances reports an empty list, and that parses.

        This is the case the missing-key rejection has to be told apart from:
        the check ran, found nothing to look at, and said so.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            check_dir = Path(temp_dir) / "scps" / "deny_ec2_ami_owner"
            check_dir.mkdir(parents=True)

            empty = {
                "summary": {
                    "account_name": "test-account-1",
                    "account_id": "111111111111",
                    "check": "deny_ec2_ami_owner",
                    "total_instances": 0,
                    "violations": 0,
                    "exemptions": 0,
                    "compliant": 0,
                    "compliance_percentage": 100.0,
                    "unique_ami_owners": [],
                    "unknown_ami_owners": {}
                },
                "violations": [],
                "exemptions": [],
                "compliant_instances": []
            }

            with open(check_dir / "test-account-1_111111111111.json", 'w') as f:
                json.dump(empty, f)

            result = parse_scp_result_files(temp_dir, make_test_org_hierarchy())

            assert len(result) == 1
            assert result[0].allowlist_values == []


class TestAMissingViolationCountIsRejected:
    """
    A result file with no `violations` key aborts rather than reading as safe.

    Placement's whole safety test is `violations == 0`, so defaulting the
    missing key to zero turned an unanswerable question into the safest
    possible answer. That is the shape INV-01 forbids, and it was not
    hypothetical: `deny_iam_saml_provider_not_aws_sso` shipped without the key
    and had every account it rejected cleared for a root-level deny.

    A file that reaches here without the key is stale - written before its
    check emitted the count - and the fix is to delete it and let the check
    run again, which the error says.
    """

    def write_summary(self, directory: Path, summary: Dict[str, Any]) -> str:
        check_dir = directory / "scps" / "deny_ec2_imds_v1"
        check_dir.mkdir(parents=True)
        result_file = check_dir / "test-account_111111111111.json"
        result_file.write_text(json.dumps({"summary": summary}))
        return str(result_file)

    def hierarchy(self) -> OrganizationHierarchy:
        return OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="test-account",
                    parent_ou_id=None,
                    ou_path=["Root"],
                )
            },
        )

    def test_a_summary_without_the_key_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.write_summary(Path(temp_dir), {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": "deny_ec2_imds_v1",
                "compliant": 4,
            })

            with pytest.raises(RuntimeError, match="no violations count"):
                parse_scp_result_files(temp_dir, self.hierarchy())

    def test_the_missing_violations_message_says_to_delete_the_file(self) -> None:
        """
        The remedy the error prescribes has to be one that works.

        `results_exist` skips any account whose result file is already on
        disk, so "re-run the check" is a no-op: the run finds the file, skips
        the account, and the next parse raises again on the same file.
        Deleting it is the only thing that makes the re-run happen, and the
        operator can only do that if the message names the path.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            self.write_summary(Path(temp_dir), {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": "deny_ec2_imds_v1",
                "compliant": 4,
            })

            with pytest.raises(RuntimeError) as exc_info:
                parse_scp_result_files(temp_dir, self.hierarchy())

        message = str(exc_info.value)
        assert "delete" in message.lower()
        assert ".json" in message
        assert "Re-run the deny_ec2_imds_v1 check for this account" not in message

    def test_an_explicit_zero_is_not_a_missing_key(self) -> None:
        """Zero is an answer. Only absence is the failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            self.write_summary(Path(temp_dir), {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": "deny_ec2_imds_v1",
                "violations": 0,
                "compliant": 4,
            })

            parsed = parse_scp_result_files(temp_dir, self.hierarchy())

        assert [result.violations for result in parsed] == [0]


class TestAllowlistValuesFollowTheRegistry:
    """
    A parsed result carries the allowlist values its own check declares.

    The check registry names the summary key each check writes its observed
    allowlist values under, so parsing reads that key rather than comparing
    the check name against a literal (INV-13). One field on the result
    carries them for every check, so a new check needs no new field and no
    new branch here to complete its allowlist round trip (INV-07).
    """

    def parse_one_summary(
        self,
        check_name: str,
        summary: Dict[str, Any]
    ) -> List[SCPCheckResult]:
        """
        Write one account's result file for a check and parse the directory.

        Args:
            check_name: Directory under scps/ the file is written to
            summary: The file's whole summary block

        Returns:
            Every result the parse produced
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            check_dir = Path(temp_dir) / "scps" / check_name
            check_dir.mkdir(parents=True)
            result_file = check_dir / "test-account_111111111111.json"
            result_file.write_text(json.dumps({"summary": summary}))
            return parse_scp_result_files(temp_dir, make_test_org_hierarchy())

    def test_ami_owner_values_are_read_from_unique_ami_owners(self) -> None:
        """deny_ec2_ami_owner declares unique_ami_owners as its summary key."""
        parsed = self.parse_one_summary("deny_ec2_ami_owner", {
            "account_name": "test-account",
            "account_id": "111111111111",
            "check": "deny_ec2_ami_owner",
            "violations": 0,
            "unique_ami_owners": ["amazon", "444444444444"],
        })

        assert [result.allowlist_values for result in parsed] == [
            ["amazon", "444444444444"]
        ]

    def test_iam_user_values_restore_the_redacted_account_id(self) -> None:
        """
        deny_iam_user_creation's ARNs carry the account ID `exclude_account_ids` redacted.

        The values are user ARNs, so the account field is the account the
        result belongs to. The registry definition says so, and parsing puts
        it back: an ARN reading `REDACTED` allowlists no user.
        """
        parsed = self.parse_one_summary("deny_iam_user_creation", {
            "account_name": "test-account",
            "account_id": "111111111111",
            "check": "deny_iam_user_creation",
            "violations": 0,
            "users": ["arn:aws:iam::REDACTED:user/terraform-user"],
        })

        assert [result.allowlist_values for result in parsed] == [
            ["arn:aws:iam::111111111111:user/terraform-user"]
        ]

    def test_the_restore_touches_only_the_arn_account_field(self) -> None:
        """
        A user named REDACTED-svc is a user name, not a redacted account ID.

        Redaction matches the ARN's account field specifically, so a name
        carrying the token is written unchanged. Restoring by whole-string
        replacement undid that: it wrote the account ID into the name as
        well and allowlisted a user that does not exist. The restore matches
        the same field the redaction did.
        """
        parsed = self.parse_one_summary("deny_iam_user_creation", {
            "account_name": "test-account",
            "account_id": "111111111111",
            "check": "deny_iam_user_creation",
            "violations": 0,
            "users": ["arn:aws:iam::REDACTED:user/REDACTED-svc"],
        })

        assert [result.allowlist_values for result in parsed] == [
            ["arn:aws:iam::111111111111:user/REDACTED-svc"]
        ]

    @pytest.mark.parametrize(
        "check_name, summary_key",
        [
            ("deny_ec2_ami_owner", "unique_ami_owners"),
            ("deny_iam_user_creation", "users"),
        ],
    )
    def test_a_summary_key_carrying_anything_but_a_list_aborts(
        self,
        check_name: str,
        summary_key: str
    ) -> None:
        """
        `null` under the key is neither an absent key nor an empty list.

        The presence check accepts it, and what happened next depended on the
        check: restoring account IDs into None raised a bare TypeError, and
        AMI owners carried None through to placement, where the union filter
        dropped the account as if its check declared no allowlist - an
        observation lost without a word (INV-01). Both abort naming the file
        and the key.
        """
        with pytest.raises(
            RuntimeError,
            match=f"test-account_111111111111.json has {summary_key} = None in its summary, which is not a list",
        ):
            self.parse_one_summary(check_name, {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": check_name,
                "violations": 0,
                summary_key: None,
            })

    def test_a_check_with_no_allowlist_carries_no_values(self) -> None:
        """
        deny_rds_unencrypted declares no allowlist, so it reads none.

        The summary here also holds another check's summary key. The values
        belong to the check that declared the key, so this one still carries
        nothing: None is "this check has no allowlist", not "the file had no
        recognizable key".
        """
        parsed = self.parse_one_summary("deny_rds_unencrypted", {
            "account_name": "test-account",
            "account_id": "111111111111",
            "check": "deny_rds_unencrypted",
            "violations": 0,
            "unique_ami_owners": ["amazon"],
        })

        assert [result.allowlist_values for result in parsed] == [None]

    def test_an_absent_summary_key_aborts_naming_the_check_and_the_variable(self) -> None:
        """
        A missing summary key is a stale file, and it cannot pass for an empty one.

        An absent key and an empty list are indistinguishable once parsed,
        and they need opposite handling: a stale artifact to re-run, versus a
        fact about the account that leaves the policy off (INV-01). The error
        names the check to re-run and the allowlist that would have been
        built, because the operator holds neither.
        """
        with pytest.raises(RuntimeError) as exc_info:
            self.parse_one_summary("deny_ec2_ami_owner", {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": "deny_ec2_ami_owner",
                "violations": 0,
            })

        message = str(exc_info.value)
        assert "has no unique_ami_owners in its summary" in message
        assert "deny_ec2_ami_owner" in message
        assert "ec2_allowed_ami_owners" in message

    def test_parse_rejects_an_iam_user_result_without_users(self) -> None:
        """
        The abort belongs to every check with an allowlist, not to one of them.

        deny_iam_user_creation's absent key costs more than deny_ec2_ami_owner's:
        an empty allowlist renders `NotResource: []`, which Organizations
        rejects as malformed, taking every other statement in the module with
        it. Reading the key from the registry is what makes one rule cover
        both checks and the next one to declare an allowlist (INV-13).
        """
        with pytest.raises(RuntimeError, match="has no users in its summary"):
            self.parse_one_summary("deny_iam_user_creation", {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": "deny_iam_user_creation",
                "violations": 0,
            })

    def test_an_empty_list_is_an_observation_and_not_an_absent_key(self) -> None:
        """
        An account that observed nothing says so, and that parses.

        This is the case the absent-key abort has to be told apart from: the
        check ran, found no instance with a resolvable AMI owner, and
        recorded that. It leaves the policy off here (INV-06) rather than
        stopping the run.
        """
        parsed = self.parse_one_summary("deny_ec2_ami_owner", {
            "account_name": "test-account",
            "account_id": "111111111111",
            "check": "deny_ec2_ami_owner",
            "violations": 0,
            "unique_ami_owners": [],
        })

        assert [result.allowlist_values for result in parsed] == [[]]

    def test_an_unregistered_check_is_rejected_before_its_summary_is_read(self) -> None:
        """
        The name is checked before anything the file says about the check.

        A stale directory is stale throughout: its files predate the code
        that would say which of their keys are required. Reporting the first
        absent key sends the operator to re-run a check that no longer
        exists, so the name is resolved before any key is required of the
        file - here a file missing the violations count as well.
        """
        with pytest.raises(
            RuntimeError,
            match="test-account_111111111111.json names check 'deny_old_check', which is not a registered SCP check",
        ):
            self.parse_one_summary("deny_old_check", {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": "deny_old_check",
            })

    def test_parse_rejects_a_result_directory_for_an_unregistered_check(self) -> None:
        """
        A result file naming a check the registry does not hold aborts.

        The results directory outlives the code that wrote it, so a renamed
        or deleted check leaves a directory behind. Parsing cannot know
        whether that check declared an allowlist, so it cannot know whether
        the file it is holding is complete - and the recommendation it would
        build feeds a policy. The name is the whole of what is wrong, so the
        error says it, names the file, and says what to do with the
        directory: the registry's own "Unknown check" names neither, and
        main reports a ValueError as a configuration error, which a stale
        results directory is not.
        """
        with pytest.raises(
            RuntimeError,
            match=r"scps/deny_old_check/test-account_111111111111.json names check 'deny_old_check', "
                  r"which is not a registered SCP check\. .* Delete the file, and the rest of "
                  r".*scps/deny_old_check when it holds only that check's results, "
                  r"or register a check under that name\.",
        ):
            self.parse_one_summary("deny_old_check", {
                "account_name": "test-account",
                "account_id": "111111111111",
                "check": "deny_old_check",
                "violations": 0,
            })


class TestPlacementUnionsAllowlistValues:
    """
    A recommendation carries the union of the values its accounts observed.

    Attaching one policy to one target means every account under it must
    keep doing what it already does, so the allowlist is the union of what
    those accounts observed rather than any one of them. The union is taken
    over the accounts the recommendation covers and no others: an account a
    target does not reach cannot widen that target's allowlist.
    """

    def test_root_placement_unions_every_accounts_values(self) -> None:
        """A root attachment reaches every account, so it allowlists every value."""
        results_data = [
            make_scp_result("111111111111", "deny_ec2_ami_owner", ["amazon"]),
            make_scp_result("222222222222", "deny_ec2_ami_owner", ["444444444444", "amazon"]),
        ]

        recommendations = determine_scp_placement(results_data, make_test_org_hierarchy())

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert recommendations[0].allowlist_values == ["444444444444", "amazon"]

    def test_ou_placement_unions_only_the_accounts_the_ou_reaches(self) -> None:
        """An account outside the OU cannot widen that OU's allowlist."""
        results_data = [
            make_scp_result("111111111111", "deny_ec2_ami_owner", ["outside"], violations=2),
            make_scp_result("222222222222", "deny_ec2_ami_owner", ["amazon"]),
        ]

        recommendations = determine_scp_placement(
            results_data,
            make_hierarchy_with_production_ou(["222222222222"])
        )

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "ou"
        assert recommendations[0].allowlist_values == ["amazon"]

    def test_account_placement_carries_that_accounts_own_values(self) -> None:
        """An account-level attachment reaches one account, so it allowlists one."""
        results_data = [
            make_scp_result("111111111111", "deny_ec2_ami_owner", ["outside"], violations=2),
            make_scp_result("222222222222", "deny_ec2_ami_owner", ["amazon"]),
            make_scp_result("333333333333", "deny_ec2_ami_owner", ["444444444444"], violations=1),
        ]

        recommendations = determine_scp_placement(
            results_data,
            make_hierarchy_with_production_ou(["222222222222", "333333333333"])
        )

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "account"
        assert recommendations[0].allowlist_values == ["amazon"]

    def test_each_safe_account_gets_only_the_values_it_observed(self) -> None:
        """
        One account's observed values never reach another account's file.

        The account tier placed a single recommendation over every uncovered
        zero-violation account and unioned their values into it, and the
        renderer then wrote that union into each of their files. An account
        was allowlisted for an IAM user it does not hold, and an account
        holding no user at all had the policy switched on for someone else's
        users instead of staying off.
        """
        results_data = [
            make_scp_result(
                "111111111111",
                "deny_iam_user_creation",
                ["arn:aws:iam::111111111111:user/alpha-user"]
            ),
            make_scp_result(
                "222222222222",
                "deny_iam_user_creation",
                ["arn:aws:iam::222222222222:user/beta-user"]
            ),
            make_scp_result(
                "333333333333",
                "deny_iam_user_creation",
                ["arn:aws:iam::333333333333:user/gamma-user"],
                violations=2
            ),
            make_scp_result("444444444444", "deny_iam_user_creation", []),
        ]
        hierarchy = OrganizationHierarchy(
            root_id="r-1111",
            organizational_units={
                "ou-1234": OrganizationalUnit(
                    "ou-1234",
                    "Production",
                    None,
                    [],
                    ["222222222222", "333333333333", "444444444444"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "alpha", "r-1111", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "beta", "ou-1234", ["Production"]),
                "333333333333": AccountOrgPlacement("333333333333", "gamma", "ou-1234", ["Production"]),
                "444444444444": AccountOrgPlacement("444444444444", "delta", "ou-1234", ["Production"]),
            }
        )

        recommendations = determine_scp_placement(results_data, hierarchy)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir)
            rendered = render_scp_terraform(recommendations, hierarchy, output_path)

            alpha_content = rendered[output_path / "alpha_scps.tf"]
            beta_content = rendered[output_path / "beta_scps.tf"]
            delta_content = rendered[output_path / "delta_scps.tf"]

            assert "alpha-user" in alpha_content
            assert "beta-user" in beta_content
            assert "alpha-user" not in beta_content
            assert "beta-user" not in alpha_content
            assert "deny_iam_user_creation = false" in delta_content
            assert "alpha-user" not in delta_content

    def test_a_check_with_no_allowlist_places_without_values(self) -> None:
        """
        No allowlist to union stays no allowlist, rather than becoming an empty one.

        The two mean opposite things downstream: a check with no allowlist
        renders its statement unconditionally, while a check whose covered
        accounts observed nothing leaves its statement off (INV-06).
        """
        results_data = [
            make_scp_result("111111111111", "deny_ec2_imds_v1", None),
            make_scp_result("222222222222", "deny_ec2_imds_v1", None),
        ]

        recommendations = determine_scp_placement(results_data, make_test_org_hierarchy())

        assert len(recommendations) == 1
        assert recommendations[0].allowlist_values is None

    def test_covered_accounts_that_observed_nothing_union_to_an_empty_allowlist(self) -> None:
        """
        Every covered account observing nothing is an answer, and it is empty.

        This is the case the absent allowlist has to be told apart from. The
        check does have an allowlist here and every account it covers filled
        it with nothing, which leaves the policy off rather than rendering it
        unconditionally.
        """
        results_data = [
            make_scp_result("111111111111", "deny_ec2_ami_owner", []),
            make_scp_result("222222222222", "deny_ec2_ami_owner", []),
        ]

        recommendations = determine_scp_placement(results_data, make_test_org_hierarchy())

        assert len(recommendations) == 1
        assert recommendations[0].allowlist_values == []


class TestTheAccountTierPlacesEachAccountSeparately:
    """
    The account tier yields one recommendation per uncovered zero-violation
    account, ordered by account ID.
    """

    def test_account_recommendations_come_back_ordered_by_account_id(self) -> None:
        """
        The account tier's recommendations are ordered by account ID.

        Results reach placement in whatever order the run collected them, so
        ordering the recommendations here is what keeps two runs over the
        same organization producing the same list rather than one that
        follows collection order.
        """
        results_data = [
            make_scp_result("222222222222", "deny_ec2_ami_owner", ["amazon"]),
            make_scp_result("111111111111", "deny_ec2_ami_owner", ["amazon"]),
            make_scp_result("333333333333", "deny_ec2_ami_owner", ["outside"], violations=2),
        ]

        recommendations = determine_scp_placement(
            results_data,
            make_hierarchy_with_production_ou(["222222222222", "333333333333"])
        )

        assert len(recommendations) == 2
        assert recommendations[0].affected_accounts == ["111111111111"]
        assert recommendations[1].affected_accounts == ["222222222222"]

    def test_the_account_tier_places_one_recommendation_per_safe_account(self) -> None:
        """
        Every safe account the tier covers gets its own recommendation.

        The recommendation is the unit of attachment, so an account tier
        covering two accounts is two attachments rather than one spanning
        both. Each names one account and carries that account's values, and
        the reasoning still reports the tier's org-wide reach.
        """
        results_data = [
            make_scp_result("111111111111", "deny_ec2_ami_owner", ["amazon"]),
            make_scp_result("222222222222", "deny_ec2_ami_owner", ["444444444444"]),
            make_scp_result("333333333333", "deny_ec2_ami_owner", ["outside"], violations=2),
        ]

        recommendations = determine_scp_placement(
            results_data,
            make_hierarchy_with_production_ou(["222222222222", "333333333333"])
        )

        assert len(recommendations) == 2
        for recommendation in recommendations:
            assert recommendation.recommended_level == "account"
            assert recommendation.target_ou_id is None
            assert recommendation.compliance_percentage == 100.0
            assert "Only 2 out of 3 accounts have zero violations" in recommendation.reasoning
        assert recommendations[0].affected_accounts == ["111111111111"]
        assert recommendations[0].allowlist_values == ["amazon"]
        assert recommendations[1].affected_accounts == ["222222222222"]
        assert recommendations[1].allowlist_values == ["444444444444"]
