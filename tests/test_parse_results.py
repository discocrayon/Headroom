"""
Tests for parse_results.py module.

Tests SCP/RCP compliance results analysis and placement recommendations.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from botocore.exceptions import ClientError

from headroom.parse_results import (
    parse_scp_result_files,
    determine_scp_placement,
    analyze_scp_compliance,
    print_policy_recommendations,
)
from headroom.terraform.generate_scps import generate_scp_terraform
from headroom.aws.organization import (
    analyze_organization_structure,
    create_account_ou_mapping,
)
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
        root_id="r-test",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="test-account",
                parent_ou_id="r-test",
                ou_path=["Root"]
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="test-account-2",
                parent_ou_id="r-test",
                ou_path=["Root"]
            ),
        }
    )


class TestOrganizationStructureAnalysis:
    """Test organization structure analysis functions."""

    def test_analyze_organization_structure_success(self) -> None:
        """Test successful organization structure analysis."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        mock_org_client.list_roots.return_value = {
            "Roots": [{"Id": "r-1234"}]
        }

        # Mock OU responses
        mock_org_client.list_organizational_units_for_parent.side_effect = [
            # Root level OUs
            {"OrganizationalUnits": [{"Id": "ou-1234", "Name": "Production"}]},
            # Child OUs (empty for simplicity)
            {"OrganizationalUnits": []},
            # Child OUs for Production OU (empty)
            {"OrganizationalUnits": []},
        ]

        # Mock account responses
        mock_org_client.list_accounts_for_parent.side_effect = [
            # Accounts under Production OU
            {"Accounts": [{"Id": "222222222222", "Name": "prod-account"}]},
            # Accounts directly under root (not in any OU)
            {"Accounts": [{"Id": "111111111111", "Name": "management-account"}]},
        ]

        result = analyze_organization_structure(mock_session)

        assert result.root_id == "r-1234"
        assert "ou-1234" in result.organizational_units
        assert "111111111111" in result.accounts
        assert "222222222222" in result.accounts

        # Verify Production OU structure
        prod_ou = result.organizational_units["ou-1234"]
        assert prod_ou.name == "Production"
        assert prod_ou.parent_ou_id is None
        assert "222222222222" in prod_ou.accounts

    def test_analyze_organization_structure_no_roots(self) -> None:
        """Test error handling when no roots found."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        mock_org_client.list_roots.return_value = {"Roots": []}

        with pytest.raises(RuntimeError, match="No roots found in organization"):
            analyze_organization_structure(mock_session)

    def test_analyze_organization_structure_client_error(self) -> None:
        """Test error handling for AWS client errors."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        mock_org_client.list_roots.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "AWS Error"}},
            "ListRoots"
        )

        with pytest.raises(RuntimeError, match="Failed to get organization root"):
            analyze_organization_structure(mock_session)

    def test_create_account_ou_mapping(self) -> None:
        """Test account to OU mapping creation."""
        mock_session = Mock()

        # Mock organization hierarchy
        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "management-account", "r-1234", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "prod-account", "ou-1234", ["Production"])
            }
        )

        with patch('headroom.aws.organization.analyze_organization_structure', return_value=mock_hierarchy):
            result = create_account_ou_mapping(mock_session)

        assert result["111111111111"] == "r-1234"
        assert result["222222222222"] == "ou-1234"

    def test_analyze_organization_structure_client_error_handling(self) -> None:
        """Test error handling for various AWS client errors."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        mock_org_client.list_roots.return_value = {
            "Roots": [{"Id": "r-1234"}]
        }

        # Mock OU responses with errors
        mock_org_client.list_organizational_units_for_parent.side_effect = [
            # Root level OUs
            {"OrganizationalUnits": [{"Id": "ou-1234", "Name": "Production"}]},
            # Child OUs (empty for simplicity)
            {"OrganizationalUnits": []},
            # Child OUs for Production OU (empty)
            {"OrganizationalUnits": []},
        ]

        # Mock account responses with errors
        mock_org_client.list_accounts_for_parent.side_effect = [
            # First call fails
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Failed to get accounts"}},
                "ListAccountsForParent"
            ),
            # Second call succeeds
            {"Accounts": [{"Id": "111111111111", "Name": "management-account"}]},
        ]

        # Should raise exception on first error
        with pytest.raises(RuntimeError, match="Failed to get accounts/child OUs for OU ou-1234"):
            analyze_organization_structure(mock_session)

    def test_analyze_organization_structure_root_accounts_error(self) -> None:
        """Test error handling when getting accounts under root fails."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        mock_org_client.list_roots.return_value = {
            "Roots": [{"Id": "r-1234"}]
        }

        # Mock OU responses (empty)
        mock_org_client.list_organizational_units_for_parent.return_value = {
            "OrganizationalUnits": []
        }

        # Mock account responses with error for root accounts
        mock_org_client.list_accounts_for_parent.side_effect = [
            # Root accounts call fails
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Failed to get root accounts"}},
                "ListAccountsForParent"
            ),
        ]

        # Should raise exception on error
        with pytest.raises(RuntimeError, match="Failed to get accounts under root"):
            analyze_organization_structure(mock_session)

    def test_analyze_organization_structure_ou_listing_error(self) -> None:
        """Test error handling when listing OUs fails."""
        mock_session = Mock()
        mock_org_client = Mock()
        mock_session.client.return_value = mock_org_client

        # Mock root response
        mock_org_client.list_roots.return_value = {
            "Roots": [{"Id": "r-1234"}]
        }

        # Mock OU listing failure
        mock_org_client.list_organizational_units_for_parent.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Failed to list OUs"}},
            "ListOrganizationalUnitsForParent"
        )

        # Mock account responses (empty)
        mock_org_client.list_accounts_for_parent.return_value = {
            "Accounts": []
        }

        # Should raise exception on error
        with pytest.raises(RuntimeError, match="Failed to list OUs for parent None"):
            analyze_organization_structure(mock_session)


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

    def test_parse_scp_result_files_with_redacted_iam_user_arns(self) -> None:
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
            assert result[0].iam_user_arns is not None
            assert len(result[0].iam_user_arns) == 2
            # Check that REDACTED was replaced with actual account ID
            assert "arn:aws:iam::111111111111:user/terraform-user" in result[0].iam_user_arns
            assert "arn:aws:iam::111111111111:user/service/github-actions" in result[0].iam_user_arns


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
            root_id="r-1234",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1234", ["Root"]),
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
            root_id="r-1234",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1234", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "ou-1234", ["Production"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "ou"
        assert result[0].target_ou_id == "ou-1234"
        assert result[0].compliance_percentage == 100.0
        assert "All accounts in OU 'Production' have zero violations" in result[0].reasoning

    def test_determine_scp_placement_account_level(self) -> None:
        """Test recommendation for account level deployment."""
        # Only some individual accounts have zero violations
        results_data = [
            SCPCheckResult("111111111111", "account-1", "deny_ec2_imds_v1", 2, 0, 3, 60.0, 5),
            SCPCheckResult("222222222222", "account-2", "deny_ec2_imds_v1", 0, 0, 3, 100.0, 3),
            SCPCheckResult("333333333333", "account-3", "deny_ec2_imds_v1", 1, 0, 2, 66.7, 3),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222", "333333333333"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1234", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "ou-1234", ["Production"]),
                "333333333333": AccountOrgPlacement("333333333333", "account-3", "ou-1234", ["Production"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "account"
        assert result[0].target_ou_id is None
        assert result[0].compliance_percentage == pytest.approx(33.3, rel=1e-1)
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
            root_id="r-1234",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1234", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "r-1234", ["Root"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "none"
        assert result[0].target_ou_id is None
        assert result[0].compliance_percentage == 0.0
        assert "No accounts have zero violations" in result[0].reasoning
        assert result[0].affected_accounts == []

    def test_determine_scp_placement_unions_iam_user_arns(self) -> None:
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
                iam_user_arns=[
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
                iam_user_arns=[
                    "arn:aws:iam::222222222222:user/cicd-deployer"
                ]
            ),
        ]

        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "account-1", "r-1234", ["Root"]),
                "222222222222": AccountOrgPlacement("222222222222", "account-2", "r-1234", ["Root"])
            }
        )

        result = determine_scp_placement(results_data, mock_hierarchy)

        assert len(result) == 1
        assert result[0].recommended_level == "root"
        assert result[0].allowed_iam_user_arns is not None
        assert len(result[0].allowed_iam_user_arns) == 3
        # Check all ARNs are present and sorted
        assert result[0].allowed_iam_user_arns == [
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
            root_id="r-1234",
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
            root_id="r-1234",
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
            root_id="r-1234",
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
            root_id="r-1234",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "test-account", "r-1234", ["Root"])
            }
        )

        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            # Should not raise any exceptions
            analyze_scp_compliance(config, mock_hierarchy)

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
            root_id="r-1234",
            organizational_units={},
            accounts={}
        )

        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            analyze_scp_compliance(config, mock_hierarchy)

    def test_parse_scp_results_no_result_files(self) -> None:
        """Test handling when no result files are found."""
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
            root_id="r-1234",
            organizational_units={},
            accounts={}
        )

        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            # Should return early without error
            analyze_scp_compliance(config, mock_hierarchy)

    def test_parse_scp_results_assume_role_failure(self) -> None:
        """Test that analyze_scp_compliance handles empty results gracefully."""
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
            root_id="r-1234",
            organizational_units={},
            accounts={}
        )

        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            # Should handle gracefully
            result = analyze_scp_compliance(config, mock_hierarchy)
            assert result == []

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
            root_id="r-1234",
            organizational_units={},
            accounts={}
        )

        with patch('headroom.parse_results.parse_scp_result_files', return_value=[]):
            result = analyze_scp_compliance(config, mock_hierarchy)
            assert result == []

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
            root_id="r-1234",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "test-account", "r-1234", ["Root"])
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
            root_id="r-1234",
            organizational_units={
                "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
            },
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "test-account", "r-1234", ["Root"]),
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

    def test_generate_scp_terraform_account_level(self) -> None:
        """Test generating Terraform files for account-level SCP recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            hierarchy = OrganizationHierarchy(
                root_id="r-1234",
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

            # Generate Terraform files
            generate_scp_terraform(recommendations, hierarchy, temp_dir)

            # Check that files were created
            output_path = Path(temp_dir)
            fort_knox_file = output_path / "fort_knox_scps.tf"
            prod_account_file = output_path / "prod_account_scps.tf"

            assert fort_knox_file.exists()
            assert prod_account_file.exists()

            # Check content of fort-knox file
            with open(fort_knox_file, 'r') as f:
                content = f.read()
                assert "fort-knox" in content
                assert "deny_ec2_imds_v1" in content
                assert "deny_ec2_imds_v1 = true" in content
                assert "local.fort_knox_account_id" in content

    def test_generate_scp_terraform_non_compliant_accounts_skipped(self) -> None:
        """Test that non-compliant accounts are skipped in Terraform generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            hierarchy = OrganizationHierarchy(
                root_id="r-1234",
                organizational_units={},
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "ou-1234", ["Production"]),
                    "111111111111": AccountOrgPlacement("111111111111", "prod-account", "ou-1234", ["Production"])
                }
            )

            # Create mock recommendations with mixed compliance
            recommendations = [
                SCPPlacementRecommendations(
                    check_name="deny_ec2_imds_v1",
                    recommended_level="account",
                    target_ou_id=None,
                    affected_accounts=["222222222222", "111111111111"],
                    compliance_percentage=50.0,  # Not 100% compliant
                    reasoning="Mixed compliance"
                )
            ]

            # Generate Terraform files
            generate_scp_terraform(recommendations, hierarchy, temp_dir)

            # Check that files were created but without the SCP flag
            output_path = Path(temp_dir)
            fort_knox_file = output_path / "fort_knox_scps.tf"

            assert fort_knox_file.exists()

            # Check content - should not have the SCP flag set to true
            with open(fort_knox_file, 'r') as f:
                content = f.read()
                assert "fort-knox" in content
                assert "deny_ec2_imds_v1 = true" not in content

    def test_generate_scp_terraform_ou_level(self) -> None:
        """Test generating Terraform files for OU-level SCP recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            hierarchy = OrganizationHierarchy(
                root_id="r-1234",
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

            # Generate Terraform files
            generate_scp_terraform(recommendations, hierarchy, temp_dir)

            # Check that OU file was created
            output_path = Path(temp_dir)
            production_ou_file = output_path / "production_ou_scps.tf"

            assert production_ou_file.exists()

            # Check content of production OU file
            with open(production_ou_file, 'r') as f:
                content = f.read()
                assert "Production" in content
                assert "deny_ec2_imds_v1" in content
                assert "deny_ec2_imds_v1 = true" in content
                assert "local.top_level_production_ou_id" in content

    def test_generate_scp_terraform_root_level(self) -> None:
        """Test generating Terraform files for root-level SCP recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            # Note: r-1234 is the org root ID, not an account. Accounts are placed under it.
            hierarchy = OrganizationHierarchy(
                root_id="r-1234",
                organizational_units={},
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "r-1234", ["Root"])
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

            # Generate Terraform files
            generate_scp_terraform(recommendations, hierarchy, temp_dir)

            # Check that root file was created
            output_path = Path(temp_dir)
            root_file = output_path / "root_scps.tf"

            assert root_file.exists()

            # Check content of root file
            with open(root_file, 'r') as f:
                content = f.read()
                assert "Organization Root" in content
                assert "deny_ec2_imds_v1" in content
                assert "deny_ec2_imds_v1 = true" in content
                assert "local.root_ou_id" in content

    def test_generate_scp_terraform_mixed_levels(self) -> None:
        """Test generating Terraform files for mixed account, OU, and root level recommendations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock organization hierarchy
            # Note: r-1234 is the org root ID. Accounts can be placed under it or under OUs.
            hierarchy = OrganizationHierarchy(
                root_id="r-1234",
                organizational_units={
                    "ou-1234": OrganizationalUnit("ou-1234", "Production", None, [], ["222222222222"])
                },
                accounts={
                    "222222222222": AccountOrgPlacement("222222222222", "fort-knox", "ou-1234", ["Production"]),
                    "111111111111": AccountOrgPlacement("111111111111", "prod-account", "r-1234", ["Root"])
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

            # Generate Terraform files
            generate_scp_terraform(recommendations, hierarchy, temp_dir)

            # Check that all files were created
            output_path = Path(temp_dir)
            fort_knox_file = output_path / "fort_knox_scps.tf"
            production_ou_file = output_path / "production_ou_scps.tf"
            root_file = output_path / "root_scps.tf"

            assert fort_knox_file.exists()
            assert production_ou_file.exists()
            assert root_file.exists()

            # Check that all files contain the SCP flag
            for file_path in [fort_knox_file, production_ou_file, root_file]:
                with open(file_path, 'r') as f:
                    content = f.read()
                    assert "deny_ec2_imds_v1 = true" in content


class TestPrintPolicyRecommendations:
    """Test print_policy_recommendations function."""

    def test_print_policy_recommendations_with_empty_list(self) -> None:
        """Test that empty recommendations list returns early without printing."""
        org_hierarchy = OrganizationHierarchy(
            root_id="r-test",
            organizational_units={},
            accounts={}
        )

        with patch('builtins.print') as mock_print:
            print_policy_recommendations([], org_hierarchy, "Test Title")

        mock_print.assert_not_called()

    def test_print_policy_recommendations_with_scp_recommendations(self) -> None:
        """Test printing SCP recommendations shows compliance percentage."""
        org_hierarchy = OrganizationHierarchy(
            root_id="r-test",
            organizational_units={
                "ou-123": OrganizationalUnit(
                    ou_id="ou-123",
                    name="Production",
                    parent_ou_id="r-test",
                    child_ous=[],
                    accounts=["111111111111"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="prod-account",
                    parent_ou_id="ou-123",
                    ou_path=["r-test", "ou-123"]
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
        assert any("Compliance:" in str(call) for call in printed_calls)

    def test_print_policy_recommendations_with_rcp_recommendations(self) -> None:
        """Test printing RCP recommendations shows third-party accounts."""
        org_hierarchy = OrganizationHierarchy(
            root_id="r-test",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="test-account",
                    parent_ou_id="r-test",
                    ou_path=["r-test"]
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
