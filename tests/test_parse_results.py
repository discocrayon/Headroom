"""
Tests for parse_results.py module.

Tests SCP/RCP compliance results analysis and placement recommendations.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError  # type: ignore

from headroom.parse_results import (
    parse_result_files,
    determine_scp_placement,
    parse_results,
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
    CheckResult,
    SCPPlacementRecommendations,
)
from headroom.config import HeadroomConfig, AccountTagLayout


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

    def test_parse_result_files_success(self) -> None:
        """Test successful parsing of result files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)

            # Create test directory structure
            check_dir = results_path / "deny_imds_v1_ec2"
            check_dir.mkdir()

            # Create test result files
            test_data = [
                {
                    "summary": {
                        "account_name": "test-account-1",
                        "account_id": "111111111111",
                        "check": "deny_imds_v1_ec2",
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
                        "check": "deny_imds_v1_ec2",
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

            result = parse_result_files(temp_dir)

            assert len(result) == 2
            # Sort by account_id for consistent ordering
            result.sort(key=lambda x: x.account_id)
            assert result[0].account_id == "111111111111"
            assert result[0].violations == 2
            assert result[1].account_id == "222222222222"
            assert result[1].violations == 0

    def test_parse_result_files_missing_directory(self) -> None:
        """Test handling of missing results directory."""
        with pytest.raises(RuntimeError, match="Results directory /nonexistent/directory does not exist"):
            parse_result_files("/nonexistent/directory")

    def test_parse_result_files_invalid_json(self) -> None:
        """Test handling of invalid JSON files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            check_dir = results_path / "deny_imds_v1_ec2"
            check_dir.mkdir()

            # Create invalid JSON file
            with open(check_dir / "invalid.json", 'w') as f:
                f.write("invalid json content")

            # Should raise exception on invalid JSON
            with pytest.raises(RuntimeError, match="Failed to parse result file .*/invalid.json"):
                parse_result_files(temp_dir)

    def test_parse_result_files_non_directory_files(self) -> None:
        """Test handling of non-directory files in results directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)

            # Create a file instead of directory
            with open(results_path / "not_a_directory.txt", 'w') as f:
                f.write("This is not a directory")

            result = parse_result_files(temp_dir)
            assert result == []

    def test_parse_result_files_without_account_id_in_json(self) -> None:
        """Test parsing files where account_id is missing from JSON but in filename."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            check_dir = results_path / "deny_imds_v1_ec2"
            check_dir.mkdir()

            test_data = {
                "summary": {
                    "account_name": "test-account",
                    "check": "deny_imds_v1_ec2",
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

            result = parse_result_files(temp_dir)

            assert len(result) == 1
            assert result[0].account_id == "111111111111"
            assert result[0].account_name == "test-account"
            assert result[0].violations == 0

    def test_parse_result_files_filename_without_account_id(self) -> None:
        """Test parsing files with only account name in filename (no account_id)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_path = Path(temp_dir)
            check_dir = results_path / "deny_imds_v1_ec2"
            check_dir.mkdir()

            test_data = {
                "summary": {
                    "account_name": "test-account",
                    "check": "deny_imds_v1_ec2",
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

            # Write file with only account name in filename (exclude_account_ids mode)
            with open(check_dir / "test-account.json", 'w') as f:
                json.dump(test_data, f)

            result = parse_result_files(temp_dir)

            assert len(result) == 1
            assert result[0].account_id == ""
            assert result[0].account_name == "test-account"
            assert result[0].violations == 0


class TestSCPPlacementDetermination:
    """Test SCP placement determination logic."""

    def test_determine_scp_placement_root_level(self) -> None:
        """Test recommendation for root level deployment."""
        # All accounts have zero violations
        results_data = [
            CheckResult("111111111111", "account-1", "deny_imds_v1_ec2", 0, 0, 5, 5, 100.0),
            CheckResult("222222222222", "account-2", "deny_imds_v1_ec2", 0, 0, 3, 3, 100.0),
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
            CheckResult("111111111111", "account-1", "deny_imds_v1_ec2", 2, 0, 3, 5, 60.0),
            CheckResult("222222222222", "account-2", "deny_imds_v1_ec2", 0, 0, 3, 3, 100.0),
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
            CheckResult("111111111111", "account-1", "deny_imds_v1_ec2", 2, 0, 3, 5, 60.0),
            CheckResult("222222222222", "account-2", "deny_imds_v1_ec2", 0, 0, 3, 3, 100.0),
            CheckResult("333333333333", "account-3", "deny_imds_v1_ec2", 1, 0, 2, 3, 66.7),
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
            CheckResult("111111111111", "account-1", "deny_imds_v1_ec2", 2, 0, 3, 5, 60.0),
            CheckResult("222222222222", "account-2", "deny_imds_v1_ec2", 1, 0, 2, 3, 66.7),
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

    def test_determine_scp_placement_missing_account_in_hierarchy(self) -> None:
        """Test handling when account is not found in organization hierarchy."""
        # Create scenario that forces OU level check (not all accounts have zero violations)
        results_data = [
            CheckResult("111111111111", "known-account", "deny_imds_v1_ec2", 2, 0, 3, 5, 60.0),  # Has violations
            CheckResult("999999999999", "unknown-account", "deny_imds_v1_ec2", 0, 0, 3, 3, 100.0),  # No violations but not in hierarchy
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
        with pytest.raises(RuntimeError, match="Account unknown-account \\(999999999999\\) not found in organization hierarchy"):
            determine_scp_placement(results_data, mock_hierarchy)


class TestParseResultsIntegration:
    """Test integration of parse_results function."""

    def test_parse_results_success(self) -> None:
        """Test successful parse_results execution."""
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

        # Mock the security session and management account session
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

        # Mock organization analysis
        mock_hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={},
            accounts={
                "111111111111": AccountOrgPlacement("111111111111", "test-account", "r-1234", ["Root"])
            }
        )

        with patch('headroom.parse_results.get_security_analysis_session', return_value=mock_security_session), \
             patch('headroom.parse_results.analyze_organization_structure', return_value=mock_hierarchy), \
             patch('headroom.parse_results.parse_result_files', return_value=[]):

            # Should not raise any exceptions
            parse_results(config)

    def test_parse_results_missing_management_account_id(self) -> None:
        """Test error handling when management_account_id is missing."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment",
                name="Name",
                owner="Owner"
            ),
            security_analysis_account_id="111111111111",
            management_account_id=None  # Missing management account ID
        )

        mock_security_session = Mock()

        with patch('headroom.parse_results.get_security_analysis_session', return_value=mock_security_session):
            # Should return early without error
            parse_results(config)

    def test_parse_results_no_result_files(self) -> None:
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

        with patch('headroom.parse_results.get_security_analysis_session', return_value=mock_security_session), \
             patch('headroom.parse_results.analyze_organization_structure', return_value=mock_hierarchy), \
             patch('headroom.parse_results.parse_result_files', return_value=[]):

            # Should return early without error
            parse_results(config)

    def test_parse_results_assume_role_failure(self) -> None:
        """Test error handling when assume role fails."""
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

        # Mock assume role failure
        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "AssumeRole"
        )

        with patch('headroom.parse_results.get_security_analysis_session', return_value=mock_security_session):
            # Should return early without error
            parse_results(config)

    def test_parse_results_organization_analysis_failure(self) -> None:
        """Test error handling when organization analysis fails."""
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

        with patch('headroom.parse_results.get_security_analysis_session', return_value=mock_security_session), \
             patch('headroom.parse_results.analyze_organization_structure', side_effect=RuntimeError("Analysis failed")):

            # Should return early without error
            parse_results(config)

    def test_parse_results_with_recommendations_output(self) -> None:
        """Test parse_results with actual recommendations output."""
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
            CheckResult("111111111111", "test-account", "deny_imds_v1_ec2", 0, 0, 5, 5, 100.0)
        ]

        with patch('headroom.parse_results.get_security_analysis_session', return_value=mock_security_session), \
             patch('headroom.parse_results.analyze_organization_structure', return_value=mock_hierarchy), \
             patch('headroom.parse_results.parse_result_files', return_value=mock_results), \
             patch('builtins.print') as mock_print:

            parse_results(config)

            # Verify that output was printed
            assert mock_print.called
            # Check that the header was printed
            print_calls = [call[0][0] for call in mock_print.call_args_list]
            assert any("SCP/RCP PLACEMENT RECOMMENDATIONS" in call for call in print_calls)

    def test_parse_results_with_ou_recommendation_output(self) -> None:
        """Test parse_results with OU-level recommendation output."""
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
            CheckResult("111111111111", "test-account", "deny_imds_v1_ec2", 2, 0, 3, 5, 60.0),  # Has violations
            CheckResult("222222222222", "prod-account", "deny_imds_v1_ec2", 0, 0, 3, 3, 100.0),  # No violations
        ]

        with patch('headroom.parse_results.get_security_analysis_session', return_value=mock_security_session), \
             patch('headroom.parse_results.analyze_organization_structure', return_value=mock_hierarchy), \
             patch('headroom.parse_results.parse_result_files', return_value=mock_results), \
             patch('builtins.print'):

            recommendations = parse_results(config)

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
                    check_name="deny_imds_v1_ec2",
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
                assert "deny_imds_v1_ec2" in content
                assert "deny_imds_v1_ec2 = true" in content
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
                    check_name="deny_imds_v1_ec2",
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
                assert "deny_imds_v1_ec2 = true" not in content

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
                    check_name="deny_imds_v1_ec2",
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
                assert "deny_imds_v1_ec2" in content
                assert "deny_imds_v1_ec2 = true" in content
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
                    check_name="deny_imds_v1_ec2",
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
                assert "deny_imds_v1_ec2" in content
                assert "deny_imds_v1_ec2 = true" in content
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
                    check_name="deny_imds_v1_ec2",
                    recommended_level="account",
                    target_ou_id=None,
                    affected_accounts=["222222222222"],
                    compliance_percentage=100.0,
                    reasoning="Account has zero violations"
                ),
                SCPPlacementRecommendations(
                    check_name="deny_imds_v1_ec2",
                    recommended_level="ou",
                    target_ou_id="ou-1234",
                    affected_accounts=["222222222222"],
                    compliance_percentage=100.0,
                    reasoning="All accounts in OU have zero violations"
                ),
                SCPPlacementRecommendations(
                    check_name="deny_imds_v1_ec2",
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
                    assert "deny_imds_v1_ec2 = true" in content
