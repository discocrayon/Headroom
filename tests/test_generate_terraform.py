"""
Tests for terraform.generate_org_info module.

Tests Terraform configuration generation for AWS Organizations structure data.
"""

from unittest.mock import Mock, patch


from headroom.terraform.generate_org_info import (
    generate_terraform_org_info,
    _generate_terraform_content,
    _make_safe_variable_name,
)
from headroom.types import OrganizationHierarchy, OrganizationalUnit, AccountOrgPlacement


class TestTerraformGeneration:
    """Test Terraform generation functionality."""

    def test_generate_terraform_content_basic(self) -> None:
        """Test basic Terraform content generation."""
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1": OrganizationalUnit("ou-1", "Production", None, [], ["acc-1"]),
                "ou-2": OrganizationalUnit("ou-2", "Development", None, [], ["acc-2"]),
            },
            accounts={
                "acc-1": AccountOrgPlacement("acc-1", "prod-account", "ou-1", ["Production"]),
                "acc-2": AccountOrgPlacement("acc-2", "dev-account", "ou-2", ["Development"]),
            }
        )

        content = _generate_terraform_content(hierarchy)

        # Check for key Terraform elements
        assert 'data "aws_organizations_organization" "org" {}' in content
        assert 'data "aws_organizations_organizational_units" "root_ou"' in content
        assert 'locals {' in content
        assert 'root_ou_id = data.aws_organizations_organization.org.roots[0].id' in content

        # Should not have any output variables
        assert 'output "' not in content

    def test_generate_terraform_content_empty_org(self) -> None:
        """Test Terraform content generation with empty organization."""
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={},
            accounts={}
        )

        content = _generate_terraform_content(hierarchy)

        # Should still have basic structure
        assert 'data "aws_organizations_organization" "org" {}' in content
        assert 'data "aws_organizations_organizational_units" "root_ou"' in content
        assert 'root_ou_id = data.aws_organizations_organization.org.roots[0].id' in content

        # Should not have OU or account data sources
        assert 'data "aws_organizations_organizational_units" "ous"' not in content
        assert 'data "aws_organizations_accounts" "accounts"' not in content

    def test_generate_terraform_content_complex_hierarchy(self) -> None:
        """Test Terraform content generation with complex hierarchy."""
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1": OrganizationalUnit("ou-1", "Production", None, ["ou-3"], ["acc-1"]),
                "ou-2": OrganizationalUnit("ou-2", "Development", None, [], ["acc-2"]),
                "ou-3": OrganizationalUnit("ou-3", "Staging", "ou-1", [], ["acc-3"]),
            },
            accounts={
                "acc-1": AccountOrgPlacement("acc-1", "prod-account", "ou-1", ["Production"]),
                "acc-2": AccountOrgPlacement("acc-2", "dev-account", "ou-2", ["Development"]),
                "acc-3": AccountOrgPlacement("acc-3", "staging-account", "ou-3", ["Production", "Staging"]),
            }
        )

        content = _generate_terraform_content(hierarchy)

        # Should have all expected elements
        assert 'data "aws_organizations_organization" "org" {}' in content
        assert 'data "aws_organizations_organizational_units" "root_ou"' in content
        assert 'locals {' in content

    @patch('headroom.terraform.generate_org_info.analyze_organization_structure')
    @patch('builtins.open', create=True)
    @patch('pathlib.Path.mkdir')
    def test_generate_terraform_org_info_success(self, mock_mkdir: Mock, mock_open: Mock, mock_analyze: Mock) -> None:
        """Test successful Terraform file generation."""
        # Mock organization hierarchy
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1": OrganizationalUnit("ou-1", "Production", None, [], ["acc-1"]),
            },
            accounts={
                "acc-1": AccountOrgPlacement("acc-1", "prod-account", "ou-1", ["Production"]),
            }
        )
        mock_analyze.return_value = hierarchy

        # Mock file operations
        mock_file = Mock()
        mock_file.write = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        mock_session = Mock()
        generate_terraform_org_info(mock_session, "test_path/grab_org_info.tf")

        # Verify calls
        mock_analyze.assert_called_once_with(mock_session)
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_open.assert_called_once()

        # Verify content was written
        written_content = mock_file.write.call_args[0][0]
        assert 'data "aws_organizations_organization" "org" {}' in written_content

    @patch('headroom.terraform.generate_org_info.analyze_organization_structure')
    def test_generate_terraform_org_info_analysis_error(self, mock_analyze: Mock) -> None:
        """Test Terraform generation with analysis error."""
        mock_analyze.side_effect = RuntimeError("Analysis failed")
        mock_session = Mock()

        # Should not raise exception, just log error
        generate_terraform_org_info(mock_session, "test_path/grab_org_info.tf")

        mock_analyze.assert_called_once_with(mock_session)

    @patch('headroom.terraform.generate_org_info.analyze_organization_structure')
    @patch('builtins.open', side_effect=IOError("File write error"))
    @patch('pathlib.Path.mkdir')
    def test_generate_terraform_org_info_file_error(self, mock_mkdir: Mock, mock_open: Mock, mock_analyze: Mock) -> None:
        """Test Terraform generation with file write error."""
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={},
            accounts={}
        )
        mock_analyze.return_value = hierarchy
        mock_session = Mock()

        # Should not raise exception, just log error
        generate_terraform_org_info(mock_session, "test_path/grab_org_info.tf")

        mock_analyze.assert_called_once_with(mock_session)
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)


class TestTerraformNamedLocals:
    """Test Terraform named local variables generation."""

    def test_make_safe_variable_name_basic(self) -> None:
        """Test basic variable name conversion."""
        assert _make_safe_variable_name("Production") == "production"
        assert _make_safe_variable_name("Dev-Test") == "dev_test"
        assert _make_safe_variable_name("Staging Environment") == "staging_environment"

    def test_make_safe_variable_name_special_chars(self) -> None:
        """Test variable name conversion with special characters."""
        assert _make_safe_variable_name("OU-123") == "ou_123"
        assert _make_safe_variable_name("Test@#$%") == "test"
        assert _make_safe_variable_name("123-OU") == "ou_123_ou"

    def test_make_safe_variable_name_edge_cases(self) -> None:
        """Test edge cases for variable name conversion."""
        assert _make_safe_variable_name("") == ""
        assert _make_safe_variable_name("   ") == ""
        assert _make_safe_variable_name("A") == "a"
        assert _make_safe_variable_name("123") == "ou_123"

    def test_generate_terraform_content_with_named_locals(self) -> None:
        """Test Terraform content generation with named local variables."""
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1": OrganizationalUnit("ou-1", "Production", None, [], ["acc-1"]),
                "ou-2": OrganizationalUnit("ou-2", "Development", None, [], ["acc-2"]),
            },
            accounts={
                "acc-1": AccountOrgPlacement("acc-1", "prod-account", "ou-1", ["Production"]),
                "acc-2": AccountOrgPlacement("acc-2", "dev-account", "ou-2", ["Development"]),
            }
        )

        content = _generate_terraform_content(hierarchy)

        # Check for account data sources derived from root_ou
        assert 'data "aws_organizations_organizational_unit_child_accounts" "production_accounts"' in content
        assert 'data "aws_organizations_organizational_unit_child_accounts" "development_accounts"' in content

        # Check for local variables with proper filtering
        assert 'top_level_production_ou_id = [' in content
        assert 'top_level_development_ou_id = [' in content
        assert 'prod_account_account_id = [' in content
        assert 'dev_account_account_id = [' in content

        # Check for validation locals
        assert 'validation_check_production_ou =' in content
        assert 'validation_check_development_ou =' in content
        assert 'validation_check_prod_account_account =' in content
        assert 'validation_check_dev_account_account =' in content

        # Should not have any output variables
        assert 'output "' not in content

    def test_generate_terraform_content_empty_org_with_named_locals(self) -> None:
        """Test Terraform content generation with empty organization."""
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={},
            accounts={}
        )

        content = _generate_terraform_content(hierarchy)

        # Should still have root OU ID referencing data source
        assert "root_ou_id = data.aws_organizations_organization.org.roots[0].id" in content

        # Should not have OU or account data sources
        assert 'data "aws_organizations_organizational_unit_child_accounts"' not in content

        # Should not have any output variables
        assert 'output "' not in content

    def test_generate_terraform_content_complex_hierarchy_with_named_locals(self) -> None:
        """Test Terraform content generation with complex hierarchy."""
        hierarchy = OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1": OrganizationalUnit("ou-1", "Production", None, ["ou-3"], ["acc-1"]),
                "ou-2": OrganizationalUnit("ou-2", "Development", None, [], ["acc-2"]),
                "ou-3": OrganizationalUnit("ou-3", "Staging", "ou-1", [], ["acc-3"]),
            },
            accounts={
                "acc-1": AccountOrgPlacement("acc-1", "prod-account", "ou-1", ["Production"]),
                "acc-2": AccountOrgPlacement("acc-2", "dev-account", "ou-2", ["Development"]),
                "acc-3": AccountOrgPlacement("acc-3", "staging-account", "ou-3", ["Production", "Staging"]),
            }
        )

        content = _generate_terraform_content(hierarchy)

        # Should have account data sources for top-level OUs only
        assert 'data "aws_organizations_organizational_unit_child_accounts" "production_accounts"' in content
        assert 'data "aws_organizations_organizational_unit_child_accounts" "development_accounts"' in content

        # Should not have data source for nested OU (Staging)
        assert 'data "aws_organizations_organizational_unit_child_accounts" "staging_accounts"' not in content

        # Should have local variables for all accounts (grouped by top-level OU)
        assert 'prod_account_account_id = [' in content
        assert 'dev_account_account_id = [' in content
        assert 'staging_account_account_id = [' in content

        # Should have validation locals for all accounts
        assert 'validation_check_prod_account_account =' in content
        assert 'validation_check_dev_account_account =' in content
        assert 'validation_check_staging_account_account =' in content
