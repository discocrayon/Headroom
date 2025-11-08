import pytest
from unittest.mock import MagicMock, patch, mock_open
from typing import Any, Dict, List
from headroom.usage import load_yaml_config, parse_cli_args, merge_configs
from headroom.main import (
    setup_configuration,
    process_policy_recommendations,
    setup_organization_context,
    handle_scp_workflow,
    handle_rcp_workflow,
    ensure_org_info_symlink,
)
from headroom.config import HeadroomConfig
from headroom.types import OrganizationHierarchy, RCPParseResult
from pydantic import ValidationError


class TestLoadYamlConfig:
    """Test load_yaml_config function with various scenarios."""

    def test_load_yaml_config_valid_file(self) -> None:
        yaml_content = """
        use_account_name_from_tags: true
        account_tag_layout:
          environment: Environment
          name: Name
          owner: Owner
        """
        with patch('builtins.open', mock_open(read_data=yaml_content)):
            result = load_yaml_config("test.yaml")
            assert result["use_account_name_from_tags"] is True
            assert result["account_tag_layout"]["environment"] == "Environment"

    def test_load_yaml_config_file_not_found(self) -> None:
        """Test handling of missing YAML file."""
        with patch('builtins.open', side_effect=FileNotFoundError):
            result = load_yaml_config("nonexistent.yaml")
            assert result == {}

    def test_load_yaml_config_empty_file(self) -> None:
        """Test loading empty YAML file."""
        with patch('builtins.open', mock_open(read_data="")):
            result = load_yaml_config("empty.yaml")
            assert result == {}

    def test_load_yaml_config_none_content(self) -> None:
        """Test loading YAML file with None content."""
        with patch('builtins.open', mock_open(read_data="null")):
            result = load_yaml_config("null.yaml")
            assert result == {}

    def test_load_yaml_config_invalid_yaml(self) -> None:
        """Test handling of invalid YAML content."""
        with patch('builtins.open', mock_open(read_data="invalid: yaml: content:")):
            with pytest.raises(Exception):
                load_yaml_config("invalid.yaml")

    def test_load_yaml_config_complex_structure(self) -> None:
        """Test loading complex YAML structure."""
        yaml_content = """
        use_account_name_from_tags: false
        account_tag_layout:
          environment: Production
          name: AccountName
          owner: TeamA
        extra_field: should_be_ignored
        nested:
          structure:
            with: values
        """
        with patch('builtins.open', mock_open(read_data=yaml_content)):
            result = load_yaml_config("complex.yaml")
            assert result["use_account_name_from_tags"] is False
            assert result["account_tag_layout"]["environment"] == "Production"
            assert result["account_tag_layout"]["name"] == "AccountName"
            assert result["account_tag_layout"]["owner"] == "TeamA"
            assert result["extra_field"] == "should_be_ignored"
            assert result["nested"]["structure"]["with"] == "values"


class TestParseCliArgs:
    """Test parse_cli_args function."""

    def test_parse_cli_args_valid(self) -> None:
        """Test parsing valid CLI arguments."""
        with patch('sys.argv', ['headroom', '--config', 'test.yaml']):
            args = parse_cli_args()
            assert args.config == "test.yaml"

    def test_parse_cli_args_missing_required(self) -> None:
        """Test parsing CLI arguments with missing required argument."""
        with patch('sys.argv', ['headroom']):
            with pytest.raises(SystemExit):
                parse_cli_args()

    def test_parse_cli_args_with_help(self) -> None:
        """Test parsing CLI arguments with help flag."""
        with patch('sys.argv', ['headroom', '--help']):
            with pytest.raises(SystemExit):
                parse_cli_args()

    def test_parse_cli_args_with_unknown_arg(self) -> None:
        """Test parsing CLI arguments with unknown argument."""
        with patch('sys.argv', ['headroom', '--config', 'test.yaml', '--unknown']):
            with pytest.raises(SystemExit):
                parse_cli_args()


class TestMergeConfigs:
    """Test merge_configs function with various scenarios."""

    def test_merge_configs_valid_yaml_and_cli(self) -> None:
        """Test merging valid YAML and CLI configs."""
        yaml_config = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        result = merge_configs(yaml_config, cli_args)

        assert result.use_account_name_from_tags is False
        assert result.account_tag_layout.environment == "Environment"

    def test_merge_configs_yaml_only(self) -> None:
        """Test merging with YAML config only."""
        yaml_config = {
            "use_account_name_from_tags": True,
            "account_tag_layout": {
                "environment": "Test",
                "name": "TestName",
                "owner": "TestOwner"
            }
        }

        cli_args = MagicMock()
        cli_args.config = "test.yaml"
        # No CLI overrides

        result = merge_configs(yaml_config, cli_args)

        assert result.use_account_name_from_tags is True
        assert result.account_tag_layout.environment == "Test"

    def test_merge_configs_empty_yaml(self) -> None:
        """Test merging with empty YAML config."""
        yaml_config: Dict[str, Any] = {}

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        with pytest.raises(ValidationError):
            merge_configs(yaml_config, cli_args)

    def test_merge_configs_missing_required_fields(self) -> None:
        """Test merging with missing required fields."""
        yaml_config = {
            "use_account_name_from_tags": True,
            # Missing other required fields
        }

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        with pytest.raises(ValidationError):
            merge_configs(yaml_config, cli_args)

    def test_merge_configs_invalid_field_types(self) -> None:
        """Test merging with invalid field types."""
        yaml_config = {
            "use_account_name_from_tags": "not_a_bool",
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        with pytest.raises(ValidationError):
            merge_configs(yaml_config, cli_args)

    def test_merge_configs_invalid_account_tag_layout(self) -> None:
        """Test merging with invalid account_tag_layout."""
        yaml_config = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                # Missing required fields
            }
        }

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        with pytest.raises(ValidationError):
            merge_configs(yaml_config, cli_args)

    def test_merge_configs_cli_overrides(self) -> None:
        """Test that CLI arguments override YAML config."""
        yaml_config = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        result = merge_configs(yaml_config, cli_args)

        assert result.use_account_name_from_tags is False

    def test_merge_configs_with_extra_yaml_fields(self) -> None:
        """Test merging with extra fields in YAML (should be ignored)."""
        yaml_config = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            },
            "extra_field": "should_be_ignored",
            "another_extra": 123
        }

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        result = merge_configs(yaml_config, cli_args)

        # Extra fields should be ignored, only model fields should be present
        assert hasattr(result, 'use_account_name_from_tags')
        assert hasattr(result, 'account_tag_layout')
        assert not hasattr(result, 'extra_field')
        assert not hasattr(result, 'another_extra')

    def test_merge_configs_deep_copy(self) -> None:
        """Test that merge_configs doesn't modify the original YAML config."""
        yaml_config: Dict[str, Any] = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }

        original_yaml = yaml_config.copy()

        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        result = merge_configs(yaml_config, cli_args)

        # Original YAML should be unchanged
        assert yaml_config == original_yaml
        assert result.use_account_name_from_tags is False


class TestSetupConfiguration:
    """Test setup_configuration function."""

    def test_setup_configuration_success(self) -> None:
        """Test successful configuration setup."""
        yaml_config = {
            "use_account_name_from_tags": True,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }
        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        with patch('builtins.print'):
            result = setup_configuration(cli_args, yaml_config)

        assert isinstance(result, HeadroomConfig)
        assert result.use_account_name_from_tags is True

    def test_setup_configuration_value_error(self) -> None:
        """Test configuration setup with ValidationError (ValueError)."""
        yaml_config: Dict[str, Any] = {}
        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        with patch('builtins.print'):
            with pytest.raises(SystemExit) as exc_info:
                setup_configuration(cli_args, yaml_config)
            assert exc_info.value.code == 1

    def test_setup_configuration_prints_config(self) -> None:
        """Test that configuration is printed."""
        yaml_config = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }
        cli_args = MagicMock()
        cli_args.config = "test.yaml"

        with patch('builtins.print') as mock_print:
            result = setup_configuration(cli_args, yaml_config)

        mock_print.assert_any_call("\n✅ Final Config")
        assert isinstance(result, HeadroomConfig)


class TestProcessPolicyRecommendations:
    """Test process_policy_recommendations function."""

    def test_process_policy_recommendations_with_recommendations(self) -> None:
        """Test processing non-empty recommendations."""
        recommendations = {"check1": "recommendation1"}
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        terraform_generator = MagicMock()

        with patch('headroom.main.print_policy_recommendations') as mock_print:
            process_policy_recommendations(
                recommendations,
                org_hierarchy,
                "Test Recommendations",
                terraform_generator,
                "arg1",
                "arg2"
            )

        mock_print.assert_called_once_with(recommendations, org_hierarchy, "Test Recommendations")
        terraform_generator.assert_called_once_with(recommendations, org_hierarchy, "arg1", "arg2")

    def test_process_policy_recommendations_empty(self) -> None:
        """Test processing empty recommendations."""
        recommendations: Dict[str, str] = {}
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        terraform_generator = MagicMock()

        with patch('headroom.main.print_policy_recommendations') as mock_print:
            process_policy_recommendations(
                recommendations,
                org_hierarchy,
                "Test Recommendations",
                terraform_generator,
                "arg1"
            )

        mock_print.assert_not_called()
        terraform_generator.assert_not_called()

    def test_process_policy_recommendations_none(self) -> None:
        """Test processing None recommendations."""
        recommendations: List[str] = []
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        terraform_generator = MagicMock()

        with patch('headroom.main.print_policy_recommendations') as mock_print:
            process_policy_recommendations(
                recommendations,
                org_hierarchy,
                "Test Recommendations",
                terraform_generator
            )

        mock_print.assert_not_called()
        terraform_generator.assert_not_called()

    def test_process_policy_recommendations_list(self) -> None:
        """Test processing list of recommendations."""
        recommendations = ["rec1", "rec2"]
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        terraform_generator = MagicMock()

        with patch('headroom.main.print_policy_recommendations') as mock_print:
            process_policy_recommendations(
                recommendations,
                org_hierarchy,
                "Test Recommendations",
                terraform_generator,
                "arg1"
            )

        mock_print.assert_called_once()
        terraform_generator.assert_called_once()


class TestSetupOrganizationContext:
    """Test setup_organization_context function."""

    def test_setup_organization_context_success(self) -> None:
        """Test successful organization context setup."""
        config = MagicMock(spec=HeadroomConfig)
        config.scps_dir = "/test/scps"
        security_session = MagicMock()
        mgmt_session = MagicMock()
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        with patch('headroom.main.get_management_account_session', return_value=mgmt_session):
            with patch('headroom.main.analyze_organization_structure', return_value=org_hierarchy):
                result_session, result_hierarchy = setup_organization_context(config, security_session)

        assert result_session == mgmt_session
        assert result_hierarchy == org_hierarchy
        # Note: generate_terraform_org_info is no longer called inside setup_organization_context
        # It's now called separately in main()

    def test_setup_organization_context_raises_value_error(self) -> None:
        """Test organization context setup with missing management account."""
        config = MagicMock(spec=HeadroomConfig)
        security_session = MagicMock()

        with patch('headroom.main.get_management_account_session', side_effect=ValueError("Missing management_account_id")):
            with pytest.raises(ValueError, match="Missing management_account_id"):
                setup_organization_context(config, security_session)


class TestHandleScpWorkflow:
    """Test handle_scp_workflow function."""

    def test_handle_scp_workflow_with_recommendations(self) -> None:
        """Test SCP workflow with recommendations."""
        config = MagicMock(spec=HeadroomConfig)
        config.scps_dir = "/test/scps"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        recommendations = {"check1": "recommendation1"}

        with patch('headroom.main.parse_scp_results', return_value=recommendations):
            with patch('headroom.main.process_policy_recommendations') as mock_process:
                handle_scp_workflow(config, org_hierarchy)

        mock_process.assert_called_once()
        call_args = mock_process.call_args
        assert call_args[0][0] == recommendations
        assert call_args[0][1] == org_hierarchy
        assert call_args[0][2] == "SCP PLACEMENT RECOMMENDATIONS"

    def test_handle_scp_workflow_no_recommendations(self) -> None:
        """Test SCP workflow with no recommendations."""
        config = MagicMock(spec=HeadroomConfig)
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        with patch('headroom.main.parse_scp_results', return_value={}):
            with patch('headroom.main.process_policy_recommendations') as mock_process:
                handle_scp_workflow(config, org_hierarchy)

        mock_process.assert_not_called()

    def test_handle_scp_workflow_none_recommendations(self) -> None:
        """Test SCP workflow with None recommendations."""
        config = MagicMock(spec=HeadroomConfig)
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        with patch('headroom.main.parse_scp_results', return_value=None):
            with patch('headroom.main.process_policy_recommendations') as mock_process:
                handle_scp_workflow(config, org_hierarchy)

        mock_process.assert_not_called()


class TestHandleRcpWorkflow:
    """Test handle_rcp_workflow function."""

    def test_handle_rcp_workflow_complete(self) -> None:
        """Test RCP workflow with complete data."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        config.rcps_dir = "/test/rcps"
        config.scps_dir = "/test/scps"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = RCPParseResult(
            account_third_party_map={"account1": {"third_party1"}},
            accounts_with_wildcards=set()
        )
        recommendations = [{"recommendation": "test"}]

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement', return_value=recommendations):
                with patch('headroom.main.process_policy_recommendations') as mock_process:
                    handle_rcp_workflow(config, org_hierarchy)

        mock_process.assert_called_once()
        call_args = mock_process.call_args
        assert call_args[0][0] == recommendations
        assert call_args[0][1] == org_hierarchy
        assert call_args[0][2] == "RCP PLACEMENT RECOMMENDATIONS"

    def test_handle_rcp_workflow_no_third_party_map(self) -> None:
        """Test RCP workflow with empty third party map."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = RCPParseResult(
            account_third_party_map={},
            accounts_with_wildcards=set()
        )

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement') as mock_determine:
                with patch('headroom.main.process_policy_recommendations') as mock_process:
                    handle_rcp_workflow(config, org_hierarchy)

        mock_determine.assert_not_called()
        mock_process.assert_not_called()

    def test_handle_rcp_workflow_no_recommendations(self) -> None:
        """Test RCP workflow with no recommendations from determine_rcp_placement."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = RCPParseResult(
            account_third_party_map={"account1": {"third_party1"}},
            accounts_with_wildcards=set()
        )

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement', return_value=[]):
                with patch('headroom.main.process_policy_recommendations') as mock_process:
                    handle_rcp_workflow(config, org_hierarchy)

        mock_process.assert_not_called()

    def test_handle_rcp_workflow_none_recommendations(self) -> None:
        """Test RCP workflow with None recommendations from determine_rcp_placement."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = RCPParseResult(
            account_third_party_map={"account1": {"third_party1"}},
            accounts_with_wildcards=set()
        )

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement', return_value=None):
                with patch('headroom.main.process_policy_recommendations') as mock_process:
                    handle_rcp_workflow(config, org_hierarchy)

        mock_process.assert_not_called()


class TestEnsureOrgInfoSymlink:
    """Test ensure_org_info_symlink function."""

    def test_ensure_org_info_symlink_creates_directory_and_symlink(self) -> None:
        """Test that ensure_org_info_symlink creates RCP directory and calls _create_org_info_symlink."""
        with (
            patch('headroom.main.Path') as mock_path_class,
            patch('headroom.main._create_org_info_symlink') as mock_create_symlink
        ):
            mock_rcps_path = MagicMock()
            mock_path_class.return_value = mock_rcps_path

            ensure_org_info_symlink("test_rcps", "test_scps")

            # Verify Path was called with rcps_dir
            mock_path_class.assert_called_once_with("test_rcps")

            # Verify mkdir was called to create directory
            mock_rcps_path.mkdir.assert_called_once_with(parents=True, exist_ok=True)

            # Verify _create_org_info_symlink was called with correct args
            mock_create_symlink.assert_called_once_with(mock_rcps_path, "test_scps")
