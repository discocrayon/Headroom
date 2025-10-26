import pytest
from unittest.mock import MagicMock, patch, mock_open
from typing import Dict, Any
from headroom.usage import load_yaml_config, parse_cli_args, merge_configs
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
