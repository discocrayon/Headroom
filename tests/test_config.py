import pytest
from typing import cast
import argparse
from pydantic import ValidationError
from headroom.config import HeadroomConfig, AccountTagLayout
from headroom.usage import merge_configs


class TestAccountTagLayout:
    """Test AccountTagLayout class with all possible configurations."""

    def test_valid_account_tag_layout(self) -> None:
        """Test creating AccountTagLayout with valid data."""
        layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        assert layout.environment == "Environment"
        assert layout.name == "Name"
        assert layout.owner == "Owner"

    def test_account_tag_layout_missing_environment(self) -> None:
        """Test AccountTagLayout with missing environment field."""
        with pytest.raises(ValidationError) as exc_info:
            AccountTagLayout(name="Name", owner="Owner")  # type: ignore
        assert "environment" in str(exc_info.value)

    def test_account_tag_layout_missing_name(self) -> None:
        """Test AccountTagLayout with missing name field."""
        with pytest.raises(ValidationError) as exc_info:
            AccountTagLayout(environment="Environment", owner="Owner")  # type: ignore
        assert "name" in str(exc_info.value)

    def test_account_tag_layout_missing_owner(self) -> None:
        """Test AccountTagLayout with missing owner field."""
        with pytest.raises(ValidationError) as exc_info:
            AccountTagLayout(environment="Environment", name="Name")  # type: ignore
        assert "owner" in str(exc_info.value)

    def test_account_tag_layout_empty_strings(self) -> None:
        """Test AccountTagLayout with empty string values."""
        layout = AccountTagLayout(
            environment="",
            name="",
            owner=""
        )
        assert layout.environment == ""
        assert layout.name == ""
        assert layout.owner == ""

    def test_account_tag_layout_special_characters(self) -> None:
        """Test AccountTagLayout with special characters in values."""
        layout = AccountTagLayout(
            environment="Env-123_Test",
            name="Name@#$%",
            owner="Owner & Co."
        )
        assert layout.environment == "Env-123_Test"
        assert layout.name == "Name@#$%"
        assert layout.owner == "Owner & Co."


class TestHeadroomConfig:
    """Test HeadroomConfig class with all possible configurations."""

    def test_valid_headroom_config(self) -> None:
        """Test creating HeadroomConfig with valid data."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=account_tag_layout
        )
        assert config.use_account_name_from_tags is False
        assert config.account_tag_layout == account_tag_layout

    def test_cli_overrides_results_and_scps_dir(self) -> None:
        yaml_cfg = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner",
            },
            "results_dir": "from_yaml/results",
            "scps_dir": "from_yaml/scps",
            "rcps_dir": "from_yaml/rcps",
        }

        cli_args = argparse.Namespace(
            config="dummy.yaml",
            results_dir="from_cli/results",
            scps_dir="from_cli/scps",
            rcps_dir="from_cli/rcps",
        )

        merged = merge_configs(yaml_cfg, cli_args)
        assert isinstance(merged, HeadroomConfig)
        assert merged.results_dir == "from_cli/results"
        assert merged.scps_dir == "from_cli/scps"
        assert merged.rcps_dir == "from_cli/rcps"

    def test_yaml_defaults_for_dirs_when_cli_not_provided(self) -> None:
        yaml_cfg = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner",
            },
            "results_dir": "from_yaml/results",
            "scps_dir": "from_yaml/scps",
            "rcps_dir": "from_yaml/rcps",
        }

        cli_args = argparse.Namespace(
            config="dummy.yaml",
            results_dir=None,
            scps_dir=None,
            rcps_dir=None,
        )

        merged = merge_configs(yaml_cfg, cli_args)
        assert merged.results_dir == "from_yaml/results"
        assert merged.scps_dir == "from_yaml/scps"
        assert merged.rcps_dir == "from_yaml/rcps"

    def test_headroom_config_missing_use_account_name_from_tags(self) -> None:
        """Test HeadroomConfig with missing use_account_name_from_tags field."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        with pytest.raises(ValidationError) as exc_info:
            HeadroomConfig(  # type: ignore
                account_tag_layout=account_tag_layout
            )
        assert "use_account_name_from_tags" in str(exc_info.value)

    def test_headroom_config_missing_account_tag_layout(self) -> None:
        """Test HeadroomConfig with missing account_tag_layout field."""
        with pytest.raises(ValidationError) as exc_info:
            HeadroomConfig(  # type: ignore
                use_account_name_from_tags=False
            )
        assert "account_tag_layout" in str(exc_info.value)

    def test_headroom_config_use_account_name_from_tags_false(self) -> None:
        """Test HeadroomConfig with use_account_name_from_tags set to False."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=account_tag_layout
        )
        assert config.use_account_name_from_tags is False

    def test_headroom_config_use_account_name_from_tags_true(self) -> None:
        """Test HeadroomConfig with use_account_name_from_tags set to True."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        config = HeadroomConfig(
            use_account_name_from_tags=True,
            account_tag_layout=account_tag_layout
        )
        assert config.use_account_name_from_tags is True

    def test_headroom_config_invalid_boolean_type(self) -> None:
        """Test HeadroomConfig with invalid boolean type for flag."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        with pytest.raises(ValidationError) as exc_info:
            HeadroomConfig(
                use_account_name_from_tags=cast(bool, "not_a_bool"),
                account_tag_layout=account_tag_layout
            )
        assert "use_account_name_from_tags" in str(exc_info.value)

    def test_headroom_config_invalid_account_tag_layout_type(self) -> None:
        """Test HeadroomConfig with invalid account_tag_layout type."""
        with pytest.raises(ValidationError) as exc_info:
            HeadroomConfig(
                use_account_name_from_tags=False,
                account_tag_layout=cast(AccountTagLayout, "not_a_layout")
            )
        assert "account_tag_layout" in str(exc_info.value)

    def test_headroom_config_model_dump(self) -> None:
        """Test HeadroomConfig model_dump method."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=account_tag_layout
        )
        dumped = config.model_dump()
        assert dumped["use_account_name_from_tags"] is False
        assert dumped["account_tag_layout"]["environment"] == "Environment"
        assert dumped["account_tag_layout"]["name"] == "Name"
        assert dumped["account_tag_layout"]["owner"] == "Owner"

    def test_headroom_config_model_fields(self) -> None:
        """Test HeadroomConfig model_fields property."""
        fields = HeadroomConfig.model_fields
        assert "use_account_name_from_tags" in fields
        assert "account_tag_layout" in fields

    def test_headroom_config_security_analysis_account_id(self) -> None:
        """Test HeadroomConfig with and without security_analysis_account_id."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        # With security_analysis_account_id
        config = HeadroomConfig(
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=account_tag_layout
        )
        assert config.security_analysis_account_id == "111111111111"
        dumped = config.model_dump()
        assert dumped["security_analysis_account_id"] == "111111111111"
        # Without security_analysis_account_id
        config2 = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=account_tag_layout
        )
        assert config2.security_analysis_account_id is None
        dumped2 = config2.model_dump()
        assert "security_analysis_account_id" in dumped2
        assert dumped2["security_analysis_account_id"] is None

    def test_headroom_config_exclude_account_ids_default(self) -> None:
        """Test HeadroomConfig exclude_account_ids defaults to False."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=account_tag_layout
        )
        assert config.exclude_account_ids is False

    def test_headroom_config_exclude_account_ids_true(self) -> None:
        """Test HeadroomConfig with exclude_account_ids=True."""
        account_tag_layout = AccountTagLayout(
            environment="Environment",
            name="Name",
            owner="Owner"
        )
        config = HeadroomConfig(
            exclude_account_ids=True,
            use_account_name_from_tags=False,
            account_tag_layout=account_tag_layout
        )
        assert config.exclude_account_ids is True

    def test_cli_overrides_exclude_account_ids(self) -> None:
        """Test that CLI --exclude-account-ids overrides YAML config."""
        yaml_cfg = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner",
            },
            "exclude_account_ids": False,
        }

        cli_args = argparse.Namespace(
            config="dummy.yaml",
            results_dir=None,
            scps_dir=None,
            exclude_account_ids=True,
        )

        merged = merge_configs(yaml_cfg, cli_args)
        assert merged.exclude_account_ids is True
