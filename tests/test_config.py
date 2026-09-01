import pytest
from pathlib import Path
from typing import cast
import argparse
from pydantic import ValidationError
from headroom.config import (
    DEFAULT_ACCOUNT_WORKERS,
    DEFAULT_RCPS_DIR,
    DEFAULT_RESULTS_DIR,
    DEFAULT_SCPS_DIR,
    MAX_ACCOUNT_WORKERS,
    AccountTagLayout,
    HeadroomConfig,
)
from headroom.usage import merge_configs

HEADROOM_PACKAGE = Path(__file__).resolve().parent.parent / "headroom"


@pytest.mark.parametrize(
    "directory_default",
    [DEFAULT_RCPS_DIR, DEFAULT_RESULTS_DIR, DEFAULT_SCPS_DIR],
)
def test_a_directory_default_is_written_in_one_place(directory_default: str) -> None:
    """
    `spec/contracts/configuration.md` gives every default one definition site.

    Copies had accumulated outside `config.py`: the `help=` strings `--help`
    prints, and the `output_dir` parameter default on each of the two
    Terraform generators, which every caller already overrides. Moving the
    path in `config.py` left all of them advertising the old one, and the
    operator reads `--help`.
    """
    holders = {
        source.relative_to(HEADROOM_PACKAGE).as_posix()
        for source in HEADROOM_PACKAGE.rglob("*.py")
        if directory_default in source.read_text()
    }

    assert holders == {"config.py"}


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

    def test_an_unrecognized_tag_key_aborts(self) -> None:
        """
        A fourth tag key must abort rather than be quietly dropped.

        Headroom reads exactly these three tags. Listing a fourth expresses an
        intent it cannot honour, and ignoring it means the operator's tag is
        never read and nothing says why.
        """
        with pytest.raises(ValidationError, match="cost_center"):
            AccountTagLayout(**{
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner",
                "cost_center": "CostCenter",
            })


class TestOutputDirectories:
    """The two Terraform output directories, checked where they are set."""

    @staticmethod
    def _config(
        scps_dir: str = DEFAULT_SCPS_DIR, rcps_dir: str = DEFAULT_RCPS_DIR
    ) -> HeadroomConfig:
        return HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Environment", name="Name", owner="Owner"
            ),
            scps_dir=scps_dir,
            rcps_dir=rcps_dir,
        )

    @pytest.mark.parametrize("key", ["scps_dir", "rcps_dir"])
    def test_a_parent_traversal_in_an_output_directory_is_rejected(
        self, key: str
    ) -> None:
        """
        `..` makes the configured path and the written path two different
        places the moment any component of it is a symlink.

        Headroom folds `..` away lexically, so `live/../scps` becomes `scps`
        and every destination is calculated from there. The OS resolves the
        same spelling by walking `live` first, which lands somewhere else
        entirely when `live` is a link. Terraform then loads one directory
        while Headroom writes the other, and both report success.
        """
        traversal = "terraform/live/../scps"
        with pytest.raises(ValidationError, match="must not contain"):
            if key == "scps_dir":
                self._config(scps_dir=traversal)
            else:
                self._config(rcps_dir=traversal)

    def test_one_directory_for_both_policy_types_is_rejected(self) -> None:
        """
        Caught here rather than at generation, which is the far side of a
        scan of every account in the organization.

        Generation rejects it too, and has to: it is the only place that can
        see two spellings reaching one directory. But a plain typo is visible
        the moment the configuration is read, and finding out then costs the
        operator a second instead of a full run.
        """
        with pytest.raises(ValidationError, match="same directory"):
            self._config(scps_dir="terraform/policies", rcps_dir="terraform/policies")

    def test_the_default_directories_are_accepted(self) -> None:
        """The shipped defaults must survive the checks above."""
        config = self._config()

        assert config.scps_dir != config.rcps_dir


class TestHeadroomConfig:
    """Test HeadroomConfig class with all possible configurations."""

    def test_skip_account_ids_defaults_to_empty(self) -> None:
        """Omitting skip_account_ids analyzes every account."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="Environment", name="Name", owner="Owner")
        )
        assert config.skip_account_ids == []

    def test_skip_account_ids_from_yaml(self) -> None:
        """skip_account_ids is a YAML-only setting with no CLI override."""
        yaml_cfg = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner",
            },
            "skip_account_ids": ["111111111111", "222222222222"],
        }

        merged = merge_configs(yaml_cfg, argparse.Namespace(config="dummy.yaml"))
        assert merged.skip_account_ids == ["111111111111", "222222222222"]

    def test_skip_account_ids_rejects_unquoted_yaml_integer(self) -> None:
        """
        An unquoted YAML account ID is an integer and must be rejected.

        Silently accepting it would compare an int against the string IDs the
        Organizations API returns, matching nothing and analyzing an account
        the operator believes is excluded.
        """
        with pytest.raises(ValidationError):
            HeadroomConfig(
                use_account_name_from_tags=False,
                account_tag_layout=AccountTagLayout(environment="Environment", name="Name", owner="Owner"),
                skip_account_ids=[111111111111],  # type: ignore[list-item]
            )

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

    def test_a_misspelled_yaml_key_aborts_rather_than_reverting_to_default(self) -> None:
        """
        An unknown key must abort, not silently fall back to the default.

        pydantic ignores unknown fields unless told otherwise, so a config
        naming `max_account_worker` -- the trailing s dropped -- ran sixteen
        workers and said nothing about it. `sample_config.yaml` ships that key
        commented out, so typing it is the only way to set it at all, and 1,
        the serial-debugging value, is the setting whose silent loss is
        hardest to notice: the run still works, just concurrently.

        This goes through merge_configs because that is the path a YAML key
        takes. CLI arguments cannot reach here misspelled -- merge_configs
        filters them against model_fields first, and argparse rejects an
        unknown flag before that.
        """
        yaml_cfg = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner",
            },
            "max_account_worker": 1,
        }

        cli_args = argparse.Namespace(config="dummy.yaml")

        with pytest.raises(ValidationError, match="max_account_worker"):
            merge_configs(yaml_cfg, cli_args)

    def test_max_account_workers_defaults_to_sixteen(self) -> None:
        """The default lives in config.py and nowhere else."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Env", name="NameTag", owner="OwnerTag"
            ),
        )

        assert config.max_account_workers == DEFAULT_ACCOUNT_WORKERS == 16

    def test_max_account_workers_rejects_zero(self) -> None:
        """Zero workers would analyze nothing while appearing to succeed."""
        with pytest.raises(ValidationError):
            HeadroomConfig(
                use_account_name_from_tags=False,
                account_tag_layout=AccountTagLayout(
                    environment="Env", name="NameTag", owner="OwnerTag"
                ),
                max_account_workers=0,
            )

    def test_max_account_workers_rejects_above_the_cap(self) -> None:
        """
        Past the cap resident memory exceeds 1.5 GB. Memory is the only
        constraint here.

        The cap is asserted as a literal, and 33 is a literal too. Written as
        `MAX_ACCOUNT_WORKERS + 1` this passed for every value of the constant,
        including 512 -- verified -- while `sample_config.yaml`, `SETUP.md`
        and `ARCHITECTURE.md` all state 32 in prose that no test reads.
        Raising the cap has to fail here so those three get revisited.
        """
        assert MAX_ACCOUNT_WORKERS == 32

        with pytest.raises(ValidationError):
            HeadroomConfig(
                use_account_name_from_tags=False,
                account_tag_layout=AccountTagLayout(
                    environment="Env", name="NameTag", owner="OwnerTag"
                ),
                max_account_workers=33,
            )
