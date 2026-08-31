import io
import pytest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch, mock_open
from typing import Any, Callable, Dict, List, Optional
from pathlib import Path
from headroom.usage import load_yaml_config, parse_cli_args, merge_configs
from headroom.main import (
    main,
    setup_configuration,
    process_policy_recommendations,
    handle_scp_workflow,
    handle_rcp_workflow,
    ensure_org_info_symlink,
)
from headroom.config import AccountTagLayout, HeadroomConfig
from headroom.constants import DENY_STS_THIRD_PARTY_ASSUMEROLE
from headroom.checks.registry import get_check_names
from headroom.types import (
    OrganizationHierarchy,
    OrganizationSnapshot,
    RCPCheckParseResult,
)
from tests.constants import ORG_ID
from pydantic import ValidationError


def _record(
    seen: List[object], returns: Optional[List[Path]] = None
) -> Callable[..., Optional[List[Path]]]:
    """Record the hierarchy a generator was handed, and return `returns`."""
    def recorder(*args: object) -> Optional[List[Path]]:
        seen.extend(arg for arg in args if isinstance(arg, OrganizationHierarchy))
        return returns
    return recorder


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

    def test_the_worker_help_states_the_default_and_the_cap(self) -> None:
        """
        An operator reading --help should not have to open config.py.

        The three directory flags each state their default. This one stated
        neither its default nor its bound, so the only way to discover that 33
        is refused was to be refused. The numbers are asserted as literals,
        the same ones sample_config.yaml and SETUP.md print, so interpolating
        some other constant fails here rather than quietly rewording the help.
        """
        parser_output = io.StringIO()
        with patch('sys.argv', ['headroom', '--help']):
            with redirect_stdout(parser_output):
                with pytest.raises(SystemExit):
                    parse_cli_args()

        help_text = " ".join(parser_output.getvalue().split())

        assert "default 16, maximum 32" in help_text


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

    def test_max_account_workers_flows_from_the_command_line(self) -> None:
        """
        The only flag with no plumbing test, in both directions.

        Nothing exercised parse_cli_args -> merge_configs -> HeadroomConfig
        for this option. It works because argparse carries no `default=`, so
        merge_configs' `v is not None` filter drops it when it is absent;
        adding a default would silently make the CLI override the YAML on
        every run, and no test would have noticed.
        """
        yaml_config: Dict[str, Any] = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner",
            },
            "max_account_workers": 8,
        }

        with patch('sys.argv', ['headroom', '--config', 'test.yaml', '--max-account-workers', '4']):
            with_flag = parse_cli_args()
        assert merge_configs(yaml_config, with_flag).max_account_workers == 4

        with patch('sys.argv', ['headroom', '--config', 'test.yaml']):
            without_flag = parse_cli_args()
        assert merge_configs(yaml_config, without_flag).max_account_workers == 8

    def test_merge_configs_rejects_extra_yaml_fields(self) -> None:
        """
        A key Headroom does not recognize aborts the run.

        This asserted the opposite until `HeadroomConfig` forbade extras.
        Dropping them was indistinguishable from a misspelling, and the key
        most likely to be misspelled is one whose loss changes how the run
        behaves without changing whether it succeeds. `setup_configuration`
        turns the ValidationError into `Configuration Error` and exit 1.
        """
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

        with pytest.raises(ValidationError) as raised:
            merge_configs(yaml_config, cli_args)

        reported = {error["loc"][0] for error in raised.value.errors()}
        assert reported == {"extra_field", "another_extra"}

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
        """
        Empty recommendations still reach the generator.

        The generator's plan is what the directory is reconciled against, so
        skipping it here would leave a previous run's policy files deployed.
        """
        recommendations: Dict[str, str] = {}
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        terraform_generator = MagicMock(return_value={})

        with patch('headroom.main.print_policy_recommendations') as mock_print:
            plan = process_policy_recommendations(
                recommendations,
                org_hierarchy,
                "Test Recommendations",
                terraform_generator,
                "arg1"
            )

        assert plan == {}
        mock_print.assert_called_once_with(recommendations, org_hierarchy, "Test Recommendations")
        terraform_generator.assert_called_once_with(recommendations, org_hierarchy, "arg1")

    def test_process_policy_recommendations_returns_the_plan(self) -> None:
        """The generator's plan is handed back for the caller to reconcile against."""
        recommendations: List[str] = ["rec1"]
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        expected = {Path("/out/root_scps.tf"): "content"}
        terraform_generator = MagicMock(return_value=expected)

        with patch('headroom.main.print_policy_recommendations'):
            plan = process_policy_recommendations(
                recommendations,
                org_hierarchy,
                "Test Recommendations",
                terraform_generator
            )

        assert plan == expected

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


class TestMainDiscoversOnce:
    """`main` reads the organization once and hands the same view to every stage."""

    def test_discovery_happens_once_and_feeds_every_stage(self) -> None:
        """
        One snapshot, one hierarchy object, reaching all three generators.

        Object identity rather than equality: two equal hierarchies read at
        different moments is exactly the bug this change removes, and equality
        cannot tell that case from the fixed one.
        """
        hierarchy = OrganizationHierarchy(
            root_id="r-1111", organizational_units={}, accounts={}
        )
        snapshot = OrganizationSnapshot(
            organization_id=ORG_ID,
            member_account_ids=frozenset({"111111111111"}),
            analyzable_accounts=(),
            hierarchy=hierarchy,
        )
        seen: List[object] = []

        # A real config, not a MagicMock: main builds Path(config.scps_dir),
        # and Path of a MagicMock raises.
        config = HeadroomConfig(
            management_account_id="111111111111",
            security_analysis_account_id="222222222222",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner"),
        )

        with patch("headroom.main.get_security_analysis_session"), \
             patch("headroom.main.get_management_account_session"), \
             patch("headroom.main.discover_organization", return_value=snapshot) as discover, \
             patch("headroom.main.perform_analysis"), \
             patch("headroom.main.parse_cli_args"), \
             patch("headroom.main.load_yaml_config"), \
             patch("headroom.main.setup_configuration", return_value=config), \
             patch("headroom.main.reconcile_generated_terraform"), \
             patch("headroom.main.ensure_org_info_symlink"), \
             patch("headroom.main.generate_terraform_org_info", side_effect=_record(seen)), \
             patch("headroom.main.handle_scp_workflow", side_effect=_record(seen, returns=[])), \
             patch("headroom.main.handle_rcp_workflow", side_effect=_record(seen, returns=[])):
            main()

        discover.assert_called_once()
        assert len(seen) == 3
        assert all(observed is hierarchy for observed in seen)

    def test_the_scan_is_handed_the_snapshot_discovery_built(self) -> None:
        """
        `perform_analysis` consumes the same capture the generators do.

        Without this, `main` could satisfy the identity assertion above while
        the scan still read Organizations for itself -- the two stages would
        then be back to reasoning about two different organizations, which is
        the failure this whole change removes.
        """
        snapshot = OrganizationSnapshot(
            organization_id=ORG_ID,
            member_account_ids=frozenset({"111111111111"}),
            analyzable_accounts=(),
            hierarchy=OrganizationHierarchy(
                root_id="r-1111", organizational_units={}, accounts={}
            ),
        )
        config = HeadroomConfig(
            management_account_id="111111111111",
            security_analysis_account_id="222222222222",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(environment="env", name="name", owner="owner"),
        )
        security_session = MagicMock()

        with patch("headroom.main.get_security_analysis_session", return_value=security_session), \
             patch("headroom.main.get_management_account_session"), \
             patch("headroom.main.discover_organization", return_value=snapshot), \
             patch("headroom.main.perform_analysis") as scan, \
             patch("headroom.main.parse_cli_args"), \
             patch("headroom.main.load_yaml_config"), \
             patch("headroom.main.setup_configuration", return_value=config), \
             patch("headroom.main.reconcile_generated_terraform"), \
             patch("headroom.main.ensure_org_info_symlink"), \
             patch("headroom.main.generate_terraform_org_info"), \
             patch("headroom.main.handle_scp_workflow", return_value=[]), \
             patch("headroom.main.handle_rcp_workflow", return_value=[]):
            main()

        scan.assert_called_once_with(config, security_session, snapshot)


class TestHandleScpWorkflow:
    """Test handle_scp_workflow function."""

    def test_handle_scp_workflow_with_recommendations(self) -> None:
        """Test SCP workflow with recommendations."""
        config = MagicMock(spec=HeadroomConfig)
        config.scps_dir = "/test/scps"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)
        recommendations = {"check1": "recommendation1"}

        with patch('headroom.main.analyze_scp_compliance', return_value=recommendations):
            with patch('headroom.main.process_policy_recommendations') as mock_process:
                handle_scp_workflow(config, org_hierarchy)

        mock_process.assert_called_once()
        call_args = mock_process.call_args
        assert call_args[0][0] == recommendations
        assert call_args[0][1] == org_hierarchy
        assert call_args[0][2] == "SCP PLACEMENT RECOMMENDATIONS"

    def test_handle_scp_workflow_no_recommendations(self) -> None:
        """
        Nothing to place still generates, producing an empty plan.

        Reconciliation deletes what the plan omits, so an empty plan is how a
        policy that lost its placement loses the file that deploys it.
        """
        config = MagicMock(spec=HeadroomConfig)
        config.scps_dir = "/test/scps"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        with patch('headroom.main.analyze_scp_compliance', return_value=[]):
            with patch(
                'headroom.main.process_policy_recommendations', return_value={}
            ) as mock_process:
                plan = handle_scp_workflow(config, org_hierarchy)

        assert plan == {}
        mock_process.assert_called_once()
        assert mock_process.call_args[0][0] == []


class TestHandleRcpWorkflow:
    """Test handle_rcp_workflow function."""

    def test_handle_rcp_workflow_complete(self) -> None:
        """Test RCP workflow with complete data."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        config.rcps_dir = "/test/rcps"
        config.scps_dir = "/test/scps"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = [
            RCPCheckParseResult(
                check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                account_third_party_map={"111111111111": {"999999999999"}},
                accounts_with_blockers=set(),
            )
        ]
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
        """
        Nothing parsed at all stops the run rather than emptying the directory.

        Zero parse results is the absence of evidence. Treating it as "no
        policies needed" would delete every RCP file and detach every RCP in
        the organization on the next apply.
        """
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result: List[RCPCheckParseResult] = []

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement') as mock_determine:
                with pytest.raises(RuntimeError, match="No RCP result files"):
                    handle_rcp_workflow(config, org_hierarchy)

        mock_determine.assert_not_called()

    def test_handle_rcp_workflow_blocked_accounts_count_as_evidence(self) -> None:
        """
        An account that blocks every check read a file, so the run proceeds.

        Its third-party map is empty for the same reason an unread directory's
        is, and only accounts_with_blockers tells the two apart.
        """
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        config.rcps_dir = "/test/rcps"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = [
            RCPCheckParseResult(
                check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                account_third_party_map={},
                accounts_with_blockers={"111111111111"},
            )
        ]

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement', return_value=[]):
                with patch(
                    'headroom.main.process_policy_recommendations', return_value={}
                ) as mock_process:
                    assert handle_rcp_workflow(config, org_hierarchy) == {}

        mock_process.assert_called_once()

    def test_handle_rcp_workflow_all_checks_empty(self) -> None:
        """Test RCP workflow when every check parsed but found nothing."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = [
            RCPCheckParseResult(
                check_name=check_name,
                account_third_party_map={},
                accounts_with_blockers=set(),
            )
            for check_name in get_check_names("rcps")
        ]

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement') as mock_determine:
                with pytest.raises(RuntimeError, match="No RCP result files"):
                    handle_rcp_workflow(config, org_hierarchy)

        mock_determine.assert_not_called()

    def test_handle_rcp_workflow_no_recommendations(self) -> None:
        """Placing nothing still generates, so reconciliation can empty the directory."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = [
            RCPCheckParseResult(
                check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                account_third_party_map={"111111111111": {"999999999999"}},
                accounts_with_blockers=set(),
            )
        ]

        config.rcps_dir = "/test/rcps"

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement', return_value=[]):
                with patch(
                    'headroom.main.process_policy_recommendations', return_value={}
                ) as mock_process:
                    assert handle_rcp_workflow(config, org_hierarchy) == {}

        mock_process.assert_called_once()
        assert mock_process.call_args[0][0] == []

    def test_handle_rcp_workflow_none_recommendations(self) -> None:
        """A generator handed None still runs, and its plan is what reconciles."""
        config = MagicMock(spec=HeadroomConfig)
        config.results_dir = "/test/results"
        org_hierarchy = MagicMock(spec=OrganizationHierarchy)

        parse_result = [
            RCPCheckParseResult(
                check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                account_third_party_map={"111111111111": {"999999999999"}},
                accounts_with_blockers=set(),
            )
        ]

        config.rcps_dir = "/test/rcps"

        with patch('headroom.main.parse_rcp_result_files', return_value=parse_result):
            with patch('headroom.main.determine_rcp_placement', return_value=None):
                with patch(
                    'headroom.main.process_policy_recommendations', return_value={}
                ) as mock_process:
                    assert handle_rcp_workflow(config, org_hierarchy) == {}

        mock_process.assert_called_once()


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
