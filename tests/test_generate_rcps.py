"""
Tests for headroom.terraform.generate_rcps module.

Tests for RCP Terraform generation functions.
"""

import json
import os
import re
import tempfile
import shutil
import pytest
from pathlib import Path
from typing import Any, Dict, List, Set, Generator
from headroom.constants import (
    DENY_ECR_THIRD_PARTY_ACCESS,
    DENY_KMS_THIRD_PARTY_ACCESS,
    DENY_S3_THIRD_PARTY_ACCESS,
    DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
    DENY_STS_THIRD_PARTY_ASSUMEROLE,
)
from headroom.terraform.generate_rcps import (
    parse_rcp_result_files,
    determine_rcp_placement,
    generate_rcp_terraform,
    _create_org_info_symlink,
    _render_account_rcp_terraform,
    _render_ou_rcp_terraform,
    _render_root_rcp_terraform,
    _build_rcp_terraform_module,
    _create_root_level_rcp_recommendation,
    _create_ou_level_rcp_recommendations,
    _create_account_level_rcp_recommendations,
    RCP_TERRAFORM_VARIABLES
)
from headroom.checks.registry import get_check_names
from headroom.placement.hierarchy import PlacementCandidate
from headroom.types import (
    AccountThirdPartyMap,
    OrganizationHierarchy,
    OrganizationalUnit,
    AccountOrgPlacement,
    RCPCheckParseResult,
    RCPPlacementRecommendations
)


def write_rcp_result(
    results_dir: str,
    check_name: str,
    account_id: str,
    account_name: str,
    third_party_account_ids: List[str],
    violations: int = 0,
) -> None:
    """
    Write one RCP check result file, shaped as the checks write it.

    Args:
        results_dir: Base results directory
        check_name: Registered RCP check the result belongs to
        account_id: Account the check ran against
        account_name: Account name, also used as the filename stem
        third_party_account_ids: Third parties the account's policies allow
        violations: Resources whose principals no allowlist can express
    """
    check_dir = Path(results_dir) / "rcps" / check_name
    check_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "summary": {
            "account_id": account_id,
            "account_name": account_name,
            "check": check_name,
            "unique_third_party_accounts": third_party_account_ids,
            "violations": violations,
        }
    }

    with open(check_dir / f"{account_name}.json", "w") as f:
        json.dump(payload, f)


def seed_all_rcp_check_dirs(results_dir: str) -> None:
    """
    Create a results directory for every registered RCP check.

    Parsing aborts on a registered check with no directory, so a test that
    exercises one check still needs the rest to exist.

    Args:
        results_dir: Base results directory
    """
    for check_name in get_check_names("rcps"):
        (Path(results_dir) / "rcps" / check_name).mkdir(parents=True, exist_ok=True)


class TestParseRcpResultFiles:
    """Test parse_rcp_result_files function."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_org_hierarchy(self) -> OrganizationHierarchy:
        """Create sample organization hierarchy for testing."""
        return OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1111": OrganizationalUnit(
                    ou_id="ou-1111",
                    name="Production",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["111111111111", "222222222222"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="test-account",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                ),
                "222222222222": AccountOrgPlacement(
                    account_id="222222222222",
                    account_name="account2",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                )
            }
        )

    def test_parse_single_account(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test parsing results from a single account."""
        seed_all_rcp_check_dirs(temp_results_dir)
        write_rcp_result(
            temp_results_dir,
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_id="111111111111",
            account_name="test-account",
            third_party_account_ids=["999999999999", "888888888888"],
        )

        results = parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

        sts = next(r for r in results if r.check_name == DENY_STS_THIRD_PARTY_ASSUMEROLE)
        assert len(sts.account_third_party_map) == 1
        assert sts.account_third_party_map["111111111111"] == {"999999999999", "888888888888"}
        assert len(sts.accounts_with_blockers) == 0

    def test_parse_multiple_accounts(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test parsing results from multiple accounts."""
        seed_all_rcp_check_dirs(temp_results_dir)
        write_rcp_result(
            temp_results_dir,
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_id="111111111111",
            account_name="test-account",
            third_party_account_ids=["999999999999"],
        )
        write_rcp_result(
            temp_results_dir,
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_id="222222222222",
            account_name="account2",
            third_party_account_ids=["888888888888", "777777777777"],
        )

        results = parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

        sts = next(r for r in results if r.check_name == DENY_STS_THIRD_PARTY_ASSUMEROLE)
        assert len(sts.account_third_party_map) == 2
        assert sts.account_third_party_map["111111111111"] == {"999999999999"}
        assert sts.account_third_party_map["222222222222"] == {"888888888888", "777777777777"}
        assert len(sts.accounts_with_blockers) == 0

    def test_parse_nonexistent_directory(self, sample_org_hierarchy: OrganizationHierarchy) -> None:
        """
        Test parsing when the results directory doesn't exist.

        A totally missing results directory means every registered check is
        missing its own directory, so the abort names all of them, STS
        included.
        """
        with pytest.raises(RuntimeError, match=DENY_STS_THIRD_PARTY_ASSUMEROLE):
            parse_rcp_result_files("/nonexistent/path", sample_org_hierarchy)

    def test_parse_empty_directory(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test parsing empty directory."""
        seed_all_rcp_check_dirs(temp_results_dir)

        results = parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

        sts = next(r for r in results if r.check_name == DENY_STS_THIRD_PARTY_ASSUMEROLE)
        assert sts.account_third_party_map == {}
        assert sts.accounts_with_blockers == set()

    def test_parse_invalid_json(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test parsing with invalid JSON file."""
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE

        # Create invalid JSON file
        result_file = check_dir / "invalid.json"
        with open(result_file, 'w') as f:
            f.write("{invalid json")

        # Should raise exception on invalid JSON file
        with pytest.raises(RuntimeError, match="Failed to parse result file .*/invalid.json"):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

    def test_parse_missing_summary_key(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test parsing with file missing required summary key."""
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE

        # Create file with missing summary key - should fail with RuntimeError
        result_data = {
            "some_other_key": "value"
        }
        result_file = check_dir / "bad.json"
        with open(result_file, 'w') as f:
            json.dump(result_data, f)

        # Should raise exception when account_name and account_id are both missing
        with pytest.raises(RuntimeError, match="missing both account_id and account_name"):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

    def test_parse_separates_blocked_accounts(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that accounts with blocking violations are separated out."""
        seed_all_rcp_check_dirs(temp_results_dir)
        write_rcp_result(
            temp_results_dir,
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_id="111111111111",
            account_name="test-account",
            third_party_account_ids=["999999999999"],
            violations=1,
        )
        write_rcp_result(
            temp_results_dir,
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_id="222222222222",
            account_name="account2",
            third_party_account_ids=["888888888888"],
        )

        results = parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)
        sts = next(r for r in results if r.check_name == DENY_STS_THIRD_PARTY_ASSUMEROLE)

        # Only the account with no blocking violation should be in the map
        assert len(sts.account_third_party_map) == 1
        assert "222222222222" in sts.account_third_party_map
        assert "111111111111" not in sts.account_third_party_map
        assert sts.account_third_party_map["222222222222"] == {"888888888888"}

        # The account with a blocking violation should be in the blocked set
        assert len(sts.accounts_with_blockers) == 1
        assert "111111111111" in sts.accounts_with_blockers

    def test_parse_looks_up_missing_account_id(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that missing account_id is looked up from account_name."""
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE

        # Result without account_id (e.g., from exclude_account_ids=True)
        result_data = {
            "summary": {
                "account_name": "test-account",
                "check": DENY_STS_THIRD_PARTY_ASSUMEROLE,
                "unique_third_party_accounts": ["999999999999"],
                "violations": 0,
            }
        }

        result_file = check_dir / "test-account.json"
        with open(result_file, 'w') as f:
            json.dump(result_data, f)

        results = parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)
        sts = next(r for r in results if r.check_name == DENY_STS_THIRD_PARTY_ASSUMEROLE)

        # Should have looked up account_id from account_name
        assert len(sts.account_third_party_map) == 1
        assert "111111111111" in sts.account_third_party_map
        assert sts.account_third_party_map["111111111111"] == {"999999999999"}

    def test_parse_fails_when_account_name_not_found(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that an error is raised when account_name is not in org hierarchy."""
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE

        # Result with unknown account name
        result_data = {
            "summary": {
                "account_name": "unknown-account",
                "check": DENY_STS_THIRD_PARTY_ASSUMEROLE,
                "unique_third_party_accounts": ["999999999999"],
                "violations": 0,
            }
        }

        result_file = check_dir / "unknown.json"
        with open(result_file, 'w') as f:
            json.dump(result_data, f)

        with pytest.raises(RuntimeError, match="Account name 'unknown-account'.* not found in organization hierarchy"):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

    def test_parse_aborts_when_a_check_directory_is_missing(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        A registered check with no results directory must abort the run.

        Results gate RCP deployment, and a check absent from them is
        indistinguishable from a check that found nothing.
        """
        seed_all_rcp_check_dirs(temp_results_dir)
        shutil.rmtree(Path(temp_results_dir) / "rcps" / DENY_S3_THIRD_PARTY_ACCESS)

        with pytest.raises(RuntimeError, match=DENY_S3_THIRD_PARTY_ACCESS):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

    def test_parse_aborts_when_violations_field_is_absent(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        A result file without a violations count must abort the run.

        Defaulting the count to zero would read a malformed file as an
        account with nothing blocking deployment.
        """
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE
        with open(check_dir / "test-account.json", "w") as f:
            json.dump({
                "summary": {
                    "account_id": "111111111111",
                    "check": DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    "unique_third_party_accounts": [],
                }
            }, f)

        with pytest.raises(RuntimeError, match="violations"):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

    def test_parse_aborts_when_third_party_accounts_field_is_absent(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        A result file without a third-party allowlist must abort the run.

        Defaulting the allowlist to empty would read a malformed file as an
        account that trusts nobody, which renders the check enabled with an
        empty allowlist and denies every third-party integration it has.
        """
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE
        with open(check_dir / "test-account.json", "w") as f:
            json.dump({
                "summary": {
                    "account_id": "111111111111",
                    "check": DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    "violations": 0,
                }
            }, f)

        with pytest.raises(RuntimeError, match="test-account.json.*unique_third_party_accounts"):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

    def test_parse_aborts_when_summary_check_field_is_absent(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        A result file that names no check must abort the run.

        Treating the absent name as agreeing with the directory disarms the
        mismatch guard for exactly the files it exists to catch.
        """
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE
        with open(check_dir / "test-account.json", "w") as f:
            json.dump({
                "summary": {
                    "account_id": "111111111111",
                    "unique_third_party_accounts": [],
                    "violations": 0,
                }
            }, f)

        with pytest.raises(RuntimeError, match="test-account.json.*names no check"):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

    def test_absent_and_mismatched_check_names_report_differently(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        The two check-name failures must be told apart from the message.

        A file that names nothing needs regenerating; a file that names
        another check has been filed in the wrong directory.
        """
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE
        summary: Dict[str, Any] = {
            "account_id": "111111111111",
            "unique_third_party_accounts": [],
            "violations": 0,
        }

        with open(check_dir / "test-account.json", "w") as f:
            json.dump({"summary": summary}, f)
        with pytest.raises(RuntimeError) as absent:
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

        with open(check_dir / "test-account.json", "w") as f:
            json.dump({"summary": {**summary, "check": DENY_S3_THIRD_PARTY_ACCESS}}, f)
        with pytest.raises(RuntimeError) as mismatch:
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)

        assert str(absent.value) != str(mismatch.value)
        assert "does not match" not in str(absent.value)
        assert "names no check" not in str(mismatch.value)

    def test_parse_aborts_when_summary_check_disagrees_with_directory(
        self,
        temp_results_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """A result filed under the wrong check directory must abort."""
        seed_all_rcp_check_dirs(temp_results_dir)
        check_dir = Path(temp_results_dir) / "rcps" / DENY_STS_THIRD_PARTY_ASSUMEROLE
        with open(check_dir / "test-account.json", "w") as f:
            json.dump({
                "summary": {
                    "account_id": "111111111111",
                    "check": DENY_S3_THIRD_PARTY_ACCESS,
                    "unique_third_party_accounts": [],
                    "violations": 0,
                }
            }, f)

        with pytest.raises(RuntimeError, match="does not match"):
            parse_rcp_result_files(temp_results_dir, sample_org_hierarchy)


class TestDetermineRcpPlacement:
    """Test determine_rcp_placement function."""

    @pytest.fixture
    def sample_org_hierarchy(self) -> OrganizationHierarchy:
        """Create sample organization hierarchy."""
        return OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1111": OrganizationalUnit(
                    ou_id="ou-1111",
                    name="Production",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["111111111111", "222222222222"]
                ),
                "ou-2222": OrganizationalUnit(
                    ou_id="ou-2222",
                    name="Development",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["333333333333"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="prod-account-1",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                ),
                "222222222222": AccountOrgPlacement(
                    account_id="222222222222",
                    account_name="prod-account-2",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                ),
                "333333333333": AccountOrgPlacement(
                    account_id="333333333333",
                    account_name="dev-account-1",
                    parent_ou_id="ou-2222",
                    ou_path=["Development"]
                )
            }
        )

    def test_recommends_root_level_when_all_accounts_have_identical_third_party_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test root level placement when all accounts have same third-party accounts."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"999999999999"},
            "333333333333": {"999999999999"}
        }

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers=set(),
                )
            ],
            sample_org_hierarchy,
        )

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert recommendations[0].target_ou_id is None
        # Verify affected_accounts includes ALL accounts in the org
        assert set(recommendations[0].affected_accounts) == {"111111111111", "222222222222", "333333333333"}
        assert recommendations[0].third_party_account_ids == ["999999999999"]
        assert "All 3 accounts can be protected with root-level RCP" in recommendations[0].reasoning

    def test_recommends_root_level_with_different_third_party_accounts_unioned(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test root level placement unions different third-party accounts from different accounts."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"},
            "333333333333": {"999999999999", "777777777777"}
        }

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers=set(),
                )
            ],
            sample_org_hierarchy,
        )

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert recommendations[0].target_ou_id is None
        # Verify affected_accounts includes ALL accounts in the org
        assert set(recommendations[0].affected_accounts) == {"111111111111", "222222222222", "333333333333"}
        # Should union all third-party account IDs
        assert set(recommendations[0].third_party_account_ids) == {"777777777777", "888888888888", "999999999999"}
        assert "All 3 accounts can be protected with root-level RCP" in recommendations[0].reasoning
        assert "allowlist contains 3 third-party accounts" in recommendations[0].reasoning

    def test_recommends_ou_level_when_ou_accounts_have_identical_third_party_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test OU level placement unions third-party accounts from accounts in OU."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999", "888888888888"},
            "222222222222": {"999999999999", "666666666666"},
            "333333333333": {"777777777777"}
        }

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers=set(),
                )
            ],
            sample_org_hierarchy,
        )

        # Should NOT get root-level since wildcards would prevent it
        # Should get OU-level for ou-1111 with unioned third-party IDs
        # Should get account-level for account in ou-2222

        root_recs = [r for r in recommendations if r.recommended_level == "root"]
        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        account_recs = [r for r in recommendations if r.recommended_level == "account"]

        # With union logic, all accounts can be covered at root since no wildcards
        assert len(root_recs) == 1
        assert len(ou_recs) == 0
        assert len(account_recs) == 0

        # Root should have union of all third-party IDs
        assert set(root_recs[0].third_party_account_ids) == {"666666666666", "777777777777", "888888888888", "999999999999"}

    def test_recommends_account_level_when_each_account_has_unique_third_party_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        Test that root-level is recommended even when accounts have different third-party accounts.

        With union logic, different third-party requirements can be combined at root level.
        """
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"},
            "333333333333": {"777777777777"}
        }

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers=set(),
                )
            ],
            sample_org_hierarchy,
        )

        # With union logic, this should recommend root-level with all IDs unioned
        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert set(recommendations[0].third_party_account_ids) == {"777777777777", "888888888888", "999999999999"}

    def test_returns_empty_list_when_no_third_party_accounts_found(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test with no third-party accounts."""
        account_third_party_map: AccountThirdPartyMap = {}

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers=set(),
                )
            ],
            sample_org_hierarchy,
        )

        assert len(recommendations) == 0

    def test_skips_root_level_when_any_account_has_wildcards(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        Test that root-level RCP is NOT recommended when ANY account has wildcards.

        Critical fix: Even if all non-wildcard accounts have identical third-party
        requirements, we cannot deploy at root if any account has wildcards because
        the root RCP would affect those accounts too.
        """
        # Two accounts with identical (empty) third-party sets
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": set(),
            "222222222222": set()
        }

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    # One account has wildcards (like shared-foo-bar in test_environment)
                    accounts_with_blockers={"333333333333"},
                )
            ],
            sample_org_hierarchy,
        )

        # Should NOT get root-level recommendation
        root_recs = [r for r in recommendations if r.recommended_level == "root"]
        assert len(root_recs) == 0, "Should not recommend root-level RCP when any account has wildcards"

        # Should get OU-level recommendation for ou-1111 (which has 2 accounts without wildcards)
        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        assert len(ou_recs) == 1
        assert ou_recs[0].target_ou_id == "ou-1111"
        # OU-level should union the third-party IDs from both accounts (even if they're both empty)
        assert ou_recs[0].third_party_account_ids == []

    def test_skips_ou_level_recommendation_when_any_account_in_ou_has_wildcards(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that OU-level RCP is skipped when any account in OU has wildcards, falls back to account-level."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            # 222222222222 has wildcards, not in map
            "333333333333": {"777777777777"}
        }

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers={"222222222222"},
                )
            ],
            sample_org_hierarchy,
        )

        # Should NOT get root-level (wildcard blocks it)
        root_recs = [r for r in recommendations if r.recommended_level == "root"]
        assert len(root_recs) == 0

        # Should get OU-level recommendations
        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        # ou-1111 has wildcard so skipped, but ou-2222 (Development) has 1 account without wildcards so gets OU-level
        assert len(ou_recs) == 1
        assert ou_recs[0].target_ou_id == "ou-2222"  # Development OU with single account
        assert ou_recs[0].affected_accounts == ["333333333333"]

        # Should get account-level recommendation for the account in ou-1111 (which has wildcard blocking OU-level)
        account_recs = [r for r in recommendations if r.recommended_level == "account"]
        assert len(account_recs) == 1
        assert account_recs[0].affected_accounts == ["111111111111"]

    def test_skips_accounts_not_in_hierarchy_when_building_ou_mappings(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        Test that accounts not in the hierarchy cause a failure during OU-level processing.

        We need to block root-level with wildcards to force OU-level processing.
        """
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"999999999999"},
            "999999999999": {"888888888888"}  # This account doesn't exist in hierarchy
        }
        # Should raise exception for account not in hierarchy during OU-level processing
        with pytest.raises(RuntimeError, match="Account \\(999999999999\\) not found in organization hierarchy"):
            determine_rcp_placement(
                [
                    RCPCheckParseResult(
                        check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                        account_third_party_map=account_third_party_map,
                        # Add a blocker to prevent root-level and force OU-level processing
                        accounts_with_blockers={"some_wildcard_account"},
                    )
                ],
                sample_org_hierarchy,
            )

    def test_with_empty_third_party_sets(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test with accounts that have empty third-party sets."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": set(),
            "222222222222": set(),
            "333333333333": set()
        }

        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers=set(),
                )
            ],
            sample_org_hierarchy,
        )

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert recommendations[0].third_party_account_ids == []
        assert "All 3 accounts can be protected with root-level RCP" in recommendations[0].reasoning
        assert "allowlist contains 0 third-party accounts" in recommendations[0].reasoning
        # Verify affected_accounts includes ALL accounts in the org
        assert set(recommendations[0].affected_accounts) == {"111111111111", "222222222222", "333333333333"}

    def test_ou_level_rcp_for_single_account_ou(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that OU-level RCP works even for single-account OUs (no minimum threshold)."""
        account_third_party_map: AccountThirdPartyMap = {
            "333333333333": {"999999999999"}  # Single account in Development OU (ou-2222)
        }
        recommendations = determine_rcp_placement(
            [
                RCPCheckParseResult(
                    check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                    account_third_party_map=account_third_party_map,
                    accounts_with_blockers={"dummy_account"},  # Block root to force OU processing
                )
            ],
            sample_org_hierarchy,
        )

        # Should get OU-level recommendation even though OU has only 1 account
        # (no minimum threshold anymore)
        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "ou"
        assert recommendations[0].target_ou_id == "ou-2222"
        assert recommendations[0].affected_accounts == ["333333333333"]

    def test_blocking_account_suppresses_only_its_own_check(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        A blocked account must not suppress placement for other checks.

        An S3 bucket policy with a wildcard principal makes the S3 RCP unsafe
        for that account. It says nothing about that account's IAM trust
        policies, so the STS RCP is still safe at root.
        """
        parse_results = [
            RCPCheckParseResult(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_third_party_map={"222222222222": {"999999999999"}},
                accounts_with_blockers={"111111111111"},
            ),
            RCPCheckParseResult(
                check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
                account_third_party_map={
                    "111111111111": {"999999999999"},
                    "222222222222": {"999999999999"},
                },
                accounts_with_blockers=set(),
            ),
        ]

        recommendations = determine_rcp_placement(parse_results, sample_org_hierarchy)

        by_check = {rec.check_name: rec for rec in recommendations}
        assert by_check[DENY_STS_THIRD_PARTY_ASSUMEROLE].recommended_level == "root"
        assert by_check[DENY_S3_THIRD_PARTY_ACCESS].recommended_level != "root"


class TestCreateRootLevelRcpRecommendation:
    """Test _create_root_level_rcp_recommendation helper function."""

    @pytest.fixture
    def sample_org_hierarchy(self) -> OrganizationHierarchy:
        """Create sample organization hierarchy."""
        return OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1111": OrganizationalUnit(
                    ou_id="ou-1111",
                    name="Production",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["111111111111", "222222222222"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="prod-account-1",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                ),
                "222222222222": AccountOrgPlacement(
                    account_id="222222222222",
                    account_name="prod-account-2",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                )
            }
        )

    def test_creates_root_recommendation_with_single_account(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test creating root recommendation with single account."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }

        recommendation = _create_root_level_rcp_recommendation(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert recommendation.check_name == "deny_sts_third_party_assumerole"
        assert recommendation.recommended_level == "root"
        assert recommendation.target_ou_id is None
        assert set(recommendation.affected_accounts) == {"111111111111", "222222222222"}
        assert recommendation.third_party_account_ids == ["999999999999"]
        assert "All 2 accounts can be protected with root-level RCP" in recommendation.reasoning
        assert "allowlist contains 1 third-party accounts" in recommendation.reasoning

    def test_creates_root_recommendation_with_multiple_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test creating root recommendation with multiple accounts."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999", "888888888888"},
            "222222222222": {"777777777777"}
        }

        recommendation = _create_root_level_rcp_recommendation(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert recommendation.recommended_level == "root"
        assert set(recommendation.affected_accounts) == {"111111111111", "222222222222"}
        assert set(recommendation.third_party_account_ids) == {"777777777777", "888888888888", "999999999999"}
        assert "allowlist contains 3 third-party accounts" in recommendation.reasoning

    def test_creates_root_recommendation_with_empty_third_party_sets(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test creating root recommendation with empty third-party sets."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": set(),
            "222222222222": set()
        }

        recommendation = _create_root_level_rcp_recommendation(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert recommendation.recommended_level == "root"
        assert recommendation.third_party_account_ids == []
        assert "allowlist contains 0 third-party accounts" in recommendation.reasoning

    def test_unions_overlapping_third_party_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that overlapping third-party accounts are properly unioned."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999", "888888888888"},
            "222222222222": {"999999999999", "777777777777"}
        }

        recommendation = _create_root_level_rcp_recommendation(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert set(recommendation.third_party_account_ids) == {"777777777777", "888888888888", "999999999999"}
        assert len(recommendation.third_party_account_ids) == 3

    def test_includes_all_org_accounts_in_affected_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that affected_accounts includes all accounts in the org, not just those in map."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }

        recommendation = _create_root_level_rcp_recommendation(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert set(recommendation.affected_accounts) == {"111111111111", "222222222222"}

    def test_sorts_third_party_account_ids(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that third-party account IDs are sorted."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999", "111111111111", "555555555555"}
        }

        recommendation = _create_root_level_rcp_recommendation(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert recommendation.third_party_account_ids == ["111111111111", "555555555555", "999999999999"]


class TestCreateOuLevelRcpRecommendations:
    """Test _create_ou_level_rcp_recommendations helper function."""

    @pytest.fixture
    def sample_org_hierarchy(self) -> OrganizationHierarchy:
        """Create sample organization hierarchy."""
        return OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1111": OrganizationalUnit(
                    ou_id="ou-1111",
                    name="Production",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["111111111111", "222222222222"]
                ),
                "ou-2222": OrganizationalUnit(
                    ou_id="ou-2222",
                    name="Development",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["333333333333"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="prod-account-1",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                ),
                "222222222222": AccountOrgPlacement(
                    account_id="222222222222",
                    account_name="prod-account-2",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                ),
                "333333333333": AccountOrgPlacement(
                    account_id="333333333333",
                    account_name="dev-account-1",
                    parent_ou_id="ou-2222",
                    ou_path=["Development"]
                )
            }
        )

    def test_creates_single_ou_recommendation(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test creating single OU-level recommendation."""
        candidates = [
            PlacementCandidate(
                level="ou",
                target_id="ou-1111",
                affected_accounts=["111111111111", "222222222222"],
                reasoning="OU-level deployment safe"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"999999999999"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "ou"
        assert recommendations[0].target_ou_id == "ou-1111"
        assert set(recommendations[0].affected_accounts) == {"111111111111", "222222222222"}
        assert recommendations[0].third_party_account_ids == ["999999999999"]
        assert "Production" in recommendations[0].reasoning
        assert covered_accounts == {"111111111111", "222222222222"}

    def test_creates_multiple_ou_recommendations(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test creating multiple OU-level recommendations."""
        candidates = [
            PlacementCandidate(
                level="ou",
                target_id="ou-1111",
                affected_accounts=["111111111111", "222222222222"],
                reasoning="OU-level deployment safe"
            ),
            PlacementCandidate(
                level="ou",
                target_id="ou-2222",
                affected_accounts=["333333333333"],
                reasoning="OU-level deployment safe"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"999999999999"},
            "333333333333": {"888888888888"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 2
        assert covered_accounts == {"111111111111", "222222222222", "333333333333"}

    def test_skips_non_ou_candidates(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that non-OU candidates are skipped."""
        candidates = [
            PlacementCandidate(
                level="root",
                target_id=None,
                affected_accounts=["111111111111"],
                reasoning="Root-level deployment"
            ),
            PlacementCandidate(
                level="account",
                target_id=None,
                affected_accounts=["222222222222"],
                reasoning="Account-level deployment"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 0
        assert len(covered_accounts) == 0

    def test_skips_ou_candidates_with_none_target_id(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that OU candidates with None target_id are skipped."""
        candidates = [
            PlacementCandidate(
                level="ou",
                target_id=None,
                affected_accounts=["111111111111"],
                reasoning="Invalid OU candidate"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 0
        assert len(covered_accounts) == 0

    def test_unions_third_party_accounts_within_ou(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that third-party accounts are unioned within an OU."""
        candidates = [
            PlacementCandidate(
                level="ou",
                target_id="ou-1111",
                affected_accounts=["111111111111", "222222222222"],
                reasoning="OU-level deployment safe"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999", "888888888888"},
            "222222222222": {"777777777777", "999999999999"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 1
        assert set(recommendations[0].third_party_account_ids) == {"777777777777", "888888888888", "999999999999"}

    def test_handles_accounts_not_in_map(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that accounts not in the third-party map are handled gracefully."""
        candidates = [
            PlacementCandidate(
                level="ou",
                target_id="ou-1111",
                affected_accounts=["111111111111", "222222222222"],
                reasoning="OU-level deployment safe"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 1
        assert recommendations[0].third_party_account_ids == ["999999999999"]
        assert covered_accounts == {"111111111111", "222222222222"}

    def test_handles_empty_third_party_sets(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test handling of empty third-party account sets."""
        candidates = [
            PlacementCandidate(
                level="ou",
                target_id="ou-1111",
                affected_accounts=["111111111111"],
                reasoning="OU-level deployment safe"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": set()
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 1
        assert recommendations[0].third_party_account_ids == []

    def test_returns_empty_for_empty_candidates(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that empty candidates list returns empty results."""
        candidates: List[PlacementCandidate] = []
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 0
        assert len(covered_accounts) == 0

    def test_uses_ou_id_as_fallback_name(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that OU ID is used as fallback when OU not found in hierarchy."""
        candidates = [
            PlacementCandidate(
                level="ou",
                target_id="ou-9999",
                affected_accounts=["111111111111"],
                reasoning="OU-level deployment safe"
            )
        ]
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }

        recommendations, covered_accounts = _create_ou_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            candidates,
            account_third_party_map,
            sample_org_hierarchy
        )

        assert len(recommendations) == 1
        assert "ou-9999" in recommendations[0].reasoning


class TestCreateAccountLevelRcpRecommendations:
    """Test _create_account_level_rcp_recommendations helper function."""

    def test_creates_recommendations_for_uncovered_accounts(self) -> None:
        """Test creating account-level recommendations for uncovered accounts."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"},
            "333333333333": {"777777777777"}
        }
        covered_accounts: Set[str] = {"222222222222"}

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 2
        account_ids = [r.affected_accounts[0] for r in recommendations]
        assert "111111111111" in account_ids
        assert "333333333333" in account_ids
        assert "222222222222" not in account_ids

    def test_skips_covered_accounts(self) -> None:
        """Test that covered accounts are not included in recommendations."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"}
        }
        covered_accounts: Set[str] = {"111111111111", "222222222222"}

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 0

    def test_creates_recommendation_with_correct_structure(self) -> None:
        """Test that recommendations have correct structure."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999", "888888888888"}
        }
        covered_accounts: Set[str] = set()

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 1
        rec = recommendations[0]
        assert rec.check_name == "deny_sts_third_party_assumerole"
        assert rec.recommended_level == "account"
        assert rec.target_ou_id is None
        assert rec.affected_accounts == ["111111111111"]
        assert set(rec.third_party_account_ids) == {"888888888888", "999999999999"}
        assert "Account has unique third-party account requirements" in rec.reasoning
        assert "2 accounts" in rec.reasoning

    def test_handles_empty_third_party_sets(self) -> None:
        """Test handling of empty third-party account sets."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": set()
        }
        covered_accounts: Set[str] = set()

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 1
        assert recommendations[0].third_party_account_ids == []
        assert "0 accounts" in recommendations[0].reasoning

    def test_returns_empty_for_empty_map(self) -> None:
        """Test that empty account map returns empty recommendations."""
        account_third_party_map: AccountThirdPartyMap = {}
        covered_accounts: Set[str] = set()

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 0

    def test_returns_empty_when_all_accounts_covered(self) -> None:
        """Test that all covered accounts returns empty recommendations."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"}
        }
        covered_accounts: Set[str] = {"111111111111"}

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 0

    def test_sorts_third_party_account_ids(self) -> None:
        """Test that third-party account IDs are sorted."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999", "111111111111", "555555555555"}
        }
        covered_accounts: Set[str] = set()

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert recommendations[0].third_party_account_ids == ["111111111111", "555555555555", "999999999999"]

    def test_multiple_accounts_each_get_own_recommendation(self) -> None:
        """Test that each account gets its own recommendation."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"},
            "333333333333": {"777777777777"}
        }
        covered_accounts: Set[str] = set()

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 3
        for rec in recommendations:
            assert len(rec.affected_accounts) == 1
            assert rec.recommended_level == "account"

    def test_handles_partially_covered_accounts(self) -> None:
        """Test handling of partially covered account sets."""
        account_third_party_map: AccountThirdPartyMap = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"},
            "333333333333": {"777777777777"},
            "444444444444": {"666666666666"}
        }
        covered_accounts: Set[str] = {"111111111111", "333333333333"}

        recommendations = _create_account_level_rcp_recommendations(
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_third_party_map,
            covered_accounts
        )

        assert len(recommendations) == 2
        account_ids = {r.affected_accounts[0] for r in recommendations}
        assert account_ids == {"222222222222", "444444444444"}


class TestGenerateRcpTerraform:
    """Test generate_rcp_terraform function."""

    @pytest.fixture
    def temp_base_dir(self) -> Generator[str, None, None]:
        """Create temporary base directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def temp_output_dir(self, temp_base_dir: str) -> str:
        """Create temporary RCP output directory."""
        return f"{temp_base_dir}/rcps"

    @pytest.fixture
    def temp_scps_dir(self, temp_base_dir: str) -> str:
        """Create temporary SCP directory."""
        return f"{temp_base_dir}/scps"

    @pytest.fixture
    def sample_org_hierarchy(self) -> OrganizationHierarchy:
        """Create sample organization hierarchy."""
        return OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1111": OrganizationalUnit(
                    ou_id="ou-1111",
                    name="Production",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["111111111111"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="prod-account-1",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                )
            }
        )

    def test_generate_root_level_terraform(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test generating root level RCP Terraform."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="root",
                target_ou_id=None,
                affected_accounts=["111111111111"],
                third_party_account_ids=["999999999999", "888888888888"],
                reasoning="Test root level"
            )
        ]

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        root_file = Path(temp_output_dir) / "root_rcps.tf"
        assert root_file.exists()

        content = root_file.read_text()
        assert "module \"rcps_root\"" in content
        assert "local.root_ou_id" in content
        assert "999999999999" in content
        assert "888888888888" in content
        assert "deny_sts_third_party_assumerole = true" in content

    def test_generate_ou_level_terraform(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test generating OU level RCP Terraform."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="ou",
                target_ou_id="ou-1111",
                affected_accounts=["111111111111"],
                third_party_account_ids=["999999999999"],
                reasoning="Test OU level"
            )
        ]

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        ou_file = Path(temp_output_dir) / "production_ou_rcps.tf"
        assert ou_file.exists()

        content = ou_file.read_text()
        assert "module \"rcps_production_ou\"" in content
        assert "local.production_ou_id" in content
        assert "999999999999" in content
        assert "deny_sts_third_party_assumerole = true" in content

    def test_generate_account_level_terraform(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test generating account level RCP Terraform."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=["111111111111"],
                third_party_account_ids=["999999999999"],
                reasoning="Test account level"
            )
        ]

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        account_file = Path(temp_output_dir) / "prod_account_1_rcps.tf"
        assert account_file.exists()

        content = account_file.read_text()
        assert "module \"rcps_prod_account_1\"" in content
        assert "local.prod_account_1_account_id" in content
        assert "999999999999" in content
        assert "deny_sts_third_party_assumerole = true" in content

    def test_generate_skips_missing_ou(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that missing OU in hierarchy raises exception."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="ou",
                target_ou_id="ou-9999",
                affected_accounts=["111111111111"],
                third_party_account_ids=["999999999999"],
                reasoning="Test OU not found"
            )
        ]

        # Should raise exception for missing OU
        with pytest.raises(RuntimeError, match="OU ou-9999 not found in organization hierarchy"):
            generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

    def test_generate_skips_missing_account(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that missing account in hierarchy raises exception."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=["999999999999"],
                third_party_account_ids=["888888888888"],
                reasoning="Test account not found"
            )
        ]

        # Should raise exception for missing account
        with pytest.raises(RuntimeError, match="Account \\(999999999999\\) not found in organization hierarchy"):
            generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

    def test_generate_no_recommendations(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test generating with no recommendations."""
        recommendations: List[RCPPlacementRecommendations] = []

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        output_path = Path(temp_output_dir)
        assert not output_path.exists() or len(list(output_path.glob("*.tf"))) == 0

    def test_no_symlink_created_by_generate_rcp_terraform(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        Test that grab_org_info.tf symlink is NOT created by generate_rcp_terraform.

        After refactoring, symlink creation is handled explicitly in main.py,
        not as a side effect of generate_rcp_terraform.
        """
        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=["111111111111"],
                third_party_account_ids=["999999999999"],
                reasoning="Test no symlink creation"
            )
        ]

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        symlink_path = Path(temp_output_dir) / "grab_org_info.tf"
        # Symlink should NOT be created by generate_rcp_terraform
        assert not symlink_path.exists()

    def test_symlink_replaces_existing_file(
        self,
        temp_output_dir: str,
        temp_scps_dir: str
    ) -> None:
        """Test that an existing regular file is replaced by a symlink using _create_org_info_symlink."""
        output_path = Path(temp_output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        existing_file = output_path / "grab_org_info.tf"

        # Create a regular file
        with open(existing_file, 'w') as f:
            f.write("# Old content")

        assert existing_file.exists()
        assert not existing_file.is_symlink()

        # Call the helper directly (now this is called from main.py, not generate_rcp_terraform)
        _create_org_info_symlink(output_path, temp_scps_dir)

        # Should now be a symlink (broken symlinks return False for exists())
        assert existing_file.is_symlink()
        expected_target = os.path.relpath(f"{temp_scps_dir}/grab_org_info.tf", temp_output_dir)
        assert os.readlink(existing_file) == expected_target

    def test_symlink_updates_existing_symlink(
        self,
        temp_output_dir: str,
        temp_scps_dir: str
    ) -> None:
        """Test that an existing symlink is recreated (handles broken symlinks) using _create_org_info_symlink."""
        output_path = Path(temp_output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        symlink_path = output_path / "grab_org_info.tf"

        # Create a symlink to a different location
        os.symlink("../wrong/path.tf", symlink_path)

        assert symlink_path.is_symlink()
        assert os.readlink(symlink_path) == "../wrong/path.tf"

        # Call the helper directly (now this is called from main.py, not generate_rcp_terraform)
        _create_org_info_symlink(output_path, temp_scps_dir)

        # Should now point to the correct location
        assert symlink_path.is_symlink()
        expected_target = os.path.relpath(f"{temp_scps_dir}/grab_org_info.tf", temp_output_dir)
        assert os.readlink(symlink_path) == expected_target

    def test_no_terraform_files_with_no_recommendations(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that no Terraform files or symlinks are created when no recommendations exist."""
        recommendations: List[RCPPlacementRecommendations] = []

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        # No terraform files should be created
        output_path = Path(temp_output_dir)
        assert not output_path.exists() or len(list(output_path.glob("*.tf"))) == 0

    def test_create_org_info_symlink_direct(self, temp_output_dir: str, temp_scps_dir: str) -> None:
        """Test _create_org_info_symlink helper function directly."""
        output_path = Path(temp_output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        symlink_path = output_path / "grab_org_info.tf"

        # Create symlink
        _create_org_info_symlink(output_path, temp_scps_dir)

        # Check is_symlink (broken symlinks return False for exists())
        assert symlink_path.is_symlink()
        expected_target = os.path.relpath(f"{temp_scps_dir}/grab_org_info.tf", temp_output_dir)
        assert os.readlink(symlink_path) == expected_target


class TestRcpTerraformVariableTable:
    """Test the table that maps RCP checks to Terraform variables."""

    def test_table_covers_every_registered_rcp_check(self) -> None:
        """
        Every registered RCP check must have Terraform variables declared.

        A check missing from the table is collected on every run and then
        dropped at render time, emitting no module parameters at all, so the
        omission surfaces as a Terraform plan failure instead of here.
        """
        assert set(RCP_TERRAFORM_VARIABLES) == set(get_check_names("rcps"))

    def test_table_declares_distinct_variables_per_check(self) -> None:
        """Each check must own its enable flag and allowlist variable."""
        enable_vars = [v.enable_var for v in RCP_TERRAFORM_VARIABLES.values()]
        allowlist_vars = [v.allowlist_var for v in RCP_TERRAFORM_VARIABLES.values()]

        assert len(set(enable_vars)) == len(enable_vars)
        assert len(set(allowlist_vars)) == len(allowlist_vars)


class TestBuildRcpTerraformModule:
    """Test _build_rcp_terraform_module helper function."""

    def test_build_module_with_third_party_accounts(self) -> None:
        """Should generate module with third-party account allowlist."""
        rec = RCPPlacementRecommendations(
            check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["111111111111", "222222222222"],
            reasoning="Test"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_test_account",
            target_id_reference="local.test_account_account_id",
            recommendations=[rec],
            comment="Test Account"
        )

        assert 'module "rcps_test_account"' in result
        assert "target_id = local.test_account_account_id" in result
        assert "sts_third_party_assumerole_account_ids_allowlist" in result
        assert '"111111111111"' in result
        assert '"222222222222"' in result
        assert "deny_sts_third_party_assumerole = true" in result

    def test_build_module_includes_comment(self) -> None:
        """Should include comment in generated content."""
        rec = RCPPlacementRecommendations(
            check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["000000000000"],
            reasoning="Test"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_root",
            target_id_reference="local.root_ou_id",
            recommendations=[rec],
            comment="Organization Root"
        )

        assert "# Auto-generated RCP Terraform configuration for Organization Root" in result
        # Verify section comments are present
        assert "  # ECR" in result
        assert "  # S3" in result
        assert "  # SQS" in result
        assert "  # STS" in result
        # Verify blank lines separate sections (not '  #' lines)
        assert "  #\n" not in result, "Should not have '  #' comment lines, only blank lines for spacing"

    def test_build_module_output_format(self) -> None:
        """Test exact RCP output format with section comments and proper blank line spacing."""
        assume_role_rec = RCPPlacementRecommendations(
            check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["555555555555"],
            reasoning="Test"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_test",
            target_id_reference="local.test_ou_id",
            recommendations=[assume_role_rec],
            comment="Test OU"
        )

        expected = '''# Code generated by Headroom. DO NOT EDIT.
# Auto-generated RCP Terraform configuration for Test OU
# Generated by Headroom based on third-party account analysis

module "rcps_test" {
  source = "../modules/rcps"
  target_id = local.test_ou_id

  # ECR
  deny_ecr_third_party_access = false

  # KMS
  deny_kms_third_party_access = false

  # S3
  deny_s3_third_party_access = false

  # Secrets Manager
  deny_secrets_manager_third_party_access = false

  # SQS
  deny_sqs_third_party_access = false

  # STS
  deny_sts_third_party_assumerole = true
  sts_third_party_assumerole_account_ids_allowlist = [
    "555555555555",
  ]

  # Service confused deputy
  deny_service_confused_deputy = false
}
'''
        assert result == expected

    def test_build_module_with_s3_third_party_accounts(self) -> None:
        """Should generate module with S3 third-party account allowlist."""
        s3_rec = RCPPlacementRecommendations(
            check_name="deny_s3_third_party_access",
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["333333333333", "444444444444"],
            reasoning="Test S3 access"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_test_account",
            target_id_reference="local.test_account_account_id",
            recommendations=[s3_rec],
            comment="Test Account"
        )

        assert 'module "rcps_test_account"' in result
        assert "s3_third_party_access_account_ids_allowlist" in result
        assert '"333333333333"' in result
        assert '"444444444444"' in result
        assert "deny_s3_third_party_access = true" in result

    def test_build_module_without_s3_third_party_accounts(self) -> None:
        """Should generate module with deny_s3_third_party_access = false when no S3 accounts."""
        result = _build_rcp_terraform_module(
            module_name="rcps_test",
            target_id_reference="local.test_id",
            recommendations=[],
            comment="Test"
        )

        assert 'module "rcps_test"' in result
        assert "s3_third_party_access_account_ids_allowlist" not in result
        assert "deny_s3_third_party_access = false" in result

    def test_build_module_with_ecr_recommendations(self) -> None:
        """Should generate module with ECR recommendations."""
        ecr_rec = RCPPlacementRecommendations(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["333333333333", "444444444444"],
            reasoning="Test ECR access"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_test",
            target_id_reference="local.test_id",
            recommendations=[ecr_rec],
            comment="Test"
        )

        assert "ecr_third_party_access_account_ids_allowlist" in result
        assert '"333333333333"' in result
        assert '"444444444444"' in result
        assert "deny_ecr_third_party_access = true" in result
        assert "deny_sts_third_party_assumerole = false" in result

    def test_build_module_with_kms_recommendations(self) -> None:
        """Should generate module with KMS recommendations."""
        kms_rec = RCPPlacementRecommendations(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["000011113333"],
            reasoning="Test KMS access"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_test",
            target_id_reference="local.test_id",
            recommendations=[kms_rec],
            comment="Test"
        )

        assert "kms_third_party_access_account_ids_allowlist" in result
        assert '"000011113333"' in result
        assert "deny_kms_third_party_access = true" in result
        assert "deny_sts_third_party_assumerole = false" in result

    def test_build_module_with_secrets_manager_recommendations(self) -> None:
        """Should generate module with Secrets Manager recommendations."""
        secrets_manager_rec = RCPPlacementRecommendations(
            check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["000011112222"],
            reasoning="Test Secrets Manager access"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_test",
            target_id_reference="local.test_id",
            recommendations=[secrets_manager_rec],
            comment="Test"
        )

        assert "secrets_manager_third_party_account_ids_allowlist" in result
        assert '"000011112222"' in result
        assert "deny_secrets_manager_third_party_access = true" in result

    def test_build_module_with_both_ecr_and_iam(self) -> None:
        """Should generate module with both ECR and IAM RCP recommendations."""
        ecr_rec = RCPPlacementRecommendations(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["333333333333"],
            reasoning="Test ECR access"
        )
        iam_rec = RCPPlacementRecommendations(
            check_name=DENY_STS_THIRD_PARTY_ASSUMEROLE,
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["999999999999"],
            reasoning="Test IAM access"
        )
        result = _build_rcp_terraform_module(
            module_name="rcps_test",
            target_id_reference="local.test_id",
            recommendations=[ecr_rec, iam_rec],
            comment="Test"
        )

        assert "ecr_third_party_access_account_ids_allowlist" in result
        assert '"333333333333"' in result
        assert "deny_ecr_third_party_access = true" in result
        assert "sts_third_party_assumerole_account_ids_allowlist" in result
        assert '"999999999999"' in result
        assert "deny_sts_third_party_assumerole = true" in result

    def test_confused_deputy_recommendation_renders_both_variables(self) -> None:
        """
        A confused deputy recommendation must reach the module call.

        A check whose variables never render is collected on every run and
        then dropped, which surfaces as a Terraform plan failure rather
        than here.
        """
        recommendation = RCPPlacementRecommendations(
            check_name="deny_service_confused_deputy",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=["111111111111"],
            third_party_account_ids=["999999999999"],
            reasoning="test",
        )

        rendered = _build_rcp_terraform_module(
            "rcps_root", "local.root_ou_id", [recommendation], "Organization Root"
        )

        assert "deny_service_confused_deputy" in rendered
        assert "service_confused_deputy_source_account_ids_allowlist" in rendered
        assert "999999999999" in rendered
        # The enable flag must render true, not merely appear. Alignment
        # padding varies, so collapse runs of spaces before matching.
        collapsed = re.sub(r"[ \t]+", " ", rendered)
        assert "deny_service_confused_deputy = true" in collapsed


class TestRenderAccountRcpTerraform:
    """Test _render_account_rcp_terraform helper function."""

    @pytest.fixture
    def sample_org(self) -> OrganizationHierarchy:
        """Create sample organization for testing."""
        return OrganizationHierarchy(
            root_id="r-root",
            organizational_units={},
            accounts={
                "000000000000": AccountOrgPlacement(
                    account_id="000000000000",
                    account_name="Test Account",
                    parent_ou_id="ou-test",
                    ou_path=["r-root", "ou-test"]
                )
            }
        )

    @pytest.fixture
    def sample_rcp_rec(self) -> RCPPlacementRecommendations:
        """Create sample RCP recommendation."""
        return RCPPlacementRecommendations(
            check_name="deny_sts_third_party_assumerole",
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["999999999999", "888888888888"],
            reasoning="Test recommendation"
        )

    def test_names_the_file_for_the_account(
        self,
        sample_org: OrganizationHierarchy,
        sample_rcp_rec: RCPPlacementRecommendations
    ) -> None:
        """Should render Terraform content under the account's filename."""
        output_path = Path("/nonexistent")

        filepath, content = _render_account_rcp_terraform(
            "000000000000", [sample_rcp_rec], sample_org, output_path
        )

        # Rendering touches no filesystem, so a directory that does not exist is fine.
        assert filepath == output_path / "test_account_rcps.tf"
        assert "rcps_test_account" in content
        assert "local.test_account_account_id" in content
        assert '"999999999999"' in content
        assert '"888888888888"' in content

    def test_rejects_a_folded_name_collision(
        self,
        sample_rcp_rec: RCPPlacementRecommendations
    ) -> None:
        """
        Two account names that fold alike abort rather than overwrite.

        RCPs carry the same collision as SCPs: the plan is keyed on the path,
        so the second account's file replaces the first's during plan
        construction. Only one of the two is being rendered, because the
        account it collides with need not be one this run generates for.
        """
        org = OrganizationHierarchy(
            root_id="r-root",
            organizational_units={},
            accounts={
                "000000000000": AccountOrgPlacement(
                    account_id="000000000000",
                    account_name="Prod-US",
                    parent_ou_id="ou-test",
                    ou_path=["r-root", "ou-test"]
                ),
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="Prod US",
                    parent_ou_id="ou-test",
                    ou_path=["r-root", "ou-test"]
                ),
            }
        )

        with pytest.raises(RuntimeError, match="prod_us"):
            _render_account_rcp_terraform(
                "000000000000", [sample_rcp_rec], org, Path("/nonexistent")
            )

    def test_raises_error_for_missing_account(
        self,
        sample_rcp_rec: RCPPlacementRecommendations
    ) -> None:
        """Should raise RuntimeError when account not in organization hierarchy."""
        empty_org = OrganizationHierarchy(root_id="r-root", organizational_units={}, accounts={})

        with pytest.raises(RuntimeError, match="Account \\(999999999999\\) not found in organization hierarchy"):
            _render_account_rcp_terraform(
                "999999999999", [sample_rcp_rec], empty_org, Path("/nonexistent")
            )


class TestRenderOuRcpTerraform:
    """Test _render_ou_rcp_terraform helper function."""

    @pytest.fixture
    def sample_org(self) -> OrganizationHierarchy:
        """Create sample organization for testing."""
        return OrganizationHierarchy(
            root_id="r-root",
            organizational_units={
                "ou-12345": OrganizationalUnit(
                    ou_id="ou-12345",
                    name="Test OU",
                    parent_ou_id="r-root",
                    child_ous=[],
                    accounts=["000000000000"]
                )
            },
            accounts={
                "000000000000": AccountOrgPlacement(
                    account_id="000000000000",
                    account_name="Test Account",
                    parent_ou_id="ou-12345",
                    ou_path=["r-root", "ou-12345"]
                )
            }
        )

    @pytest.fixture
    def sample_ou_rec(self) -> RCPPlacementRecommendations:
        """Create sample OU-level RCP recommendation."""
        return RCPPlacementRecommendations(
            check_name="deny_sts_third_party_assumerole",
            recommended_level="ou",
            target_ou_id="ou-12345",
            affected_accounts=["000000000000"],
            third_party_account_ids=["999999999999"],
            reasoning="Test OU recommendation"
        )

    def test_names_the_file_for_the_ou(
        self,
        sample_org: OrganizationHierarchy,
        sample_ou_rec: RCPPlacementRecommendations
    ) -> None:
        """Should render Terraform content under the OU's filename."""
        output_path = Path("/nonexistent")

        filepath, content = _render_ou_rcp_terraform(
            "ou-12345", [sample_ou_rec], sample_org, output_path
        )

        assert filepath == output_path / "test_ou_ou_rcps.tf"
        assert "rcps_test_ou_ou" in content
        assert "local.test_ou_ou_id" in content
        assert '"999999999999"' in content

    def test_raises_error_for_missing_ou(
        self,
        sample_ou_rec: RCPPlacementRecommendations
    ) -> None:
        """Should raise RuntimeError when OU not in organization hierarchy."""
        empty_org = OrganizationHierarchy(root_id="r-root", organizational_units={}, accounts={})

        with pytest.raises(RuntimeError, match="OU ou-unknown not found in organization hierarchy"):
            _render_ou_rcp_terraform(
                "ou-unknown", [sample_ou_rec], empty_org, Path("/nonexistent")
            )


class TestRenderRootRcpTerraform:
    """Test _render_root_rcp_terraform helper function."""

    @pytest.fixture
    def sample_root_rec(self) -> RCPPlacementRecommendations:
        """Create sample root-level RCP recommendation."""
        return RCPPlacementRecommendations(
            check_name="deny_sts_third_party_assumerole",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=["000000000000", "000011114444"],
            third_party_account_ids=["999999999999", "888888888888"],
            reasoning="Test root recommendation"
        )

    def test_names_the_file_for_the_root(
        self,
        sample_root_rec: RCPPlacementRecommendations
    ) -> None:
        """Should render Terraform content under root_rcps.tf."""
        output_path = Path("/nonexistent")

        filepath, content = _render_root_rcp_terraform([sample_root_rec], output_path)

        assert filepath == output_path / "root_rcps.tf"
        assert "rcps_root" in content
        assert "local.root_ou_id" in content
        assert '"999999999999"' in content
        assert '"888888888888"' in content
        assert "Organization Root" in content

    def test_build_module_with_sqs_third_party_accounts(self) -> None:
        """Test building Terraform module with SQS third-party accounts."""
        sqs_rec = RCPPlacementRecommendations(
            check_name="deny_sqs_third_party_access",
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=["000000000000"],
            third_party_account_ids=["444444444444", "555555555555"],
            reasoning="Test SQS"
        )
        terraform = _build_rcp_terraform_module(
            module_name="test_module",
            target_id_reference="local.account_id",
            recommendations=[sqs_rec],
            comment="Test Account"
        )

        assert "test_module" in terraform
        assert "local.account_id" in terraform
        assert "444444444444" in terraform
        assert "555555555555" in terraform
        assert "deny_sqs_third_party_access = true" in terraform
        assert "sqs_third_party_access_account_ids_allowlist" in terraform

    def test_plan_omits_root_when_nothing_is_placed_there(self, tmp_path: Path) -> None:
        """
        No root recommendation means no root file in the plan.

        Reconciliation deletes what the plan omits, so this is what removes a
        root_rcps.tf left behind by a run that did place a policy there.
        """
        org = OrganizationHierarchy(root_id="r-root", organizational_units={}, accounts={})

        plan = generate_rcp_terraform([], org, str(tmp_path))

        assert plan == {}
        assert not (tmp_path / "root_rcps.tf").exists()


class TestEveryRcpCheckReachesTerraform:
    """Test that every registered RCP check flows through to Terraform."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def temp_output_dir(self) -> Generator[str, None, None]:
        """Create temporary Terraform output directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def single_account_hierarchy(self) -> OrganizationHierarchy:
        """Create a one-account, one-OU organization hierarchy."""
        return OrganizationHierarchy(
            root_id="r-1234",
            organizational_units={
                "ou-1111": OrganizationalUnit(
                    ou_id="ou-1111",
                    name="Production",
                    parent_ou_id="r-1234",
                    child_ous=[],
                    accounts=["111111111111"]
                )
            },
            accounts={
                "111111111111": AccountOrgPlacement(
                    account_id="111111111111",
                    account_name="test-account",
                    parent_ou_id="ou-1111",
                    ou_path=["Production"]
                )
            }
        )

    def test_every_registered_check_is_enabled_in_generated_terraform(
        self,
        temp_results_dir: str,
        temp_output_dir: str,
        single_account_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        Results for every RCP check must reach the generated Terraform.

        Drives the real pipeline rather than hand-building recommendations,
        because the defect this guards against lived between parsing and
        rendering while both ends worked.
        """
        for check_name in get_check_names("rcps"):
            write_rcp_result(
                temp_results_dir,
                check_name,
                account_id="111111111111",
                account_name="test-account",
                third_party_account_ids=["999999999999"],
            )

        parse_results = parse_rcp_result_files(temp_results_dir, single_account_hierarchy)
        recommendations = determine_rcp_placement(parse_results, single_account_hierarchy)
        generate_rcp_terraform(recommendations, single_account_hierarchy, temp_output_dir)

        content = (Path(temp_output_dir) / "root_rcps.tf").read_text()

        for tf_vars in RCP_TERRAFORM_VARIABLES.values():
            assert f"{tf_vars.enable_var} = true" in content
            assert tf_vars.allowlist_var in content
        assert '"999999999999"' in content

    def test_parse_returns_one_result_per_registered_check(
        self,
        temp_results_dir: str,
        single_account_hierarchy: OrganizationHierarchy
    ) -> None:
        """Parsing must yield an entry for every registered RCP check."""
        seed_all_rcp_check_dirs(temp_results_dir)

        parse_results = parse_rcp_result_files(temp_results_dir, single_account_hierarchy)

        assert [r.check_name for r in parse_results] == sorted(get_check_names("rcps"))

    def test_account_with_no_third_parties_is_locked_down(
        self,
        temp_results_dir: str,
        temp_output_dir: str,
        single_account_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        An account with results but no third parties must be enforced.

        An empty allowlist means deny all third-party access to the service.
        It must not collapse into the absent-recommendation case, which
        renders the flag false and enforces nothing.
        """
        seed_all_rcp_check_dirs(temp_results_dir)
        write_rcp_result(
            temp_results_dir,
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_id="111111111111",
            account_name="test-account",
            third_party_account_ids=[],
        )

        parse_results = parse_rcp_result_files(temp_results_dir, single_account_hierarchy)
        recommendations = determine_rcp_placement(parse_results, single_account_hierarchy)
        generate_rcp_terraform(recommendations, single_account_hierarchy, temp_output_dir)

        content = (Path(temp_output_dir) / "root_rcps.tf").read_text()

        assert "deny_sts_third_party_assumerole = true" in content
        assert "sts_third_party_assumerole_account_ids_allowlist = []" in content

    def test_check_with_no_results_is_not_enabled(
        self,
        temp_results_dir: str,
        temp_output_dir: str,
        single_account_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        A check whose directory holds no findings must render as disabled.

        This is the case that must stay distinguishable from an unwired
        check, which is why an absent directory aborts instead.
        """
        seed_all_rcp_check_dirs(temp_results_dir)
        write_rcp_result(
            temp_results_dir,
            DENY_STS_THIRD_PARTY_ASSUMEROLE,
            account_id="111111111111",
            account_name="test-account",
            third_party_account_ids=["999999999999"],
        )

        parse_results = parse_rcp_result_files(temp_results_dir, single_account_hierarchy)
        recommendations = determine_rcp_placement(parse_results, single_account_hierarchy)
        generate_rcp_terraform(recommendations, single_account_hierarchy, temp_output_dir)

        content = (Path(temp_output_dir) / "root_rcps.tf").read_text()

        assert "deny_sts_third_party_assumerole = true" in content
        assert "deny_s3_third_party_access = false" in content
