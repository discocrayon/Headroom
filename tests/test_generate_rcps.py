"""
Tests for headroom.terraform.generate_rcps module.

Tests for RCP Terraform generation functions.
"""

import json
import tempfile
import shutil
import pytest
from pathlib import Path
from typing import Dict, List, Set, Generator
from headroom.terraform.generate_rcps import (
    parse_rcp_result_files,
    determine_rcp_placement,
    generate_rcp_terraform,
    _check_root_level_placement
)
from headroom.types import (
    OrganizationHierarchy,
    OrganizationalUnit,
    AccountOrgPlacement,
    RCPPlacementRecommendations
)


class TestParseRcpResultFiles:
    """Test parse_rcp_result_files function."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_parse_single_account(self, temp_results_dir: str) -> None:
        """Test parsing results from a single account."""
        check_dir = Path(temp_results_dir) / "third_party_role_access"
        check_dir.mkdir(parents=True)

        result_data = {
            "summary": {
                "account_id": "111111111111",
                "account_name": "test-account",
                "unique_third_party_accounts": ["999999999999", "888888888888"],
                "roles_with_wildcards": 0
            }
        }

        result_file = check_dir / "test-account.json"
        with open(result_file, 'w') as f:
            json.dump(result_data, f)

        result = parse_rcp_result_files(temp_results_dir)

        assert len(result.account_third_party_map) == 1
        assert "111111111111" in result.account_third_party_map
        assert result.account_third_party_map["111111111111"] == {"999999999999", "888888888888"}
        assert len(result.accounts_with_wildcards) == 0

    def test_parse_multiple_accounts(self, temp_results_dir: str) -> None:
        """Test parsing results from multiple accounts."""
        check_dir = Path(temp_results_dir) / "third_party_role_access"
        check_dir.mkdir(parents=True)

        result_data_1 = {
            "summary": {
                "account_id": "111111111111",
                "unique_third_party_accounts": ["999999999999"],
                "roles_with_wildcards": 0
            }
        }

        result_data_2 = {
            "summary": {
                "account_id": "222222222222",
                "unique_third_party_accounts": ["888888888888", "777777777777"],
                "roles_with_wildcards": 0
            }
        }

        with open(check_dir / "account1.json", 'w') as f:
            json.dump(result_data_1, f)

        with open(check_dir / "account2.json", 'w') as f:
            json.dump(result_data_2, f)

        result = parse_rcp_result_files(temp_results_dir)

        assert len(result.account_third_party_map) == 2
        assert result.account_third_party_map["111111111111"] == {"999999999999"}
        assert result.account_third_party_map["222222222222"] == {"888888888888", "777777777777"}
        assert len(result.accounts_with_wildcards) == 0

    def test_parse_nonexistent_directory(self) -> None:
        """Test parsing when directory doesn't exist."""
        result = parse_rcp_result_files("/nonexistent/path")
        assert result.account_third_party_map == {}
        assert result.accounts_with_wildcards == set()

    def test_parse_empty_directory(self, temp_results_dir: str) -> None:
        """Test parsing empty directory."""
        check_dir = Path(temp_results_dir) / "third_party_role_access"
        check_dir.mkdir(parents=True)

        result = parse_rcp_result_files(temp_results_dir)
        assert result.account_third_party_map == {}
        assert result.accounts_with_wildcards == set()

    def test_parse_invalid_json(self, temp_results_dir: str) -> None:
        """Test parsing with invalid JSON file."""
        check_dir = Path(temp_results_dir) / "third_party_role_access"
        check_dir.mkdir(parents=True)

        # Create invalid JSON file
        result_file = check_dir / "invalid.json"
        with open(result_file, 'w') as f:
            f.write("{invalid json")

        # Create valid JSON file
        valid_data = {
            "summary": {
                "account_id": "111111111111",
                "account_name": "test-account",
                "unique_third_party_accounts": ["999999999999"],
                "roles_with_wildcards": 0
            }
        }
        valid_file = check_dir / "valid.json"
        with open(valid_file, 'w') as f:
            json.dump(valid_data, f)

        # Should skip invalid file but parse valid one
        result = parse_rcp_result_files(temp_results_dir)
        assert len(result.account_third_party_map) == 1
        assert result.account_third_party_map["111111111111"] == {"999999999999"}
        assert len(result.accounts_with_wildcards) == 0

    def test_parse_missing_summary_key(self, temp_results_dir: str) -> None:
        """Test parsing with file missing required summary key."""
        check_dir = Path(temp_results_dir) / "third_party_role_access"
        check_dir.mkdir(parents=True)

        # Create file with missing summary key
        result_data = {
            "some_other_key": "value"
        }
        result_file = check_dir / "bad.json"
        with open(result_file, 'w') as f:
            json.dump(result_data, f)

        # Create valid file
        valid_data = {
            "summary": {
                "account_id": "111111111111",
                "account_name": "test-account",
                "unique_third_party_accounts": ["999999999999"],
                "roles_with_wildcards": 0
            }
        }
        valid_file = check_dir / "valid.json"
        with open(valid_file, 'w') as f:
            json.dump(valid_data, f)

        # Should skip bad file but parse valid one
        result = parse_rcp_result_files(temp_results_dir)
        assert len(result.account_third_party_map) == 1
        assert result.account_third_party_map["111111111111"] == {"999999999999"}
        assert len(result.accounts_with_wildcards) == 0

    def test_parse_skips_accounts_with_wildcards(self, temp_results_dir: str) -> None:
        """Test that accounts with wildcard principals are skipped."""
        check_dir = Path(temp_results_dir) / "third_party_role_access"
        check_dir.mkdir(parents=True)

        # Account with wildcard - should be skipped
        result_data_with_wildcard = {
            "summary": {
                "account_id": "111111111111",
                "unique_third_party_accounts": ["999999999999"],
                "roles_with_wildcards": 2
            }
        }

        # Account without wildcard - should be included
        result_data_without_wildcard = {
            "summary": {
                "account_id": "222222222222",
                "unique_third_party_accounts": ["888888888888"],
                "roles_with_wildcards": 0
            }
        }

        with open(check_dir / "account1.json", 'w') as f:
            json.dump(result_data_with_wildcard, f)

        with open(check_dir / "account2.json", 'w') as f:
            json.dump(result_data_without_wildcard, f)

        result = parse_rcp_result_files(temp_results_dir)

        # Only account without wildcard should be included in map
        assert len(result.account_third_party_map) == 1
        assert "222222222222" in result.account_third_party_map
        assert "111111111111" not in result.account_third_party_map
        assert result.account_third_party_map["222222222222"] == {"888888888888"}

        # Account with wildcard should be in wildcard set
        assert len(result.accounts_with_wildcards) == 1
        assert "111111111111" in result.accounts_with_wildcards


class TestCheckRootLevelPlacement:
    """Test _check_root_level_placement helper function."""

    def test_returns_none_when_account_map_is_empty(self) -> None:
        """Test that None is returned when no accounts are provided."""
        result = _check_root_level_placement({})
        assert result is None


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
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999"},
            "222222222222": {"999999999999"},
            "333333333333": {"999999999999"}
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards)

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert recommendations[0].target_ou_id is None
        assert set(recommendations[0].affected_accounts) == {"111111111111", "222222222222", "333333333333"}
        assert recommendations[0].third_party_account_ids == ["999999999999"]

    def test_recommends_ou_level_when_ou_accounts_have_identical_third_party_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test OU level placement when accounts in OU have same third-party accounts."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999", "888888888888"},
            "222222222222": {"999999999999", "888888888888"},
            "333333333333": {"777777777777"}
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=False)

        assert len(recommendations) == 2

        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        account_recs = [r for r in recommendations if r.recommended_level == "account"]

        assert len(ou_recs) == 1
        assert ou_recs[0].target_ou_id == "ou-1111"
        assert set(ou_recs[0].affected_accounts) == {"111111111111", "222222222222"}
        assert set(ou_recs[0].third_party_account_ids) == {"888888888888", "999999999999"}

        assert len(account_recs) == 1
        assert account_recs[0].affected_accounts == ["333333333333"]
        assert account_recs[0].third_party_account_ids == ["777777777777"]

    def test_recommends_account_level_when_each_account_has_unique_third_party_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test account level placement when each account has unique third-party accounts."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"},
            "333333333333": {"777777777777"}
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=False)

        assert len(recommendations) == 3
        assert all(r.recommended_level == "account" for r in recommendations)

        account_ids = [r.affected_accounts[0] for r in recommendations]
        assert set(account_ids) == {"111111111111", "222222222222", "333333333333"}

    def test_returns_empty_list_when_no_third_party_accounts_found(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test with no third-party accounts."""
        account_third_party_map: Dict[str, Set[str]] = {}
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards)

        assert len(recommendations) == 0

    def test_skips_ou_level_recommendation_when_any_account_in_ou_has_wildcards(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that OU-level RCP is skipped when any account in OU has wildcards."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999"},
            # 222222222222 has wildcards, not in map
            "333333333333": {"777777777777"}
        }
        accounts_with_wildcards: Set[str] = {"222222222222"}

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=False)

        # Should only get account-level recommendations, no OU-level for ou-1111
        assert len(recommendations) == 2
        assert all(r.recommended_level == "account" for r in recommendations)

        account_ids = [r.affected_accounts[0] for r in recommendations]
        assert set(account_ids) == {"111111111111", "333333333333"}

    def test_skips_accounts_not_in_hierarchy_when_building_ou_mappings(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that accounts not in the hierarchy are skipped when building OU mappings."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999"},
            "222222222222": {"999999999999"},
            "999999999999": {"888888888888"}
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=False)

        # Account 111111111111 and 222222222222 should get OU-level RCP
        # Account 999999999999 should get account-level (not in hierarchy, can't be part of OU)
        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        account_recs = [r for r in recommendations if r.recommended_level == "account"]

        assert len(ou_recs) == 1
        assert set(ou_recs[0].affected_accounts) == {"111111111111", "222222222222"}

        assert len(account_recs) == 1
        assert account_recs[0].affected_accounts == ["999999999999"]

    def test_rcp_always_root_aggregates_all_third_party_accounts(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test rcp_always_root=True aggregates all third-party accounts at root level."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999", "888888888888"},
            "222222222222": {"999999999999", "777777777777"},
            "333333333333": {"666666666666"}
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=True)

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert recommendations[0].target_ou_id is None
        assert set(recommendations[0].affected_accounts) == {"111111111111", "222222222222", "333333333333"}
        assert set(recommendations[0].third_party_account_ids) == {"666666666666", "777777777777", "888888888888", "999999999999"}
        assert "Aggregated all third-party accounts" in recommendations[0].reasoning

    def test_rcp_always_root_with_default_parameter(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that rcp_always_root defaults to True when not specified."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"}
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards)

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert set(recommendations[0].third_party_account_ids) == {"888888888888", "999999999999"}

    def test_rcp_always_root_false_with_identical_accounts_uses_natural_root(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test rcp_always_root=False with identical accounts naturally recommends root."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999"},
            "222222222222": {"999999999999"},
            "333333333333": {"999999999999"}
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=False)

        assert len(recommendations) == 1
        assert recommendations[0].recommended_level == "root"
        assert recommendations[0].third_party_account_ids == ["999999999999"]
        assert "All 3 accounts have identical" in recommendations[0].reasoning

    def test_rcp_always_root_with_empty_third_party_sets(
        self,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test rcp_always_root=True with accounts that have empty third-party sets."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": set(),
            "222222222222": set()
        }
        accounts_with_wildcards: Set[str] = set()

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=True)

        assert len(recommendations) == 0

    def test_rcp_always_root_fails_fast_when_wildcards_present(
        self,
        sample_org_hierarchy: OrganizationHierarchy,
        caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test rcp_always_root=True returns empty list when any account has wildcards."""
        account_third_party_map: Dict[str, Set[str]] = {
            "111111111111": {"999999999999"},
            "222222222222": {"888888888888"}
        }
        accounts_with_wildcards: Set[str] = {"333333333333", "444444444444"}

        recommendations = determine_rcp_placement(account_third_party_map, sample_org_hierarchy, accounts_with_wildcards, rcp_always_root=True)

        assert len(recommendations) == 0
        assert "Cannot deploy RCP at root level" in caplog.text
        assert "2 account(s) have wildcard principals" in caplog.text
        assert "333333333333" in caplog.text
        assert "444444444444" in caplog.text


class TestGenerateRcpTerraform:
    """Test generate_rcp_terraform function."""

    @pytest.fixture
    def temp_output_dir(self) -> Generator[str, None, None]:
        """Create temporary output directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

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
                check_name="third_party_role_access",
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
        assert "enforce_assume_role_org_identities = true" in content

    def test_generate_ou_level_terraform(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test generating OU level RCP Terraform."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="third_party_role_access",
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
        assert "local.top_level_production_ou_id" in content
        assert "999999999999" in content
        assert "enforce_assume_role_org_identities = true" in content

    def test_generate_account_level_terraform(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test generating account level RCP Terraform."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="third_party_role_access",
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
        assert "enforce_assume_role_org_identities = true" in content

    def test_generate_skips_missing_ou(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that missing OU in hierarchy is skipped with warning."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="third_party_role_access",
                recommended_level="ou",
                target_ou_id="ou-9999",
                affected_accounts=["111111111111"],
                third_party_account_ids=["999999999999"],
                reasoning="Test OU not found"
            )
        ]

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        # No file should be created for missing OU
        assert not any(Path(temp_output_dir).glob("*_ou_rcps.tf"))

    def test_generate_skips_missing_account(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test that missing account in hierarchy is skipped with warning."""
        recommendations = [
            RCPPlacementRecommendations(
                check_name="third_party_role_access",
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=["999999999999"],
                third_party_account_ids=["888888888888"],
                reasoning="Test account not found"
            )
        ]

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        # No file should be created for missing account
        assert not any(Path(temp_output_dir).glob("*_rcps.tf"))

    def test_generate_no_recommendations(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """Test generating with no recommendations."""
        recommendations: List[RCPPlacementRecommendations] = []

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        output_path = Path(temp_output_dir)
        assert len(list(output_path.glob("*.tf"))) == 0

    def test_generate_with_wildcard_disables_enforcement(
        self,
        temp_output_dir: str,
        sample_org_hierarchy: OrganizationHierarchy
    ) -> None:
        """
        Test that wildcard in third_party_account_ids sets enforce_assume_role_org_identities to false.

        When a wildcard is present, it means trusting all account IDs which could cause
        outages if the RCP is deployed, so enforcement should be disabled.
        The third_party_assumerole_account_ids parameter should not be passed when enforcement is false.
        """
        recommendations = [
            RCPPlacementRecommendations(
                check_name="third_party_role_access",
                recommended_level="root",
                target_ou_id=None,
                affected_accounts=["111111111111"],
                third_party_account_ids=["*"],
                reasoning="Test wildcard detection"
            )
        ]

        generate_rcp_terraform(recommendations, sample_org_hierarchy, temp_output_dir)

        root_file = Path(temp_output_dir) / "root_rcps.tf"
        assert root_file.exists()

        content = root_file.read_text()
        assert "enforce_assume_role_org_identities = false" in content
        assert "third_party_assumerole_account_ids" not in content
