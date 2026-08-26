"""
Tests for organizations whose OUs nest more than one level below the root.

A policy attached to an OU governs every account beneath it, including
accounts inside child OUs. Headroom used to reason one level at a time: an
OU's safety and its allowlist were computed from the accounts whose immediate
parent was that OU, and only OUs directly under the root got an ID local in
grab_org_info.tf. A three-level organization therefore produced a policy that
was declared safe for accounts it never examined, and Terraform that referred
to locals nobody declared.

These tests pin the subtree as the unit of reasoning, at every depth.
"""

import re
from pathlib import Path
from typing import Dict, List, Set

import pytest

from headroom.parse_results import determine_scp_placement
from headroom.placement.hierarchy import (
    HierarchyPlacementAnalyzer,
    accounts_under_ou,
    ou_subtree_ids,
)
from headroom.terraform.generate_org_info import _generate_terraform_content
from headroom.terraform.generate_rcps import (
    _should_skip_ou_for_rcp,
    generate_rcp_terraform,
)
from headroom.terraform.generate_scps import generate_scp_terraform
from headroom.terraform.utils import make_ou_base_names, ou_id_local_name
from headroom.types import (
    AccountOrgPlacement,
    RCPPlacementRecommendations,
    OrganizationHierarchy,
    OrganizationalUnit,
    SCPCheckResult,
)

ROOT_ID = "r-fake"
PRODUCTION_OU = "ou-fake-production"
PAYMENTS_OU = "ou-fake-payments"
LEDGER_OU = "ou-fake-ledger"
PROD_APP_ACCOUNT = "111111111111"
PAYMENTS_ACCOUNT = "222222222222"
LEDGER_ACCOUNT = "333333333333"


def make_nested_hierarchy() -> OrganizationHierarchy:
    """
    Build a three-level organization.

    Root
      Production ................ prod-app
        Payments ................ payments-core
          Ledger ................ ledger-core
    """
    return OrganizationHierarchy(
        root_id=ROOT_ID,
        organizational_units={
            PRODUCTION_OU: OrganizationalUnit(
                ou_id=PRODUCTION_OU,
                name="Production",
                parent_ou_id=None,
                child_ous=[PAYMENTS_OU],
                accounts=[PROD_APP_ACCOUNT],
            ),
            PAYMENTS_OU: OrganizationalUnit(
                ou_id=PAYMENTS_OU,
                name="Payments",
                parent_ou_id=PRODUCTION_OU,
                child_ous=[LEDGER_OU],
                accounts=[PAYMENTS_ACCOUNT],
            ),
            LEDGER_OU: OrganizationalUnit(
                ou_id=LEDGER_OU,
                name="Ledger",
                parent_ou_id=PAYMENTS_OU,
                child_ous=[],
                accounts=[LEDGER_ACCOUNT],
            ),
        },
        accounts={
            PROD_APP_ACCOUNT: AccountOrgPlacement(
                account_id=PROD_APP_ACCOUNT,
                account_name="prod-app",
                parent_ou_id=PRODUCTION_OU,
                ou_path=["Production"],
            ),
            PAYMENTS_ACCOUNT: AccountOrgPlacement(
                account_id=PAYMENTS_ACCOUNT,
                account_name="payments-core",
                parent_ou_id=PAYMENTS_OU,
                ou_path=["Production", "Payments"],
            ),
            LEDGER_ACCOUNT: AccountOrgPlacement(
                account_id=LEDGER_ACCOUNT,
                account_name="ledger-core",
                parent_ou_id=LEDGER_OU,
                ou_path=["Production", "Payments", "Ledger"],
            ),
        },
    )


def make_scp_result(
    account_id: str,
    account_name: str,
    violations: int
) -> SCPCheckResult:
    """Build one SCP check result with the given violation count."""
    return SCPCheckResult(
        account_id=account_id,
        account_name=account_name,
        check_name="deny_iam_user_creation",
        violations=violations,
        exemptions=0,
        compliant=1,
        compliance_percentage=0.0 if violations else 100.0,
    )


class TestSubtreeHelpers:
    """Tests for ou_subtree_ids() and accounts_under_ou()."""

    def test_subtree_includes_the_ou_itself_and_every_descendant(self) -> None:
        """An OU's subtree starts at the OU and reaches the deepest child."""
        ous = make_nested_hierarchy().organizational_units

        assert ou_subtree_ids(PRODUCTION_OU, ous) == [
            PRODUCTION_OU, PAYMENTS_OU, LEDGER_OU
        ]

    def test_subtree_of_a_leaf_ou_is_just_that_ou(self) -> None:
        """A childless OU governs only itself."""
        ous = make_nested_hierarchy().organizational_units

        assert ou_subtree_ids(LEDGER_OU, ous) == [LEDGER_OU]

    def test_subtree_of_an_unknown_ou_is_just_that_ou(self) -> None:
        """An OU absent from the hierarchy contributes no children."""
        assert ou_subtree_ids("ou-fake-absent", {}) == ["ou-fake-absent"]

    def test_subtree_skips_child_ous_missing_from_the_hierarchy(self) -> None:
        """A child_ous entry naming no known OU is not invented as a member."""
        ous = {
            PRODUCTION_OU: OrganizationalUnit(
                ou_id=PRODUCTION_OU,
                name="Production",
                parent_ou_id=None,
                child_ous=["ou-fake-vanished"],
                accounts=[],
            ),
        }

        assert ou_subtree_ids(PRODUCTION_OU, ous) == [PRODUCTION_OU]

    def test_subtree_raises_on_a_cycle(self) -> None:
        """A hierarchy that loops is reported, not walked forever."""
        ous = {
            PRODUCTION_OU: OrganizationalUnit(
                ou_id=PRODUCTION_OU, name="Production", parent_ou_id=None,
                child_ous=[PAYMENTS_OU], accounts=[],
            ),
            PAYMENTS_OU: OrganizationalUnit(
                ou_id=PAYMENTS_OU, name="Payments", parent_ou_id=PRODUCTION_OU,
                child_ous=[PRODUCTION_OU], accounts=[],
            ),
        }

        with pytest.raises(RuntimeError, match="cycle"):
            ou_subtree_ids(PRODUCTION_OU, ous)

    def test_accounts_under_ou_reaches_accounts_in_child_ous(self) -> None:
        """The top-level OU owns every account below it, at any depth."""
        org = make_nested_hierarchy()

        assert accounts_under_ou(PRODUCTION_OU, org) == {
            PROD_APP_ACCOUNT, PAYMENTS_ACCOUNT, LEDGER_ACCOUNT
        }

    def test_accounts_under_ou_excludes_accounts_above_it(self) -> None:
        """A child OU does not own its parent's accounts."""
        org = make_nested_hierarchy()

        assert accounts_under_ou(PAYMENTS_OU, org) == {
            PAYMENTS_ACCOUNT, LEDGER_ACCOUNT
        }


class TestSubtreeAwarePlacement:
    """
    Tests that OU placement judges the whole subtree.

    Attaching a policy to an OU attaches it to every account beneath that OU.
    Judging safety on the immediate children alone declared a parent policy
    safe while descendants it would govern were never consulted.
    """

    def test_violation_in_a_descendant_blocks_the_ancestor_ou(self) -> None:
        """An unsafe grandchild account keeps the policy off the top-level OU."""
        org = make_nested_hierarchy()
        analyzer: HierarchyPlacementAnalyzer[str] = HierarchyPlacementAnalyzer(org)
        unsafe = {LEDGER_ACCOUNT}

        candidates = analyzer.determine_placement(
            check_results=[PROD_APP_ACCOUNT, PAYMENTS_ACCOUNT, LEDGER_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: not any(r in unsafe for r in results),
            get_account_id=lambda r: r,
        )

        ou_targets = [c.target_id for c in candidates if c.level == "ou"]
        assert PRODUCTION_OU not in ou_targets
        assert PAYMENTS_OU not in ou_targets

    def test_safe_ou_covers_every_account_in_its_subtree(self) -> None:
        """One candidate at the top-level OU claims the nested accounts too."""
        org = make_nested_hierarchy()
        analyzer: HierarchyPlacementAnalyzer[str] = HierarchyPlacementAnalyzer(org)

        candidates = analyzer.determine_placement(
            check_results=[PROD_APP_ACCOUNT, PAYMENTS_ACCOUNT, LEDGER_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: True,
            get_account_id=lambda r: r,
        )

        assert len(candidates) == 1
        assert candidates[0].target_id == PRODUCTION_OU
        assert sorted(candidates[0].affected_accounts) == [
            PROD_APP_ACCOUNT, PAYMENTS_ACCOUNT, LEDGER_ACCOUNT
        ]

    def test_descendant_ou_is_not_given_its_own_redundant_policy(self) -> None:
        """A safe ancestor already covers its children, so they are not targeted."""
        org = make_nested_hierarchy()
        analyzer: HierarchyPlacementAnalyzer[str] = HierarchyPlacementAnalyzer(org)

        candidates = analyzer.determine_placement(
            check_results=[PROD_APP_ACCOUNT, PAYMENTS_ACCOUNT, LEDGER_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: True,
            get_account_id=lambda r: r,
        )

        assert [c.target_id for c in candidates] == [PRODUCTION_OU]

    def test_falls_through_to_the_deepest_safe_ou(self) -> None:
        """An unsafe ancestor hands placement down to the safe OU beneath it."""
        org = make_nested_hierarchy()
        analyzer: HierarchyPlacementAnalyzer[str] = HierarchyPlacementAnalyzer(org)
        unsafe = {PROD_APP_ACCOUNT}

        candidates = analyzer.determine_placement(
            check_results=[PROD_APP_ACCOUNT, PAYMENTS_ACCOUNT, LEDGER_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: not any(r in unsafe for r in results),
            get_account_id=lambda r: r,
        )

        ou_candidates = [c for c in candidates if c.level == "ou"]
        assert [c.target_id for c in ou_candidates] == [PAYMENTS_OU]
        assert sorted(ou_candidates[0].affected_accounts) == [
            PAYMENTS_ACCOUNT, LEDGER_ACCOUNT
        ]

    def test_account_above_the_safe_ou_is_placed_individually(self) -> None:
        """An account left uncovered by every safe OU still gets a candidate."""
        org = make_nested_hierarchy()
        analyzer: HierarchyPlacementAnalyzer[str] = HierarchyPlacementAnalyzer(org)
        unsafe = {PROD_APP_ACCOUNT}

        candidates = analyzer.determine_placement(
            check_results=[PROD_APP_ACCOUNT, PAYMENTS_ACCOUNT, LEDGER_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: not any(r in unsafe for r in results),
            get_account_id=lambda r: r,
        )

        account_candidates = [c for c in candidates if c.level == "account"]
        assert len(account_candidates) == 1
        assert account_candidates[0].affected_accounts == [PROD_APP_ACCOUNT]


class TestNestedOuScpAllowlists:
    """
    Tests that an OU recommendation reports and allows for its whole subtree.

    The allowlist a generated SCP carries is unioned over the accounts the
    recommendation names. Naming only the immediate children left a nested
    account governed by a policy whose allowlist never saw its resources.
    """

    def test_ou_recommendation_names_accounts_in_child_ous(self) -> None:
        """affected_accounts covers the subtree, not the immediate children."""
        org = make_nested_hierarchy()

        # One violator at the top keeps the root out and forces an OU decision.
        recommendations = determine_scp_placement(
            [
                make_scp_result(PROD_APP_ACCOUNT, "prod-app", 3),
                make_scp_result(PAYMENTS_ACCOUNT, "payments-core", 0),
                make_scp_result(LEDGER_ACCOUNT, "ledger-core", 0),
            ],
            org,
        )

        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        assert len(ou_recs) == 1
        assert ou_recs[0].target_ou_id == PAYMENTS_OU
        assert sorted(ou_recs[0].affected_accounts) == [
            PAYMENTS_ACCOUNT, LEDGER_ACCOUNT
        ]

    def test_ou_allowlist_unions_iam_users_from_child_ous(self) -> None:
        """An account in a child OU contributes its IAM users to the allowlist."""
        org = make_nested_hierarchy()
        payments = make_scp_result(PAYMENTS_ACCOUNT, "payments-core", 0)
        payments.check_name = "deny_iam_user_creation"
        payments.iam_user_arns = ["arn:aws:iam::222222222222:user/payments-svc"]
        ledger = make_scp_result(LEDGER_ACCOUNT, "ledger-core", 0)
        ledger.check_name = "deny_iam_user_creation"
        ledger.iam_user_arns = ["arn:aws:iam::333333333333:user/ledger-svc"]

        recommendations = determine_scp_placement(
            [make_scp_result(PROD_APP_ACCOUNT, "prod-app", 3), payments, ledger],
            org,
        )

        ou_recs = [r for r in recommendations if r.recommended_level == "ou"]
        assert ou_recs[0].allowed_iam_user_arns == [
            "arn:aws:iam::222222222222:user/payments-svc",
            "arn:aws:iam::333333333333:user/ledger-svc",
        ]

    def test_violation_in_a_child_ou_keeps_the_scp_off_the_parent(self) -> None:
        """The reported OU is never one whose subtree holds a violation."""
        org = make_nested_hierarchy()

        recommendations = determine_scp_placement(
            [
                make_scp_result(PROD_APP_ACCOUNT, "prod-app", 0),
                make_scp_result(PAYMENTS_ACCOUNT, "payments-core", 0),
                make_scp_result(LEDGER_ACCOUNT, "ledger-core", 7),
            ],
            org,
        )

        ou_targets = [
            r.target_ou_id for r in recommendations if r.recommended_level == "ou"
        ]
        assert PRODUCTION_OU not in ou_targets
        assert PAYMENTS_OU not in ou_targets


class TestRcpBlockerInDescendant:
    """Tests that an RCP blocker anywhere in the subtree skips the OU."""

    def test_blocker_in_a_child_ou_skips_the_parent_ou(self) -> None:
        """One unallowlistable account below the OU disqualifies the whole OU."""
        org = make_nested_hierarchy()

        assert _should_skip_ou_for_rcp(PRODUCTION_OU, org, {LEDGER_ACCOUNT}) is True

    def test_blocker_outside_the_subtree_leaves_the_ou_alone(self) -> None:
        """An account the OU does not govern cannot disqualify it."""
        org = make_nested_hierarchy()

        assert _should_skip_ou_for_rcp(PAYMENTS_OU, org, {PROD_APP_ACCOUNT}) is False


class TestOuBaseNames:
    """
    Tests for make_ou_base_names().

    Two OUs may share a name under different parents, so the Terraform
    identifier for an OU is built from its path down from the root.
    """

    def test_top_level_ou_is_named_for_itself(self) -> None:
        """A depth-one OU needs no path prefix."""
        ous = make_nested_hierarchy().organizational_units

        assert make_ou_base_names(ous)[PRODUCTION_OU] == "production"

    def test_nested_ou_is_named_for_its_path(self) -> None:
        """A nested OU carries its ancestors so the name stays unique."""
        ous = make_nested_hierarchy().organizational_units
        base_names = make_ou_base_names(ous)

        assert base_names[PAYMENTS_OU] == "production_payments"
        assert base_names[LEDGER_OU] == "production_payments_ledger"

    def test_same_name_under_different_parents_stays_distinct(self) -> None:
        """Two OUs named alike in different branches get different identifiers."""
        ous = {
            "ou-fake-a": OrganizationalUnit(
                "ou-fake-a", "Alpha", None, ["ou-fake-a-shared"], []),
            "ou-fake-b": OrganizationalUnit(
                "ou-fake-b", "Beta", None, ["ou-fake-b-shared"], []),
            "ou-fake-a-shared": OrganizationalUnit(
                "ou-fake-a-shared", "Shared", "ou-fake-a", [], []),
            "ou-fake-b-shared": OrganizationalUnit(
                "ou-fake-b-shared", "Shared", "ou-fake-b", [], []),
        }

        base_names = make_ou_base_names(ous)

        assert base_names["ou-fake-a-shared"] == "alpha_shared"
        assert base_names["ou-fake-b-shared"] == "beta_shared"

    def test_ou_whose_parent_is_the_root_id_is_treated_as_top_level(self) -> None:
        """A parent naming no OU is the organization root, not a missing link."""
        ous = {
            PRODUCTION_OU: OrganizationalUnit(
                PRODUCTION_OU, "Production", ROOT_ID, [], []),
        }

        assert make_ou_base_names(ous)[PRODUCTION_OU] == "production"

    def test_colliding_names_are_reported(self) -> None:
        """Paths that canonicalize alike abort rather than overwrite each other."""
        ous = {
            "ou-fake-a": OrganizationalUnit(
                "ou-fake-a", "Alpha Beta", None, ["ou-fake-c"], []),
            "ou-fake-b": OrganizationalUnit(
                "ou-fake-b", "Alpha", None, ["ou-fake-d"], []),
            "ou-fake-c": OrganizationalUnit(
                "ou-fake-c", "Gamma", "ou-fake-a", [], []),
            "ou-fake-d": OrganizationalUnit(
                "ou-fake-d", "Beta Gamma", "ou-fake-b", [], []),
        }

        with pytest.raises(RuntimeError, match="alpha_beta_gamma"):
            make_ou_base_names(ous)

    def test_ou_named_root_is_rejected(self) -> None:
        """'root' would collide with the root_ou_id local the file already has."""
        ous = {
            PRODUCTION_OU: OrganizationalUnit(
                PRODUCTION_OU, "Root", None, [], []),
        }

        with pytest.raises(RuntimeError, match="root"):
            make_ou_base_names(ous)

    def test_ou_whose_name_canonicalizes_to_nothing_is_rejected(self) -> None:
        """A name of only separators cannot become a Terraform identifier."""
        ous = {
            PRODUCTION_OU: OrganizationalUnit(PRODUCTION_OU, "--", None, [], []),
        }

        with pytest.raises(RuntimeError, match="Terraform identifier"):
            make_ou_base_names(ous)

    def test_cycle_in_the_parent_chain_is_reported(self) -> None:
        """Walking up a looping hierarchy stops rather than spinning."""
        ous = {
            PRODUCTION_OU: OrganizationalUnit(
                PRODUCTION_OU, "Production", PAYMENTS_OU, [], []),
            PAYMENTS_OU: OrganizationalUnit(
                PAYMENTS_OU, "Payments", PRODUCTION_OU, [], []),
        }

        with pytest.raises(RuntimeError, match="cycle"):
            make_ou_base_names(ous)


class TestNestedOuOrgInfo:
    """Tests that grab_org_info.tf declares an ID local for every OU."""

    def test_nested_ou_gets_an_id_local(self) -> None:
        """The local a nested OU's policy references is actually declared."""
        content = _generate_terraform_content(make_nested_hierarchy())

        assert "production_payments_ou_id = [" in content
        assert "production_payments_ledger_ou_id = [" in content

    def test_nested_ou_resolves_through_its_parents_children(self) -> None:
        """A nested OU is looked up among its own parent's children, not the root's."""
        content = _generate_terraform_content(make_nested_hierarchy())

        payments_block = content.split("production_payments_ou_id = [")[1]
        assert (
            "data.aws_organizations_organizational_units"
            ".production_children.children" in payments_block
        )

    def test_children_data_source_emitted_for_each_parent_ou(self) -> None:
        """Every OU with children exposes the list its children resolve against."""
        content = _generate_terraform_content(make_nested_hierarchy())

        assert (
            'data "aws_organizations_organizational_units" "production_children"'
            in content
        )
        assert (
            'data "aws_organizations_organizational_units"'
            ' "production_payments_children"' in content
        )

    def test_children_data_source_is_parented_by_the_ou_local(self) -> None:
        """The chain hangs off the OU's own ID local, so it works at any depth."""
        content = _generate_terraform_content(make_nested_hierarchy())

        block = content.split(
            'data "aws_organizations_organizational_units" "production_children" {'
        )[1]
        assert "parent_id = local.production_ou_id" in block.split("}")[0]

    def test_leaf_ou_gets_no_children_data_source(self) -> None:
        """An OU with no child OUs needs no list of them."""
        content = _generate_terraform_content(make_nested_hierarchy())

        assert "production_payments_ledger_children" not in content

    def test_nested_account_resolves_through_its_own_ou(self) -> None:
        """A nested account is not looked for among its top-level OU's children."""
        content = _generate_terraform_content(make_nested_hierarchy())

        ledger_block = content.split("ledger_core_account_id = [")[1]
        assert (
            "data.aws_organizations_organizational_unit_child_accounts"
            ".production_payments_ledger_accounts.accounts" in ledger_block
        )

    def test_ou_holding_no_accounts_gets_no_child_accounts_data_source(self) -> None:
        """Nothing references it, so nothing is emitted for it."""
        org = make_nested_hierarchy()
        del org.accounts[PROD_APP_ACCOUNT]

        content = _generate_terraform_content(org)

        assert (
            'data "aws_organizations_organizational_unit_child_accounts"'
            ' "production_accounts"' not in content
        )


def declared_locals(org_info: str) -> Set[str]:
    """Collect every local variable name grab_org_info.tf declares."""
    locals_block = org_info.split("locals {", 1)[1]
    return set(re.findall(r"^\s{2}(\w+)\s*=", locals_block, flags=re.MULTILINE))


def referenced_locals(terraform: str) -> Set[str]:
    """Collect every local variable name a generated policy file reads."""
    return set(re.findall(r"local\.(\w+)", terraform))


class TestGeneratedTerraformResolves:
    """
    Tests that every local a generated policy reads is one grab_org_info declares.

    This is the check that the split between the two generators kept evading:
    each side was tested alone, so a reference to a local nobody declared read
    as correct in both test suites and failed only at terraform plan.
    """

    def make_results(self) -> List[SCPCheckResult]:
        """One violating account at the top, forcing placement lower down."""
        return [
            make_scp_result(PROD_APP_ACCOUNT, "prod-app", 3),
            make_scp_result(PAYMENTS_ACCOUNT, "payments-core", 0),
            make_scp_result(LEDGER_ACCOUNT, "ledger-core", 0),
        ]

    def test_nested_ou_scp_references_only_declared_locals(
        self,
        tmp_path: Path
    ) -> None:
        """A policy on a nested OU resolves against the generated org info."""
        org = make_nested_hierarchy()
        recommendations = determine_scp_placement(self.make_results(), org)

        generate_scp_terraform(recommendations, org, output_dir=str(tmp_path))

        declared = declared_locals(_generate_terraform_content(org))
        for generated in tmp_path.glob("*.tf"):
            missing = referenced_locals(generated.read_text()) - declared
            assert not missing, f"{generated.name} reads undeclared {missing}"

    def test_nested_ou_policy_file_is_named_for_its_path(self, tmp_path: Path) -> None:
        """Two OUs of the same name in different branches cannot share a file."""
        org = make_nested_hierarchy()
        recommendations = determine_scp_placement(self.make_results(), org)

        generate_scp_terraform(recommendations, org, output_dir=str(tmp_path))

        assert (tmp_path / "production_payments_ou_scps.tf").exists()

    def test_nested_rcp_references_only_declared_locals(self, tmp_path: Path) -> None:
        """The RCP generator resolves against the same org info the SCPs do."""
        org = make_nested_hierarchy()
        recommendations = [
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="ou",
                target_ou_id=PAYMENTS_OU,
                affected_accounts=[PAYMENTS_ACCOUNT, LEDGER_ACCOUNT],
                third_party_account_ids=["999999999999"],
                reasoning="Nested OU RCP",
            ),
            RCPPlacementRecommendations(
                check_name="deny_sts_third_party_assumerole",
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=[PROD_APP_ACCOUNT],
                third_party_account_ids=["888888888888"],
                reasoning="Account RCP",
            ),
        ]

        generate_rcp_terraform(recommendations, org, output_dir=str(tmp_path))

        declared = declared_locals(_generate_terraform_content(org))
        generated = sorted(path.name for path in tmp_path.glob("*.tf"))
        assert generated == ["prod_app_rcps.tf", "production_payments_ou_rcps.tf"]
        for path in tmp_path.glob("*.tf"):
            missing = referenced_locals(path.read_text()) - declared
            assert not missing, f"{path.name} reads undeclared {missing}"


class TestOuLocalNameRule:
    """Tests for ou_id_local_name(), the single rule both generators share."""

    def test_local_name_is_the_base_name_with_the_ou_id_suffix(self) -> None:
        """Declaration and reference are built by the same function."""
        assert ou_id_local_name("production_payments") == "production_payments_ou_id"

    def test_base_names_and_local_names_agree_for_every_ou(self) -> None:
        """No OU can be declared under one name and referenced under another."""
        ous = make_nested_hierarchy().organizational_units
        base_names: Dict[str, str] = make_ou_base_names(ous)
        content = _generate_terraform_content(make_nested_hierarchy())

        for base in base_names.values():
            assert f"  {ou_id_local_name(base)} = [" in content


class TestAncestorWalkEdges:
    """
    Tests the walk up from an account to the OUs that govern it.

    Grouping an account under every OU above it means following the parent
    chain, and a chain that loops or dead-ends has to end the walk rather
    than the process.
    """

    def make_analyzer(
        self,
        ous: Dict[str, OrganizationalUnit],
        parent_ou_id: str
    ) -> HierarchyPlacementAnalyzer[str]:
        """Build an analyzer over one account parented at the given OU."""
        return HierarchyPlacementAnalyzer(OrganizationHierarchy(
            root_id=ROOT_ID,
            organizational_units=ous,
            accounts={
                PROD_APP_ACCOUNT: AccountOrgPlacement(
                    account_id=PROD_APP_ACCOUNT,
                    account_name="prod-app",
                    parent_ou_id=parent_ou_id,
                    ou_path=["Production"],
                ),
            },
        ))

    def test_cycle_in_the_parent_chain_is_reported(self) -> None:
        """Two OUs parenting each other stop the walk instead of spinning."""
        analyzer = self.make_analyzer(
            {
                PRODUCTION_OU: OrganizationalUnit(
                    PRODUCTION_OU, "Production", PAYMENTS_OU, [], []),
                PAYMENTS_OU: OrganizationalUnit(
                    PAYMENTS_OU, "Payments", PRODUCTION_OU, [], []),
            },
            PRODUCTION_OU,
        )

        with pytest.raises(RuntimeError, match="cycle"):
            analyzer._group_results_by_ou_subtree([PROD_APP_ACCOUNT], lambda r: r)

    def test_account_whose_parent_ou_is_absent_is_placed_individually(self) -> None:
        """A parent OU the hierarchy never listed ends the walk, not the run."""
        analyzer = self.make_analyzer({}, "ou-fake-ghost")

        candidates = analyzer.determine_placement(
            check_results=[PROD_APP_ACCOUNT],
            is_safe_for_root=lambda results: False,
            is_safe_for_ou=lambda ou_id, results: True,
            get_account_id=lambda r: r,
        )

        assert [c.level for c in candidates] == ["account"]
        assert candidates[0].affected_accounts == [PROD_APP_ACCOUNT]
