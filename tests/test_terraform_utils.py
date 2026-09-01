"""
Tests for terraform.utils naming and plan assembly.

Covers the Terraform-identifier claim tables shared by every renderer, and
claim_plan_path, the one place a path collision across them is caught.
"""

from pathlib import Path
from typing import Dict

import pytest

from headroom.terraform.utils import (
    account_id_local_name,
    claim_plan_path,
    make_account_base_names,
)
from headroom.types import AccountOrgPlacement


class TestAccountBaseNames:
    """
    Tests for make_account_base_names().

    Accounts get the claim table OUs already have. Every generated reference
    to an account -- its policy filename, its module name, the ID local it
    targets -- is built from one identifier, so two accounts claiming the same
    one has to abort rather than let the second overwrite the first.
    """

    def test_names_differing_only_in_separators_are_reported(self) -> None:
        """
        'Prod-US' and 'Prod US' both fold to 'prod_us'.

        make_safe_variable_name turns a hyphen and a space into the same
        underscore, so these two names are one Terraform identifier. Left
        unguarded the second account's policy file overwrites the first's.
        """
        accounts = {
            "111111111111": AccountOrgPlacement(
                "111111111111", "Prod-US", None, []),
            "222222222222": AccountOrgPlacement(
                "222222222222", "Prod US", None, []),
        }

        with pytest.raises(RuntimeError, match="prod_us"):
            make_account_base_names(accounts)

    def test_account_whose_name_canonicalizes_to_nothing_is_rejected(self) -> None:
        """A name of only separators cannot become a Terraform identifier."""
        accounts = {
            "111111111111": AccountOrgPlacement("111111111111", "--", None, []),
        }

        with pytest.raises(RuntimeError, match="Terraform identifier"):
            make_account_base_names(accounts)


def test_account_id_local_name_names_the_local_org_info_declares() -> None:
    """
    grab_org_info.tf declares this local; SCP and RCP modules target it.

    Both sides of that contract call this function, which is what stops a
    policy from targeting a local nobody declared.
    """
    assert account_id_local_name("prod_us") == "prod_us_account_id"


class TestClaimPlanPath:
    """
    Tests for claim_plan_path().

    The plan is a dict keyed on the destination path, so a second write to
    one path replaces the first with nothing raised. This is the last place
    that can still be caught: after it, render-before-mutate is writing a
    plan that is already missing a file.
    """

    def test_two_paths_both_land_in_the_plan(self) -> None:
        """Distinct paths are an ordinary insert."""
        plan: Dict[Path, str] = {}

        claim_plan_path(plan, Path("a_scps.tf"), "a", "account 'A'")
        claim_plan_path(plan, Path("b_scps.tf"), "b", "account 'B'")

        assert plan == {Path("a_scps.tf"): "a", Path("b_scps.tf"): "b"}

    def test_a_second_claim_on_one_path_aborts(self) -> None:
        """
        The second claimant would have replaced the first silently.

        make_account_base_names catches two accounts folding together, but
        not an account folding onto the root policy file or onto an OU's,
        because those identifiers are built in different namespaces.
        """
        plan: Dict[Path, str] = {}
        claim_plan_path(plan, Path("root_scps.tf"), "root", "the organization root")

        with pytest.raises(RuntimeError, match="root_scps.tf"):
            claim_plan_path(plan, Path("root_scps.tf"), "acct", "account 'Root'")
