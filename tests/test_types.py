"""Tests for headroom/types.py."""

import dataclasses

import pytest

from headroom.types import (
    AccountInfo,
    AccountOrgPlacement,
    OrganizationHierarchy,
    OrganizationSnapshot,
)


def test_the_snapshot_cannot_be_reassigned_after_discovery() -> None:
    """
    The snapshot is the one organization view a run gets.

    Freezing the outer dataclass is what stops a later stage swapping a
    projection for one it computed itself, which is the class of bug this
    whole change exists to remove. The hierarchy inside stays mutable; deep
    immutability is a separate concern.
    """
    snapshot = OrganizationSnapshot(
        organization_id="o-11111111111",
        member_account_ids=frozenset({"111111111111"}),
        analyzable_accounts=(
            AccountInfo(
                account_id="111111111111",
                environment="prod",
                name="payments",
                owner="payments-team",
            ),
        ),
        hierarchy=OrganizationHierarchy(
            root_id="r-1111", organizational_units={}, accounts={}
        ),
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.organization_id = "o-22222222222"  # type: ignore[misc]


def test_the_hierarchy_stays_mutable_after_the_snapshot_freezes() -> None:
    """
    Freezing OrganizationSnapshot blocks reassigning its fields; it says
    nothing about mutating what a field already points to. This test pins
    that scope boundary deliberately, so a future change that deep-freezes
    the hierarchy is a visible decision rather than a silent contradiction
    of the docstring.
    """
    snapshot = OrganizationSnapshot(
        organization_id="o-11111111111",
        member_account_ids=frozenset({"111111111111"}),
        analyzable_accounts=(),
        hierarchy=OrganizationHierarchy(
            root_id="r-1111", organizational_units={}, accounts={}
        ),
    )

    snapshot.hierarchy.accounts["222222222222"] = AccountOrgPlacement(
        account_id="222222222222",
        account_name="added-after-freeze",
        parent_ou_id=None,
        ou_path=["Root"],
    )

    assert snapshot.hierarchy.accounts["222222222222"].account_name == "added-after-freeze"
