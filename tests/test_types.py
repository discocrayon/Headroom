"""Tests for headroom/types.py."""

import dataclasses

import pytest

from headroom.types import AccountInfo, OrganizationHierarchy, OrganizationSnapshot


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
