"""
Tests for headroom.terraform.disabled_reasons.

Every test drives the grammar with synthetic recommendations so nothing
depends on which checks are registered.
"""

from typing import List, Optional

import pytest

from headroom.terraform.disabled_reasons import _descendant_ids, disabled_reasons, placed_targets, split_placements
from headroom.types import (
    AccountOrgPlacement,
    CheckCoverage,
    OrganizationalUnit,
    OrganizationHierarchy,
    SCPPlacementRecommendations,
)


def make_hierarchy() -> OrganizationHierarchy:
    """
    Build a two-level organization the whole module is tested against.

    Root r-1111
      OU production (ou-1111-11111111)
        OU data (ou-1111-22222222) .... acme-co (111111111111)
        fort-knox (222222222222)
      shared-foo-bar (333333333333)

    Returns:
        A hierarchy with two nested OUs, an account inside the inner one, an
        account attached directly to the outer one, and an account attached
        directly to the root
    """
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={
            "ou-1111-11111111": OrganizationalUnit(
                ou_id="ou-1111-11111111",
                name="production",
                parent_ou_id=None,
                child_ous=["ou-1111-22222222"],
                accounts=["222222222222"],
            ),
            "ou-1111-22222222": OrganizationalUnit(
                ou_id="ou-1111-22222222",
                name="data",
                parent_ou_id="ou-1111-11111111",
                child_ous=[],
                accounts=["111111111111"],
            ),
        },
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="acme-co",
                parent_ou_id="ou-1111-22222222",
                ou_path=["production", "data"],
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="fort-knox",
                parent_ou_id="ou-1111-11111111",
                ou_path=["production"],
            ),
            "333333333333": AccountOrgPlacement(
                account_id="333333333333",
                account_name="shared-foo-bar",
                parent_ou_id=None,
                ou_path=[],
            ),
        },
    )


def make_wide_hierarchy() -> OrganizationHierarchy:
    """
    Build a one-level organization: four accounts attached to the root.

    Root r-1111
      acme-co (111111111111)
      fort-knox (222222222222)
      shared-foo-bar (333333333333)
      security-tooling (444444444444)

    Returns:
        A hierarchy with no OUs, so every account attaches to the root
        directly
    """
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="acme-co",
                parent_ou_id=None,
                ou_path=[],
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="fort-knox",
                parent_ou_id=None,
                ou_path=[],
            ),
            "333333333333": AccountOrgPlacement(
                account_id="333333333333",
                account_name="shared-foo-bar",
                parent_ou_id=None,
                ou_path=[],
            ),
            "444444444444": AccountOrgPlacement(
                account_id="444444444444",
                account_name="security-tooling",
                parent_ou_id=None,
                ou_path=[],
            ),
        },
    )


def make_nested_hierarchy() -> OrganizationHierarchy:
    """
    Build the three-OU organization test_environment itself deploys.

    Root r-1111
      acme_acquisition (ou-1111-11111111) ....... acme-co (111111111111)
      shared_services (ou-1111-22222222) ........ shared-foo-bar (333333333333)
      high_value_assets (ou-1111-33333333) ....... fort-knox (222222222222),
        security-tooling (444444444444)

    Returns:
        A hierarchy with three sibling OUs - two holding one account each,
        one holding two - and none nested inside another
    """
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={
            "ou-1111-11111111": OrganizationalUnit(
                ou_id="ou-1111-11111111",
                name="acme_acquisition",
                parent_ou_id=None,
                child_ous=[],
                accounts=["111111111111"],
            ),
            "ou-1111-22222222": OrganizationalUnit(
                ou_id="ou-1111-22222222",
                name="shared_services",
                parent_ou_id=None,
                child_ous=[],
                accounts=["333333333333"],
            ),
            "ou-1111-33333333": OrganizationalUnit(
                ou_id="ou-1111-33333333",
                name="high_value_assets",
                parent_ou_id=None,
                child_ous=[],
                accounts=["222222222222", "444444444444"],
            ),
        },
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="acme-co",
                parent_ou_id="ou-1111-11111111",
                ou_path=["acme_acquisition"],
            ),
            "333333333333": AccountOrgPlacement(
                account_id="333333333333",
                account_name="shared-foo-bar",
                parent_ou_id="ou-1111-22222222",
                ou_path=["shared_services"],
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="fort-knox",
                parent_ou_id="ou-1111-33333333",
                ou_path=["high_value_assets"],
            ),
            "444444444444": AccountOrgPlacement(
                account_id="444444444444",
                account_name="security-tooling",
                parent_ou_id="ou-1111-33333333",
                ou_path=["high_value_assets"],
            ),
        },
    )


def make_many_account_hierarchy(n: int) -> OrganizationHierarchy:
    """
    Build a root holding n accounts, for testing the name cap and wrapping.

    Root r-1111
      account-1 (111111111111)
      account-2 (222222222222)
      ... n accounts, the i-th named account-i with ID str(i) * 12

    Args:
        n: How many accounts to attach directly to the root

    Returns:
        A hierarchy with no OUs and n accounts attached to the root
    """
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={},
        accounts={
            str(i) * 12: AccountOrgPlacement(
                account_id=str(i) * 12,
                account_name=f"account-{i}",
                parent_ou_id=None,
                ou_path=[],
            )
            for i in range(1, n + 1)
        },
    )


def make_recommendation(
    check_name: str,
    recommended_level: str,
    target_ou_id: Optional[str],
    affected_accounts: List[str],
) -> SCPPlacementRecommendations:
    """
    Build a placement recommendation carrying only what this module reads.

    Args:
        check_name: Check this recommendation is for
        recommended_level: "root", "ou", or "account"
        target_ou_id: The OU this attaches to, for an "ou" recommendation
        affected_accounts: Accounts this recommendation covers

    Returns:
        An SCPPlacementRecommendations with a fixed compliance percentage
        and reasoning, since placed_targets and disabled_reasons read neither
    """
    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level=recommended_level,
        target_ou_id=target_ou_id,
        affected_accounts=affected_accounts,
        compliance_percentage=100.0,
        reasoning="test",
    )


def test_placed_targets_keys_every_level_by_its_real_id() -> None:
    """
    A placement becomes the ID of the thing it attaches to.

    Root, OU, and account IDs share no format, so one set per check is
    enough to answer both "is this enforced above me" and "below me".
    """
    org = make_hierarchy()
    recommendations = [
        make_recommendation("deny_ec2_ami_owner", "root", None, ["111111111111"]),
        make_recommendation(
            "deny_rds_unencrypted", "ou", "ou-1111-22222222", ["111111111111"]
        ),
        make_recommendation(
            "deny_rds_unencrypted", "account", None, ["222222222222"]
        ),
    ]

    assert placed_targets(recommendations, org) == {
        "deny_ec2_ami_owner": frozenset({"r-1111"}),
        "deny_rds_unencrypted": frozenset({"ou-1111-22222222", "222222222222"}),
    }


def test_shape_four_names_a_check_that_analyzed_nothing() -> None:
    """
    No results is not no findings.

    Four of the nine SCP checks in the committed examples have no results
    directory at all, and rendered the same bare false as a check that was
    scanned and came back blocked. INV-01 is the whole reason this shape
    exists.
    """
    org = make_hierarchy()

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={},
        coverage={"deny_ec2_public_ip": CheckCoverage(frozenset(), frozenset())},
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_ec2_public_ip": ["No results for this check - not evidence of safety"]
    }


def test_a_check_placed_at_the_target_gets_no_reason() -> None:
    """
    A reason is for a false. The renderer keys on the entry being there.

    This is also what keeps INV-06 intact: a check forced off by an empty
    allowlist has a recommendation for this target, so it is absent here and
    keeps its own empty-allowlist comment.
    """
    org = make_hierarchy()
    placed = {"deny_ec2_imds_v1": frozenset({"r-1111"})}

    assert disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_imds_v1"],
        placed=placed,
        coverage={},
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    ) == {}


def test_shape_one_names_the_root_that_already_enforces_it() -> None:
    """
    An OU's false often means the root has it covered.

    This is the case the whole feature was asked for: a reader of an OU file
    cannot tell an unprotected OU from one already inheriting the guardrail.
    """
    org = make_hierarchy()
    placed = {"deny_ec2_ami_owner": frozenset({"r-1111"})}
    coverage = {
        "deny_ec2_ami_owner": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111"}),
            unsafe_accounts=frozenset(),
        )
    }

    reasons = disabled_reasons(
        "ou-1111-22222222",
        check_names=["deny_ec2_ami_owner"],
        placed=placed,
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {"deny_ec2_ami_owner": ["Enforced at the organization root"]}


def test_shape_one_names_an_ancestor_ou_by_its_path() -> None:
    """A nested OU inherits from the OU above it, named root-down."""
    org = make_hierarchy()
    placed = {"deny_rds_unencrypted": frozenset({"ou-1111-11111111"})}

    reasons = disabled_reasons(
        "ou-1111-22222222",
        check_names=["deny_rds_unencrypted"],
        placed=placed,
        coverage={},
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {"deny_rds_unencrypted": ["Enforced at OU production"]}


def test_shape_one_reaches_an_account_from_the_ou_above_it() -> None:
    """An account file inherits from its parent OU as well as from the root."""
    org = make_hierarchy()
    placed = {"deny_rds_unencrypted": frozenset({"ou-1111-22222222"})}

    reasons = disabled_reasons(
        "111111111111",
        check_names=["deny_rds_unencrypted"],
        placed=placed,
        coverage={},
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_rds_unencrypted": ["Enforced at OU production / data"]
    }


def test_an_unknown_target_raises_rather_than_rendering_a_comment() -> None:
    """
    A target the hierarchy does not hold is a bug in the run.

    Every other stage raises on one, and a silently omitted comment would
    read as a shape the grammar does not define.
    """
    org = make_hierarchy()

    with pytest.raises(RuntimeError, match="is not the organization root"):
        disabled_reasons(
            "ou-1111-99999999",
            check_names=["deny_ec2_public_ip"],
            placed={},
            coverage={},
            organization_hierarchy=org,
            flipped={},
            flipped_comment={},
        )


def test_shape_three_counts_the_accounts_that_blocked_it() -> None:
    """
    Counts are relative to the target: an OU file counts its own subtree.

    N of M is the plain case; the collapses below cover the rest.
    """
    org = make_wide_hierarchy()
    coverage = {
        "deny_rds_unencrypted": CheckCoverage(
            analyzed_accounts=frozenset(
                {"111111111111", "222222222222", "333333333333", "444444444444"}
            ),
            unsafe_accounts=frozenset({"111111111111", "333333333333"}),
        )
    }

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_rds_unencrypted"],
        placed={},
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_rds_unencrypted": [
            "Blocked by 2 of 4 analyzed accounts (acme-co, shared-foo-bar)"
        ]
    }


def test_shape_three_collapses_when_every_analyzed_account_blocked_it() -> None:
    """"2 of 2" reads as a coincidence. "all 2" states the fact."""
    org = make_wide_hierarchy()
    coverage = {
        "deny_ec2_public_ip": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111", "222222222222"}),
            unsafe_accounts=frozenset({"111111111111", "222222222222"}),
        )
    }

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={},
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_ec2_public_ip": [
            "Blocked by all 2 analyzed accounts (acme-co, fort-knox)"
        ]
    }


def test_shape_three_collapses_when_the_target_reached_one_account() -> None:
    """An OU holding one analyzed account should not read "1 of 1"."""
    org = make_hierarchy()
    coverage = {
        "deny_rds_unencrypted": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111"}),
            unsafe_accounts=frozenset({"111111111111"}),
        )
    }

    reasons = disabled_reasons(
        "ou-1111-22222222",
        check_names=["deny_rds_unencrypted"],
        placed={},
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_rds_unencrypted": ["Blocked by the only analyzed account (acme-co)"]
    }


def test_shape_three_in_an_account_file_does_not_repeat_the_account() -> None:
    """
    An account file reaches exactly one account, and the filename names it.

    Naming it again inside the comment says nothing the reader does not have.
    """
    org = make_hierarchy()
    coverage = {
        "deny_rds_unencrypted": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111"}),
            unsafe_accounts=frozenset({"111111111111"}),
        )
    }

    reasons = disabled_reasons(
        "111111111111",
        check_names=["deny_rds_unencrypted"],
        placed={},
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_rds_unencrypted": ["Blocked by this account's violations"]
    }


def test_shape_two_names_the_targets_below_and_who_blocked_the_rest() -> None:
    """
    A root file's false can mean the policy is deployed at OUs below it.

    Both clauses are always present: the root was passed over only because
    an analyzed account under it was unsafe, so a placement below implies a
    violation somewhere.
    """
    org = make_nested_hierarchy()
    placed = {
        "deny_ec2_imds_v1": frozenset({"ou-1111-11111111", "ou-1111-33333333"})
    }
    coverage = {
        "deny_ec2_imds_v1": CheckCoverage(
            analyzed_accounts=frozenset(
                {"111111111111", "222222222222", "333333333333", "444444444444"}
            ),
            unsafe_accounts=frozenset({"333333333333"}),
        )
    }

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_imds_v1"],
        placed=placed,
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert " ".join(reasons["deny_ec2_imds_v1"]) == (
        "Enforced below at OU acme_acquisition, OU high_value_assets; "
        "blocked elsewhere by 1 of 4 analyzed accounts (shared-foo-bar)"
    )


def test_shape_two_names_an_account_below_as_readily_as_an_ou() -> None:
    """A descendant is any target below, and account placement is one."""
    org = make_nested_hierarchy()
    placed = {"deny_rds_unencrypted": frozenset({"444444444444"})}
    coverage = {
        "deny_rds_unencrypted": CheckCoverage(
            analyzed_accounts=frozenset({"333333333333", "444444444444"}),
            unsafe_accounts=frozenset({"333333333333"}),
        )
    }

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_rds_unencrypted"],
        placed=placed,
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert " ".join(reasons["deny_rds_unencrypted"]) == (
        "Enforced below at account security-tooling; blocked elsewhere "
        "by 1 of 2 analyzed accounts (shared-foo-bar)"
    )


def test_an_account_file_never_reports_a_placement_below_it() -> None:
    """
    An account is a leaf. Nothing is below it to inherit from.

    A sibling account carrying the check is not below this one, so this file
    reports its own violations instead.
    """
    org = make_nested_hierarchy()
    placed = {"deny_rds_unencrypted": frozenset({"444444444444"})}
    coverage = {
        "deny_rds_unencrypted": CheckCoverage(
            analyzed_accounts=frozenset({"222222222222", "444444444444"}),
            unsafe_accounts=frozenset({"222222222222"}),
        )
    }

    reasons = disabled_reasons(
        "222222222222",
        check_names=["deny_rds_unencrypted"],
        placed=placed,
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_rds_unencrypted": ["Blocked by this account's violations"]
    }


def test_blocked_accounts_are_named_in_account_name_order_not_account_id_order() -> None:
    """
    Exists to discriminate name-sorting from ID-sorting.

    Every other test's blocked accounts happen to sort the same way by name
    and by ID. security-tooling (444444444444) and shared-foo-bar
    (333333333333) do not: by ID, shared-foo-bar comes first; by name,
    security-tooling does. The clause must use the name order.
    """
    org = make_nested_hierarchy()
    coverage = {
        "deny_ec2_public_ip": CheckCoverage(
            analyzed_accounts=frozenset(
                {"111111111111", "222222222222", "333333333333", "444444444444"}
            ),
            unsafe_accounts=frozenset({"333333333333", "444444444444"}),
        )
    }

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={},
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert reasons == {
        "deny_ec2_public_ip": [
            "Blocked by 2 of 4 analyzed accounts (security-tooling, "
            "shared-foo-bar)"
        ]
    }


def test_a_long_blocked_list_is_capped_rather_than_scaling_with_the_org() -> None:
    """
    These files are committed. A comment that grows with the organization
    turns every generated file into a wall of account names.
    """
    org = make_many_account_hierarchy(8)
    coverage = {
        "deny_ec2_public_ip": CheckCoverage(
            analyzed_accounts=frozenset(f"{n}" * 12 for n in range(1, 9)),
            unsafe_accounts=frozenset(f"{n}" * 12 for n in range(1, 8)),
        )
    }

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={},
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    assert " ".join(reasons["deny_ec2_public_ip"]) == (
        "Blocked by 7 of 8 analyzed accounts (account-1, account-2, "
        "account-3, account-4, account-5, and 2 more)"
    )


def test_a_long_reason_wraps_into_several_comment_lines() -> None:
    """
    A comment has no escape syntax and no line-continuation.

    `comment_text` folds a real line break into a literal backslash-n, so a
    long reason has to arrive as separate lines for the renderer to emit as
    separate comments.
    """
    org = make_many_account_hierarchy(8)
    coverage = {
        "deny_ec2_public_ip": CheckCoverage(
            analyzed_accounts=frozenset(f"{n}" * 12 for n in range(1, 9)),
            unsafe_accounts=frozenset(f"{n}" * 12 for n in range(1, 8)),
        )
    }

    lines = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={},
        coverage=coverage,
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )["deny_ec2_public_ip"]

    assert len(lines) == 2
    assert all(len(line) <= 72 for line in lines)
    assert lines[0].startswith("Blocked by 7 of 8 analyzed accounts")


def test_a_short_reason_stays_on_one_line() -> None:
    """Wrapping must not split what already fits."""
    org = make_hierarchy()
    placed = {"deny_ec2_ami_owner": frozenset({"r-1111"})}

    assert disabled_reasons(
        "ou-1111-22222222",
        check_names=["deny_ec2_ami_owner"],
        placed=placed,
        coverage={},
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    ) == {"deny_ec2_ami_owner": ["Enforced at the organization root"]}


def test_a_flipped_placement_explains_itself_below_instead_of_claiming_enforcement() -> None:
    """
    A root placement an empty allowlist turned off enforces nothing.

    Shape 1 would name the root as the enforcing target, which is the one
    thing a reader must not believe: the root's own file renders the check
    false. The check's own comment says why, and stays true below the root
    because an empty union stays empty over any subset of its accounts.
    """
    org = make_nested_hierarchy()

    reasons = disabled_reasons(
        "ou-1111-11111111",
        check_names=["deny_ec2_ami_owner"],
        placed={},
        coverage={"deny_ec2_ami_owner": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111"}),
            unsafe_accounts=frozenset(),
        )},
        organization_hierarchy=org,
        flipped={"deny_ec2_ami_owner": frozenset({"r-1111"})},
        flipped_comment={"deny_ec2_ami_owner": "no resolvable AMI owner, so the allowlist would be empty"},
    )

    assert reasons == {
        "deny_ec2_ami_owner": [
            "no resolvable AMI owner, so the allowlist would be empty"
        ]
    }


def test_a_flipped_ancestor_does_not_speak_for_accounts_nothing_scanned() -> None:
    """
    Below a flipped placement, an unscanned target still says it was unscanned.

    The flipped comment is a claim about what the covered accounts held - no
    resolvable AMI owner, no third-party principal - and it is only true of
    accounts something looked at. A target whose accounts produced no result
    contributed nothing to that empty union, so repeating the sentence there
    reports absence of evidence as evidence of safety (INV-01). Shape 4 is
    the honest answer and outranks the flipped ancestor.
    """
    org = make_nested_hierarchy()

    reasons = disabled_reasons(
        "ou-1111-22222222",
        check_names=["deny_ec2_ami_owner"],
        placed={},
        coverage={"deny_ec2_ami_owner": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111"}),
            unsafe_accounts=frozenset(),
        )},
        organization_hierarchy=org,
        flipped={"deny_ec2_ami_owner": frozenset({"r-1111"})},
        flipped_comment={"deny_ec2_ami_owner": "no resolvable AMI owner, so the allowlist would be empty"},
    )

    assert reasons == {
        "deny_ec2_ami_owner": ["No results for this check - not evidence of safety"]
    }


def test_a_blocked_clause_with_nothing_blocking_raises_rather_than_naming_nobody() -> None:
    """
    Shapes 2 and 3 both rest on a premise, so a run that breaks it must stop.

    A target takes no placement of its own only when some analyzed account
    under it is unsafe, which is what gives both clauses an account to name.
    Inputs that break the premise - a coverage map disagreeing with the
    placements it was built beside - would otherwise render "blocked by the
    only analyzed account ()", a sentence naming nobody and blaming them.
    """
    org = make_nested_hierarchy()

    with pytest.raises(RuntimeError, match="no unsafe account"):
        disabled_reasons(
            "r-1111",
            check_names=["deny_ec2_public_ip"],
            placed={"deny_ec2_public_ip": frozenset({"ou-1111-11111111"})},
            coverage={"deny_ec2_public_ip": CheckCoverage(
                analyzed_accounts=frozenset({"111111111111"}),
                unsafe_accounts=frozenset(),
            )},
            organization_hierarchy=org,
            flipped={},
            flipped_comment={},
        )


def test_a_check_missing_from_coverage_raises_rather_than_reporting_no_results() -> None:
    """
    An incomplete coverage map is a bug, and shape 4 would hide it.

    Both builders name every registered check of their policy type, present
    with empty sets when it produced nothing, so a name absent from the map
    never means "scanned nothing" - it means a caller assembled the map
    wrong. Defaulting would answer that with "No results for this check",
    a sentence indistinguishable from the honest one.
    """
    org = make_nested_hierarchy()

    with pytest.raises(RuntimeError, match="names no check 'deny_ec2_public_ip'"):
        disabled_reasons(
            "ou-1111-11111111",
            check_names=["deny_ec2_public_ip"],
            placed={},
            coverage={},
            organization_hierarchy=org,
            flipped={},
            flipped_comment={},
        )


def test_shape_two_names_a_flipped_descendant_beside_the_enforcing_one() -> None:
    """
    Naming only the live placements below invites the reader to do arithmetic.

    "Enforced below at OU acme_acquisition; blocked elsewhere by 1 of 3" is
    literally true and still misleads: three accounts, one blocking, one
    covered below, and the reader concludes the third is covered too. It is
    not - its OU carries the check with an empty allowlist, which enforces
    nothing. That is the same harm as claiming enforcement outright, reached
    by omission, so the flipped targets below are named beside the live ones.
    """
    org = make_nested_hierarchy()

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={"deny_ec2_public_ip": frozenset({"ou-1111-11111111"})},
        coverage={"deny_ec2_public_ip": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111", "333333333333", "222222222222"}),
            unsafe_accounts=frozenset({"222222222222"}),
        )},
        organization_hierarchy=org,
        flipped={"deny_ec2_public_ip": frozenset({"ou-1111-22222222"})},
        flipped_comment={"deny_ec2_public_ip": "nothing to allowlist"},
    )

    assert reasons == {
        "deny_ec2_public_ip": [
            "Enforced below at OU acme_acquisition; off below at OU shared_services;",
            "blocked elsewhere by 1 of 3 analyzed accounts (fort-knox)",
        ]
    }


def test_a_hyphenated_account_name_is_never_split_across_two_lines() -> None:
    """
    Every account in the committed examples is hyphenated.

    `textwrap` treats a hyphen as a break opportunity, so a name landing on
    the boundary renders as `security-tooling-` on one line and `production)`
    on the next - two strings, neither of which is an account, in a file a
    reader greps by account name.
    """
    org = OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="acme-co",
                parent_ou_id=None,
                ou_path=[],
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="security-tooling-production",
                parent_ou_id=None,
                ou_path=[],
            ),
        },
    )
    every_account = frozenset({"111111111111", "222222222222"})

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={},
        coverage={"deny_ec2_public_ip": CheckCoverage(every_account, every_account)},
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    lines = reasons["deny_ec2_public_ip"]
    assert [line for line in lines if "security-tooling-production" in line]
    assert not [line for line in lines if line.endswith("-")]


def test_a_descendant_walk_from_an_unknown_target_raises() -> None:
    """
    An ID the hierarchy does not know is a bug, not a target with nothing below.

    The sibling that resolves the accounts a target reaches raises for the
    same input, and the one that walks upward lets the dict index raise. A
    silent empty set here would be the one answer of the three a caller
    could mistake for a leaf.
    """
    with pytest.raises(RuntimeError, match="is not the organization root, an OU, or an account"):
        _descendant_ids("ou-1111-99999999", make_nested_hierarchy())


def test_the_blocked_clause_guard_covers_an_account_target() -> None:
    """
    The premise holds for an account as much as for an OU or the root.

    A safe analyzed account takes a placement at itself or above, so an
    account file reaching shape 3 has that account among the unsafe. An
    account-shaped clause that skipped the guard would blame a clean
    account for its own violations.
    """
    org = make_nested_hierarchy()

    with pytest.raises(RuntimeError, match="no unsafe account"):
        disabled_reasons(
            "111111111111",
            check_names=["deny_ec2_public_ip"],
            placed={},
            coverage={"deny_ec2_public_ip": CheckCoverage(
                analyzed_accounts=frozenset({"111111111111"}),
                unsafe_accounts=frozenset(),
            )},
            organization_hierarchy=org,
            flipped={},
            flipped_comment={},
        )


def test_shape_three_names_a_flipped_descendant_beside_the_blocked_accounts() -> None:
    """
    A count with safe accounts in it, at shape 3, means flipped placements below.

    A safe analyzed account under an unplaced target sits under some
    placement below it, and were that placement live the target would be
    shape 2. So "blocked by 1 of 3" with nothing enforced below leaves two
    accounts the reader cannot place, and naming the flipped targets says
    where they went and that nothing protects them there.
    """
    org = make_nested_hierarchy()

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_ami_owner"],
        placed={},
        coverage={"deny_ec2_ami_owner": CheckCoverage(
            analyzed_accounts=frozenset({"111111111111", "222222222222", "333333333333"}),
            unsafe_accounts=frozenset({"222222222222"}),
        )},
        organization_hierarchy=org,
        flipped={"deny_ec2_ami_owner": frozenset({"ou-1111-11111111", "ou-1111-22222222"})},
        flipped_comment={"deny_ec2_ami_owner": "nothing to allowlist"},
    )

    assert " ".join(reasons["deny_ec2_ami_owner"]) == (
        "Blocked by 1 of 3 analyzed accounts (fort-knox); "
        "off below at OU acme_acquisition, OU shared_services"
    )


def test_a_name_with_spaces_is_never_split_across_two_lines() -> None:
    """
    An account name is one word to the wrapper, whatever it contains.

    `textwrap` breaks on spaces, so an account named `security tooling
    production` landing on the width rendered as `security tooling` on one
    line and `production)` on the next - two strings, neither of them an
    account. The fixtures already hold `Prod US` and `Test Account`, so the
    case is not hypothetical.
    """
    org = OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="acme-co",
                parent_ou_id=None,
                ou_path=[],
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="security tooling production",
                parent_ou_id=None,
                ou_path=[],
            ),
        },
    )
    every_account = frozenset({"111111111111", "222222222222"})

    reasons = disabled_reasons(
        "r-1111",
        check_names=["deny_ec2_public_ip"],
        placed={},
        coverage={"deny_ec2_public_ip": CheckCoverage(every_account, every_account)},
        organization_hierarchy=org,
        flipped={},
        flipped_comment={},
    )

    lines = reasons["deny_ec2_public_ip"]
    assert len(lines) == 2
    assert [line for line in lines if "security tooling production)" in line]
    assert "\xa0" not in "".join(lines)


def test_split_placements_files_each_target_by_what_its_allowlist_renders() -> None:
    """
    One check, two targets, one empty allowlist: live at one, flipped at the other.

    The split runs before recommendations are reduced to targets, so the
    same check can be enforcing at one OU and turned off at its sibling,
    and each OU's file - and every file below each - says the right thing.
    Both generators call this rather than keeping a copy of the split.
    """
    live = SCPPlacementRecommendations(
        check_name="deny_ec2_ami_owner",
        recommended_level="ou",
        target_ou_id="ou-1111-11111111",
        affected_accounts=["111111111111"],
        compliance_percentage=100.0,
        reasoning="one owner observed",
        allowlist_values=["111111111111"],
    )
    off = SCPPlacementRecommendations(
        check_name="deny_ec2_ami_owner",
        recommended_level="ou",
        target_ou_id="ou-1111-22222222",
        affected_accounts=["333333333333"],
        compliance_percentage=100.0,
        reasoning="no owner observed",
        allowlist_values=[],
    )

    placed, flipped = split_placements(
        [live, off], lambda rec: rec.allowlist_values, make_nested_hierarchy()
    )

    assert placed == {"deny_ec2_ami_owner": frozenset({"ou-1111-11111111"})}
    assert flipped == {"deny_ec2_ami_owner": frozenset({"ou-1111-22222222"})}


def test_split_placements_drops_a_none_recommendation_before_reading_its_allowlist() -> None:
    """
    A `none` recommendation places nothing, so the split files it nowhere.

    Placement materializes one when no account is safe for a check, and it
    leaves `allowlist_values` at None because it unioned nothing over the
    accounts it covers - there are none. Asking `renders_enabled` about it
    would raise over that None as if it were lost data, and abort Terraform
    generation for the whole organization over one unplaceable check.
    """
    none_rec = SCPPlacementRecommendations(
        check_name="deny_ec2_ami_owner",
        recommended_level="none",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=0.0,
        reasoning="no account is safe",
    )

    placed, flipped = split_placements(
        [none_rec], lambda rec: rec.allowlist_values, make_nested_hierarchy()
    )

    assert placed == {}
    assert flipped == {}
