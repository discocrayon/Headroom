"""
Derive why a check renders false for a target.

Every registered check renders as a Terraform boolean for every target, and
most are false for reasons that have nothing to do with that target: already
enforced by an ancestor, blocked by a violation somewhere below, or never
scanned at all. This module derives which, from the placements and coverage
a run already produced. It names no check (INV-13): a check name arrives
only as data, read from `check_names` and the keys of the maps it is handed,
and the one sentence it does not compose - the comment a check gives for an
empty allowlist - arrives as data too.
"""

from collections import defaultdict
from typing import (
    Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, TypeVar,
)

from .models import unbreakable, wrap_comment
from .parameters import renders_enabled
from .utils import ou_path_names
from ..checks.registry import get_check_definition
from ..enums import PlacementLevel
from ..placement.hierarchy import (
    accounts_under_ou, ancestor_ou_ids, ou_subtree_ids,
)
from ..types import (
    CheckCoverage,
    OrganizationHierarchy,
    PolicyRecommendation,
    RCPPlacementRecommendations,
    SCPPlacementRecommendations,
)

# The two recommendation types agree on where a policy attaches and differ
# in what they carry about it, so a function reading only the placement
# fields takes either, and one that also reads the allowlist is told which.
RecommendationT = TypeVar("RecommendationT", SCPPlacementRecommendations, RCPPlacementRecommendations)


def placed_targets(
    recommendations: Sequence[PolicyRecommendation],
    organization_hierarchy: OrganizationHierarchy
) -> Dict[str, FrozenSet[str]]:
    """
    Map each check to the IDs of the targets the given recommendations attach at.

    This reduces whatever placements it is handed; which placements those
    are is the caller's decision. A generator calls it twice over disjoint
    subsets of one run - the recommendations that render `true` and the ones
    an empty allowlist turned off (INV-06) - and gets a map per subset.

    A root placement becomes the organization root's own ID rather than
    None, so ancestry is one set-membership question at every level instead
    of three shapes to case over.

    A `none` recommendation attaches nowhere and contributes nothing; it is
    dropped here the same way the generators' grouping loops drop it.

    Args:
        recommendations: Placements for one policy type, or the subset of
            them the caller is asking about
        organization_hierarchy: Organization structure, for the root's ID

    Returns:
        Each check the given recommendations place, mapped to the target IDs
        those recommendations attach it at
    """
    targets: Dict[str, Set[str]] = defaultdict(set)
    for rec in recommendations:
        if rec.recommended_level == PlacementLevel.ROOT.value:
            targets[rec.check_name].add(organization_hierarchy.root_id)
            continue
        if rec.recommended_level == PlacementLevel.OU.value and rec.target_ou_id:
            targets[rec.check_name].add(rec.target_ou_id)
            continue
        if rec.recommended_level == PlacementLevel.ACCOUNT.value:
            targets[rec.check_name].update(rec.affected_accounts)
    return {name: frozenset(ids) for name, ids in targets.items()}


NO_RESULTS = "No results for this check - not evidence of safety"


def split_placements(
    recommendations: Sequence[RecommendationT],
    allowlist_of: Callable[[RecommendationT], Optional[List[str]]],
    organization_hierarchy: OrganizationHierarchy,
) -> Tuple[Dict[str, FrozenSet[str]], Dict[str, FrozenSet[str]]]:
    """
    Split placements into those rendering true and those an empty allowlist turned off.

    A placement whose allowlist came back empty renders false at its own
    target (INV-06), so it enforces nothing and cannot be reported as an
    enforcing ancestor anywhere below it. Splitting the recommendations
    before they are reduced to targets keeps that per-target: one check can
    be placed at two targets with only one of the two allowlists empty.

    Args:
        recommendations: Every placement of one policy type
        allowlist_of: Reads the allowlist values a recommendation carries;
            the field differs between the two recommendation types
        organization_hierarchy: Organization structure

    Returns:
        The live placements, then the flipped ones, each as `placed_targets`
        shapes them

    Raises:
        RuntimeError: If a declaring check's placing recommendation carries
            None rather than a list, which `renders_enabled` refuses
    """
    live: List[RecommendationT] = []
    off: List[RecommendationT] = []
    for rec in recommendations:
        # A `none` recommendation places nothing, so there is nothing to file
        # as live or flipped - and it carries no allowlist, since placement
        # unioned one over no accounts. Asking `renders_enabled` about it
        # would read that None as lost data and abort the whole generation
        # stage over one check no account is safe for.
        if rec.recommended_level == PlacementLevel.NONE.value:
            continue
        if renders_enabled(get_check_definition(rec.check_name), allowlist_of(rec)):
            live.append(rec)
            continue
        off.append(rec)
    return placed_targets(live, organization_hierarchy), placed_targets(off, organization_hierarchy)


def _accounts_under(
    target_id: str,
    organization_hierarchy: OrganizationHierarchy
) -> Set[str]:
    """
    Return the accounts a policy attached at this target would reach.

    Args:
        target_id: The organization root, an OU, or an account
        organization_hierarchy: Organization structure

    Returns:
        Every account ID beneath the target, or the account itself

    Raises:
        RuntimeError: If the ID names nothing in the hierarchy
    """
    if target_id == organization_hierarchy.root_id:
        return set(organization_hierarchy.accounts)
    if target_id in organization_hierarchy.organizational_units:
        return accounts_under_ou(target_id, organization_hierarchy)
    if target_id in organization_hierarchy.accounts:
        return {target_id}
    raise RuntimeError(
        f"Target {target_id} is not the organization root, an OU, or an "
        f"account in the hierarchy"
    )


def _ancestor_ids(
    target_id: str,
    organization_hierarchy: OrganizationHierarchy
) -> Set[str]:
    """
    Return every target strictly above this one, the root included.

    Args:
        target_id: The organization root, an OU, or an account
        organization_hierarchy: Organization structure

    Returns:
        The IDs of the OUs above the target plus the organization root,
        empty when the target is the root itself
    """
    if target_id == organization_hierarchy.root_id:
        return set()
    if target_id in organization_hierarchy.accounts:
        parent = organization_hierarchy.accounts[target_id].parent_ou_id
    else:
        parent = organization_hierarchy.organizational_units[target_id].parent_ou_id
    above = set(
        ancestor_ou_ids(
            parent,
            organization_hierarchy.organizational_units,
            organization_hierarchy.root_id
        )
    )
    above.add(organization_hierarchy.root_id)
    return above


def _descendant_ids(
    target_id: str,
    organization_hierarchy: OrganizationHierarchy
) -> Set[str]:
    """
    Return every target strictly below this one.

    An account is a leaf, so an account file never has one - which is why
    shape 2 cannot arise there.

    Args:
        target_id: The organization root, an OU, or an account
        organization_hierarchy: Organization structure

    Returns:
        The IDs of the OUs and accounts beneath the target, empty for an
        account

    Raises:
        RuntimeError: If the ID names nothing in the hierarchy
    """
    if target_id == organization_hierarchy.root_id:
        return set(organization_hierarchy.organizational_units) | set(organization_hierarchy.accounts)
    if target_id in organization_hierarchy.organizational_units:
        below = set(
            ou_subtree_ids(target_id, organization_hierarchy.organizational_units)
        )
        below.discard(target_id)
        return below | accounts_under_ou(target_id, organization_hierarchy)
    if target_id in organization_hierarchy.accounts:
        return set()
    raise RuntimeError(
        f"Target {target_id} is not the organization root, an OU, or an "
        f"account in the hierarchy"
    )


def _describe_target(
    target_id: str,
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """
    Name a target for a comment: the root with its article, an OU by its
    root-down path, an account by name.

    Args:
        target_id: The organization root, an OU, or an account
        organization_hierarchy: Organization structure

    Returns:
        A phrase naming the target
    """
    if target_id == organization_hierarchy.root_id:
        return unbreakable("the organization root")
    if target_id in organization_hierarchy.organizational_units:
        path = " / ".join(
            ou_path_names(target_id, organization_hierarchy.organizational_units)
        )
        return unbreakable(f"OU {path}")
    return unbreakable(f"account {organization_hierarchy.accounts[target_id].account_name}")


def _describe_all(
    target_ids: Iterable[str],
    organization_hierarchy: OrganizationHierarchy
) -> List[str]:
    """
    Name several targets, sorted by the name rather than by the ID.

    Sorting on the rendered phrase is what makes two runs over one result
    set produce identical bytes, the way the parameter order already does.

    Args:
        target_ids: Targets to name
        organization_hierarchy: Organization structure

    Returns:
        The phrases, sorted
    """
    return sorted(
        _describe_target(target_id, organization_hierarchy)
        for target_id in target_ids
    )


MAX_NAMES_IN_A_COMMENT = 5


def _name_list(names: List[str]) -> str:
    """
    Join names for a comment, capping how many are spelled out.

    A comment must not scale with the size of the organization: these files
    are committed, and a five-hundred-account list would bury the fact the
    comment exists to state.

    Args:
        names: The names to list, already sorted

    Returns:
        The names, comma-separated, with a count standing in for the tail
    """
    if len(names) <= MAX_NAMES_IN_A_COMMENT:
        return ", ".join(names)
    listed = ", ".join(names[:MAX_NAMES_IN_A_COMMENT])
    return f"{listed}, and {len(names) - MAX_NAMES_IN_A_COMMENT} more"


def _blocked_clause(
    target_id: str,
    unsafe: FrozenSet[str],
    analyzed: FrozenSet[str],
    organization_hierarchy: OrganizationHierarchy,
    elsewhere: bool = False
) -> str:
    """
    Say which of the accounts a target reaches kept the check off.

    The clause collapses grammatically the way placement's own reasoning
    collapses its analyzed-of-reached counts. An account file gets the
    shortest form of all: it reaches one account, and that account is the
    one the filename already names.

    Args:
        target_id: The target being rendered
        unsafe: Accounts under the target the check judged unsafe
        analyzed: Accounts under the target the check judged at all
        organization_hierarchy: Organization structure, for account names
        elsewhere: True when shape 2 appends this clause after naming the
            targets below that already carry the check, so the violation
            reads as "blocked elsewhere" rather than "blocked"

    Returns:
        The clause, uncapitalized, so shape 2 can append it after a
        semicolon and shape 3 can capitalize it

    Raises:
        RuntimeError: If no account under the target is unsafe, which the
            placement traversal makes impossible for an unplaced target
    """
    # The traversal places a check at every target whose analyzed accounts
    # are all safe, so an unplaced target always has an unsafe one to name -
    # an account included, since a clean one takes a placement at itself.
    # Reaching here without one means the coverage map and the placements
    # disagree, and the clause would name nobody while blaming them.
    if not unsafe:
        raise RuntimeError(
            f"Target {target_id} carries no placement for this check yet no "
            f"unsafe account among the {len(analyzed)} analyzed under it - "
            f"the coverage map and the placements disagree"
        )

    lead = "blocked elsewhere by" if elsewhere else "blocked by"
    if target_id in organization_hierarchy.accounts:
        return f"{lead} this account's violations"

    names = sorted(
        organization_hierarchy.accounts[account_id].account_name
        for account_id in unsafe
    )
    named = _name_list([unbreakable(name) for name in names])
    if len(analyzed) == 1:
        return f"{lead} the only analyzed account ({named})"
    if len(unsafe) == len(analyzed):
        return f"{lead} all {len(analyzed)} analyzed accounts ({named})"
    return f"{lead} {len(unsafe)} of {len(analyzed)} analyzed accounts ({named})"


def _off_below_clause(
    off_below: FrozenSet[str],
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """
    Name the flipped placements below a target, as a clause to append.

    Args:
        off_below: The targets below this one carrying the check with an
            empty allowlist, possibly none
        organization_hierarchy: Organization structure

    Returns:
        "; off below at ..." naming them, or "" when there are none
    """
    if not off_below:
        return ""
    return f"; off below at {_name_list(_describe_all(off_below, organization_hierarchy))}"


def disabled_reasons(
    target_id: str,
    *,
    check_names: Sequence[str],
    placed: Mapping[str, FrozenSet[str]],
    coverage: Mapping[str, CheckCoverage],
    organization_hierarchy: OrganizationHierarchy,
    flipped: Mapping[str, FrozenSet[str]],
    flipped_comment: Mapping[str, str],
) -> Dict[str, List[str]]:
    """
    Say why each check renders false for one target.

    Exactly one of four shapes applies to every check that is not placed
    here, and the traversal that produced the placements is what makes them
    exclusive - a check enforced above required every analyzed account below
    it to be safe, so it can carry no violation and no placement further
    down.

    A placement an empty allowlist turned off (INV-06) enforces nothing, so
    it is none of the four shapes. Below such a placement the check's own
    comment renders instead, which stays true there because an empty union
    over a target's accounts is empty over any subset of them - unless
    nothing under the target was scanned, in which case shape 4 renders,
    because the comment describes what was observed and an unscanned target
    contributed nothing to that union (INV-01).

    Args:
        target_id: The organization root, an OU, or an account - the target
            whose file is being rendered
        check_names: Every check the module renders, in any order
        placed: Each check mapped to the target IDs carrying it and
            rendering true there
        coverage: Every registered check of this policy type, mapped to its
            coverage. A check that produced no result is present with empty
            sets; a name absent from the map raises
        organization_hierarchy: Organization structure
        flipped: Each check mapped to the target IDs carrying it and
            rendering false there anyway, because the allowlist its
            statement is scoped by came back empty
        flipped_comment: Each check in `flipped`, mapped to the comment its
            own registration gives for an empty allowlist

    Returns:
        Each check rendering false, mapped to the lines of its comment. A
        check placed at this target is absent, whether it renders true there
        or the empty allowlist turned it off - the renderer emits that
        check's own comment itself.

    Raises:
        RuntimeError: If target_id names nothing in the hierarchy
    """
    reached = _accounts_under(target_id, organization_hierarchy)
    ancestors = _ancestor_ids(target_id, organization_hierarchy)
    descendants = _descendant_ids(target_id, organization_hierarchy)
    reasons: Dict[str, List[str]] = {}

    for check_name in check_names:
        carried = placed.get(check_name, frozenset())
        if target_id in carried:
            continue

        # A recommendation for this target renders its own comment, so the
        # two mechanisms stay disjoint here the way an enabled one does.
        off = flipped.get(check_name, frozenset())
        if target_id in off:
            continue

        above = carried & ancestors
        if above:
            named = _name_list(_describe_all(above, organization_hierarchy))
            reasons[check_name] = wrap_comment(f"Enforced at {named}")
            continue

        # Both builders name every registered check of their policy type, so
        # a missing name is an assembly bug and never a check that scanned
        # nothing. Defaulting would answer it with shape 4, which reads
        # exactly like the honest answer, and a bare KeyError would escape
        # the run's failure handling as a traceback.
        if check_name not in coverage:
            raise RuntimeError(
                f"Coverage map names no check {check_name!r}. Both coverage "
                f"builders enter every registered check, so a missing name is a "
                f"map assembled wrong rather than a check that scanned nothing"
            )
        judged = coverage[check_name]
        analyzed = judged.analyzed_accounts & reached
        if not analyzed:
            reasons[check_name] = wrap_comment(NO_RESULTS)
            continue

        # A genuine enforcing ancestor wins over a flipped one, which is why
        # shape 1 is asked before both: a check can be placed at two targets
        # with only one of the two allowlists empty. Shape 4 is asked before
        # this one for a different reason. Shape 1 names where the policy
        # attaches, which is true of a target whatever was scanned under it,
        # but the flipped comment describes what the covered accounts held -
        # and a target nothing scanned contributed nothing to that empty
        # union, so repeating the sentence there would report absence of
        # evidence as evidence of safety (INV-01).
        if off & ancestors:
            reasons[check_name] = wrap_comment(flipped_comment[check_name])
            continue

        unsafe = judged.unsafe_accounts & reached
        below = carried & descendants
        # A flipped placement below enforces nothing, so the accounts under
        # it are protected nowhere. Shape 2 without it invites subtraction:
        # three analyzed, one blocking, one covered below, so the third must
        # be covered too. Shape 3 without it leaves the safe accounts in its
        # count unplaced - a safe account under an unplaced target sits under
        # some placement below, and were that placement live the target would
        # be shape 2 - so both shapes say where those accounts went.
        off_clause = _off_below_clause(off & descendants, organization_hierarchy)
        if below:
            named = _name_list(_describe_all(below, organization_hierarchy))
            clause = _blocked_clause(
                target_id, unsafe, analyzed, organization_hierarchy, elsewhere=True
            )
            reasons[check_name] = wrap_comment(f"Enforced below at {named}{off_clause}; {clause}")
            continue

        clause = _blocked_clause(target_id, unsafe, analyzed, organization_hierarchy)
        reasons[check_name] = wrap_comment(f"{clause[0].upper()}{clause[1:]}{off_clause}")

    return reasons
