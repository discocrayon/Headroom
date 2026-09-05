"""
The one renderer that turns check definitions into module parameters.

Both generators call `render_check_parameters` with the definitions of
their policy type, in the order `get_check_definitions` supplies, and a
map of the checks their recommendations enable. Nothing here names a
check (INV-13).
"""

import logging
from itertools import groupby
from typing import Dict, List, Mapping, Optional, Sequence

from .models import TerraformComment, TerraformElement, TerraformParameter, hcl_escape, wrap_comment
from .utils import account_id_local_name
from ..checks.registry import CheckDefinition
from ..enums import TerraformSection
from ..types import OrganizationHierarchy
from ..utils import make_safe_variable_name

logger = logging.getLogger(__name__)


def renders_enabled(
    definition: CheckDefinition,
    values: Optional[List[str]]
) -> bool:
    """
    Say whether a recommendation for this check actually renders enabled.

    A check whose statement takes no allowlist always does. One that takes
    an allowlist and observed nothing renders disabled where the check
    declares a comment for that case, because an empty allowlist denies
    everything rather than narrowing anything (INV-06).

    Args:
        definition: The check being rendered
        values: The allowlist values its recommendation carries

    Returns:
        True where the boolean renders true

    Raises:
        RuntimeError: If the check declares an allowlist and values is None,
            which is lost data rather than an observed-empty allowlist
    """
    allowlist = definition.allowlist
    if allowlist is None:
        return True
    # Parsing gives a declaring check a list, empty when the covered accounts
    # observed nothing, or aborts before placement (INV-01). The generators
    # ask this to split placements into live and flipped before any module
    # is built, so reading None as empty here would file the placement as
    # flipped and compute every other module's comments from that.
    if values is None:
        raise RuntimeError(
            f"{definition.check_name} declares an allowlist but its recommendation "
            f"carries None instead of a list - an observed-empty allowlist is []."
        )
    if values:
        return True
    return not allowlist.empty_allowlist_comment


def empty_allowlist_comments(
    definitions: Sequence[CheckDefinition]
) -> Dict[str, str]:
    """
    Map each check that keeps its statement off on an empty allowlist to why.

    These are the checks `renders_enabled` can answer False for, and the
    sentence each one wrote for that case. A generator hands the map to
    `disabled_reasons`, which reads a check name only as data (INV-13), so
    the targets below a flipped placement can say what the flipped target's
    own file says.

    Args:
        definitions: Every definition of one policy type

    Returns:
        Each declaring check's name, mapped to its comment. A check whose
        statement takes no allowlist, or whose empty allowlist renders as
        `[]`, is absent
    """
    comments: Dict[str, str] = {}
    for definition in definitions:
        allowlist = definition.allowlist
        if allowlist is None:
            continue
        if not allowlist.empty_allowlist_comment:
            continue
        comments[definition.check_name] = allowlist.empty_allowlist_comment
    return comments


def _definition_section(definition: CheckDefinition) -> TerraformSection:
    """
    Name the section a definition's parameters render under.

    `groupby` needs a key function and a nested one is not allowed here, so
    the key lives at module level where its types stay exact.

    Args:
        definition: The definition being grouped

    Returns:
        The definition's Terraform section
    """
    return definition.terraform_section


def _replace_account_id_in_arn(
    arn: str,
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """
    Replace an ARN's account ID with the account's Terraform local reference.

    Reads the account field, whatever service the ARN names: a definition
    setting `restores_account_ids` promises that field is rewritten for every
    account in the hierarchy, and a rewrite that knew only IAM would commit a
    KMS or SQS allowlist's real account IDs into Terraform. An ARN naming an
    account outside the hierarchy, one with no account field, and a value
    that is not an ARN all keep their text.

    The result is HCL template text, not data: the reference must stay live,
    so the allowlist renders with `template=True` and the escaping
    `TerraformParameter` would otherwise apply is done here, on every
    segment but the reference. An IAM user name cannot hold a character that
    needs it, but the path before it admits any printable ASCII character,
    `${` and `"` included, so the escape is live. A value the rewrite leaves
    alone is escaped the same way, since it renders under the same flag.

    Args:
        arn: One allowlist value (e.g., "arn:aws:iam::111111111111:user/path/username")
        organization_hierarchy: Organization structure for account ID lookups

    Returns:
        The value's segments escaped as data, with the account field replaced
        by a local variable reference where the hierarchy holds the account
        (e.g., "arn:aws:iam::${local.account_name_account_id}:user/path/username")
    """
    parts = arn.split(":")
    escaped = [hcl_escape(part) for part in parts]
    is_arn = len(parts) >= 5 and parts[0] == "arn"
    account_info = organization_hierarchy.accounts.get(parts[4]) if is_arn else None
    if account_info is not None:
        safe_account_name = make_safe_variable_name(account_info.account_name)
        escaped[4] = f"${{local.{account_id_local_name(safe_account_name)}}}"
    return ":".join(escaped)


def _render_definition(
    definition: CheckDefinition,
    *,
    allowlists: Mapping[str, Optional[List[str]]],
    module_name: str,
    organization_hierarchy: OrganizationHierarchy,
    reasons: Mapping[str, List[str]],
) -> List[TerraformElement]:
    """
    Render the parameters of one check.

    Args:
        definition: The check being rendered
        allowlists: Each check this module enables, mapped to the values its
            allowlist carries - None for a check whose statement takes no
            allowlist; a list, possibly empty, for one that does. A check
            absent from the map renders disabled
        module_name: Terraform module being built, named in the warning and
            the error
        organization_hierarchy: Organization structure, for rewriting
            account IDs in ARN allowlists to generated locals
        reasons: Each check rendering false, mapped to the lines of the
            comment saying why, already wrapped. A check with a
            recommendation for this target is absent.

    Returns:
        The check's boolean, preceded by an explanatory comment and followed
        by its allowlist where those apply

    Raises:
        RuntimeError: If this check declares an allowlist and its
            recommendation carries None rather than a list, or if it is
            enabled here and the reasons map names it anyway
    """
    explanation: List[TerraformElement] = [
        TerraformComment(line) for line in reasons.get(definition.check_name, [])
    ]

    recommended = definition.check_name in allowlists
    # The reasons map holds the checks with no recommendation here and the
    # allowlists map the checks with one, so a name in both means the two
    # were assembled from different placements - and rendering both would
    # put a reason for being off above `= true`.
    if recommended and definition.check_name in reasons:
        raise RuntimeError(
            f"Module {module_name}: {definition.check_name} is enabled here and also "
            f"carries a reason for being off - the placements and the reasons disagree"
        )
    allowlist = definition.allowlist
    if allowlist is None or not recommended:
        return explanation + [TerraformParameter(definition.check_name, recommended)]

    values = allowlists[definition.check_name]
    # Parsing gives a declaring check a list, empty when the covered accounts
    # observed nothing, or aborts before placement (INV-01). None here is
    # lost data, and rendering it as empty would turn the statement off over
    # a bug rather than over a fact about the organization.
    if values is None:
        raise RuntimeError(
            f"Module {module_name}: {definition.check_name} declares an allowlist but "
            f"its recommendation carries None instead of a list - an observed-empty "
            f"allowlist is []."
        )

    if allowlist.restores_account_ids:
        values = [
            _replace_account_id_in_arn(value, organization_hierarchy)
            for value in values
        ]

    elements: List[TerraformElement] = explanation

    # An empty allowlist is not a narrower statement. It is one that denies
    # everything, or one Organizations rejects as malformed, so a check
    # declaring a comment for that case stays off and says why (INV-06). The
    # comment is the check's own sentence, wrapped to the width every other
    # comment in the file is wrapped to.
    enabled = renders_enabled(definition, values)
    comment = allowlist.empty_allowlist_comment
    if not enabled and comment:
        logger.warning(f"Module {module_name}: {comment}")
        elements.extend(TerraformComment(line) for line in wrap_comment(comment))

    elements.append(TerraformParameter(definition.check_name, enabled))
    if enabled:
        # A restored allowlist is template text: the rewrite escaped its data
        # and inserted the one interpolation that must survive rendering.
        elements.append(
            TerraformParameter(allowlist.terraform_variable, values, template=allowlist.restores_account_ids)
        )
    return elements


def render_check_parameters(
    definitions: List[CheckDefinition],
    *,
    allowlists: Mapping[str, Optional[List[str]]],
    module_name: str,
    organization_hierarchy: OrganizationHierarchy,
    reasons: Mapping[str, List[str]],
) -> List[TerraformElement]:
    """
    Render one module's parameters from its definitions.

    Args:
        definitions: Every definition of this module's policy type, already
            in render order
        allowlists: Each check this module enables, mapped to the values its
            allowlist carries - None for a check whose statement takes no
            allowlist; a list, possibly empty, for one that does. A check
            absent from the map renders disabled
        module_name: Terraform module being built, named in the warning and
            the error
        organization_hierarchy: Organization structure, for rewriting
            account IDs in ARN allowlists to generated locals
        reasons: Each check rendering false, mapped to the lines of the
            comment saying why, already wrapped. A check with a
            recommendation for this target is absent.

    Returns:
        Section comments, booleans, and allowlists in render order

    Raises:
        RuntimeError: If `allowlists` names a check no definition describes,
            or carries None for a check that declares an allowlist
    """
    described = {definition.check_name for definition in definitions}
    for check_name in allowlists:
        if check_name in described:
            continue
        raise RuntimeError(
            f"Module {module_name} was given a recommendation for {check_name}, "
            f"which no registered check describes"
        )

    elements: List[TerraformElement] = []

    # The definitions arrive in render order, so adjacent runs are the
    # sections. A blank line goes between two sections and never above the
    # first one, where it would leave a gap under the module's header.
    for index, (section, group) in enumerate(groupby(definitions, key=_definition_section)):
        if index:
            elements.append(TerraformComment(""))
        elements.append(TerraformComment(section.value))
        for definition in group:
            elements.extend(
                _render_definition(
                    definition,
                    allowlists=allowlists,
                    module_name=module_name,
                    organization_hierarchy=organization_hierarchy,
                    reasons=reasons,
                )
            )

    return elements
