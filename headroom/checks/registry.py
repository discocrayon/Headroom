"""
Check registry: the one place a check is described.

A check registers itself with `@register_check`, which records a frozen
`CheckDefinition` - the class, the name and type, the Terraform section its
parameters render under, and the allowlist its statement is scoped by, if
any. Every later stage reads the definition rather than naming the check:
collection and result writing iterate the registry, parsing reads each
allowlist's summary key from it, and both Terraform generators render from
`get_check_definitions`, so registering a check is the whole of wiring it
into the pipeline (INV-13).
"""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple, Type

from .base import BaseCheck
from ..constants import register_check_type as _register_check_type
from ..enums import CheckType, TerraformSection


@dataclass(frozen=True)
class Allowlist:
    """
    The allowlist a check's policy statement is scoped by.

    Attributes:
        summary_key: The `summary` key the check writes its observed values
            under. Parsing reads it and aborts when it is absent: an absent
            key and an empty list mean opposite things (INV-01)
        terraform_variable: The module variable the unioned values render
            into, written only when the check is enabled
        restores_account_ids: True when the values are ARNs carrying the
            owning account's ID. Parsing substitutes the account ID back in
            for `REDACTED`, and rendering rewrites the account field to the
            `${local.<name>_account_id}` reference for accounts in the
            hierarchy
        empty_allowlist_comment: When set, an empty allowlist leaves the
            statement off and this comment renders above it, because the
            empty list would deny everything or be rejected as malformed
            (INV-06). When None, the empty list renders as `[]` and the
            module omits the clause. The empty string is neither and is
            rejected at registration
    """
    summary_key: str
    terraform_variable: str
    restores_account_ids: bool = False
    empty_allowlist_comment: Optional[str] = None


@dataclass(frozen=True)
class CheckDefinition:
    """
    Everything the pipeline knows about one registered check.

    Attributes:
        check_class: The `BaseCheck` subclass collection instantiates
        check_name: The registered name, the results directory, and the
            Terraform boolean that enables the statement
        check_type: `scps` or `rcps`
        terraform_section: The section its parameters render under
        allowlist: The allowlist its statement is scoped by, or None
    """
    check_class: Type[BaseCheck]
    check_name: str
    check_type: str
    terraform_section: TerraformSection
    allowlist: Optional[Allowlist]


_CHECK_REGISTRY: Dict[str, CheckDefinition] = {}

# Render order. `TerraformSection` declaration order is the order a module's
# parameters are grouped in, so a section's rank is its position there.
_SECTION_RANK: Dict[TerraformSection, int] = {
    section: rank for rank, section in enumerate(TerraformSection)
}

# The two results directories a check can write into, which are the only two
# values `check_type` can take.
_CHECK_TYPES: Tuple[str, str] = (CheckType.SCPS.value, CheckType.RCPS.value)


def _validate_registration(
    check_class: Type[BaseCheck],
    check_name: str,
    check_type: str,
    allowlist: Optional[Allowlist],
) -> None:
    """
    Reject a registration the rest of the pipeline could not carry out.

    Called before anything is recorded, so a malformed check fails at import
    rather than part way through a run - or silently, as a statement that
    collects and places and then renders nowhere.

    Args:
        check_class: The class being registered
        check_name: Name the check is registering under
        check_type: Type of check (scps, rcps)
        allowlist: The allowlist the statement is scoped by, if any

    Raises:
        ValueError: If the name is taken or already claimed as an allowlist
            variable, the class is already registered under another name,
            the type is not a plain string or names no results directory, an
            RCP declares no allowlist, an allowlist is missing a field or
            carries an empty comment, or its Terraform variable is already
            claimed
    """
    if check_name in _CHECK_REGISTRY:
        raise ValueError(f"Check {check_name!r} is already registered")
    # The decorator stamps the name onto the class and the framework reads it
    # back from there, so a class registered twice would carry the second name
    # only and write the first name's results into the second's directory.
    for definition in _CHECK_REGISTRY.values():
        if definition.check_class is check_class:
            raise ValueError(
                f"Check {check_name!r} registers {check_class.__name__}, which is "
                f"already registered as {definition.check_name!r}; a class holds one CHECK_NAME"
            )
    # Check names and allowlist variables are one namespace: both render as
    # parameters of the same module, so either can collide with either. This
    # map answers both directions, and this registration's own name goes into
    # it below, so a check claiming its own name for its allowlist collides
    # with itself rather than with nothing.
    claimed_by: Dict[str, str] = {}
    for definition in _CHECK_REGISTRY.values():
        claimed_by[definition.check_name] = definition.check_name
        if definition.allowlist is not None:
            claimed_by[definition.allowlist.terraform_variable] = definition.check_name
    if check_name in claimed_by:
        raise ValueError(
            f"Check {check_name!r} is already claimed as the allowlist variable of {claimed_by[check_name]!r}"
        )
    claimed_by[check_name] = check_name
    # A CheckType member is a str, so it passes the membership test below and
    # every lookup that compares by equality. It does not format as one: the
    # result writer builds a check's directory by formatting the type in the
    # constants mirror, and a member there renders results/CheckType.SCPS/
    # while the parser reads results/scps/.
    if type(check_type) is not str:
        raise ValueError(
            f"Check {check_name!r} has check_type {check_type!r}, which is not "
            f"a plain string; pass 'scps' or 'rcps'"
        )
    if check_type not in _CHECK_TYPES:
        raise ValueError(
            f"Check {check_name!r} has unknown type {check_type!r}; expected 'scps' or 'rcps'"
        )
    if check_type == CheckType.RCPS.value and allowlist is None:
        raise ValueError(
            f"RCP check {check_name!r} declares no allowlist; "
            "RCP placement is built from one"
        )
    if allowlist is None:
        return
    if not allowlist.summary_key or not allowlist.terraform_variable:
        raise ValueError(
            f"Check {check_name!r} allowlist needs a summary_key and a terraform_variable"
        )
    # The renderer tests the comment for truth, so "" would render the empty
    # allowlist as [] while reading as though the author asked for the
    # statement to be turned off with a reason.
    if allowlist.empty_allowlist_comment == "":
        raise ValueError(
            f"Check {check_name!r} allowlist empty_allowlist_comment is empty; pass None "
            f"to render an empty allowlist as [], or a comment saying why the statement stays off"
        )
    variable = allowlist.terraform_variable
    if variable in claimed_by:
        raise ValueError(
            f"Check {check_name!r} allowlist variable {variable!r} is already claimed by {claimed_by[variable]!r}"
        )


def register_check(
    check_type: str,
    check_name: str,
    *,
    terraform_section: TerraformSection,
    allowlist: Optional[Allowlist] = None,
) -> Callable[[Type[BaseCheck]], Type[BaseCheck]]:
    """
    Decorator to register a check class under a complete definition.

    Args:
        check_type: Type of check (scps, rcps)
        check_name: Name of the check (deny_ec2_imds_v1, deny_sts_third_party_assumerole)
        terraform_section: Section the check's parameters render under
        allowlist: The allowlist the statement is scoped by, if any

    Returns:
        Decorator function that registers a check class

    Raises:
        ValueError: When the returned decorator is applied to a class, if the
            registration is malformed. Nothing is recorded in that case

    Usage:
        @register_check("scps", "deny_ec2_imds_v1", terraform_section=TerraformSection.EC2)
        class DenyEc2ImdsV1Check(BaseCheck):
            ...
    """
    def decorator(cls: Type[BaseCheck]) -> Type[BaseCheck]:
        _validate_registration(cls, check_name, check_type, allowlist)
        definition = CheckDefinition(
            check_class=cls,
            check_name=check_name,
            check_type=check_type,
            terraform_section=terraform_section,
            allowlist=allowlist,
        )
        _CHECK_REGISTRY[check_name] = definition
        cls.CHECK_NAME = check_name
        cls.CHECK_TYPE = check_type
        # Also register with constants module for write_results
        _register_check_type(check_name, check_type)
        return cls
    return decorator


def get_check_definition(check_name: str) -> CheckDefinition:
    """
    Get the complete definition of one registered check.

    Args:
        check_name: Name of the check

    Returns:
        The check's definition

    Raises:
        ValueError: If check name is not registered
    """
    if check_name not in _CHECK_REGISTRY:
        raise ValueError(f"Unknown check: {check_name}")
    return _CHECK_REGISTRY[check_name]


def _definitions_of_type(check_type: Optional[str]) -> List[CheckDefinition]:
    """
    Get the definitions of one type, or every definition.

    The definitions come back in registration order, which is module import
    order; the accessor that imposes render order is `get_check_definitions`.

    Args:
        check_type: Filter by check type (scps, rcps), or None for all

    Returns:
        List of check definitions

    Raises:
        ValueError: If check type is neither scps nor rcps. A misspelling
            would otherwise filter to nothing, and a caller iterating that
            runs no checks and writes no results (INV-01)
    """
    if check_type is None:
        return list(_CHECK_REGISTRY.values())
    if check_type not in _CHECK_TYPES:
        raise ValueError(f"Unknown check type: {check_type!r}; expected 'scps' or 'rcps'")
    return [
        definition
        for definition in _CHECK_REGISTRY.values()
        if definition.check_type == check_type
    ]


def get_check_definitions(check_type: str) -> List[CheckDefinition]:
    """
    Get every definition of one type, in render order.

    Render order is `TerraformSection` declaration order, then check name
    within a section. Registration order is module import order, and no
    generated file may depend on it (INV-13).

    Args:
        check_type: Type of check (scps, rcps)

    Returns:
        List of check definitions in render order

    Raises:
        ValueError: If check type is neither scps nor rcps
    """
    return sorted(
        _definitions_of_type(check_type),
        key=lambda definition: (
            _SECTION_RANK[definition.terraform_section],
            definition.check_name,
        ),
    )


def get_allowlist(check_name: str) -> Allowlist:
    """
    Get the allowlist one check's statement is scoped by.

    Args:
        check_name: Name of the check

    Returns:
        The check's allowlist

    Raises:
        ValueError: If check name is not registered, or the check declares no
            allowlist
    """
    allowlist = get_check_definition(check_name).allowlist
    if allowlist is None:
        raise ValueError(f"Check {check_name!r} declares no allowlist")
    return allowlist


def get_check_class(check_name: str) -> Type[BaseCheck]:
    """
    Get check class by name.

    Args:
        check_name: Name of the check

    Returns:
        Check class

    Raises:
        ValueError: If check name is not registered
    """
    return get_check_definition(check_name).check_class


def get_all_check_classes(check_type: Optional[str] = None) -> List[Type[BaseCheck]]:
    """
    Get all registered check classes, optionally filtered by type.

    Args:
        check_type: Filter by check type (scps, rcps), or None for all

    Returns:
        List of check classes

    Raises:
        ValueError: If check type is neither scps, rcps, nor None
    """
    return [definition.check_class for definition in _definitions_of_type(check_type)]


def get_check_names(check_type: Optional[str] = None) -> List[str]:
    """
    Get all check names, optionally filtered by type.

    Args:
        check_type: Filter by check type (scps, rcps), or None for all

    Returns:
        List of check names

    Raises:
        ValueError: If check type is neither scps, rcps, nor None
    """
    return [definition.check_name for definition in _definitions_of_type(check_type)]


def get_check_type_map() -> Dict[str, str]:
    """
    Get mapping of check names to check types.

    Returns:
        Dictionary mapping check names to check types (scps, rcps)
    """
    return {
        definition.check_name: definition.check_type
        for definition in _CHECK_REGISTRY.values()
    }
