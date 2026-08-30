"""
Terraform Utility Functions

Shared utility functions used across the Terraform generation modules.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from .models import TerraformPlan
from ..types import OrganizationalUnit
from ..utils import make_safe_variable_name

logger = logging.getLogger(__name__)

__all__ = [
    "make_ou_base_names",
    "make_safe_variable_name",
    "ou_id_local_name",
    "ou_path_names",
    "write_terraform_file",
    "write_terraform_plan",
]

# Identifiers grab_org_info.tf already spends on the organization root. An OU
# canonicalizing to one of these would silently redefine it.
RESERVED_OU_BASE_NAMES = frozenset({"root"})


def ou_id_local_name(base_name: str) -> str:
    """
    Return the name of the local variable holding an OU's ID.

    Both sides of the contract call this: generate_org_info declares the
    local, generate_scps and generate_rcps reference it. Keeping the rule in
    one function is what stops a policy from targeting a local that nobody
    declared.

    Args:
        base_name: OU identifier from make_ou_base_names()

    Returns:
        Local variable name, without the "local." prefix
    """
    return f"{base_name}_ou_id"


def ou_path_names(
    ou_id: str,
    organizational_units: Dict[str, OrganizationalUnit]
) -> List[str]:
    """
    Return the names of the OUs from the top level down to this one.

    The walk stops at the first parent that is not itself an OU here, which is
    the organization root: analyze_organization_structure records a top-level
    OU's parent as None, and hierarchies assembled elsewhere sometimes record
    the root ID instead.

    Args:
        ou_id: OU to describe
        organizational_units: All OUs in the organization

    Returns:
        OU names, outermost first

    Raises:
        RuntimeError: If the parent chain loops
    """
    names: List[str] = []
    seen: Set[str] = set()
    current: Optional[str] = ou_id

    while current is not None and current in organizational_units:
        if current in seen:
            raise RuntimeError(
                f"OU hierarchy contains a cycle: {current} is its own ancestor"
            )
        seen.add(current)
        ou = organizational_units[current]
        names.append(ou.name)
        current = ou.parent_ou_id

    names.reverse()
    return names


def make_ou_base_names(
    organizational_units: Dict[str, OrganizationalUnit]
) -> Dict[str, str]:
    """
    Map every OU to the Terraform identifier that names it.

    An OU is named for its path down from the top level, so two OUs sharing a
    name under different parents stay apart. Everything generated for an OU -
    its ID local, its data sources, its policy file - is built from this one
    name, at every depth.

    Args:
        organizational_units: All OUs in the organization

    Returns:
        Dictionary mapping OU ID -> Terraform identifier

    Raises:
        RuntimeError: If two OUs canonicalize to the same identifier, if an
            identifier is one grab_org_info.tf already uses, or if a name
            reduces to nothing a Terraform identifier can be built from
    """
    base_names: Dict[str, str] = {}
    claimed_by: Dict[str, str] = {}

    for ou_id in sorted(organizational_units):
        path = ou_path_names(ou_id, organizational_units)
        base_name = make_safe_variable_name(" ".join(path))

        if not base_name:
            raise RuntimeError(
                f"OU {ou_id} (path '{' / '.join(path)}') has no name that can "
                "become a Terraform identifier"
            )
        if base_name in RESERVED_OU_BASE_NAMES:
            raise RuntimeError(
                f"OU {ou_id} (path '{' / '.join(path)}') claims the Terraform "
                f"identifier '{base_name}', which grab_org_info.tf already uses "
                "for the organization root. Rename the OU."
            )
        if base_name in claimed_by:
            raise RuntimeError(
                f"OUs {claimed_by[base_name]} and {ou_id} both claim the "
                f"Terraform identifier '{base_name}'. Their paths differ in "
                "characters that a Terraform identifier cannot keep. Rename one."
            )

        claimed_by[base_name] = ou_id
        base_names[ou_id] = base_name

    return base_names


def write_terraform_file(filepath: Path, content: str, policy_type: str) -> None:
    """
    Write Terraform content to a file, unless the file already says that.

    A run that changes nothing must leave the filesystem alone: these
    directories are committed, and rewriting identical bytes turns every run
    into apparent churn.

    Args:
        filepath: Path object for the file to write
        content: Terraform content to write
        policy_type: Type of policy being written (e.g., "SCP", "RCP")
    """
    try:
        if filepath.read_text() == content:
            logger.debug(f"Unchanged {policy_type} Terraform file: {filepath}")
            return
    except (OSError, UnicodeDecodeError):
        # Absent, or holding bytes that cannot be compared. Either way the
        # rendered content is what should be there.
        pass

    with open(filepath, 'w') as f:
        f.write(content)
    logger.info(f"Generated {policy_type} Terraform file: {filepath}")


def write_terraform_plan(plan: TerraformPlan, policy_type: str) -> None:
    """
    Write every file in a rendered plan.

    The plan is rendered in full before this is called, so a generation that
    raises partway through has replaced none of the previous output.

    Args:
        plan: Rendered file contents, keyed by destination path
        policy_type: Type of policy being written (e.g., "SCP", "RCP")
    """
    for filepath in sorted(plan):
        write_terraform_file(filepath, plan[filepath], policy_type)
