"""
The generated Terraform and the module it calls must agree in both directions.

test_environment/scps/ and rcps/ are committed as worked examples of what a
run produces. Nothing compared them to the module they call, so they drifted:
three variables were added to the SCP module and to the generator, and the
three committed calls - last written before those variables existed - went on
omitting them. A module call missing a variable with no default is a call
`terraform plan` refuses, so the committed example could not be planned at
all.

The other direction is the registry's: every check name and allowlist variable
a definition declares is an argument the generator passes, and a module that
does not declare it is a module `terraform plan` refuses with an unsupported
argument - after every test has passed, at the operator's desk.
"""
import re
from pathlib import Path
from typing import List, Set

import pytest

from headroom.checks.registry import _CHECK_REGISTRY, Allowlist, CheckDefinition, get_check_definitions
from headroom.checks.scps.deny_ec2_public_ip import DenyEc2PublicIpCheck
from headroom.enums import TerraformSection

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
TEST_ENVIRONMENT = REPOSITORY_ROOT / "test_environment"


def required_module_variables(variables_tf: Path) -> Set[str]:
    """
    Return the variables a module declares with no default.

    Brace counting rather than a regex over the whole block, because a
    validation block nests braces and a non-greedy match stops at the first
    inner close - which reported variables as required that carry a default.

    Args:
        variables_tf: A module's variables.tf

    Returns:
        The names Terraform will demand at plan time
    """
    required: Set[str] = set()
    name = None
    depth = 0
    has_default = False

    for line in variables_tf.read_text().splitlines():
        opening = re.match(r'variable\s+"([^"]+)"\s*\{', line)
        if opening and depth == 0:
            name, depth, has_default = opening.group(1), 1, False
            continue
        if name is None:
            continue
        if depth == 1 and re.match(r'\s*default\s*=', line):
            has_default = True
        depth += line.count("{") - line.count("}")
        if depth > 0:
            continue
        if not has_default:
            required.add(name)
        name = None

    return required


def variables_passed(module_call: Path) -> Set[str]:
    """
    Return the variable names a generated module call assigns.

    Args:
        module_call: One generated .tf file

    Returns:
        The names assigned at the module block's own indentation
    """
    return set(re.findall(r"^\s{2}([a-z_0-9]+)\s*=", module_call.read_text(), re.MULTILINE))


@pytest.mark.parametrize("policy_type", ["scps", "rcps"])
def test_every_committed_module_call_passes_every_required_variable(policy_type: str) -> None:
    """
    A call missing a required variable is a call terraform plan refuses.

    Three variables were added to the SCP module and to the generator; the
    committed calls predate them and omitted all three, so the worked
    example this repository ships could not be planned. Nothing noticed,
    because nothing compared a committed artifact to the module it calls.
    """
    required = required_module_variables(
        TEST_ENVIRONMENT / "modules" / policy_type / "variables.tf"
    )
    assert required, f"no required variables parsed from the {policy_type} module"

    calls = sorted((TEST_ENVIRONMENT / policy_type).glob(f"*_{policy_type}.tf"))
    assert calls, f"no committed {policy_type} module calls found"

    missing = {
        call.name: sorted(required - variables_passed(call))
        for call in calls
        if required - variables_passed(call)
    }

    assert missing == {}


def declared_module_variables(variables_tf: Path) -> Set[str]:
    """
    Return every variable a module declares, with or without a default.

    Args:
        variables_tf: A module's variables.tf

    Returns:
        The names the module accepts as arguments
    """
    return set(re.findall(r'^variable\s+"([^"]+)"\s*\{', variables_tf.read_text(), re.MULTILINE))


def undeclared_module_variables(policy_type: str) -> List[str]:
    """
    Report the registry's names for one policy type that its module does not declare.

    Every registered check name is passed as the module's boolean, and every
    allowlist's terraform_variable alongside it when the check is enabled, so
    each must be a variable the module declares. In render order, so the
    failure reads the way the module would.

    Args:
        policy_type: scps or rcps

    Returns:
        Check names and allowlist variables the module does not declare
    """
    declared = declared_module_variables(
        TEST_ENVIRONMENT / "modules" / policy_type / "variables.tf"
    )
    passed: List[str] = []
    for definition in get_check_definitions(policy_type):
        passed.append(definition.check_name)
        if definition.allowlist is not None:
            passed.append(definition.allowlist.terraform_variable)
    return [name for name in passed if name not in declared]


@pytest.mark.parametrize("policy_type", ["scps", "rcps"])
def test_every_registered_check_is_declared_by_its_module(policy_type: str) -> None:
    """
    A check the module does not declare is an argument terraform plan refuses.

    Registering a check is meant to be the whole of wiring it into the
    pipeline (INV-13), and the render guards prove the name reaches the
    module call. This is the step after: the module has to accept it. A
    check registered without its variable block passed every test and failed
    at the operator's terraform plan with an unsupported argument.
    """
    assert undeclared_module_variables(policy_type) == []


def test_the_declaration_guard_names_an_undeclared_check_and_its_allowlist(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The guard reports both names a definition would pass, in render order.

    A registered check whose variable block was never written is the case
    the guard exists for, and it cannot be reproduced against the committed
    module without breaking it, so a definition is registered here instead.
    """
    monkeypatch.setitem(
        _CHECK_REGISTRY,
        "deny_ec2_undeclared",
        CheckDefinition(
            check_class=DenyEc2PublicIpCheck,
            check_name="deny_ec2_undeclared",
            check_type="scps",
            terraform_section=TerraformSection.EC2,
            allowlist=Allowlist("unique_widgets", "ec2_allowed_widgets"),
        ),
    )

    assert undeclared_module_variables("scps") == ["deny_ec2_undeclared", "ec2_allowed_widgets"]


def statement_text(locals_tf: Path) -> str:
    """
    Return a module's locals.tf with its comment lines removed.

    The comment above each statement names the variable that gates it, so a
    match against the raw file would find the comment where no statement
    reads the variable.

    Args:
        locals_tf: A module's locals.tf

    Returns:
        The lines that are not comments, joined
    """
    return "\n".join(
        line for line in locals_tf.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


def unread_module_variables(policy_type: str) -> List[str]:
    """
    Report the registry's names for one policy type that no statement in its module reads.

    A check's boolean gates its statement as `include = var.<check name>`, and
    that statement reads the allowlist as `var.<terraform variable>`. A
    variable the module declares and no statement reads is an argument
    `terraform plan` accepts and the policy ignores, so the check would report
    its policy in place while the module attached nothing for it. In render
    order, so the failure reads the way the module would.

    Args:
        policy_type: scps or rcps

    Returns:
        Check names whose boolean gates no statement, and allowlist variables
        no statement reads
    """
    statements = statement_text(TEST_ENVIRONMENT / "modules" / policy_type / "locals.tf")
    unread: List[str] = []
    for definition in get_check_definitions(policy_type):
        if not re.search(rf"include\s*=\s*var\.{definition.check_name}\b", statements):
            unread.append(definition.check_name)
        if definition.allowlist is None:
            continue
        if not re.search(rf"\bvar\.{definition.allowlist.terraform_variable}\b", statements):
            unread.append(definition.allowlist.terraform_variable)
    return unread


@pytest.mark.parametrize("policy_type", ["scps", "rcps"])
def test_every_registered_check_is_read_by_a_statement(policy_type: str) -> None:
    """
    A declared variable no statement reads is a policy that silently omits the check.

    The declaration guard proves the module accepts the argument; this is the
    step after: a statement has to be gated by the boolean and, where the
    check declares one, read the allowlist. Neither guard reads the statement
    itself, so what it denies stays with the check specification.
    """
    assert unread_module_variables(policy_type) == []


def test_the_statement_guard_names_an_unread_check_and_its_allowlist(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The guard reports both names a definition would pass, in render order.

    A registered check with no statement in the module is the case the guard
    exists for, and it cannot be reproduced against the committed module
    without breaking it, so a definition is registered here instead.
    """
    monkeypatch.setitem(
        _CHECK_REGISTRY,
        "deny_ec2_unread",
        CheckDefinition(
            check_class=DenyEc2PublicIpCheck,
            check_name="deny_ec2_unread",
            check_type="scps",
            terraform_section=TerraformSection.EC2,
            allowlist=Allowlist("unique_gadgets", "ec2_allowed_gadgets"),
        ),
    )

    assert unread_module_variables("scps") == ["deny_ec2_unread", "ec2_allowed_gadgets"]


def test_statement_text_drops_the_comment_that_names_each_variable(tmp_path: Path) -> None:
    """
    The comment above a statement names the variable that gates it, so a
    match against the raw file would find the comment where no statement
    reads the variable.
    """
    locals_tf = tmp_path / "locals.tf"
    locals_tf.write_text("    # var.deny_ec2_commented\n    {\n      include = var.deny_ec2_read,\n")

    assert statement_text(locals_tf) == "    {\n      include = var.deny_ec2_read,"
