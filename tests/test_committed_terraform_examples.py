"""
The committed Terraform under test_environment/ must still plan.

test_environment/scps/ and rcps/ are committed as worked examples of what a
run produces. Nothing compared them to the module they call, so they drifted:
three variables were added to the SCP module and to the generator, and the
three committed calls - last written before those variables existed - went on
omitting them. A module call missing a variable with no default is a call
`terraform plan` refuses, so the committed example could not be planned at
all.
"""
import re
from pathlib import Path
from typing import Set

import pytest

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
