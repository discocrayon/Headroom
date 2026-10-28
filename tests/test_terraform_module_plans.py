"""
Each Terraform module plans, and renders what its specification says.

`terraform validate` accepted a conditional whose arms were objects keyed
`NotResource` and `Resource`, and `terraform plan` refused it: the list the
arm is built from is unknown at validate time, so `flatten()` left the arm
untyped, and known at plan time, where the two object types do not unify.
Two commits shipped on validate alone. Each module now carries
`tests/plan.tftest.hcl`, which plans the module with the real provider and
no credentials - `aws_iam_policy_document` is computed locally, and the one
data source that would call AWS is overridden - and asserts on the policy
document the provider renders. This file runs those files under `tox`, so
the gate is a plan rather than a hand-typed validate.

Running needs `terraform` on the PATH. The first `init` downloads the AWS
provider into the module's git-ignored `.terraform/`; later runs reuse it.
"""
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
MODULES_ROOT = REPOSITORY_ROOT / "test_environment" / "modules"
POLICY_MODULES = ("rcps", "scps")


def terraform_binary() -> str:
    """
    The terraform executable on the PATH.

    A missing binary fails rather than skips: a skip would report the
    modules as planned when nothing ran, which is the absence-of-evidence
    reading INV-01 forbids.

    Returns:
        The executable to run

    Raises:
        Failed: If no terraform is on the PATH
    """
    binary = shutil.which("terraform")
    if binary is None:
        pytest.fail("terraform is not on the PATH, so the module plan tests cannot run; install it and re-run tox")
    return binary


def declared_runs(module: Path) -> int:
    """
    Count the `run` blocks across a module's test files.

    Args:
        module: The module directory

    Returns:
        How many runs `terraform test` must report passed
    """
    return sum(
        len(re.findall(r'^run "', test_file.read_text(), re.MULTILINE))
        for test_file in sorted((module / "tests").glob("*.tftest.hcl"))
    )


def run_terraform(binary: str, module: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """
    Run one terraform command in a module directory.

    Args:
        binary: The executable
        module: The module directory to run in
        *arguments: The subcommand and its flags

    Returns:
        The completed process, output captured
    """
    # No stdin: terraform itself is told not to ask by `-input=false`, and a
    # wrapper script on the PATH that prompts before running the binary
    # reads end-of-file and has to decide on its own rather than hang the
    # suite waiting on a terminal.
    return subprocess.run(
        [binary, *arguments, "-no-color"],
        cwd=module,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("module_name", POLICY_MODULES)
def test_every_run_in_the_module_plan_tests_passes(module_name: str) -> None:
    """
    `terraform test` passes every run the module's test files declare.

    The passed count is compared with the declared count rather than the
    exit status alone, because `terraform test` with no test file exits 0
    and reports nothing passed.
    """
    module = MODULES_ROOT / module_name
    expected = declared_runs(module)
    assert expected > 0, f"{module_name} declares no run block under tests/"

    binary = terraform_binary()
    init = run_terraform(binary, module, "init", "-input=false")
    assert init.returncode == 0, init.stdout + init.stderr
    result = run_terraform(binary, module, "test")
    assert result.returncode == 0, result.stdout + result.stderr

    summary = re.search(r"Success! (\d+) passed, 0 failed\.", result.stdout)
    assert summary is not None, result.stdout
    assert int(summary.group(1)) == expected


def test_a_missing_terraform_fails_rather_than_skips() -> None:
    """
    No terraform on the PATH is a failure, not a skip.
    """
    with (
        patch("shutil.which", return_value=None),
        pytest.raises(pytest.fail.Exception, match="terraform is not on the PATH"),
    ):
        terraform_binary()
