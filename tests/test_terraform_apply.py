"""
Tests for terraform.apply: the only place Headroom mutates Terraform output.

Covers which files Headroom claims as its own, which it must never touch, and
that a preflight conflict anywhere stops every mutation everywhere.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Tuple

import pytest

from headroom.config import AccountTagLayout, HeadroomConfig
from headroom.constants import GENERATED_MARKER, ORG_INFO_FILENAME
from headroom.terraform.apply import apply_terraform_plan
from headroom.terraform.plan import TerraformPlan, compile_terraform_plan
from headroom.types import (
    AccountOrgPlacement,
    OrganizationHierarchy,
    OrganizationalUnit,
    SCPPlacementRecommendations,
)


def generated(body: str = 'module "x" {}\n') -> str:
    """Content carrying the marker Headroom stamps on its own output."""
    return f"{GENERATED_MARKER}\n{body}"


def dirs(tmp_path: Path) -> Tuple[Path, Path]:
    """The two managed directories, created and canonical."""
    scps = Path(os.path.abspath(tmp_path / "scps"))
    rcps = Path(os.path.abspath(tmp_path / "rcps"))
    scps.mkdir()
    rcps.mkdir()
    return scps, rcps


def plan_for(
    scps: Path,
    rcps: Path,
    files: Dict[Path, str],
) -> TerraformPlan:
    """A plan holding the given files plus the reserved link."""
    return TerraformPlan(
        managed_directories=(scps, rcps),
        files=files,
        symlinks={rcps / ORG_INFO_FILENAME: f"../{scps.name}/{ORG_INFO_FILENAME}"},
    )


def aliased_dirs(tmp_path: Path) -> Tuple[Path, Path]:
    """
    Two spellings of one directory: the RCP directory is a symlink to the SCP
    directory.

    A directory symlink pins the failure on every filesystem. The
    case-variant spelling that motivates this reaches the same inode too, but
    only where the filesystem is case-insensitive.
    """
    scps = Path(os.path.abspath(tmp_path / "scps"))
    rcps = Path(os.path.abspath(tmp_path / "rcps"))
    scps.mkdir()
    rcps.symlink_to(scps, target_is_directory=True)
    return scps, rcps


def org_with_one_ou() -> OrganizationHierarchy:
    """One OU holding one account, enough to place at every level."""
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={
            "ou-1111-11111111": OrganizationalUnit(
                ou_id="ou-1111-11111111",
                name="Test OU",
                parent_ou_id="r-1111",
                child_ous=[],
                accounts=["111111111111"],
            )
        },
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="payments",
                parent_ou_id="ou-1111-11111111",
                ou_path=["r-1111", "ou-1111-11111111"],
            )
        },
    )


def config_at(scps: Path, rcps: Path) -> HeadroomConfig:
    """A configuration pointing at two already-canonical directories."""
    return HeadroomConfig(
        management_account_id="111111111111",
        use_account_name_from_tags=False,
        account_tag_layout=AccountTagLayout(
            environment="Env", name="Name", owner="Owner"
        ),
        scps_dir=str(scps),
        rcps_dir=str(rcps),
    )


def scp_rec(
    level: str,
    target_ou_id: str | None = None,
    affected_accounts: list[str] | None = None,
) -> SCPPlacementRecommendations:
    return SCPPlacementRecommendations(
        check_name="deny-ec2-imds-v1",
        recommended_level=level,
        target_ou_id=target_ou_id,
        affected_accounts=affected_accounts if affected_accounts is not None else [],
        compliance_percentage=100.0,
        reasoning="test",
    )


def converge(recommendations: list, scps: Path, rcps: Path) -> None:
    """Compile SCP recommendations into a plan, then apply it."""
    apply_terraform_plan(compile_terraform_plan(
        config_at(scps, rcps), org_with_one_ou(), recommendations, [],
    ))


def test_one_unowned_destination_prevents_every_other_mutation(
    tmp_path: Path
) -> None:
    """
    Preflight is complete before anything is written, so a conflict on one
    file leaves the other files, the link, and the stale deletions all undone.
    """
    scps, rcps = dirs(tmp_path)
    hand_written = scps / "payments_scps.tf"
    hand_written.write_text('module "mine" {}\n')
    stale = scps / "retired_ou_scps.tf"
    stale.write_text(generated())

    plan = plan_for(scps, rcps, {
        scps / ORG_INFO_FILENAME: generated("# org info\n"),
        hand_written: generated("# regenerated\n"),
    })

    with pytest.raises(RuntimeError, match="does not own"):
        apply_terraform_plan(plan)

    assert hand_written.read_text() == 'module "mine" {}\n'
    assert not (scps / ORG_INFO_FILENAME).exists()
    assert stale.exists()
    assert not (rcps / ORG_INFO_FILENAME).exists()


def test_an_unmarked_file_at_the_link_path_survives(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    theirs = rcps / ORG_INFO_FILENAME
    theirs.write_text("# someone else's file\n")

    with pytest.raises(RuntimeError, match="does not own"):
        apply_terraform_plan(plan_for(scps, rcps, {}))

    assert not theirs.is_symlink()
    assert theirs.read_text() == "# someone else's file\n"


def test_a_marked_legacy_file_at_the_link_path_migrates(tmp_path: Path) -> None:
    """An earlier layout wrote a real file where the link now belongs."""
    scps, rcps = dirs(tmp_path)
    legacy = rcps / ORG_INFO_FILENAME
    legacy.write_text(generated("# copied org info\n"))

    apply_terraform_plan(plan_for(scps, rcps, {}))

    assert legacy.is_symlink()
    assert os.readlink(legacy) == f"../{scps.name}/{ORG_INFO_FILENAME}"


def test_a_correct_link_is_left_exactly_as_it_is(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    link = rcps / ORG_INFO_FILENAME
    link.symlink_to(Path("..") / scps.name / ORG_INFO_FILENAME)
    before = link.lstat().st_mtime_ns

    apply_terraform_plan(plan_for(scps, rcps, {}))

    assert link.lstat().st_mtime_ns == before


def test_an_incorrect_link_gets_the_relative_target(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    link = rcps / ORG_INFO_FILENAME
    link.symlink_to(Path("/somewhere/else/grab_org_info.tf"))

    apply_terraform_plan(plan_for(scps, rcps, {}))

    assert os.readlink(link) == f"../{scps.name}/{ORG_INFO_FILENAME}"


def test_an_unrelated_symlink_is_left_alone(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    unrelated = scps / "shared_modules.tf"
    unrelated.symlink_to(Path("..") / "modules" / "shared.tf")

    apply_terraform_plan(plan_for(scps, rcps, {}))

    assert unrelated.is_symlink()


def test_a_symlink_to_a_live_marked_file_is_left_alone(tmp_path: Path) -> None:
    """
    README.md promises every symlink but the reserved one is left alone. The
    dangling link above never reaches the ownership test -- `is_file` is
    already False -- so only a link whose target really exists and really
    carries the marker exercises the symlink check itself. Reading through
    such a link finds the marker and deletes an operator's link.
    """
    scps, rcps = dirs(tmp_path)
    modules = tmp_path / "modules"
    modules.mkdir()
    target = modules / "shared.tf"
    target.write_text(generated("# shared by hand\n"))
    operator_link = scps / "shared_modules.tf"
    operator_link.symlink_to(Path("..") / "modules" / "shared.tf")

    apply_terraform_plan(plan_for(scps, rcps, {}))

    assert operator_link.is_symlink()
    assert target.read_text() == generated("# shared by hand\n")


def test_stale_marked_files_are_deleted(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    stale = scps / "retired_ou_scps.tf"
    stale.write_text(generated())
    kept = scps / "payments_scps.tf"

    apply_terraform_plan(plan_for(scps, rcps, {kept: generated("# kept\n")}))

    assert not stale.exists()
    assert kept.exists()


def test_a_deleted_stale_file_is_named_in_the_log(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    The deletion log line is an operator's only record of what a run just
    destroyed. A message that stops naming the path would still satisfy "some
    INFO record exists" without that record being any use after the fact.
    """
    scps, rcps = dirs(tmp_path)
    stale = scps / "retired_ou_scps.tf"
    stale.write_text(generated())

    with caplog.at_level(logging.INFO, logger="headroom.terraform.apply"):
        apply_terraform_plan(plan_for(scps, rcps, {}))

    assert str(stale) in caplog.text


def test_a_converged_apply_produces_no_info_record(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    A no-op run must stay silent at INFO. The unchanged-file line logs at
    DEBUG precisely so a converged run does not read like one that just did
    work; this pins the level, not merely that some message exists.
    """
    scps, rcps = dirs(tmp_path)
    plan = plan_for(scps, rcps, {
        scps / "payments_scps.tf": generated("# payments\n"),
    })
    apply_terraform_plan(plan)

    with caplog.at_level(logging.INFO, logger="headroom.terraform.apply"):
        apply_terraform_plan(plan)

    assert caplog.text == ""


def test_unmanaged_files_are_never_deleted(tmp_path: Path) -> None:
    # test_environment/scps/README.md opens with "All of these files are
    # auto-generated by Headroom." A substring scan over every file deletes it.
    scps, rcps = dirs(tmp_path)
    readme = scps / "README.md"
    readme.write_text(
        f"All of these files are auto-generated by Headroom.\n{GENERATED_MARKER}\n"
    )
    handwritten = scps / "provider.tf"
    handwritten.write_text('provider "aws" {}\n')
    late_marker = scps / "late.tf"
    late_marker.write_text(f"# something else\n{GENERATED_MARKER}\n")
    binary = scps / "binary.tf"
    binary.write_bytes(b"\xff\xfe\x00\x01")

    apply_terraform_plan(plan_for(scps, rcps, {}))

    assert readme.exists()
    assert handwritten.exists()
    assert late_marker.exists()
    assert binary.exists()


def test_a_planned_destination_that_is_a_directory_aborts(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    (scps / "root_scps.tf").mkdir()

    with pytest.raises(RuntimeError, match="directory or other non-file"):
        apply_terraform_plan(plan_for(scps, rcps, {scps / "root_scps.tf": generated()}))


def test_a_planned_destination_that_is_a_symlink_aborts(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    (scps / "root_scps.tf").symlink_to(Path("..") / "elsewhere.tf")

    with pytest.raises(RuntimeError, match="is a symlink"):
        apply_terraform_plan(plan_for(scps, rcps, {scps / "root_scps.tf": generated()}))


def test_an_undecodable_planned_destination_aborts(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    (scps / "root_scps.tf").write_bytes(b"\xff\xfe\x00\x01")

    with pytest.raises(RuntimeError, match="first line is not"):
        apply_terraform_plan(plan_for(scps, rcps, {scps / "root_scps.tf": generated()}))


def test_every_conflict_is_reported_at_once(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    first = scps / "root_scps.tf"
    first.write_text('module "mine" {}\n')
    second = scps / "payments_scps.tf"
    second.write_text('module "also mine" {}\n')

    with pytest.raises(RuntimeError) as exc_info:
        apply_terraform_plan(plan_for(scps, rcps, {
            first: generated(), second: generated(),
        }))

    message = str(exc_info.value)
    assert str(first) in message
    assert str(second) in message
    assert "2 destination(s)" in message


def test_a_missing_managed_directory_is_created(tmp_path: Path) -> None:
    scps = Path(os.path.abspath(tmp_path / "scps"))
    rcps = Path(os.path.abspath(tmp_path / "rcps"))

    apply_terraform_plan(plan_for(scps, rcps, {
        scps / ORG_INFO_FILENAME: generated("# org info\n"),
    }))

    assert (scps / ORG_INFO_FILENAME).read_text() == generated("# org info\n")
    assert os.readlink(rcps / ORG_INFO_FILENAME) == f"../scps/{ORG_INFO_FILENAME}"


def test_two_identical_applies_preserve_metadata(tmp_path: Path) -> None:
    """
    An unchanged run must leave the filesystem alone: these directories are
    committed, and rewriting identical bytes turns every run into churn.
    """
    scps, rcps = dirs(tmp_path)
    plan = plan_for(scps, rcps, {
        scps / ORG_INFO_FILENAME: generated("# org info\n"),
        scps / "payments_scps.tf": generated("# payments\n"),
    })

    apply_terraform_plan(plan)
    before = {
        path: path.lstat().st_mtime_ns
        for path in sorted(scps.iterdir()) + sorted(rcps.iterdir())
    }

    apply_terraform_plan(plan)

    assert {
        path: path.lstat().st_mtime_ns
        for path in sorted(scps.iterdir()) + sorted(rcps.iterdir())
    } == before


def test_an_empty_plan_keeps_org_info_and_the_link_and_drops_the_policies(
    tmp_path: Path
) -> None:
    """
    Empty recommendations are a plan for directories holding only the shared
    data sources, not a no-op. This is how a policy that lost its placement
    stops being deployed.
    """
    scps, rcps = dirs(tmp_path)
    org_info = scps / ORG_INFO_FILENAME
    org_info.write_text(generated("# org info\n"))
    (scps / "payments_scps.tf").write_text(generated())
    (rcps / "payments_rcps.tf").write_text(generated())

    apply_terraform_plan(plan_for(scps, rcps, {org_info: generated("# org info\n")}))

    assert sorted(p.name for p in scps.iterdir()) == [ORG_INFO_FILENAME]
    assert sorted(p.name for p in rcps.iterdir()) == [ORG_INFO_FILENAME]
    assert (rcps / ORG_INFO_FILENAME).is_symlink()


def test_a_marked_file_whose_content_changed_is_rewritten(tmp_path: Path) -> None:
    """
    Ownership is proven by the marker, but staying unchanged still requires
    matching content: a changed recommendation must overwrite the old file,
    not be mistaken for nothing-to-do.
    """
    scps, rcps = dirs(tmp_path)
    changed = scps / "payments_scps.tf"
    changed.write_text(generated("# old\n"))

    apply_terraform_plan(plan_for(scps, rcps, {changed: generated("# new\n")}))

    assert changed.read_text() == generated("# new\n")


def test_a_directory_at_the_link_path_aborts(tmp_path: Path) -> None:
    scps, rcps = dirs(tmp_path)
    theirs = rcps / ORG_INFO_FILENAME
    theirs.mkdir()
    surprise = theirs / "not_ours.txt"
    surprise.write_text("do not touch\n")

    with pytest.raises(
        RuntimeError, match="directory where the shared org-info link belongs"
    ):
        apply_terraform_plan(plan_for(scps, rcps, {}))

    assert theirs.is_dir()
    assert surprise.read_text() == "do not touch\n"


def test_a_marked_file_that_cannot_be_read_to_compare_aborts(tmp_path: Path) -> None:
    """
    _first_line's readline() decodes only its first buffered chunk and
    returns as soon as it sees the marker line's newline; the later
    full-content comparison decodes the whole file and only then reaches an
    undecodable tail far past that chunk. A big enough real file reaches
    this branch on its own -- no need to fake a read failing.
    """
    scps, rcps = dirs(tmp_path)
    destination = scps / "payments_scps.tf"
    destination.write_bytes(
        f"{GENERATED_MARKER}\n".encode("utf-8") + b"x" * 200_000 + b"\xff\xfe"
    )

    with pytest.raises(RuntimeError, match="cannot be read to compare"):
        apply_terraform_plan(plan_for(scps, rcps, {destination: generated()}))


def test_a_to_delete_candidate_that_is_really_a_planned_write_survives(
    tmp_path: Path
) -> None:
    """
    A case-insensitive or Unicode-normalization-insensitive filesystem (APFS,
    the common case on macOS) can give a planned destination and a
    differently-spelled on-disk entry the same inode, so the glob-based
    stale scan finds what is really the file this run is about to write,
    under its other name, and would delete it right back out. Path equality
    cannot see that aliasing. Two names hard-linked to one inode pin the
    same failure deterministically, regardless of whether this test's own
    filesystem happens to be case- or normalization-insensitive.
    """
    scps, rcps = dirs(tmp_path)
    on_disk_name = scps / "existing_scps.tf"
    on_disk_name.write_text(generated("# old\n"))
    planned_name = scps / "planned_scps.tf"
    os.link(on_disk_name, planned_name)

    apply_terraform_plan(plan_for(scps, rcps, {planned_name: generated("# new\n")}))

    assert planned_name.read_text() == generated("# new\n")
    assert on_disk_name.exists()


def test_two_names_for_one_output_directory_abort_with_both_named(
    tmp_path: Path
) -> None:
    """
    The compiler compares the two output directories lexically, on purpose:
    it reads nothing, so the same plan validates identically everywhere. That
    comparison cannot see two paths reaching one inode, and applying such a
    plan writes the shared org-info file, unlinks it under the other
    spelling, and symlinks it to itself -- content gone, exit 0.
    """
    scps, rcps = aliased_dirs(tmp_path)
    earlier_run = scps / ORG_INFO_FILENAME
    earlier_run.write_text(generated("# an earlier run's org info\n"))

    with pytest.raises(RuntimeError) as exc_info:
        converge([], scps, rcps)

    message = str(exc_info.value)
    assert str(scps) in message
    assert str(rcps) in message
    assert "resolve to the same directory" in message
    assert earlier_run.read_text() == generated("# an earlier run's org info\n")


def test_two_names_for_one_output_directory_abort_before_any_deletion(
    tmp_path: Path
) -> None:
    """
    The stale scan globs both spellings, so one inode is listed twice and
    unlinked twice: the second unlink raises FileNotFoundError partway
    through the mutation phase, after the org-info file has already been
    destroyed.
    """
    scps, rcps = aliased_dirs(tmp_path)
    (scps / ORG_INFO_FILENAME).write_text(generated("# an earlier run's org info\n"))
    stale = scps / "retired_ou_scps.tf"
    stale.write_text(generated())

    with pytest.raises(RuntimeError, match="resolve to the same directory"):
        converge([], scps, rcps)

    assert stale.read_text() == generated()


def test_one_output_directory_under_two_names_joins_the_one_report(
    tmp_path: Path
) -> None:
    """
    An operator reads one report. The aliased directories are the cause of
    every filename collision that follows, so listing them beside the
    hand-edited files preflight also refused is what lets that operator fix
    the run in one pass instead of one error at a time.
    """
    scps, rcps = aliased_dirs(tmp_path)
    hand_written = scps / "root_scps.tf"
    hand_written.write_text('module "mine" {}\n')

    with pytest.raises(RuntimeError) as exc_info:
        converge([scp_rec("root")], scps, rcps)

    message = str(exc_info.value)
    assert "2 destination(s)" in message
    assert "resolve to the same directory" in message
    assert str(hand_written) in message
    assert hand_written.read_text() == 'module "mine" {}\n'


def test_output_directories_that_only_mkdir_makes_one_abort_before_any_write(
    tmp_path: Path
) -> None:
    """
    Neither directory exists yet, so there is nothing on disk for preflight
    to compare -- mkdir itself is what creates the alias. Checking again once
    the directories exist still happens before the first write, and mkdir
    destroys nothing.
    """
    real = tmp_path / "terraform"
    real.mkdir()
    (tmp_path / "aliased").symlink_to(real, target_is_directory=True)
    scps = Path(os.path.abspath(real / "scps"))
    rcps = Path(os.path.abspath(tmp_path / "aliased" / "scps"))

    with pytest.raises(RuntimeError, match="resolve to the same directory"):
        converge([], scps, rcps)

    assert list(scps.iterdir()) == []


def test_a_failed_write_leaves_stale_files_undeleted(tmp_path: Path) -> None:
    """
    Deleting last is what makes a stale file's removal conditional on the
    desired writes having succeeded: pins the ordering itself, not merely
    the end state of a run where nothing goes wrong.
    """
    scps, rcps = dirs(tmp_path)
    stale = scps / "retired_ou_scps.tf"
    stale.write_text(generated())
    unwritable = scps / "missing_parent" / "broken_scps.tf"

    with pytest.raises(OSError):
        apply_terraform_plan(plan_for(scps, rcps, {unwritable: generated()}))

    assert stale.exists()


# End-to-end convergence: compile, then apply what was compiled, twice. These
# are the scenarios that motivated reconciliation - each one leaves a file
# deploying a policy the current run did not ask for.
def test_moving_a_policy_from_root_to_an_account_drops_the_root_attachment(
    tmp_path: Path
) -> None:
    scps, rcps = dirs(tmp_path)
    converge([scp_rec("root")], scps, rcps)
    assert (scps / "root_scps.tf").exists()

    converge([scp_rec("account", affected_accounts=["111111111111"])], scps, rcps)

    assert not (scps / "root_scps.tf").exists()
    assert "deny_ec2_imds_v1 = true" in (scps / "payments_scps.tf").read_text()


def test_an_ou_losing_its_recommendation_loses_its_file(tmp_path: Path) -> None:
    # The check moves down to the account, which is what happens when another
    # account under the OU starts violating it. The OU-wide attachment must go,
    # or it keeps denying the account that just proved it cannot take the policy.
    scps, rcps = dirs(tmp_path)
    converge([scp_rec("ou", target_ou_id="ou-1111-11111111")], scps, rcps)
    assert (scps / "test_ou_ou_scps.tf").exists()

    converge([scp_rec("account", affected_accounts=["111111111111"])], scps, rcps)

    assert not (scps / "test_ou_ou_scps.tf").exists()
