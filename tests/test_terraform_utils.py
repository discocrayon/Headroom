"""
Tests for terraform.utils file writing.

Covers the write half of plan-then-apply: identical content must not touch the
filesystem, so a run that changes nothing leaves no trace.
"""

import logging
from pathlib import Path

import pytest

from headroom.terraform.utils import write_terraform_file, write_terraform_plan


def test_write_terraform_file_creates_the_file(tmp_path: Path) -> None:
    target = tmp_path / "root_scps.tf"

    write_terraform_file(target, "content\n", "SCP")

    assert target.read_text() == "content\n"


def test_write_terraform_file_leaves_identical_content_untouched(tmp_path: Path) -> None:
    target = tmp_path / "root_scps.tf"
    write_terraform_file(target, "content\n", "SCP")
    before = target.stat().st_mtime_ns

    write_terraform_file(target, "content\n", "SCP")

    assert target.stat().st_mtime_ns == before


def test_write_terraform_file_rewrites_changed_content(tmp_path: Path) -> None:
    target = tmp_path / "root_scps.tf"
    write_terraform_file(target, "before\n", "SCP")

    write_terraform_file(target, "after\n", "SCP")

    assert target.read_text() == "after\n"


def test_write_terraform_file_logs_only_when_it_writes(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    target = tmp_path / "root_scps.tf"
    write_terraform_file(target, "content\n", "SCP")

    with caplog.at_level(logging.INFO, logger="headroom.terraform.utils"):
        write_terraform_file(target, "content\n", "SCP")

    assert "Generated" not in caplog.text


def test_write_terraform_file_reports_an_unreadable_existing_file_as_changed(
    tmp_path: Path
) -> None:
    # A file we cannot decode cannot be compared, so it is rewritten rather
    # than silently left in place.
    target = tmp_path / "root_scps.tf"
    target.write_bytes(b"\xff\xfe\x00\x01")

    write_terraform_file(target, "content\n", "SCP")

    assert target.read_text() == "content\n"


def test_write_terraform_plan_writes_every_entry(tmp_path: Path) -> None:
    plan = {
        tmp_path / "root_scps.tf": "root\n",
        tmp_path / "acme_ou_scps.tf": "acme\n",
    }

    write_terraform_plan(plan, "SCP")

    assert {p.name: p.read_text() for p in tmp_path.iterdir()} == {
        "root_scps.tf": "root\n",
        "acme_ou_scps.tf": "acme\n",
    }


def test_write_terraform_plan_accepts_an_empty_plan(tmp_path: Path) -> None:
    write_terraform_plan({}, "SCP")

    assert not any(tmp_path.iterdir())
