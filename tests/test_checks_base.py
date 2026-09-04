"""
Tests for headroom.checks.base module.

Covers the summary fields BaseCheck.execute writes for every check,
independently of any one check's own fields.
"""

import time
from datetime import datetime
from typing import Iterator, List, cast
from unittest.mock import MagicMock, patch

import pytest
from boto3.session import Session

from headroom.checks.base import BaseCheck, CategorizedCheckResult
from headroom.enums import CheckCategory
from headroom.types import JsonDict


class StubCheck(BaseCheck[str]):
    """
    A check that makes no AWS calls, to exercise the base class alone.

    Writes the base document shape, as all nine SCP checks and one RCP
    check do.
    """

    CHECK_TYPE = "scps"

    def analyze(self, session: Session) -> List[str]:
        """Return one compliant resource without touching AWS."""
        return ["ami-11111111111111111"]

    def categorize_result(self, result: str) -> tuple[CheckCategory, JsonDict]:
        """Report every resource as compliant."""
        return CheckCategory.COMPLIANT, {"image_id": result}

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """Contribute only the violation count every check writes."""
        return {"violations": len(check_result.violations)}


class TwoListStubCheck(StubCheck):
    """
    A check that names its keys for what it scanned.

    Stands in for the six RCP checks that override `_build_results_data`,
    which receive a summary the base class has already built.
    """

    CHECK_TYPE = "rcps"

    def _build_results_data(self, check_result: CategorizedCheckResult) -> JsonDict:
        """Write the two-list shape in place of the base one."""
        return {
            "summary": check_result.summary,
            "keys_third_parties_can_access": [],
            "keys_with_wildcards": [],
        }


@pytest.fixture
def pacific_timezone(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """
    Run the test as though the scanning machine sits in US Pacific time.

    `scanned_at` renders in the local zone of whatever machine ran the scan,
    so the expected string is fixed only once that zone is.
    """
    monkeypatch.setenv("TZ", "America/Los_Angeles")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def write_results_for(check: StubCheck) -> JsonDict:
    """
    Run a check against a stub session and return what it would have written.

    Args:
        check: The check to execute

    Returns:
        The results_data dictionary handed to the writer
    """
    with (
        patch("headroom.checks.base.datetime") as mock_datetime,
        patch("headroom.checks.base.write_check_results") as mock_write,
    ):
        mock_datetime.now.return_value = datetime(2026, 9, 4, 16, 15)
        check.execute(MagicMock())
    results_data: JsonDict = mock_write.call_args[1]["results_data"]
    return results_data


class TestScannedAt:
    """The scan time every check records in its summary."""

    def test_execute_writes_the_scan_time_in_the_documented_format(
        self,
        pacific_timezone: None,
    ) -> None:
        """
        `summary.scanned_at` reads as the operator's wall clock.

        The expected string is written out rather than formatted, so the
        test and the code cannot agree by construction.
        """
        check = StubCheck(
            check_name="deny_ec2_ami_owner",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        summary = write_results_for(check)["summary"]

        assert summary == {
            "account_name": "security-tooling",
            "account_id": "111111111111",
            "check": "deny_ec2_ami_owner",
            "scanned_at": "09-04-2026 4:15 PM PDT",
            "violations": 0,
        }

    def test_the_two_list_shape_carries_the_scan_time_too(
        self,
        pacific_timezone: None,
    ) -> None:
        """
        Overriding `_build_results_data` does not drop the scan time.

        The six RCP checks that override it are handed a summary the base
        class built, so none of them has to remember the key.
        """
        check = TwoListStubCheck(
            check_name="deny_kms_third_party_access",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        summary = cast(JsonDict, write_results_for(check)["summary"])

        assert summary["scanned_at"] == "09-04-2026 4:15 PM PDT"
