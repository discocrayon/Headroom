"""
Tests for headroom.checks.scps.deny_ec2_imds_hop_limit module.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator

from headroom.checks.scps.deny_ec2_imds_hop_limit import DenyEc2ImdsHopLimitCheck
from headroom.constants import DENY_EC2_IMDS_HOP_LIMIT
from headroom.aws.ec2 import DenyEc2ImdsHopLimit


class TestCheckDenyEc2ImdsHopLimit:
    """Test deny_ec2_imds_hop_limit check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    def run_check(
        self,
        results: List[DenyEc2ImdsHopLimit],
        temp_results_dir: str,
    ) -> dict:
        """Execute the check against canned analysis results and return results_data."""
        mock_session = MagicMock()

        with (
            patch(
                "headroom.checks.scps.deny_ec2_imds_hop_limit.get_ec2_imds_hop_limit_analysis"
            ) as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyEc2ImdsHopLimitCheck(
                check_name=DENY_EC2_IMDS_HOP_LIMIT,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            assert mock_write.called
            results_data: dict = mock_write.call_args.kwargs["results_data"]
            return results_data

    def test_hop_limit_above_one_is_a_violation(self, temp_results_dir: str) -> None:
        """An instance with hop limit 2 and IMDS enabled is a violation."""
        results_data = self.run_check(
            [
                DenyEc2ImdsHopLimit(
                    region="us-east-1",
                    instance_id="i-11111111111111111",
                    hop_limit=2,
                    imds_enabled=True,
                )
            ],
            temp_results_dir,
        )

        assert len(results_data["violations"]) == 1
        assert results_data["violations"][0]["instance_id"] == "i-11111111111111111"
        assert results_data["violations"][0]["hop_limit"] == 2
        assert len(results_data["compliant_instances"]) == 0

    def test_hop_limit_of_one_is_compliant(self, temp_results_dir: str) -> None:
        """An instance at the maximum allowed hop limit of 1 is compliant."""
        results_data = self.run_check(
            [
                DenyEc2ImdsHopLimit(
                    region="us-east-1",
                    instance_id="i-22222222222222222",
                    hop_limit=1,
                    imds_enabled=True,
                )
            ],
            temp_results_dir,
        )

        assert len(results_data["violations"]) == 0
        assert len(results_data["compliant_instances"]) == 1

    def test_imds_disabled_is_still_a_violation_at_a_high_hop_limit(
        self, temp_results_dir: str
    ) -> None:
        """
        The hop limit is counted whether or not the endpoint is reachable.

        This test replaces one asserting the opposite, that a disabled endpoint
        made any hop limit compliant. That reading of the resource was right -
        no IMDS is listening, so no hop can cross - but it disagreed with the
        SCP, which reads the request. A dry run against a live account confirms
        MaxImdsHopLimit denies a launch specifying hop=3 alongside
        HttpEndpoint=disabled: AWS accepts the combination, so the condition
        key is present and NumericGreaterThan fires.

        Counting the hop limit unconditionally is the simpler of the two ways
        to close that gap, and it costs the operator nothing: lowering the hop
        limit on an instance whose metadata endpoint is off changes no
        behaviour, because nothing reads it.
        """
        results_data = self.run_check(
            [
                DenyEc2ImdsHopLimit(
                    region="us-west-2",
                    instance_id="i-33333333333333333",
                    hop_limit=3,
                    imds_enabled=False,
                )
            ],
            temp_results_dir,
        )

        assert len(results_data["violations"]) == 1
        assert len(results_data["compliant_instances"]) == 0
        assert results_data["violations"][0]["hop_limit"] == 3
        assert results_data["violations"][0]["imds_enabled"] is False

    def test_mixed_results_summary(self, temp_results_dir: str) -> None:
        """Summary counts and compliance percentage reflect a mixed fleet."""
        results_data = self.run_check(
            [
                DenyEc2ImdsHopLimit(
                    region="us-east-1",
                    instance_id="i-aaa",
                    hop_limit=2,
                    imds_enabled=True,
                ),
                DenyEc2ImdsHopLimit(
                    region="us-east-1",
                    instance_id="i-bbb",
                    hop_limit=1,
                    imds_enabled=True,
                ),
                DenyEc2ImdsHopLimit(
                    region="eu-west-1",
                    instance_id="i-ccc",
                    hop_limit=64,
                    imds_enabled=True,
                ),
            ],
            temp_results_dir,
        )

        summary = results_data["summary"]
        assert summary["total_instances"] == 3
        assert summary["violations"] == 2
        assert summary["compliant"] == 1
        assert summary["compliance_percentage"] == pytest.approx(33.33, rel=0.01)

    def test_all_compliant_reports_full_compliance(self, temp_results_dir: str) -> None:
        """A fleet entirely at hop limit 1 reports 100 percent compliance."""
        results_data = self.run_check(
            [
                DenyEc2ImdsHopLimit(
                    region="us-east-1",
                    instance_id="i-aaa",
                    hop_limit=1,
                    imds_enabled=True,
                ),
                DenyEc2ImdsHopLimit(
                    region="us-west-2",
                    instance_id="i-bbb",
                    hop_limit=1,
                    imds_enabled=True,
                ),
            ],
            temp_results_dir,
        )

        summary = results_data["summary"]
        assert summary["total_instances"] == 2
        assert summary["violations"] == 0
        assert summary["compliance_percentage"] == 100

    def test_no_instances_reports_full_compliance(self, temp_results_dir: str) -> None:
        """An account with no instances is fully compliant rather than a divide by zero."""
        results_data = self.run_check([], temp_results_dir)

        summary = results_data["summary"]
        assert summary["total_instances"] == 0
        assert summary["violations"] == 0
        assert summary["compliance_percentage"] == 100

    def test_result_dict_carries_all_fields(self, temp_results_dir: str) -> None:
        """Every analysis field is written through to the result record."""
        results_data = self.run_check(
            [
                DenyEc2ImdsHopLimit(
                    region="ap-southeast-1",
                    instance_id="i-ddd",
                    hop_limit=2,
                    imds_enabled=True,
                )
            ],
            temp_results_dir,
        )

        violation = results_data["violations"][0]
        assert violation == {
            "instance_id": "i-ddd",
            "region": "ap-southeast-1",
            "hop_limit": 2,
            "imds_enabled": True,
        }
