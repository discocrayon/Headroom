"""
Tests for headroom.aws.aoss module.
"""

from unittest.mock import MagicMock

from boto3.session import Session
import pytest

from headroom.aws.aoss import analyze_aoss_resource_policies


class TestAnalyzeAossResourcePolicies:
    """
    Tests for the no-op OpenSearch Serverless analysis.
    """

    def test_returns_no_violations(self) -> None:
        """
        The helper should always return an empty list.
        """

        session = MagicMock(spec=Session)
        result = analyze_aoss_resource_policies(session, {"111111111111"})
        assert result == []

    def test_logs_skip_message(self, caplog: pytest.LogCaptureFixture) -> None:
        """
        The helper should log that analysis is being skipped.
        """

        session = MagicMock(spec=Session)
        with caplog.at_level("INFO"):
            analyze_aoss_resource_policies(session, {"111111111111"})

        assert "Skipping OpenSearch Serverless analysis" in caplog.text
