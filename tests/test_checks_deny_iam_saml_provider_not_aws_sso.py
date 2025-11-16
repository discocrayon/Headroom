"""Tests for headroom.checks.scps.deny_iam_saml_provider_not_aws_sso module."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3

from headroom.aws.iam import SamlProviderAnalysis
from headroom.checks.scps.deny_iam_saml_provider_not_aws_sso import (
    DenySamlProviderNotAwsSsoCheck,
)


class TestCheckDenySamlProviderNotAwsSso:
    """Test deny_iam_saml_provider_not_aws_sso check."""

    def test_single_awssso_provider_compliant(self, tmp_path: Path) -> None:
        """Test that a single AWS SSO provider is compliant."""
        check = DenySamlProviderNotAwsSsoCheck(
            check_name="deny_iam_saml_provider_not_aws_sso",
            account_name="test-account",
            account_id="111111111111",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=boto3.Session)
        awssso_provider = SamlProviderAnalysis(
            arn="arn:aws:iam::111111111111:saml-provider/AWSSSO_ABC123_us-east-1",
            name="AWSSSO_ABC123_us-east-1",
            create_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

        with patch(
            "headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.get_saml_providers_analysis"
        ) as mock_get_providers:
            mock_get_providers.return_value = [awssso_provider]
            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_saml_provider_not_aws_sso" / "test-account_111111111111.json"
        assert results_file.exists()

        with open(results_file) as file_handle:
            results = json.load(file_handle)

        summary = results["summary"]
        assert summary["total_saml_providers"] == 1
        assert summary["awssso_provider_count"] == 1
        assert summary["non_awssso_provider_count"] == 0
        assert summary["allowed_provider_arn"] == (
            "arn:aws:iam::111111111111:saml-provider/AWSSSO_ABC123_us-east-1"
        )
        assert summary["violating_provider_arns"] == []

        compliant_entries = results["compliant_instances"]
        assert len(compliant_entries) == 1
        compliant = compliant_entries[0]
        assert compliant["arn"] == awssso_provider.arn
        assert compliant["name"] == awssso_provider.name
        assert compliant["create_date"] == "2025-01-01T00:00:00+00:00"
        assert compliant["valid_until"] == "2026-01-01T00:00:00+00:00"
        assert "violation_reason" not in compliant
        assert results["violations"] == []

    def test_multiple_providers_violation(self, tmp_path: Path) -> None:
        """Test that multiple providers create violations."""
        check = DenySamlProviderNotAwsSsoCheck(
            check_name="deny_iam_saml_provider_not_aws_sso",
            account_name="test-account",
            account_id="111111111111",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=boto3.Session)
        awssso_provider = SamlProviderAnalysis(
            arn="arn:aws:iam::111111111111:saml-provider/AWSSSO_ABC123_us-east-1",
            name="AWSSSO_ABC123_us-east-1",
            create_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        custom_provider = SamlProviderAnalysis(
            arn="arn:aws:iam::111111111111:saml-provider/CustomProvider",
            name="CustomProvider",
            create_date=None,
            valid_until=None,
        )

        with patch(
            "headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.get_saml_providers_analysis"
        ) as mock_get_providers:
            mock_get_providers.return_value = [awssso_provider, custom_provider]
            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_saml_provider_not_aws_sso" / "test-account_111111111111.json"
        assert results_file.exists()

        with open(results_file) as file_handle:
            results = json.load(file_handle)

        summary = results["summary"]
        assert summary["total_saml_providers"] == 2
        assert summary["awssso_provider_count"] == 1
        assert summary["non_awssso_provider_count"] == 1
        assert summary["allowed_provider_arn"] is None
        assert summary["violating_provider_arns"] == [
            awssso_provider.arn,
            custom_provider.arn,
        ]

        violations = results["violations"]
        assert len(violations) == 2
        reasons = {violation["arn"]: violation["violation_reason"] for violation in violations}
        assert reasons[awssso_provider.arn] == "multiple_saml_providers_present"
        assert reasons[custom_provider.arn] == "provider_prefix_not_awssso"

        compliant_entries = results["compliant_instances"]
        assert compliant_entries == []

    def test_no_providers_summary(self, tmp_path: Path) -> None:
        """Test that summary is produced even when no providers exist."""
        check = DenySamlProviderNotAwsSsoCheck(
            check_name="deny_iam_saml_provider_not_aws_sso",
            account_name="test-account",
            account_id="111111111111",
            results_dir=str(tmp_path),
        )

        mock_session = MagicMock(spec=boto3.Session)

        with patch(
            "headroom.checks.scps.deny_iam_saml_provider_not_aws_sso.get_saml_providers_analysis"
        ) as mock_get_providers:
            mock_get_providers.return_value = []
            check.execute(mock_session)

        results_file = tmp_path / "scps" / "deny_iam_saml_provider_not_aws_sso" / "test-account_111111111111.json"
        assert results_file.exists()

        with open(results_file) as file_handle:
            results = json.load(file_handle)

        summary = results["summary"]
        assert summary["total_saml_providers"] == 0
        assert summary["awssso_provider_count"] == 0
        assert summary["non_awssso_provider_count"] == 0
        assert summary["allowed_provider_arn"] is None
        assert summary["violating_provider_arns"] == []
        assert results["violations"] == []
        assert results["compliant_instances"] == []
