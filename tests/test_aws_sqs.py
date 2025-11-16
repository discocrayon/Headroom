"""
Tests for headroom.aws.sqs module.
"""

import json
import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.sqs import (
    analyze_sqs_queue_policies,
    _extract_account_ids_from_principal,
    _check_for_wildcard_principal,
    _check_for_non_account_principals,
    _normalize_actions,
    UnknownPrincipalTypeError,
    UnsupportedPrincipalTypeError,
)


class TestExtractAccountIdsFromPrincipal:
    """Test _extract_account_ids_from_principal function."""

    def test_extract_from_arn(self) -> None:
        """Test extracting account ID from ARN format."""
        principal = "arn:aws:iam::111111111111:root"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111"}

    def test_extract_from_plain_account_id(self) -> None:
        """Test extracting plain 12-digit account ID."""
        principal = "222222222222"
        result = _extract_account_ids_from_principal(principal)
        assert result == {"222222222222"}

    def test_extract_from_list(self) -> None:
        """Test extracting from list of principals."""
        principal = [
            "arn:aws:iam::111111111111:root",
            "222222222222",
        ]
        result = _extract_account_ids_from_principal(principal)  # type: ignore[arg-type]
        assert result == {"111111111111", "222222222222"}

    def test_extract_from_dict_aws_key(self) -> None:
        """Test extracting from dict with AWS key."""
        principal = {
            "AWS": [
                "arn:aws:iam::333333333333:root",
                "444444444444"
            ]
        }
        result = _extract_account_ids_from_principal(principal)  # type: ignore[arg-type]
        assert result == {"333333333333", "444444444444"}

    def test_wildcard_returns_empty_set(self) -> None:
        """Test that wildcard principal returns empty set."""
        principal = "*"
        result = _extract_account_ids_from_principal(principal)
        assert result == set()

    def test_unknown_principal_type_raises_error(self) -> None:
        """Test that unknown principal type raises error."""
        principal = {"UnknownType": "value"}
        with pytest.raises(UnknownPrincipalTypeError):
            _extract_account_ids_from_principal(principal)  # type: ignore[arg-type]


class TestCheckForWildcardPrincipal:
    """Test _check_for_wildcard_principal function."""

    def test_string_wildcard(self) -> None:
        """Test detecting wildcard in string."""
        assert _check_for_wildcard_principal("*") is True

    def test_string_not_wildcard(self) -> None:
        """Test non-wildcard string."""
        assert _check_for_wildcard_principal("arn:aws:iam::111111111111:root") is False

    def test_list_with_wildcard(self) -> None:
        """Test detecting wildcard in list."""
        assert _check_for_wildcard_principal(["*", "arn:aws:iam::111111111111:root"]) is True

    def test_list_without_wildcard(self) -> None:
        """Test list without wildcard."""
        assert _check_for_wildcard_principal(["arn:aws:iam::111111111111:root"]) is False

    def test_dict_with_wildcard(self) -> None:
        """Test detecting wildcard in dict."""
        assert _check_for_wildcard_principal({"AWS": "*"}) is True

    def test_dict_without_wildcard(self) -> None:
        """Test dict without wildcard."""
        assert _check_for_wildcard_principal({"AWS": "arn:aws:iam::111111111111:root"}) is False


class TestCheckForNonAccountPrincipals:
    """Test _check_for_non_account_principals function."""

    def test_detects_federated_principal(self) -> None:
        """Test detecting Federated principal."""
        principal = {"Federated": "arn:aws:iam::111111111111:saml-provider/MyProvider"}
        assert _check_for_non_account_principals(principal) is True  # type: ignore[arg-type]

    def test_ignores_aws_principal(self) -> None:
        """Test that AWS principal is not flagged."""
        principal = {"AWS": "arn:aws:iam::111111111111:root"}
        assert _check_for_non_account_principals(principal) is False  # type: ignore[arg-type]

    def test_ignores_service_principal(self) -> None:
        """Test that Service principal is not flagged."""
        principal = {"Service": "sqs.amazonaws.com"}
        assert _check_for_non_account_principals(principal) is False  # type: ignore[arg-type]

    def test_mixed_with_federated(self) -> None:
        """Test mixed principals with Federated."""
        principal = {
            "AWS": "arn:aws:iam::111111111111:root",
            "Federated": "arn:aws:iam::111111111111:saml-provider/MyProvider"
        }
        assert _check_for_non_account_principals(principal) is True  # type: ignore[arg-type]


class TestNormalizeActions:
    """Test _normalize_actions function."""

    def test_string_action(self) -> None:
        """Test normalizing single string action."""
        result = _normalize_actions("sqs:SendMessage")
        assert result == {"sqs:SendMessage"}

    def test_list_actions(self) -> None:
        """Test normalizing list of actions."""
        result = _normalize_actions(["sqs:SendMessage", "sqs:ReceiveMessage"])
        assert result == {"sqs:SendMessage", "sqs:ReceiveMessage"}


class TestAnalyzeSQSQueuePolicies:
    """Test analyze_sqs_queue_policies function."""

    def test_single_queue_with_third_party(self) -> None:
        """Test analyzing single queue with third-party access."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"],
                "Resource": queue_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].queue_url == queue_url
        assert results[0].queue_arn == queue_arn
        assert results[0].region == "us-east-1"
        assert results[0].third_party_account_ids == {"222222222222"}
        assert results[0].has_wildcard_principal is False
        assert results[0].has_non_account_principals is False
        assert "222222222222" in results[0].actions_by_account
        assert results[0].actions_by_account["222222222222"] == {"sqs:SendMessage", "sqs:ReceiveMessage"}

    def test_queue_with_wildcard_principal(self) -> None:
        """Test queue with wildcard principal."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/public-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:public-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:*",
                "Resource": queue_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_queue_with_federated_principal_raises_error(self) -> None:
        """Test queue with Federated principal raises UnsupportedPrincipalTypeError."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/federated-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:federated-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "arn:aws:iam::111111111111:saml-provider/MyProvider"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}

        with pytest.raises(UnsupportedPrincipalTypeError) as exc_info:
            analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert "Federated principal" in str(exc_info.value)
        assert queue_arn in str(exc_info.value)

    def test_queue_without_policy_skipped(self) -> None:
        """Test queues without policies are skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/no-policy-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "QueueArn": "arn:aws:sqs:us-east-1:111111111111:no-policy-queue"
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_multiple_third_party_accounts(self) -> None:
        """Test queue with multiple third-party accounts."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/multi-party-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:multi-party-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::222222222222:root", "333333333333"]},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::444444444444:root"},
                    "Action": "sqs:ReceiveMessage",
                    "Resource": queue_arn
                }
            ]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"222222222222", "333333333333", "444444444444"}
        assert results[0].actions_by_account["222222222222"] == {"sqs:SendMessage"}
        assert results[0].actions_by_account["333333333333"] == {"sqs:SendMessage"}
        assert results[0].actions_by_account["444444444444"] == {"sqs:ReceiveMessage"}

    def test_multi_region_queues(self) -> None:
        """Test analyzing queues across multiple regions."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()

        mock_sqs_clients = {}
        for region in ["us-east-1", "us-west-2"]:
            mock_sqs_clients[region] = MagicMock()

        def client_factory(service: str, **kwargs: dict) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            return mock_sqs_clients[kwargs["region_name"]]  # type: ignore[index]

        mock_session.client.side_effect = client_factory

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        queue_url_east = "https://sqs.us-east-1.amazonaws.com/111111111111/queue-east"
        queue_arn_east = "arn:aws:sqs:us-east-1:111111111111:queue-east"

        queue_url_west = "https://sqs.us-west-2.amazonaws.com/111111111111/queue-west"
        queue_arn_west = "arn:aws:sqs:us-west-2:111111111111:queue-west"

        paginator_east = MagicMock()
        paginator_east.paginate.return_value = [{"QueueUrls": [queue_url_east]}]
        mock_sqs_clients["us-east-1"].get_paginator.return_value = paginator_east

        paginator_west = MagicMock()
        paginator_west.paginate.return_value = [{"QueueUrls": [queue_url_west]}]
        mock_sqs_clients["us-west-2"].get_paginator.return_value = paginator_west

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:*",
                "Resource": "*"
            }]
        }

        mock_sqs_clients["us-east-1"].get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn_east
            }
        }

        mock_sqs_clients["us-west-2"].get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn_west
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 2
        assert results[0].region == "us-east-1"
        assert results[1].region == "us-west-2"

    def test_access_denied_region_continues(self) -> None:
        """Test that AccessDenied in one region doesn't stop analysis."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()

        mock_sqs_clients = {}
        for region in ["us-east-1", "us-west-2"]:
            mock_sqs_clients[region] = MagicMock()

        def client_factory(service: str, **kwargs: dict) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            return mock_sqs_clients[kwargs["region_name"]]  # type: ignore[index]

        mock_session.client.side_effect = client_factory

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        paginator_east = MagicMock()
        paginator_east.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListQueues"
        )
        mock_sqs_clients["us-east-1"].get_paginator.return_value = paginator_east

        queue_url_west = "https://sqs.us-west-2.amazonaws.com/111111111111/queue-west"
        queue_arn_west = "arn:aws:sqs:us-west-2:111111111111:queue-west"

        paginator_west = MagicMock()
        paginator_west.paginate.return_value = [{"QueueUrls": [queue_url_west]}]
        mock_sqs_clients["us-west-2"].get_paginator.return_value = paginator_west

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:*",
                "Resource": queue_arn_west
            }]
        }

        mock_sqs_clients["us-west-2"].get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn_west
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].region == "us-west-2"

    def test_deny_statement_ignored(self) -> None:
        """Test that Deny statements are ignored."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                    "Action": "sqs:DeleteMessage",
                    "Resource": queue_arn
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn
                }
            ]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert "222222222222" in results[0].actions_by_account
        assert results[0].actions_by_account["222222222222"] == {"sqs:SendMessage"}
        assert "sqs:DeleteMessage" not in results[0].actions_by_account["222222222222"]

    def test_statement_not_as_list(self) -> None:
        """Test that Statement field as a dict (not list) is handled."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        # Statement as a dict instead of a list
        policy = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn
            }
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert "222222222222" in results[0].third_party_account_ids

    def test_missing_principal(self) -> None:
        """Test that statements without Principal are skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        # Statement without Principal
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": queue_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        # Should still return a result, but with no third-party accounts
        assert len(results) == 1
        assert len(results[0].third_party_account_ids) == 0
        assert not results[0].has_wildcard_principal
        assert not results[0].has_non_account_principals

    def test_get_paginator_fails_access_denied(self) -> None:
        """Test that AccessDenied errors from get_paginator are logged and handled."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_sqs_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListQueues"
        )

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_get_paginator_fails_non_access_denied(self) -> None:
        """Test that non-AccessDenied errors from get_paginator are logged and handled."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_sqs_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable"}},
            "ListQueues"
        )

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_paginate_fails_non_access_denied(self) -> None:
        """Test that non-AccessDenied errors from paginate are logged and handled."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable"}},
            "ListQueues"
        )
        mock_sqs_client.get_paginator.return_value = paginator

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_get_queue_attributes_fails(self) -> None:
        """Test that get_queue_attributes failures are handled gracefully."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.side_effect = ClientError(
            {"Error": {"Code": "InvalidParameterValue"}},
            "GetQueueAttributes"
        )

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_json_decode_error(self) -> None:
        """Test that JSON decode errors are handled gracefully."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        # Invalid JSON
        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": "{invalid json",
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 0
