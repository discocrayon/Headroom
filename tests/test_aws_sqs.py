"""
Tests for headroom.aws.sqs module.
"""

import json
from typing import Any

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.sqs import (
    analyze_sqs_queue_policies,
)
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)
from tests.constants import ORG_ID


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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_a_federated_principal_blocks_the_queue_rather_than_the_run(self) -> None:
        """A Federated principal blocks the account rather than aborting the run."""
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

        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].queue_arn == queue_arn
        assert results[0].has_non_account_principals is True

    def test_a_canonical_user_blocks_the_queue_rather_than_the_run(self) -> None:
        """
        A canonical user ID names no account any allowlist can carry.

        SQS is the one of the five resource-policy analyzers with no
        CanonicalUser case, so this path was reachable and unpinned. The
        verdict must match the Federated one above: block the account, and
        let the other accounts' scans finish.
        """
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

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/canonical-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:canonical-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"CanonicalUser": "d" * 64},
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

        results = analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

        assert len(results) == 1
        assert results[0].queue_arn == queue_arn
        assert results[0].has_non_account_principals is True
        assert results[0].third_party_account_ids == set()

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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"222222222222", "333333333333", "444444444444"}
        assert results[0].actions_by_account["222222222222"] == {"sqs:SendMessage"}
        assert results[0].actions_by_account["333333333333"] == {"sqs:SendMessage"}
        assert results[0].actions_by_account["444444444444"] == {"sqs:ReceiveMessage"}

    def test_an_in_organization_grantee_is_not_recorded(self) -> None:
        """
        A grant to an account inside the organization is not a finding.

        The queue is still returned for the third party it also grants to,
        but the in-organization account belongs in neither the account set
        nor the action map. Keying it into the action map is what fed
        in-organization IDs into `actions_by_third_party_account` and
        `queues_by_third_party_account`, whose names promise the opposite.
        """
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

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/shared-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:shared-queue"

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
                    "Principal": {"AWS": "arn:aws:iam::555555555555:root"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
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

        org_account_ids = {"111111111111", "555555555555"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"222222222222"}
        assert results[0].actions_by_account == {"222222222222": {"sqs:ReceiveMessage"}}

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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 2
        assert results[0].region == "us-east-1"
        assert results[1].region == "us-west-2"

    def test_access_denied_in_one_region_aborts_the_run(self) -> None:
        """
        AccessDenied in one region aborts the whole analysis.

        The results of this check populate
        `sqs_third_party_access_account_ids_allowlist`, so a region that could
        not be read is indistinguishable from a region with no third-party
        access. Continuing would emit an allowlist missing every partner whose
        queues live only in the unreadable region, and deploying that RCP would
        deny them. Headroom requires its role to be exempt from region-allowlist
        SCPs, so an AccessDenied here is a real permissions gap, not an expected
        regional block.

        us-east-1 is analyzed first, so the later region proves the abort is
        immediate rather than deferred to the end of the loop.
        """
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

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"
        # The failure aborted before us-west-2 was touched at all.
        mock_sqs_clients["us-west-2"].get_paginator.assert_not_called()

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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert "222222222222" in results[0].third_party_account_ids

    def test_statement_neither_object_nor_list_raises(self) -> None:
        """A Statement of any other type aborts rather than reporting nothing."""
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

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps({"Version": "2012-10-17", "Statement": "Allow"}),
                "QueueArn": queue_arn
            }
        }

        with pytest.raises(MalformedPolicyError, match="Statement of type str"):
            analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

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
        results = analyze_sqs_queue_policies(mock_session, org_account_ids, ORG_ID)

        # Should still return a result, but with no third-party accounts
        assert len(results) == 1
        assert len(results[0].third_party_account_ids) == 0
        assert not results[0].has_wildcard_principal
        assert not results[0].has_non_account_principals

    def _single_region_session(self) -> tuple[MagicMock, MagicMock]:
        """Build a session mock wired to one region and return (session, sqs_client)."""
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
        return mock_session, mock_sqs_client

    def test_listing_queues_asks_for_a_page_size(self) -> None:
        """
        ListQueues is paginated only when the request carries MaxResults.

        SQS is the one API here that returns no NextToken unless the request
        set MaxResults, so a paginator that sends none reads a single page of
        at most 1000 queues and stops, silently. Queue 1001 is never read: a
        partner granted there is left out of the allowlist and denied on
        deploy, and a wildcard there lets the RCP deploy where it should be
        withheld (INV-01). botocore sends MaxResults only when PageSize is
        set, and 1000 is the largest value the API accepts.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": []}]
        mock_sqs_client.get_paginator.return_value = paginator

        analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

        paginator.paginate.assert_called_once_with(
            PaginationConfig={"PageSize": 1000}
        )

    def test_listing_queues_raises_on_access_denied(self) -> None:
        """
        AccessDenied while listing queues raises rather than returning nothing.

        Returning an empty list would report the region as having no queues with
        third-party access, which is the same value a genuinely empty region
        produces. Nothing downstream can tell the two apart.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListQueues"
        )
        mock_sqs_client.get_paginator.return_value = paginator

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_listing_queues_raises_on_service_error(self) -> None:
        """A transient service error is not silently reinterpreted as zero findings."""
        mock_session, mock_sqs_client = self._single_region_session()

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable"}},
            "ListQueues"
        )
        mock_sqs_client.get_paginator.return_value = paginator

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

        assert exc_info.value.response["Error"]["Code"] == "ServiceUnavailable"

    def test_get_paginator_failure_propagates(self) -> None:
        """
        A failure building the paginator propagates.

        `get_paginator` issues no API call, so this is defensive rather than
        reachable in practice. It is pinned so the path cannot regress into
        swallowing if that ever changes.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        mock_sqs_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListQueues"
        )

        with pytest.raises(ClientError):
            analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

    def test_reading_queue_attributes_raises(self) -> None:
        """
        A failure reading one queue's policy aborts rather than skipping it.

        Skipping drops that queue's third-party accounts from the allowlist,
        which is the failure this check exists to prevent.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "GetQueueAttributes"
        )

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_queue_deleted_during_scan_is_skipped(self) -> None:
        """
        A queue deleted between listing and reading is skipped, not fatal.

        This is the one benign reason a read fails: the queue is genuinely gone,
        so it holds no policy and can grant nobody access. Later queues are still
        analyzed, which distinguishes this from the aborting cases above.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        deleted_url = "https://sqs.us-east-1.amazonaws.com/111111111111/deleted"
        live_url = "https://sqs.us-east-1.amazonaws.com/111111111111/live"
        live_arn = "arn:aws:sqs:us-east-1:111111111111:live"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [deleted_url, live_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:SendMessage",
                "Resource": live_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.side_effect = [
            ClientError(
                {"Error": {"Code": "AWS.SimpleQueueService.NonExistentQueue"}},
                "GetQueueAttributes"
            ),
            {"Attributes": {"Policy": json.dumps(policy), "QueueArn": live_arn}},
        ]

        results = analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

        assert len(results) == 1
        assert results[0].queue_arn == live_arn
        assert results[0].third_party_account_ids == {"222222222222"}

    def test_json_decode_error_aborts_the_run(self) -> None:
        """
        An unparseable queue policy ends the run rather than being recorded.

        Recording the queue as clean would let the RCP deploy over whatever
        the policy actually grants, which is INV-01's case. The analyzer
        catches nothing here, so the JSONDecodeError ends the run, as it
        does from the other five resource-policy analyzers.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {"Policy": "{invalid json", "QueueArn": queue_arn}
        }

        with pytest.raises(json.JSONDecodeError):
            analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

    def test_an_undocumented_principal_key_aborts_the_run(self) -> None:
        """
        A key AWS could not have stored means Headroom misread the document.

        The statement walk reads service principal sources before it reaches
        the principal types that raise, so this queue's first statement has
        already yielded a guarded out-of-organization source when the second
        raises. That source dies with the raise, and so does every other
        account's result. Recording the queue instead once kept the run
        going, but left every field the deny_sqs_third_party_access check
        reads empty, which cleared the account on the strength of a queue
        nobody had read. Aborting is what the other five analyzers do.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/mixed"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:mixed"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": "999999999999"}
                    },
                },
                {
                    "Effect": "Allow",
                    "Principal": {"NotAThing": "whoever"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                },
            ],
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {"Policy": json.dumps(policy), "QueueArn": queue_arn}
        }

        with pytest.raises(
            UnknownPrincipalTypeError,
            match=r"Queue arn:aws:sqs:us-east-1:111111111111:mixed in us-east-1 names principal type\(s\) \['NotAThing'\]",
        ):
            analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)


class TestPolicyGrammar:
    """Policy elements the queue analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
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

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        return analyze_sqs_queue_policies(mock_session, {"111111111111"}, ORG_ID)

    def test_not_principal_is_read_as_a_wildcard(self) -> None:
        """
        An Allow with NotPrincipal grants to everyone it does not name.

        Skipping the statement for want of a Principal reported the queue
        clean, so the account kept its RCP and the grant's real audience -
        every account outside the exclusion list - lost access on apply.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111111111111:test-queue"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()

    def test_deny_with_not_principal_is_not_a_wildcard(self) -> None:
        """
        Deny with NotPrincipal restricts rather than grants.

        It is the form AWS recommends, and a resource policy's Deny cannot
        hand access to anyone, so it must not block the RCP. This analyzer
        reports every queue carrying a policy, so the queue is still
        returned - with nothing found on it.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111111111111:test-queue"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is False
        assert results[0].third_party_account_ids == set()

    def test_guarded_service_principal_is_recorded(self) -> None:
        """
        A queue policy pinning a third-party source records it.

        The account reaches the allowlist through the confused deputy
        check, not through this analysis's third_party_account_ids.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111111111111:test-queue",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "999999999999"}
                },
            }],
        })

        assert len(results[0].service_principal_sources) == 1
        source = results[0].service_principal_sources[0]
        assert source.service_principal == "sns.amazonaws.com"
        assert source.source_account_ids == ["999999999999"]

        # The source is inert here: it belongs to deny_service_confused_deputy,
        # and folding it into these fields would widen this check's allowlist
        # with an account that drives a service call rather than making one.
        assert results[0].third_party_account_ids == set()
        assert results[0].has_wildcard_principal is False

    def test_a_wildcard_pinned_to_a_topic_is_both_a_wildcard_and_a_source(self) -> None:
        """
        AWS's documented cross-account SNS subscription policy.

        `Principal: "*"` narrowed by `aws:SourceArn` to the topic. This
        check does not read Condition, so the queue is still a wildcard
        violation here; the topic's account reaches the confused deputy
        allowlist through the source, so that statement stays deployable.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111111111111:test-queue",
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": "arn:aws:sns:us-east-1:999999999999:a-topic"}
                },
            }],
        })

        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()
        assert len(results[0].service_principal_sources) == 1
        source = results[0].service_principal_sources[0]
        assert source.service_principal == "*"
        assert source.source_account_ids == ["999999999999"]

    def test_a_policy_with_no_service_principal_records_nothing(self) -> None:
        """The field stays empty when no statement names a service."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111111111111:test-queue"
            }],
        })

        assert results[0].service_principal_sources == []
