"""
Tests for headroom.aws.s3 module.
"""

import json
from typing import Any

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.s3 import (
    ALL_USERS_GROUP_URI,
    AUTHENTICATED_USERS_GROUP_URI,
    LOG_DELIVERY_GROUP_URI,
    analyze_s3_bucket_policies,
    _extract_account_ids_from_principal,
    _has_wildcard_principal,
    _normalize_actions,
    UnknownGranteeTypeError,
    UnknownPrincipalTypeError,
)
from headroom.aws.policy_documents import MalformedPolicyError


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
        result = _extract_account_ids_from_principal(principal)
        assert result == {"111111111111", "222222222222"}

    def test_extract_from_dict_aws_key(self) -> None:
        """Test extracting from dict with AWS key."""
        principal = {
            "AWS": [
                "arn:aws:iam::333333333333:root",
                "444444444444"
            ]
        }
        result = _extract_account_ids_from_principal(principal)
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
            _extract_account_ids_from_principal(principal)


class TestHasWildcardPrincipal:
    """Test _has_wildcard_principal function."""

    def test_string_wildcard(self) -> None:
        """Test detecting wildcard in string."""
        assert _has_wildcard_principal("*") is True

    def test_string_not_wildcard(self) -> None:
        """Test non-wildcard string."""
        assert _has_wildcard_principal("arn:aws:iam::111111111111:root") is False

    def test_list_with_wildcard(self) -> None:
        """Test detecting wildcard in list."""
        assert _has_wildcard_principal(["*", "arn:aws:iam::111111111111:root"]) is True

    def test_list_without_wildcard(self) -> None:
        """Test list without wildcard."""
        assert _has_wildcard_principal(["arn:aws:iam::111111111111:root"]) is False

    def test_dict_with_wildcard(self) -> None:
        """Test detecting wildcard in dict."""
        assert _has_wildcard_principal({"AWS": "*"}) is True

    def test_dict_without_wildcard(self) -> None:
        """Test dict without wildcard."""
        assert _has_wildcard_principal({"AWS": "arn:aws:iam::111111111111:root"}) is False


class TestHasNonAccountPrincipals:
    """Test _has_non_account_principals function."""

    def test_detects_federated_principal(self) -> None:
        """Test detecting Federated principal."""
        from headroom.aws.s3 import _has_non_account_principals
        principal = {"Federated": "arn:aws:iam::555555555555:saml-provider/MyProvider"}
        assert _has_non_account_principals(principal) is True

    def test_detects_canonical_user_principal(self) -> None:
        """Test detecting CanonicalUser principal."""
        from headroom.aws.s3 import _has_non_account_principals
        principal = {"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}
        assert _has_non_account_principals(principal) is True

    def test_ignores_aws_principal(self) -> None:
        """Test that AWS principal is not flagged."""
        from headroom.aws.s3 import _has_non_account_principals
        principal = {"AWS": "arn:aws:iam::555555555555:root"}
        assert _has_non_account_principals(principal) is False

    def test_ignores_service_principal(self) -> None:
        """Test that Service principal is not flagged."""
        from headroom.aws.s3 import _has_non_account_principals
        principal = {"Service": "cloudtrail.amazonaws.com"}
        assert _has_non_account_principals(principal) is False

    def test_mixed_with_federated(self) -> None:
        """Test mixed principals with Federated."""
        from headroom.aws.s3 import _has_non_account_principals
        principal = {"AWS": "arn:aws:iam::555555555555:root", "Federated": "arn:aws:iam::555555555555:saml-provider/MyProvider"}
        assert _has_non_account_principals(principal) is True


class TestNormalizeActions:
    """Test _normalize_actions function."""

    def test_string_action(self) -> None:
        """Test normalizing single string action."""
        result = _normalize_actions("s3:GetObject")
        assert result == {"s3:GetObject"}

    def test_list_actions(self) -> None:
        """Test normalizing list of actions."""
        result = _normalize_actions(["s3:GetObject", "s3:PutObject"])
        assert result == {"s3:GetObject", "s3:PutObject"}

    def test_empty_or_invalid(self) -> None:
        """Test normalizing empty or invalid actions."""
        assert _normalize_actions(None) == set()
        assert _normalize_actions({}) == set()


class TestAnalyzeS3BucketPolicies:
    """Test analyze_s3_bucket_policies function."""

    def test_analyze_buckets_with_third_party_access(self) -> None:
        """Test analyzing buckets with third-party account access."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "test-bucket-1"},
                {"Name": "test-bucket-2"},
            ]
        }

        policies = {
            "test-bucket-1": {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": "arn:aws:s3:::test-bucket-1/*"
                        }
                    ]
                })
            },
            "test-bucket-2": {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::test-bucket-2/*"
                        }
                    ]
                })
            }
        }
        mock_s3_client.get_bucket_policy.side_effect = lambda Bucket: policies[Bucket]

        org_account_ids = {"333333333333", "444444444444"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 2
        assert results[0].bucket_name == "test-bucket-1"
        assert results[0].third_party_account_ids == {"111111111111"}
        assert results[0].actions_by_account["111111111111"] == {"s3:GetObject", "s3:PutObject"}
        assert results[1].bucket_name == "test-bucket-2"
        assert results[1].third_party_account_ids == {"222222222222"}

    def test_analyze_bucket_with_wildcard(self) -> None:
        """Test analyzing bucket with wildcard principal."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "wildcard-bucket"}]
        }

        mock_s3_client.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::wildcard-bucket/*"
                    }
                ]
            })
        }

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].bucket_name == "wildcard-bucket"

    def test_analyze_bucket_without_policy(self) -> None:
        """Test analyzing bucket without bucket policy."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "no-policy-bucket"}]
        }

        error_response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        mock_s3_client.get_bucket_policy.side_effect = ClientError(error_response, "GetBucketPolicy")  # type: ignore[arg-type]

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_bucket_with_org_account(self) -> None:
        """Test analyzing bucket with org account (should be filtered out)."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "org-bucket"}]
        }

        mock_s3_client.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::333333333333:root"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::org-bucket/*"
                    }
                ]
            })
        }

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_empty_bucket_list(self) -> None:
        """Test analyzing with no buckets."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {"Buckets": []}

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_list_buckets_error(self) -> None:
        """Test handling of list_buckets API error."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        error_response = {"Error": {"Code": "AccessDenied"}}
        mock_s3_client.list_buckets.side_effect = ClientError(error_response, "ListBuckets")  # type: ignore[arg-type]

        org_account_ids = {"333333333333"}
        with pytest.raises(ClientError):
            analyze_s3_bucket_policies(mock_session, org_account_ids)

    def test_analyze_bucket_policy_get_error(self) -> None:
        """Test handling of GetBucketPolicy API errors other than NoSuchBucketPolicy."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "error-bucket"}]
        }

        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        mock_s3_client.get_bucket_policy.side_effect = ClientError(error_response, "GetBucketPolicy")  # type: ignore[arg-type]

        org_account_ids = {"999999999999"}
        with pytest.raises(ClientError):
            analyze_s3_bucket_policies(mock_session, org_account_ids)

    def test_analyze_bucket_with_deny_statement(self) -> None:
        """Test bucket with Deny statement (should be ignored)."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "deny-bucket"}]
        }

        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "s3:*"
                }
            ]
        }
        mock_s3_client.get_bucket_policy.return_value = {
            "Policy": json.dumps(policy)
        }

        org_account_ids = {"999999999999"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)
        assert len(results) == 0

    def test_analyze_bucket_with_no_principal(self) -> None:
        """Test bucket with statement that has no Principal field."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "no-principal-bucket"}]
        }

        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject"
                }
            ]
        }
        mock_s3_client.get_bucket_policy.return_value = {
            "Policy": json.dumps(policy)
        }

        org_account_ids = {"999999999999"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)
        assert len(results) == 0

    def test_analyze_bucket_with_federated_principal(self) -> None:
        """Test bucket with Federated principal is detected."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {
            "Buckets": [{"Name": "federated-bucket"}]
        }

        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::555555555555:saml-provider/MyProvider"
                    },
                    "Action": "s3:GetObject"
                }
            ]
        }
        mock_s3_client.get_bucket_policy.return_value = {
            "Policy": json.dumps(policy)
        }

        org_account_ids = {"999999999999"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids)
        assert len(results) == 1
        assert results[0].has_non_account_principals is True
        assert results[0].bucket_name == "federated-bucket"

    def test_has_wildcard_principal_list_with_wildcard(self) -> None:
        """Test detection of wildcard in list of principals."""
        from headroom.aws.s3 import _has_wildcard_principal
        principal = {"AWS": ["arn:aws:iam::111111111111:root", "*"]}
        assert _has_wildcard_principal(principal) is True


class TestPolicyGrammar:
    """Policy elements the bucket analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
        mock_s3_client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}

        return analyze_s3_bucket_policies(mock_session, {"111111111111"})

    def test_lone_statement_object_is_analyzed(self) -> None:
        """The third party in a lone statement object is found, not missed."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }
        })

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].actions_by_account["999999999999"] == {"s3:GetObject"}

    def test_statement_neither_object_nor_list_raises(self) -> None:
        """A Statement of any other type aborts rather than reporting nothing."""
        with pytest.raises(MalformedPolicyError, match="Statement of type str"):
            self._analyze({"Version": "2012-10-17", "Statement": "Allow"})

    def test_not_principal_is_read_as_a_wildcard(self) -> None:
        """
        An Allow with NotPrincipal grants to everyone it does not name.

        Skipping the statement for want of a Principal reported the resource
        clean, so the account kept its RCP and the grant's real audience -
        every account outside the exclusion list - lost access on apply.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()

    def test_deny_with_not_principal_is_not_a_wildcard(self) -> None:
        """
        Deny with NotPrincipal restricts rather than grants.

        It is the form AWS recommends, and a resource policy's Deny cannot
        hand access to anyone, so it must not block the RCP.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }
        })

        assert results == []


class TestBucketAcl:
    """
    Grants the bucket ACL carries, which no policy statement records.

    A bucket ACL authorizes principals independently of the bucket policy.
    Reading only the policy reported such a bucket clean, so the account kept
    its RCP and the ACL's grantees lost access the moment it applied.
    """

    # Canonical user IDs are 64 hex characters. These are placeholders.
    OWNER_ID = "a" * 64
    EXTERNAL_ID = "b" * 64

    @staticmethod
    def _grant(grantee: Any, permission: str = "READ") -> Any:
        """Build one ACL grant entry."""
        return {"Grantee": grantee, "Permission": permission}

    @staticmethod
    def _analyze(grants: Any, policy: Any = None) -> Any:
        """
        Run the analyzer over one bucket carrying the given ACL grants.

        A policy of None stands for a bucket with no policy at all, which is
        the shape a bucket sharing only by ACL arrives in.
        """
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        mock_s3_client.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
        mock_s3_client.get_bucket_acl.return_value = {
            "Owner": {"ID": TestBucketAcl.OWNER_ID},
            "Grants": grants,
        }
        if policy is None:
            mock_s3_client.get_bucket_policy.side_effect = ClientError(
                {"Error": {"Code": "NoSuchBucketPolicy", "Message": "Not found"}},
                "GetBucketPolicy",
            )
        else:
            mock_s3_client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}

        return analyze_s3_bucket_policies(mock_session, {"111111111111"})

    def test_owner_only_acl_finds_nothing(self) -> None:
        """
        The default ACL grants the bucket owner alone and shares nothing.

        Every bucket carries this grant, so counting it would block every
        account in the organization from taking any S3 RCP.
        """
        results = self._analyze([
            self._grant({"Type": "CanonicalUser", "ID": self.OWNER_ID}, "FULL_CONTROL"),
        ])

        assert results == []

    def test_external_canonical_user_is_not_allowlistable(self) -> None:
        """
        A grantee that is not the bucket owner is a third party we cannot name.

        A canonical user ID does not resolve to an account ID, so
        `aws:PrincipalAccount` cannot express it and the account has to keep
        its exemption from the RCP instead.
        """
        results = self._analyze([
            self._grant({"Type": "CanonicalUser", "ID": self.EXTERNAL_ID}),
        ])

        assert len(results) == 1
        assert results[0].has_non_account_principals is True
        assert results[0].has_wildcard_principal is False
        assert results[0].third_party_account_ids == set()

    def test_email_grantee_is_not_allowlistable(self) -> None:
        """An email address grantee resolves to no account ID either."""
        results = self._analyze([
            self._grant({
                "Type": "AmazonCustomerByEmail",
                "EmailAddress": "someone@example.com",
            }),
        ])

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    def test_all_users_group_is_a_wildcard(self) -> None:
        """The AllUsers group is public access, which is what the wildcard flag records."""
        results = self._analyze([
            self._grant({"Type": "Group", "URI": ALL_USERS_GROUP_URI}),
        ])

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_authenticated_users_group_is_a_wildcard(self) -> None:
        """
        AuthenticatedUsers is every AWS principal anywhere.

        It reads like a restriction next to AllUsers, but it admits every
        account in AWS rather than every account in the organization.
        """
        results = self._analyze([
            self._grant({"Type": "Group", "URI": AUTHENTICATED_USERS_GROUP_URI}),
        ])

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_log_delivery_group_is_ignored(self) -> None:
        """
        The log delivery group grant authorizes an AWS service principal.

        Granting the group by ACL and granting `logging.s3.amazonaws.com` by
        bucket policy authorize the same principal, and the RCP spares AWS
        services, so this grant costs the account nothing.
        """
        results = self._analyze([
            self._grant({"Type": "Group", "URI": LOG_DELIVERY_GROUP_URI}, "WRITE"),
        ])

        assert results == []

    def test_unknown_grantee_type_raises(self) -> None:
        """A grantee type the analyzer cannot classify aborts rather than being dropped."""
        with pytest.raises(UnknownGranteeTypeError, match="Martian"):
            self._analyze([self._grant({"Type": "Martian", "ID": self.EXTERNAL_ID})])

    def test_unknown_group_uri_raises(self) -> None:
        """A group URI the analyzer cannot classify aborts rather than being dropped."""
        with pytest.raises(UnknownGranteeTypeError, match="unexpected-group"):
            self._analyze([
                self._grant({
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/unexpected-group",
                }),
            ])

    def test_acl_is_read_when_the_bucket_has_no_policy(self) -> None:
        """
        A bucket that shares only by ACL carries no bucket policy at all.

        Abandoning the bucket for want of a policy skipped exactly the buckets
        an ACL grant is most likely to be the only grant on.
        """
        results = self._analyze([
            self._grant({"Type": "CanonicalUser", "ID": self.EXTERNAL_ID}),
        ])

        assert len(results) == 1
        assert results[0].bucket_name == "test-bucket"
        assert results[0].has_non_account_principals is True

    def test_policy_and_acl_findings_are_merged(self) -> None:
        """One bucket reports what its policy and its ACL each grant."""
        results = self._analyze(
            [self._grant({"Type": "Group", "URI": ALL_USERS_GROUP_URI})],
            policy={
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::test-bucket/*",
                }],
            },
        )

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == {"999999999999"}

    def test_get_bucket_acl_error_propagates(self) -> None:
        """
        A failed ACL read aborts rather than reporting the bucket clean.

        Every bucket has an ACL, so a read that fails is a read Headroom could
        not complete, not a bucket with nothing on it.
        """
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
        mock_s3_client.get_bucket_acl.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "GetBucketAcl",
        )

        with pytest.raises(ClientError):
            analyze_s3_bucket_policies(mock_session, {"111111111111"})
