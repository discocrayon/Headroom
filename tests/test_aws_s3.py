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
    UnknownGranteeTypeError,
)
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)
from tests.constants import ORG_ID


class TestAnalyzeS3BucketPolicies:
    """Test analyze_s3_bucket_policies function."""

    def test_an_unparseable_policy_aborts_the_run(self) -> None:
        """
        A document AWS could not have stored means Headroom misread it.

        Recording the bucket as clean would let the RCP deploy over whatever
        the policy actually grants, which is INV-01's case. The ACL is read
        first and finds nothing, so the abort comes from the policy alone.
        """
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [{"Buckets": [{"Name": "test-bucket"}]}]
        mock_s3_client.get_paginator.return_value = bucket_paginator
        mock_s3_client.get_bucket_acl.return_value = {
            "Owner": {"ID": TestBucketAcl.OWNER_ID},
            "Grants": [],
        }
        mock_s3_client.get_bucket_policy.return_value = {"Policy": "{not json"}

        with pytest.raises(json.JSONDecodeError):
            analyze_s3_bucket_policies(mock_session, {"111111111111"}, ORG_ID)

    def test_analyze_buckets_with_third_party_access(self) -> None:
        """Test analyzing buckets with third-party account access."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [
                    {"Name": "test-bucket-1"},
                    {"Name": "test-bucket-2"},
                ]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

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
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

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

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [{"Name": "wildcard-bucket"}]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

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
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].bucket_name == "wildcard-bucket"

    def test_analyze_bucket_without_policy(self) -> None:
        """Test analyzing bucket without bucket policy."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [{"Name": "no-policy-bucket"}]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

        error_response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        mock_s3_client.get_bucket_policy.side_effect = ClientError(error_response, "GetBucketPolicy")  # type: ignore[arg-type]

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 0

    def test_analyze_bucket_with_org_account(self) -> None:
        """Test analyzing bucket with org account (should be filtered out)."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [{"Name": "org-bucket"}]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

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
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 0

    def test_analyze_empty_bucket_list(self) -> None:
        """Test analyzing with no buckets."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [{"Buckets": []}]
        mock_s3_client.get_paginator.return_value = bucket_paginator

        org_account_ids = {"333333333333"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

        assert len(results) == 0

    def test_buckets_beyond_the_first_page_are_analyzed(self) -> None:
        """
        Every page of ListBuckets is read, not just the first.

        An account holding more buckets than one response carries used to be
        silently truncated: the buckets past the first page were never
        scanned, never counted, and never reached the allowlist, and the
        output could not be told apart from an account with no third-party
        access at all. That is INV-01 exactly.
        """
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        first_page = {"Buckets": [{"Name": "bucket-on-page-one"}]}
        second_page = {"Buckets": [{"Name": "bucket-on-page-two"}]}

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [first_page, second_page]
        mock_s3_client.get_paginator.return_value = bucket_paginator

        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "s3:GetObject",
                }
            ]
        })
        mock_s3_client.get_bucket_policy.return_value = {"Policy": policy}

        org_account_ids = {"111111111111"}
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

        assert [result.bucket_name for result in results] == [
            "bucket-on-page-one",
            "bucket-on-page-two",
        ]

    def test_list_buckets_error(self) -> None:
        """Test handling of list_buckets API error."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        error_response = {"Error": {"Code": "AccessDenied"}}
        bucket_paginator = MagicMock()
        bucket_paginator.paginate.side_effect = ClientError(error_response, "ListBuckets")  # type: ignore[arg-type]
        mock_s3_client.get_paginator.return_value = bucket_paginator

        org_account_ids = {"333333333333"}
        with pytest.raises(ClientError):
            analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

    def test_analyze_bucket_policy_get_error(self) -> None:
        """Test handling of GetBucketPolicy API errors other than NoSuchBucketPolicy."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [{"Name": "error-bucket"}]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        mock_s3_client.get_bucket_policy.side_effect = ClientError(error_response, "GetBucketPolicy")  # type: ignore[arg-type]

        org_account_ids = {"999999999999"}
        with pytest.raises(ClientError):
            analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)

    def test_analyze_bucket_with_deny_statement(self) -> None:
        """Test bucket with Deny statement (should be ignored)."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [{"Name": "deny-bucket"}]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

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
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)
        assert len(results) == 0

    def test_analyze_bucket_with_no_principal(self) -> None:
        """Test bucket with statement that has no Principal field."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [{"Name": "no-principal-bucket"}]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

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
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)
        assert len(results) == 0

    def test_analyze_bucket_with_federated_principal(self) -> None:
        """Test bucket with Federated principal is detected."""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {
                "Buckets": [{"Name": "federated-bucket"}]
            }
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator

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
        results = analyze_s3_bucket_policies(mock_session, org_account_ids, ORG_ID)
        assert len(results) == 1
        assert results[0].has_non_account_principals is True
        assert results[0].bucket_name == "federated-bucket"


class TestPolicyGrammar:
    """Policy elements the bucket analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [{"Buckets": [{"Name": "test-bucket"}]}]
        mock_s3_client.get_paginator.return_value = bucket_paginator
        mock_s3_client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}

        return analyze_s3_bucket_policies(mock_session, {"111111111111"}, ORG_ID)

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

    def test_guarded_service_principal_is_recorded(self) -> None:
        """
        A bucket policy pinning a third-party source records it.

        The account reaches the allowlist through the confused deputy
        check, not through this analysis's third_party_account_ids.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*",
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

    def test_an_origin_access_identity_blocks_the_bucket(self) -> None:
        """
        A bucket granting only a CloudFront OAI is a violation, not clean.

        The OAI user ARN has no account field, so it reaches no allowlist;
        the deployed statement denies it, and AWS's data perimeter guidance
        names that break. Recording nothing here is what cleared the account.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E11111111111111"
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }],
        })

        assert len(results) == 1
        assert results[0].has_non_account_principals is True
        assert results[0].has_wildcard_principal is False
        assert results[0].third_party_account_ids == set()

    def test_a_policy_with_no_service_principal_records_nothing(self) -> None:
        """The field stays empty when no statement names a service."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }],
        })

        assert results[0].service_principal_sources == []

    def test_an_undocumented_principal_key_aborts(self) -> None:
        """
        A key AWS could not have stored means Headroom misread the document.

        Continuing would mean guessing at who the policy grants to, so the
        run aborts rather than recording the bucket as clean. Without this,
        widening the accepted key set is a silent change: the bucket parses
        as granting nobody and the RCP deploys over whatever it granted.
        """
        with pytest.raises(UnknownPrincipalTypeError):
            self._analyze({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Kerberos": "example"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::test-bucket/*"
                }]
            })


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

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [{"Buckets": [{"Name": "test-bucket"}]}]
        mock_s3_client.get_paginator.return_value = bucket_paginator
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

        return analyze_s3_bucket_policies(mock_session, {"111111111111"}, ORG_ID)

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

    def test_email_grantee_type_aborts(self) -> None:
        """
        AWS resolves an email grantee to a CanonicalUser before returning it.

        GetBucketAcl cannot answer with this type, so a response carrying it
        is one Headroom does not model. The branch that treated it as a
        non-account grantee was unreachable, and the fixture proving it was
        impossible - the case INV-08 exists to prevent.
        """
        with pytest.raises(UnknownGranteeTypeError):
            self._analyze([
                self._grant({
                    "Type": "AmazonCustomerByEmail",
                    "EmailAddress": "someone@example.com",
                }),
            ])

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
        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [{"Buckets": [{"Name": "test-bucket"}]}]
        mock_s3_client.get_paginator.return_value = bucket_paginator
        mock_s3_client.get_bucket_acl.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "GetBucketAcl",
        )

        with pytest.raises(ClientError):
            analyze_s3_bucket_policies(mock_session, {"111111111111"}, ORG_ID)
