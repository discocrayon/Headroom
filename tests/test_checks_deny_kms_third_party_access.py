"""
Tests for headroom.checks.rcps.deny_kms_third_party_access module.
"""

import json
import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import Dict, List, Generator

from headroom.checks.rcps.deny_kms_third_party_access import DenyKMSThirdPartyAccessCheck
from headroom.constants import DENY_KMS_THIRD_PARTY_ACCESS
from headroom.config import DEFAULT_RESULTS_DIR
from headroom.aws.kms import (
    GranteeAccountIDSource,
    KMSGrantFinding,
    KMSKeyPolicyAnalysis,
    UnresolvedKMSGrantFinding,
)
from tests.constants import ORG_ID

# The account under test, which owns every key these helpers build, and the
# account outside the organization that a grant hands access to.
ORG_ACCOUNT = "111111111111"
THIRD_PARTY = "999999999999"

# The two ways ListGrants names that account's role, which are the two ways a
# finding's account can have been arrived at. Most of what follows hands the
# check findings the analyzer has already resolved, so what those tests pin is
# that whichever one named the grantee arrives whole and says it was the source
# of the account beside it; tests/test_aws_kms.py is where the reading itself
# is exercised. `kms_session_holding` is the exception, and says so.
THIRD_PARTY_ROLE_ARN = f"arn:aws:iam::{THIRD_PARTY}:role/VendorRole"
THIRD_PARTY_ROLE_UNIQUE_ID = "AROA6RVFFB77QAAAAAAAA"

# A role unique ID in the older random format, which carries no account at
# all. It is the third way a grantee can be named and the only one that
# withholds the RCP from the key's account.
UNRESOLVABLE_ROLE_UNIQUE_ID = "AROAAAAAAAAAAAAAAAAAA"

# The key a scan driven from `kms_session_holding` finds.
SCANNED_KEY_ID = "key-scanned"


@pytest.fixture
def temp_results_dir() -> Generator[str, None, None]:
    """Create temporary results directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


def kms_session_holding(
    grants: List[Dict[str, object]],
    key_account_id: str = ORG_ACCOUNT,
) -> MagicMock:
    """
    Build a session whose one customer-managed key carries these grants.

    Driving the check from this rather than from a patched analyzer is what
    makes a decoded grantee's account the analyzer's arithmetic instead of
    the fixture's assertion: the identifier goes in and only ListGrants'
    own words go with it. The key's policy names its owning account and
    nobody else, so a third party the check reports came from a grant.

    Args:
        grants: ListGrants entries, verbatim
        key_account_id: Account owning the key, which its ARN and its
            policy both name

    Returns:
        A session whose KMS client serves one region holding that key
    """
    session = MagicMock()
    ec2_client = MagicMock()
    kms_client = MagicMock()

    session.client.side_effect = lambda service, **kwargs: {
        "ec2": ec2_client,
        "kms": kms_client,
    }[service]

    ec2_client.describe_regions.return_value = {
        "Regions": [{"RegionName": "us-east-1"}]
    }

    keys_paginator = MagicMock()
    keys_paginator.paginate.return_value = [
        {
            "Keys": [
                {
                    "KeyId": SCANNED_KEY_ID,
                    "KeyArn": (
                        f"arn:aws:kms:us-east-1:{key_account_id}:key/{SCANNED_KEY_ID}"
                    ),
                }
            ]
        }
    ]

    grants_paginator = MagicMock()
    grants_paginator.paginate.return_value = [{"Grants": grants}]

    kms_client.get_paginator.side_effect = lambda name: {
        "list_keys": keys_paginator,
        "list_grants": grants_paginator,
    }[name]

    kms_client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER"}}
    kms_client.get_key_policy.return_value = {
        "Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{key_account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        })
    }

    return session


def decodable_grant() -> List[Dict[str, object]]:
    """
    One grant whose grantee is named by a unique ID carrying its account.

    The account is THIRD_PARTY, which the identifier encodes and nothing
    else on the grant states.
    """
    return [
        {
            "GrantId": "grant-abc",
            "GranteePrincipal": THIRD_PARTY_ROLE_UNIQUE_ID,
            "Operations": ["Decrypt"],
        }
    ]


def unresolvable_grant() -> List[Dict[str, object]]:
    """One grant whose grantee is a unique ID carrying no account at all."""
    return [
        {
            "GrantId": "grant-def",
            "GranteePrincipal": UNRESOLVABLE_ROLE_UNIQUE_ID,
            "Operations": ["Decrypt"],
        }
    ]


def grant_sourced_key(
    key_id: str = "key-grant",
    grantee_principal: str = THIRD_PARTY_ROLE_ARN,
    grantee_account_id_source: GranteeAccountIDSource = "arn",
) -> KMSKeyPolicyAnalysis:
    """
    Build a key whose policy is clean but whose grant is not.

    The grantee defaults to the ARN naming its account outright, which is
    the ordinary case; the two parameters name it by unique ID instead.
    """
    return KMSKeyPolicyAnalysis(
        key_id=key_id,
        key_arn=f"arn:aws:kms:us-east-1:{ORG_ACCOUNT}:key/{key_id}",
        region="us-east-1",
        third_party_account_ids={THIRD_PARTY},
        actions_by_account={THIRD_PARTY: ["kms:Decrypt"]},
        has_wildcard_principal=False,
        grants=[
            KMSGrantFinding(
                grant_id="grant-abc",
                grantee_account_id=THIRD_PARTY,
                grantee_principal=grantee_principal,
                grantee_account_id_source=grantee_account_id_source,
                retiring_principal_account_id=None,
                operations=["kms:Decrypt"],
                has_constraints=False,
            )
        ],
    )


def decoded_grant_key() -> KMSKeyPolicyAnalysis:
    """Build that same key with its grantee named only by unique ID."""
    return grant_sourced_key(
        grantee_principal=THIRD_PARTY_ROLE_UNIQUE_ID,
        grantee_account_id_source="iam_unique_id",
    )


def unresolved_key() -> KMSKeyPolicyAnalysis:
    """Build a key whose only finding is an unattributable grant."""
    return KMSKeyPolicyAnalysis(
        key_id="key-unresolved",
        key_arn=f"arn:aws:kms:us-east-1:{ORG_ACCOUNT}:key/key-unresolved",
        region="us-east-1",
        third_party_account_ids=set(),
        unresolved_grants=[
            UnresolvedKMSGrantFinding(
                grant_id="grant-abc",
                grantee_principal=UNRESOLVABLE_ROLE_UNIQUE_ID,
                principal_kind="iam_role_unique_id",
                operations=["kms:Decrypt"],
                has_constraints=False,
            )
        ],
    )


def run_check(
    results: List[KMSKeyPolicyAnalysis],
    temp_results_dir: str,
) -> dict:
    """Execute the check over the given analyses and return results_data."""
    mock_session = MagicMock()

    with (
        patch(
            "headroom.checks.rcps.deny_kms_third_party_access."
            "analyze_kms_key_policies"
        ) as mock_analysis,
        patch("headroom.checks.base.write_check_results") as mock_write,
        patch("builtins.print"),
    ):
        mock_analysis.return_value = results

        check = DenyKMSThirdPartyAccessCheck(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            account_name="test-account",
            account_id=ORG_ACCOUNT,
            results_dir=temp_results_dir,
            org_account_ids={ORG_ACCOUNT},
            org_id=ORG_ID,
        )
        check.execute(mock_session)

        results_data: dict = mock_write.call_args[1]["results_data"]
        return results_data


def run_scan(
    grants: List[Dict[str, object]],
    temp_results_dir: str,
) -> dict:
    """
    Scan one key carrying these grants and return results_data.

    `run_check` hands the check findings the analyzer has already made.
    This one makes the analyzer do the reading, so an account behind a
    unique ID is arithmetic on the identifier rather than something the
    test asserted into the fixture.

    Args:
        grants: ListGrants entries the key carries, verbatim
        temp_results_dir: Base results directory, which nothing is written
            to because the writer is patched out

    Returns:
        The results_data the check would have written
    """
    with patch("headroom.checks.base.write_check_results") as mock_write:
        check = DenyKMSThirdPartyAccessCheck(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            account_name="test-account",
            account_id=ORG_ACCOUNT,
            results_dir=temp_results_dir,
            org_account_ids={ORG_ACCOUNT},
            org_id=ORG_ID,
        )
        check.execute(kms_session_holding(grants))

        results_data: dict = mock_write.call_args[1]["results_data"]
        return results_data


class TestCheckDenyKMSThirdPartyAccess:
    """Test deny_kms_third_party_access check with various scenarios."""

    @pytest.fixture
    def org_account_ids(self) -> set[str]:
        """Organization account IDs for testing."""
        return {"111111111111", "222222222222"}

    @pytest.fixture
    def sample_kms_results_mixed(self) -> List[KMSKeyPolicyAnalysis]:
        """Create sample KMS results with mixed compliance status."""
        return [
            KMSKeyPolicyAnalysis(
                key_id="key-compliant",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-compliant",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt", "kms:DescribeKey"]
                },
                has_wildcard_principal=False
            ),
            KMSKeyPolicyAnalysis(
                key_id="key-violation",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-violation",
                region="us-east-1",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
        ]

    def test_check_deny_kms_third_party_access_mixed_results(
        self,
        sample_kms_results_mixed: List[KMSKeyPolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_kms_results_mixed

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            assert mock_write.called
            results_data = mock_write.call_args[1]["results_data"]

            assert len(results_data["keys_with_wildcards"]) == 1
            assert len(results_data["keys_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_keys_analyzed"] == 2
            assert summary["keys_third_parties_can_access"] == 1
            assert summary["keys_with_wildcards"] == 1
            assert summary["violations"] == 1
            assert summary["unique_third_party_accounts"] == ["999999999999"]
            assert summary["third_party_account_count"] == 1
            assert "999999999999" in summary["actions_by_account"]
            assert "kms:Decrypt" in summary["actions_by_account"]["999999999999"]
            assert "kms:DescribeKey" in summary["actions_by_account"]["999999999999"]

    def test_check_all_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all keys compliant."""
        mock_session = MagicMock()

        all_compliant = [
            KMSKeyPolicyAnalysis(
                key_id="key-compliant-1",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-compliant-1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["keys_with_wildcards"] == 0
            assert summary["keys_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all keys as violations."""
        mock_session = MagicMock()

        all_violations = [
            KMSKeyPolicyAnalysis(
                key_id="key-wildcard-1",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-wildcard-1",
                region="us-east-1",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
            KMSKeyPolicyAnalysis(
                key_id="key-wildcard-2",
                key_arn="arn:aws:kms:us-west-2:111111111111:key/key-wildcard-2",
                region="us-west-2",
                third_party_account_ids={"888888888888"},
                actions_by_account={
                    "888888888888": ["kms:*"]
                },
                has_wildcard_principal=True
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 2
            assert summary["keys_with_wildcards"] == 2
            assert summary["keys_third_parties_can_access"] == 1

    def test_check_empty_results(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with no keys found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_keys_analyzed"] == 0
            assert summary["violations"] == 0
            assert summary["unique_third_party_accounts"] == []
            assert summary["third_party_account_count"] == 0
            assert summary["actions_by_account"] == {}

    def test_categorize_result_violation(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of violation."""
        check = DenyKMSThirdPartyAccessCheck(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = KMSKeyPolicyAnalysis(
            key_id="key-wildcard",
            key_arn="arn:aws:kms:us-east-1:111111111111:key/key-wildcard",
            region="us-east-1",
            third_party_account_ids=set(),
            actions_by_account={},
            has_wildcard_principal=True
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "violation"
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_compliant(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of compliant."""
        check = DenyKMSThirdPartyAccessCheck(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = KMSKeyPolicyAnalysis(
            key_id="key-compliant",
            key_arn="arn:aws:kms:us-east-1:111111111111:key/key-compliant",
            region="us-east-1",
            third_party_account_ids={"999999999999"},
            actions_by_account={
                "999999999999": ["kms:Decrypt"]
            },
            has_wildcard_principal=False
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "compliant"
        assert result_dict["has_wildcard_principal"] is False
        assert result_dict["third_party_account_ids"] == ["999999999999"]

    def test_categorize_result_non_account_principal_is_a_violation(
        self,
        org_account_ids: set[str],
    ) -> None:
        """A Federated or CanonicalUser principal blocks the account."""
        check = DenyKMSThirdPartyAccessCheck(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = KMSKeyPolicyAnalysis(
            key_id="key-federated",
            key_arn="arn:aws:kms:us-east-1:111111111111:key/key-federated",
            region="us-east-1",
            third_party_account_ids=set(),
            actions_by_account={},
            has_wildcard_principal=False,
            has_non_account_principals=True,
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "violation"
        assert result_dict["has_non_account_principals"] is True

    def test_a_non_account_principal_alone_is_not_cleared(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """
        A key whose only finding is a Federated principal is reported.

        No allowlist keyed on aws:PrincipalAccount can preserve that grant, so
        dropping it would clear the account and deploy an RCP that denies a
        grant the account depends on, against INV-01.
        """
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = [
                KMSKeyPolicyAnalysis(
                    key_id="key-federated",
                    key_arn="arn:aws:kms:us-east-1:111111111111:key/key-federated",
                    region="us-east-1",
                    third_party_account_ids=set(),
                    actions_by_account={},
                    has_wildcard_principal=False,
                    has_non_account_principals=True,
                )
            ]

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            summary = mock_write.call_args[1]["results_data"]["summary"]

            assert summary["violations"] == 1

    def test_actions_aggregation_across_keys(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test that actions are aggregated across multiple keys for same account."""
        mock_session = MagicMock()

        results_with_multiple_keys = [
            KMSKeyPolicyAnalysis(
                key_id="key-1",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt", "kms:DescribeKey"]
                },
                has_wildcard_principal=False
            ),
            KMSKeyPolicyAnalysis(
                key_id="key-2",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-2",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Encrypt", "kms:DescribeKey"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results_with_multiple_keys

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            actions = summary["actions_by_account"]["999999999999"]
            assert len(actions) == 3
            assert "kms:Decrypt" in actions
            assert "kms:DescribeKey" in actions
            assert "kms:Encrypt" in actions

    def test_multiple_third_party_accounts(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test tracking multiple third-party accounts."""
        mock_session = MagicMock()

        results_with_multiple_accounts = [
            KMSKeyPolicyAnalysis(
                key_id="key-multi",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-multi",
                region="us-east-1",
                third_party_account_ids={"999999999999", "888888888888"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt"],
                    "888888888888": ["kms:Encrypt"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results_with_multiple_accounts

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["third_party_account_count"] == 2
            assert set(summary["unique_third_party_accounts"]) == {"888888888888", "999999999999"}
            assert "888888888888" in summary["actions_by_account"]
            assert "999999999999" in summary["actions_by_account"]


class TestGrantSourcedResults:
    """
    Results whose third party came from a grant, not the key policy.

    A grant is invisible to GetKeyPolicy, so these are the keys that would
    have shipped an RCP that denied access the account depended on.
    """

    def test_grants_are_written_to_the_result(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The result records which grant produced the third party.

        Without it a reader sees an account in the allowlist, opens the key
        policy, finds nothing, and cannot tell where the entry came from.
        """
        results_data = run_check(
            [grant_sourced_key()], temp_results_dir
        )

        key = results_data["keys_third_parties_can_access"][0]
        assert key["grants"] == [
            {
                "grant_id": "grant-abc",
                "grantee_account_id": THIRD_PARTY,
                "grantee_principal": THIRD_PARTY_ROLE_ARN,
                "grantee_account_id_source": "arn",
                "retiring_principal_account_id": None,
                "operations": ["kms:Decrypt"],
                "has_constraints": False,
            }
        ]

    def test_grant_third_party_reaches_the_allowlist(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        A grantee account flows to the Terraform allowlist like any other.

        Grant principals are ordinary IAM ARNs, so unlike an S3 ACL grantee
        they cost the account no RCP coverage.
        """
        results_data = run_check(
            [grant_sourced_key()], temp_results_dir
        )

        summary = results_data["summary"]
        assert summary["unique_third_party_accounts"] == [THIRD_PARTY]
        assert summary["actions_by_account"][THIRD_PARTY] == ["kms:Decrypt"]

    def test_a_grant_only_key_is_not_a_violation(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        Reading grants can widen the allowlist but never withhold the RCP.

        `violations` is what sets blocks_rcp, so a grant raising it would
        cost the account an RCP it should still get.
        """
        results_data = run_check(
            [grant_sourced_key()], temp_results_dir
        )

        assert results_data["summary"]["violations"] == 0
        assert results_data["keys_with_wildcards"] == []

    def test_summary_counts_keys_with_third_party_grants(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The summary says whether the grant surface found anything.

        A key with a clean policy and a third-party grant is otherwise
        indistinguishable in the summary from one found the usual way.
        """
        policy_sourced_key = KMSKeyPolicyAnalysis(
            key_id="key-policy",
            key_arn=(
                f"arn:aws:kms:us-east-1:{ORG_ACCOUNT}:key/key-policy"
            ),
            region="us-east-1",
            third_party_account_ids={"888888888888"},
            actions_by_account={"888888888888": ["kms:DescribeKey"]},
            has_wildcard_principal=False,
        )

        results_data = run_check(
            [grant_sourced_key(), policy_sourced_key], temp_results_dir
        )

        summary = results_data["summary"]
        assert summary["total_keys_analyzed"] == 2
        assert summary["keys_with_third_party_grants"] == 1


class TestDecodedGrantResults:
    """
    Results whose third party was decoded from the grantee's unique ID.

    The account is the analyzer's arithmetic on an encoding AWS does not
    document, not something the grant spelled out, so what the result says
    about where it came from is the only warning a reader gets.
    """

    def test_the_written_grant_says_its_account_was_decoded(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The written entry carries the identifier and names it as the source.

        An operator auditing the allowlist has the grant's own words to
        check the account against, and knows to check this entry rather
        than one AWS spelled out. Truncating or redacting the identifier
        would leave them with an account and nothing to check it against.
        """
        results_data = run_check([decoded_grant_key()], temp_results_dir)

        key = results_data["keys_third_parties_can_access"][0]
        assert key["grants"] == [
            {
                "grant_id": "grant-abc",
                "grantee_account_id": THIRD_PARTY,
                "grantee_principal": THIRD_PARTY_ROLE_UNIQUE_ID,
                "grantee_account_id_source": "iam_unique_id",
                "retiring_principal_account_id": None,
                "operations": ["kms:Decrypt"],
                "has_constraints": False,
            }
        ]

    def test_a_decoded_grant_leaves_the_key_compliant(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        A grantee the analyzer could place is an ordinary third party.

        `violations` is the one field generate_rcps reads to decide an
        account cannot take this RCP, and blocking one costs the
        organization root-level placement as well. Withholding the RCP over
        an account that is already in its allowlist reads as caution and is
        the opposite: an RCP that never ships denies nobody.
        """
        results_data = run_check([decoded_grant_key()], temp_results_dir)

        assert results_data["summary"]["violations"] == 0
        assert results_data["keys_with_wildcards"] == []
        assert len(results_data["keys_third_parties_can_access"]) == 1

    def test_a_decoded_account_reaches_the_allowlist(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        Recording how the account was read does not change what is done
        with it.

        `unique_third_party_accounts` is the summary key the Terraform
        allowlist variable is rendered from, and an account left out of it
        is denied by the RCP the moment it ships. The provenance is there
        for the operator auditing the entry, not for the generator: it must
        not quietly hold the entry back.
        """
        results_data = run_check([decoded_grant_key()], temp_results_dir)

        summary = results_data["summary"]
        assert summary["unique_third_party_accounts"] == [THIRD_PARTY]
        assert summary["actions_by_account"][THIRD_PARTY] == ["kms:Decrypt"]


class TestUnresolvedGrantResults:
    """
    Results for a grant whose grantee names no account at all.

    An IAM unique ID the encoding does not support holds whatever the grant
    authorizes and offers no account an allowlist could carry - unlike one
    an account was read out of, which is an ordinary third party. So the
    only safe outcome is to withhold the RCP from the key's account until a
    human looks.
    """

    def test_an_unresolved_grant_withholds_the_rcp(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        An unattributable grantee is a violation, so the account is blocked.

        `violations` is the one signal generate_rcps reads to decide whether
        an account gets the KMS RCP. A grant naming a principal nobody can
        place would be denied by that RCP, and no allowlist entry exists to
        spare it, so shipping the RCP would break access silently.
        """
        results_data = run_check([unresolved_key()], temp_results_dir)

        assert results_data["summary"]["violations"] == 1
        assert results_data["keys_with_wildcards"][0]["key_id"] == "key-unresolved"

    def test_the_entry_names_the_grant_and_the_key(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The result says which grant is unattributable, and on which key.

        A violation an operator cannot act on is a violation they will
        ignore. The grant ID is what RetireGrant takes, the principal is
        what they search IAM for, and the key ARN and region are how they
        find the key the RCP is being withheld for.
        """
        results_data = run_check([unresolved_key()], temp_results_dir)

        key = results_data["keys_with_wildcards"][0]
        assert key["unresolved_grants"] == [
            {
                "grant_id": "grant-abc",
                "grantee_principal": "AROAAAAAAAAAAAAAAAAAA",
                "principal_kind": "iam_role_unique_id",
                "operations": ["kms:Decrypt"],
                "has_constraints": False,
            }
        ]
        assert key["key_arn"] == "arn:aws:kms:us-east-1:111111111111:key/key-unresolved"
        assert key["region"] == "us-east-1"

    def test_an_unresolved_grant_adds_nothing_to_the_allowlist(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        There is no account to allowlist, so the allowlist stays empty.

        `unique_third_party_accounts` is the summary key the Terraform
        allowlist variable is rendered from. Putting a unique ID or the
        key's own account there would exempt something nobody chose to
        exempt, which is why the RCP is withheld instead.
        """
        results_data = run_check([unresolved_key()], temp_results_dir)

        summary = results_data["summary"]
        assert summary["unique_third_party_accounts"] == []
        assert summary["third_party_account_count"] == 0
        assert summary["actions_by_account"] == {}

    def test_summary_counts_keys_with_unresolved_grants(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The summary separates the two things the grant surface can find.

        A reader deciding whether to chase a withheld RCP needs to know how
        many keys carry a grantee nobody could place, and that number is
        not the number of keys with third-party grants: neither key here is
        counted by the other's count.

        `keys_third_parties_can_access` stays at one for the same reason.
        A grantee nobody can attribute is nobody's third party, so the
        unresolved key adds no account to that count even though its entry
        rides in the list of the same name, the way a wildcard-only key
        already does.
        """
        results_data = run_check(
            [unresolved_key(), grant_sourced_key()],
            temp_results_dir,
        )

        summary = results_data["summary"]
        assert summary["keys_with_unresolved_grants"] == 1
        assert summary["keys_with_third_party_grants"] == 1
        assert summary["total_keys_analyzed"] == 2
        assert summary["keys_third_parties_can_access"] == 1

    def test_one_key_reaching_both_surfaces_is_counted_by_both(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The two grant counts count grants, so one key can be in both.

        The analyzer partitions a key's grants, not the keys themselves, so
        a key carrying a third-party grant and an unattributable one lands
        in both lists. Reading the two counts as disjoint sets of keys and
        adding them would report two keys where one exists.
        """
        both = grant_sourced_key()
        both.unresolved_grants = list(unresolved_key().unresolved_grants)

        results_data = run_check([both], temp_results_dir)

        summary = results_data["summary"]
        assert summary["total_keys_analyzed"] == 1
        assert summary["keys_with_third_party_grants"] == 1
        assert summary["keys_with_unresolved_grants"] == 1

    def test_every_entry_carries_the_field(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        A key with nothing unresolved says so rather than omitting the key.

        A later run reads these files back, and a reader that has to tell an
        absent field from an empty one cannot distinguish a clean key from
        one written before the field existed.
        """
        results_data = run_check(
            [grant_sourced_key()], temp_results_dir
        )

        key = results_data["keys_third_parties_can_access"][0]
        assert key["unresolved_grants"] == []

    def test_analyze_keeps_a_key_whose_only_finding_is_an_unresolved_grant(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The filter that drops irrelevant keys must not drop this one.

        Its policy is clean and it reaches no third-party account, so every
        other clause in that filter is false. Dropping it here would lose
        the violation before anything downstream could see it, and the
        account would quietly receive an RCP that breaks the grant.
        """
        key = unresolved_key()

        with patch(
            "headroom.checks.rcps.deny_kms_third_party_access."
            "analyze_kms_key_policies"
        ) as mock_analysis:
            mock_analysis.return_value = [key]

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id=ORG_ACCOUNT,
                results_dir=temp_results_dir,
                org_account_ids={ORG_ACCOUNT},
                org_id=ORG_ID,
            )

            assert check.analyze(MagicMock()) == [key]


class TestScannedGrantResults:
    """
    Results the analyzer produced, rather than results handed to the check.

    Every class above starts from findings already resolved, so what an
    identifier decodes to is whatever the fixture said it did. These start
    from ListGrants entries and let the analyzer read them, which is the
    only way to see what two readings of the same account do when they
    meet in one key's results.
    """

    def test_two_grants_naming_one_account_yield_one_allowlist_entry(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        Two grants, two provenances, one account, one allowlist entry.

        The allowlist is keyed on aws:PrincipalAccount, so what it carries
        is accounts and not grants. A second entry for 999999999999 would
        render a duplicate into the Terraform variable, and dropping the
        decoded grant's account to avoid one would be worse: an account
        reached twice is no less reachable than an account reached once.
        Both grants stay in the key's own `grants` list, each saying which
        reading placed it, because that list is where a reader goes to find
        out why the entry is there.
        """
        results_data = run_scan(
            [
                {
                    "GrantId": "grant-arn",
                    "GranteePrincipal": THIRD_PARTY_ROLE_ARN,
                    "Operations": ["Decrypt"],
                },
                {
                    "GrantId": "grant-unique-id",
                    "GranteePrincipal": THIRD_PARTY_ROLE_UNIQUE_ID,
                    "Operations": ["GenerateDataKey"],
                },
            ],
            temp_results_dir,
        )

        key = results_data["keys_third_parties_can_access"][0]
        assert [grant["grant_id"] for grant in key["grants"]] == [
            "grant-arn",
            "grant-unique-id",
        ]
        assert [grant["grantee_account_id"] for grant in key["grants"]] == [
            THIRD_PARTY,
            THIRD_PARTY,
        ]
        assert [grant["grantee_account_id_source"] for grant in key["grants"]] == [
            "arn",
            "iam_unique_id",
        ]
        assert results_data["summary"]["unique_third_party_accounts"] == [THIRD_PARTY]


class TestConfinedKeyPolicies:
    """
    The key's entry names the condition keys that bounded its statements.

    A KMS key policy is the one place two different keys can each bound a
    statement on their own: `kms:CallerAccount` is the caller's account as
    KMS itself reports it, and `aws:PrincipalAccount` is the same fact under
    IAM's name.
    """

    def test_the_entry_names_every_key_that_confined_it_in_order(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        Both keys are recorded, sorted, so the entry reads the same every run.

        The analysis carries a set, whose iteration order is a hash order
        that varies between processes. A file whose field reorders between
        runs is a diff on every re-scan.
        """
        key = KMSKeyPolicyAnalysis(
            key_id="key-confined",
            key_arn=f"arn:aws:kms:us-east-1:{ORG_ACCOUNT}:key/key-confined",
            region="us-east-1",
            third_party_account_ids={THIRD_PARTY},
            actions_by_account={THIRD_PARTY: ["kms:Decrypt"]},
            has_wildcard_principal=False,
            confined_by={"kms:calleraccount", "aws:principalaccount"},
        )

        results_data = run_check([key], temp_results_dir)

        entry = results_data["keys_third_parties_can_access"][0]
        assert entry["confined_by"] == ["aws:principalaccount", "kms:calleraccount"]
