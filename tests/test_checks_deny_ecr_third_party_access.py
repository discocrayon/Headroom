"""
Tests for headroom.checks.rcps.deny_ecr_third_party_access module.
"""

import json
import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import Any, Dict, Generator, List

from botocore.exceptions import ClientError

from headroom.checks.rcps.deny_ecr_third_party_access import DenyECRThirdPartyAccessCheck
from headroom.constants import DENY_ECR_THIRD_PARTY_ACCESS
from headroom.aws.ecr import ECRPolicyAnalysis
from headroom.types import JsonDict
from tests.constants import ORG_ID


class TestCheckDenyECRThirdPartyAccess:
    """Test deny_ecr_third_party_access check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def org_account_ids(self) -> set[str]:
        """Set of organization account IDs."""
        return {"111111111111", "222222222222"}

    @pytest.fixture
    def sample_ecr_results_mixed(self) -> List[ECRPolicyAnalysis]:
        """Create sample ECR results with mixed compliance status."""
        return [
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="compliant-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/compliant-repo",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
                },
                has_wildcard_principal=False
            ),
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="wildcard-repo",
                repository_arn="arn:aws:ecr:us-west-2:111111111111:repository/wildcard-repo",
                region="us-west-2",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
        ]

    def test_check_deny_ecr_third_party_access_mixed_results(
        self,
        sample_ecr_results_mixed: List[ECRPolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_ecr_results_mixed

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[1]["results_data"]

            assert len(results_data["policies_with_wildcards"]) == 1
            assert len(results_data["policies_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_policies_analyzed"] == 2
            assert summary["policies_with_wildcards"] == 1
            assert summary["policies_third_parties_can_access"] == 1
            assert summary["violations"] == 1
            assert summary["third_party_account_count"] == 1
            assert "999999999999" in summary["unique_third_party_accounts"]

    def test_check_all_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all repositories compliant."""
        mock_session = MagicMock()

        all_compliant = [
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="vendor-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/vendor-repo",
                region="us-east-1",
                third_party_account_ids={"888888888888"},
                actions_by_account={
                    "888888888888": ["ecr:BatchGetImage"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["policies_with_wildcards"] == 0
            assert summary["policies_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all repositories having wildcards."""
        mock_session = MagicMock()

        all_violations = [
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="public-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/public-repo",
                region="us-east-1",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 1
            assert summary["policies_with_wildcards"] == 1

    def test_check_empty_results(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with no repositories found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_policies_analyzed"] == 0
            assert summary["violations"] == 0
            assert summary["third_party_account_count"] == 0

    def test_categorize_result_violation(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of violation (wildcard)."""
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = ECRPolicyAnalysis(
            scope="repository",
            repository_name="wildcard-repo",
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/wildcard-repo",
            region="us-east-1",
            third_party_account_ids=set(),
            actions_by_account={},
            has_wildcard_principal=True
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of compliant (third-party but no wildcard)."""
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = ECRPolicyAnalysis(
            scope="repository",
            repository_name="vendor-repo",
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/vendor-repo",
            region="us-east-1",
            third_party_account_ids={"999999999999"},
            actions_by_account={
                "999999999999": ["ecr:GetDownloadUrlForLayer"]
            },
            has_wildcard_principal=False
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["has_wildcard_principal"] is False
        assert "999999999999" in result_dict["third_party_account_ids"]

    def test_categorize_result_non_account_principal_is_a_violation(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """A Federated or CanonicalUser principal blocks the account."""
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = ECRPolicyAnalysis(
            scope="repository",
            repository_name="federated-repo",
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/federated-repo",
            region="us-east-1",
            third_party_account_ids=set(),
            actions_by_account={},
            has_wildcard_principal=False,
            has_non_account_principals=True,
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["has_non_account_principals"] is True

    def test_a_non_account_principal_alone_is_not_cleared(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """
        A repository whose only finding is a Federated principal is reported.

        No allowlist keyed on aws:PrincipalAccount can preserve that grant, so
        dropping it would clear the account and deploy an RCP that denies a
        grant the account depends on, against INV-01.
        """
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = [
                ECRPolicyAnalysis(
                    scope="repository",
                    repository_name="federated-repo",
                    repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/federated-repo",
                    region="us-east-1",
                    third_party_account_ids=set(),
                    actions_by_account={},
                    has_wildcard_principal=False,
                    has_non_account_principals=True,
                )
            ]

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            summary = mock_write.call_args[1]["results_data"]["summary"]

            assert summary["violations"] == 1

    def test_actions_by_account_union(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test that actions are unioned across multiple repositories."""
        mock_session = MagicMock()

        results = [
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="repo1",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer"]
                },
                has_wildcard_principal=False
            ),
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="repo2",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo2",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:BatchGetImage", "ecr:DescribeImages"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            actions = summary["actions_by_account"]["999999999999"]
            assert len(actions) == 3
            assert "ecr:GetDownloadUrlForLayer" in actions
            assert "ecr:BatchGetImage" in actions
            assert "ecr:DescribeImages" in actions

    def test_multiple_third_party_accounts(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test multiple third-party accounts across repositories."""
        mock_session = MagicMock()

        results = [
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="repo1",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer"]
                },
                has_wildcard_principal=False
            ),
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="repo2",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/repo2",
                region="us-east-1",
                third_party_account_ids={"888888888888"},
                actions_by_account={
                    "888888888888": ["ecr:BatchGetImage"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["third_party_account_count"] == 2
            assert "999999999999" in summary["unique_third_party_accounts"]
            assert "888888888888" in summary["unique_third_party_accounts"]
            assert "999999999999" in summary["actions_by_account"]
            assert "888888888888" in summary["actions_by_account"]

    def test_wildcard_with_third_party_accounts(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test repository with both wildcard and third-party accounts."""
        mock_session = MagicMock()

        results = [
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="mixed-repo",
                repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/mixed-repo",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["ecr:GetDownloadUrlForLayer"]
                },
                has_wildcard_principal=True
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyECRThirdPartyAccessCheck(
                check_name=DENY_ECR_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 1
            assert summary["policies_with_wildcards"] == 1
            assert summary["policies_third_parties_can_access"] == 1
            assert summary["third_party_account_count"] == 1

    def test_result_dict_format(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test that result dict has correct format."""
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = ECRPolicyAnalysis(
            scope="repository",
            repository_name="test-repo",
            repository_arn="arn:aws:ecr:us-east-1:111111111111:repository/test-repo",
            region="us-east-1",
            third_party_account_ids={"999999999999", "888888888888"},
            actions_by_account={
                "999999999999": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                "888888888888": ["ecr:DescribeImages"]
            },
            has_wildcard_principal=False
        )

        category, result_dict = check.categorize_result(result)

        assert "repository_name" in result_dict
        assert "repository_arn" in result_dict
        assert "region" in result_dict
        assert "third_party_account_ids" in result_dict
        assert "actions_by_account" in result_dict
        assert "has_wildcard_principal" in result_dict

        assert isinstance(result_dict["third_party_account_ids"], list)
        assert result_dict["third_party_account_ids"] == sorted(["999999999999", "888888888888"])

        assert isinstance(result_dict["actions_by_account"], dict)
        for account_id, actions in result_dict["actions_by_account"].items():
            assert isinstance(actions, list)
            assert actions == sorted(actions)


class TestRegistryScopedResults:
    """
    Registry policies travel the check beside repository policies.

    They are a second resource rather than a second half of the same one, so
    each carries its own row, distinguished by scope.
    """

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create a temporary directory for check results."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @staticmethod
    def _check(temp_results_dir: str) -> DenyECRThirdPartyAccessCheck:
        """
        Build a check writing into the given directory.

        Args:
            temp_results_dir: Directory the check writes results to

        Returns:
            A check instance for one organization account
        """
        return DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids={"111111111111"},
            org_id=ORG_ID,
        )

    def test_registry_result_reports_no_repository(
        self, temp_results_dir: str
    ) -> None:
        """The row says registry, and names no repository, because there is none."""
        check = self._check(temp_results_dir)

        _, result_dict = check.categorize_result(
            ECRPolicyAnalysis(
                scope="registry",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={"999999999999": ["ecr:ReplicateImage"]},
            )
        )

        assert result_dict["scope"] == "registry"
        assert result_dict["repository_name"] is None
        assert result_dict["repository_arn"] is None
        assert result_dict["region"] == "us-east-1"

    def test_registry_third_party_reaches_the_allowlist(
        self, temp_results_dir: str
    ) -> None:
        """
        A third party seen only in a registry policy still reaches the allowlist.

        This is the gap the registry read closes: before it, the account was
        invisible, so the RCP shipped without allowlisting it and broke it.
        """
        check = self._check(temp_results_dir)
        check.categorize_result(
            ECRPolicyAnalysis(
                scope="registry",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={"999999999999": ["ecr:ReplicateImage"]},
            )
        )

        assert check.all_third_party_accounts == {"999999999999"}
        assert check.all_actions_by_account["999999999999"] == {"ecr:ReplicateImage"}

    def test_wildcard_registry_policy_is_a_violation(
        self, temp_results_dir: str
    ) -> None:
        """A wildcard registry policy withholds the RCP, as a repository one does."""
        check = self._check(temp_results_dir)

        category, _ = check.categorize_result(
            ECRPolicyAnalysis(
                scope="registry",
                region="us-east-1",
                third_party_account_ids=set(),
                has_wildcard_principal=True,
            )
        )

        assert category == "violation"

    def test_summary_counts_both_scopes(self, temp_results_dir: str) -> None:
        """
        Both scopes count toward violations, which is what blocks the RCP.

        The RCP generator reads only `violations` and
        `unique_third_party_accounts`, so a registry finding that missed
        those two keys would be invisible where it matters most.
        """
        check = self._check(temp_results_dir)
        mock_session = MagicMock()

        results = [
            ECRPolicyAnalysis(
                scope="registry",
                region="us-east-1",
                third_party_account_ids=set(),
                has_wildcard_principal=True,
            ),
            ECRPolicyAnalysis(
                scope="repository",
                repository_name="vendor-repo",
                repository_arn=(
                    "arn:aws:ecr:us-east-1:111111111111:repository/vendor-repo"
                ),
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={"999999999999": ["ecr:BatchGetImage"]},
            ),
        ]

        with (
            patch(
                "headroom.checks.rcps.deny_ecr_third_party_access.analyze_ecr_policies",
                return_value=results,
            ),
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            check.execute(mock_session)

        summary = mock_write.call_args[1]["results_data"]["summary"]

        assert summary["total_policies_analyzed"] == 2
        assert summary["policies_with_wildcards"] == 1
        assert summary["violations"] == 1
        assert summary["unique_third_party_accounts"] == ["999999999999"]


# One statement whose bare wildcard `aws:PrincipalAccount` bounds to a single
# account outside the organization. Three tests below read the same statement,
# because what varies between them is the rest of the policy around it.
CONFINED_WILDCARD_STATEMENT: JsonDict = {
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "ecr:BatchGetImage",
    "Condition": {"StringEquals": {"aws:PrincipalAccount": ["333333333333"]}},
}


class TestConfinedWildcards:
    """
    A wildcard the Condition block bounds travels the check as the accounts it admits.

    The adapter stops calling such a statement a wildcard, so the check must
    still carry the accounts it named into the allowlist. Clearing the
    violation without carrying the accounts ships an RCP that denies exactly
    the access the repository policy granted.

    The other tests in this file hand the check a pre-built ECRPolicyAnalysis,
    which cannot show whether the adapter read a wildcard as confined; these
    mock the client so analyze_ecr_policies itself does the reading.
    """

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create a temporary directory for check results."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @staticmethod
    def _session_holding(policy: JsonDict) -> MagicMock:
        """
        Build a session whose one region holds one repository with this policy.

        Args:
            policy: Repository policy document, as the API returns it

        Returns:
            A session the real ECR analyzer can read
        """
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        # Without this, get_registry_policy() returns a Mock, which the
        # analyzer would hand to json.loads().
        error_response: Any = {"Error": {"Code": "RegistryPolicyNotFoundException"}}
        mock_ecr_client.get_registry_policy.side_effect = ClientError(
            error_response, "GetRegistryPolicy"
        )

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {"repositories": [{
                "repositoryName": "vendor-repo",
                "repositoryArn": (
                    "arn:aws:ecr:us-east-1:111111111111:repository/vendor-repo"
                ),
            }]}
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }
        return mock_session

    @staticmethod
    def _results_data(temp_results_dir: str, mock_session: MagicMock) -> Dict[str, Any]:
        """
        Run the check against a session and return the document it wrote.

        Args:
            temp_results_dir: Directory the check writes results to
            mock_session: Session the analyzer reads

        Returns:
            The whole result document, summary and entries alike
        """
        check = DenyECRThirdPartyAccessCheck(
            check_name=DENY_ECR_THIRD_PARTY_ACCESS,
            account_name="test-account",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids={"111111111111", "222222222222"},
            org_id=ORG_ID,
        )

        with (
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            check.execute(mock_session)

        results_data: Dict[str, Any] = mock_write.call_args[1]["results_data"]
        return results_data

    def test_a_wildcard_confined_to_out_of_org_accounts_reaches_the_allowlist(
        self, temp_results_dir: str
    ) -> None:
        """
        Clearing the violation without allowlisting the account is the outage.

        The repository grants 333333333333 and nobody else, so the RCP may
        ship - but only carrying that account. An RCP that shipped because
        the wildcard was read as confined and then omitted the account it
        was confined to would deny the one caller the policy admits.
        """
        mock_session = self._session_holding(
            {"Version": "2012-10-17", "Statement": [CONFINED_WILDCARD_STATEMENT]}
        )

        summary = self._results_data(temp_results_dir, mock_session)["summary"]

        assert summary["violations"] == 0
        assert summary["unique_third_party_accounts"] == ["333333333333"]

    def test_a_confined_entry_names_the_key_that_confined_it(
        self, temp_results_dir: str
    ) -> None:
        """
        The entry records why the repository stopped counting as a wildcard.

        Without the key, a reader of the result file sees a repository with
        `has_wildcard_principal: false` and no way to tell a policy that
        never named a wildcard from one whose wildcard a condition bounded.
        """
        mock_session = self._session_holding(
            {"Version": "2012-10-17", "Statement": [CONFINED_WILDCARD_STATEMENT]}
        )

        results_data = self._results_data(temp_results_dir, mock_session)

        assert results_data["policies_with_wildcards"] == []
        entry = results_data["policies_third_parties_can_access"][0]
        assert entry["repository_name"] == "vendor-repo"
        assert entry["confined_by"] == ["aws:principalaccount"]

    def test_a_surviving_wildcard_does_not_erase_the_confined_statement(
        self, temp_results_dir: str
    ) -> None:
        """
        One unbounded statement blocks the repository; the bounded one is still recorded.

        `confined_by` is a union across the policy's statements, not a verdict
        on the policy, so the second statement's wildcard withholds the RCP
        without hiding what the first statement proved.
        """
        mock_session = self._session_holding({
            "Version": "2012-10-17",
            "Statement": [
                CONFINED_WILDCARD_STATEMENT,
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "ecr:DescribeImages",
                },
            ],
        })

        results_data = self._results_data(temp_results_dir, mock_session)

        entry = results_data["policies_with_wildcards"][0]
        assert entry["has_wildcard_principal"] is True
        assert entry["confined_by"] == ["aws:principalaccount"]

    def test_an_unconfined_repository_says_so_rather_than_omitting_the_field(
        self, temp_results_dir: str
    ) -> None:
        """
        A policy no condition bounded writes an empty list, not a missing key.

        The repository is reported because it names an account outside the
        organization, so the field is reached on a policy whose statements
        carry no Condition at all. A reader that has to tell an absent field
        from an empty one cannot distinguish this repository from one
        written before the field existed.
        """
        mock_session = self._session_holding({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::333333333333:root"},
                    "Action": "ecr:BatchGetImage",
                }
            ],
        })

        results_data = self._results_data(temp_results_dir, mock_session)

        entry = results_data["policies_third_parties_can_access"][0]
        assert entry["third_party_account_ids"] == ["333333333333"]
        assert entry["confined_by"] == []
