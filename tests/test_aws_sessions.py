"""
Tests for headroom.aws.sessions module.

Tests for AWS session management and role assumption utilities.
"""

import ast
import threading
import time
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from unittest.mock import ANY, MagicMock, patch

import headroom
from headroom.aws.sessions import (
    RETRY_MAX_ATTEMPTS,
    assume_role,
    new_session,
)


@pytest.fixture
def hermetic_aws_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """
    Isolate boto3 from whatever AWS configuration happens to be on the machine.

    Assertions about a resolved region or endpoint only mean something when the
    ambient profile, environment, and config files cannot supply either value.
    AWS_STS_REGIONAL_ENDPOINTS is cleared in particular, so these tests prove
    that Headroom -- not the developer's environment -- picks the regional
    endpoint.
    """
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_STS_REGIONAL_ENDPOINTS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "FAKE_ACCESS_KEY_ID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "FAKE_SECRET_ACCESS_KEY")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "absent-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


class TestAssumeRole:
    """Test assume_role function."""

    def test_assume_role_success(self) -> None:
        """Test successful role assumption."""
        mock_base_session = MagicMock()
        mock_base_session.region_name = "us-west-2"
        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client

        mock_sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "FAKE_ACCESS_KEY_ID",
                "SecretAccessKey": "FAKE_SECRET_ACCESS_KEY",
                "SessionToken": "FAKE_SESSION_TOKEN"
            }
        }

        with patch("headroom.aws.sessions.Session") as mock_session_class:
            mock_new_session = MagicMock()
            mock_session_class.return_value = mock_new_session

            result = assume_role(
                role_arn="arn:aws:iam::111111111111:role/TestRole",
                session_name="TestSession",
                base_session=mock_base_session
            )

            mock_sts_client.assume_role.assert_called_once_with(
                RoleArn="arn:aws:iam::111111111111:role/TestRole",
                RoleSessionName="TestSession"
            )

            mock_session_class.assert_called_once_with(
                botocore_session=ANY,
                region_name="us-west-2",
                aws_access_key_id="FAKE_ACCESS_KEY_ID",
                aws_secret_access_key="FAKE_SECRET_ACCESS_KEY",
                aws_session_token="FAKE_SESSION_TOKEN"
            )

            assert result is mock_new_session

    def test_assume_role_with_default_session(self) -> None:
        """Test role assumption with default base session."""
        with patch("headroom.aws.sessions.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_sts_client = MagicMock()
            mock_session.client.return_value = mock_sts_client

            mock_sts_client.assume_role.return_value = {
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "SessionToken": "AQoDYXdzEJr...<remainder of token>"
                }
            }

            result = assume_role(
                role_arn="arn:aws:iam::111111111111:role/TestRole",
                session_name="TestSession"
            )

            mock_sts_client.assume_role.assert_called_once()
            assert result is not None

    def test_assume_role_client_error(self) -> None:
        """Test role assumption failure with ClientError."""
        mock_base_session = MagicMock()
        mock_base_session.region_name = "us-west-2"
        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client

        mock_sts_client.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}},
            "AssumeRole"
        )

        with pytest.raises(ClientError) as exc_info:
            assume_role(
                role_arn="arn:aws:iam::111111111111:role/TestRole",
                session_name="TestSession",
                base_session=mock_base_session
            )

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_assume_role_propagates_client_error_type(self) -> None:
        """Test that ClientError propagates with original error code."""
        mock_base_session = MagicMock()
        mock_base_session.region_name = "us-west-2"
        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client

        mock_sts_client.assume_role.side_effect = ClientError(
            {"Error": {"Code": "InvalidParameter", "Message": "Invalid parameter"}},
            "AssumeRole"
        )

        role_arn = "arn:aws:iam::999999999999:role/SpecificRole"

        with pytest.raises(ClientError) as exc_info:
            assume_role(
                role_arn=role_arn,
                session_name="TestSession",
                base_session=mock_base_session
            )

        assert exc_info.value.response["Error"]["Code"] == "InvalidParameter"

    def test_assume_role_extracts_credentials_correctly(self) -> None:
        """Test that credentials are extracted correctly from response."""
        mock_base_session = MagicMock()
        mock_base_session.region_name = "us-west-2"
        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client

        expected_access_key = "FAKE_ACCESS_KEY_ID"
        expected_secret_key = "FAKE_SECRET_ACCESS_KEY"
        expected_session_token = "FAKE_SESSION_TOKEN"

        mock_sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": expected_access_key,
                "SecretAccessKey": expected_secret_key,
                "SessionToken": expected_session_token
            }
        }

        with patch("headroom.aws.sessions.Session") as mock_session_class:
            mock_new_session = MagicMock()
            mock_session_class.return_value = mock_new_session

            result = assume_role(
                role_arn="arn:aws:iam::111111111111:role/TestRole",
                session_name="TestSession",
                base_session=mock_base_session
            )

            mock_session_class.assert_called_once_with(
                botocore_session=ANY,
                region_name="us-west-2",
                aws_access_key_id=expected_access_key,
                aws_secret_access_key=expected_secret_key,
                aws_session_token=expected_session_token
            )

            assert result == mock_new_session

    def test_assume_role_uses_base_session_for_sts_client(self) -> None:
        """Test that base session is used to create STS client."""
        mock_base_session = MagicMock()
        mock_base_session.region_name = "us-west-2"
        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client

        mock_sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "FAKE_ACCESS_KEY_ID",
                "SecretAccessKey": "FAKE_SECRET_ACCESS_KEY",
                "SessionToken": "FAKE_SESSION_TOKEN"
            }
        }

        assume_role(
            role_arn="arn:aws:iam::111111111111:role/TestRole",
            session_name="TestSession",
            base_session=mock_base_session
        )

        mock_base_session.client.assert_called_once_with(
            "sts", region_name="us-west-2"
        )


class TestNewSession:
    """Test the single constructor for boto3 sessions."""

    @pytest.mark.parametrize("region", ["us-east-1", "us-west-2", "eu-west-1"])
    def test_sts_resolves_to_a_regional_endpoint(
        self, hermetic_aws_env: None, region: str
    ) -> None:
        """
        STS is reached at sts.<region>.amazonaws.com, never at sts.amazonaws.com.

        Each region here is in botocore's LEGACY_GLOBAL_STS_REGIONS, where
        botocore's default `sts_regional_endpoints=legacy` setting silently
        rewrites the endpoint to the global sts.amazonaws.com. Session tokens
        minted at the global endpoint are valid only in regions that are
        enabled by default, so every Headroom call in an opt-in region fails
        with AuthFailure. Pinning the regional endpoint is what makes the
        assumed-role credentials usable everywhere Headroom scans.
        """
        session = new_session(region_name=region)

        sts_endpoint = session.client("sts").meta.endpoint_url

        assert sts_endpoint == f"https://sts.{region}.amazonaws.com"

    def test_region_is_carried_onto_the_session(self, hermetic_aws_env: None) -> None:
        """An explicit region is not re-resolved from the environment."""
        session = new_session(region_name="eu-central-1")

        assert session.region_name == "eu-central-1"

    def test_credentials_are_carried_onto_the_session(self, hermetic_aws_env: None) -> None:
        """Explicit credentials reach the session rather than the ambient chain."""
        session = new_session(
            region_name="us-west-2",
            aws_access_key_id="FAKE_ASSUMED_KEY_ID",
            aws_secret_access_key="FAKE_ASSUMED_SECRET",
            aws_session_token="FAKE_ASSUMED_TOKEN",
        )

        credentials = session.get_credentials()

        assert credentials is not None
        assert credentials.access_key == "FAKE_ASSUMED_KEY_ID"
        assert credentials.token == "FAKE_ASSUMED_TOKEN"

    def test_region_falls_back_to_the_environment(self, hermetic_aws_env: None) -> None:
        """Omitting the region leaves boto3's normal resolution in charge."""
        session = new_session()

        assert session.region_name is None


class TestAssumeRoleRegionHandling:
    """Test that assumed-role credentials work in opt-in regions."""

    @staticmethod
    def _base_session(region_name: str | None) -> MagicMock:
        base_session = MagicMock()
        base_session.region_name = region_name
        base_session.client.return_value.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "FAKE_ACCESS_KEY_ID",
                "SecretAccessKey": "FAKE_SECRET_ACCESS_KEY",
                "SessionToken": "FAKE_SESSION_TOKEN",
            }
        }
        return base_session

    def test_sts_is_called_in_the_base_session_region(self) -> None:
        """AssumeRole is issued against an explicit region, not a default."""
        base_session = self._base_session("us-west-2")

        assume_role("arn:aws:iam::111111111111:role/Headroom", "TestSession", base_session)

        base_session.client.assert_called_once_with(
            "sts", region_name="us-west-2"
        )

    def test_returned_session_reaches_sts_regionally(self, hermetic_aws_env: None) -> None:
        """
        The session handed back to callers mints its own tokens regionally too.

        Headroom chains role assumptions -- base to security account to member
        account -- so a returned session that fell back to the global endpoint
        would reintroduce the AuthFailure one hop later.
        """
        base_session = self._base_session("us-west-2")

        session = assume_role(
            "arn:aws:iam::111111111111:role/Headroom", "TestSession", base_session
        )

        assert session.region_name == "us-west-2"
        assert session.client("sts").meta.endpoint_url == "https://sts.us-west-2.amazonaws.com"

    def test_missing_region_aborts_instead_of_guessing(self) -> None:
        """
        No region means no defensible STS endpoint, so refuse to continue.

        Falling back to a default region would send AssumeRole somewhere the
        caller never asked for and mint tokens whose validity depends on which
        default was chosen.
        """
        base_session = self._base_session(None)

        with pytest.raises(RuntimeError) as exc_info:
            assume_role(
                "arn:aws:iam::111111111111:role/Headroom", "TestSession", base_session
            )

        assert "no AWS region" in str(exc_info.value)
        base_session.client.assert_not_called()


class TestSessionConstructionIsCentralised:
    """Guard the single entry point for building boto3 sessions."""

    def test_only_the_sessions_module_constructs_a_session(self) -> None:
        """
        Every boto3 Session in the package must come from new_session().

        A Session built directly inherits botocore's `legacy`
        sts_regional_endpoints default, which rewrites AssumeRole to the global
        sts.amazonaws.com endpoint whenever the caller's region is one of
        botocore's LEGACY_GLOBAL_STS_REGIONS. Tokens from there are rejected in
        every opt-in region. Nothing in a test suite that mocks AWS would notice,
        and a scan only fails once it reaches such a region, so pin the
        invariant statically instead of rediscovering it in production.
        """
        package_root = Path(headroom.__file__).parent

        builders = set()
        for path in sorted(package_root.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                func = getattr(node, "func", None)
                called = getattr(func, "attr", None) or getattr(func, "id", None)
                if called == "Session":
                    builders.add(path.relative_to(package_root).as_posix())

        assert builders == {"aws/sessions.py"}


class TestConcurrentClientConstruction:
    """Test that workers do not build STS clients from one session at once."""

    def test_client_construction_is_serialized(self) -> None:
        """
        Only one thread constructs a client from the shared session at a time.

        Every worker assumes a role using the one security-analysis session.
        Session.client() resolves the service model through the session's
        loader and mutates its component registry on first use, so concurrent
        first calls race. The lock covers construction only; the assume_role
        round trip stays outside it so workers still overlap.

        This probe can only ever false-pass, never false-fail.
        """
        live = 0
        peak = 0
        guard = threading.Lock()

        def construct(*args: object, **kwargs: object) -> MagicMock:
            nonlocal live, peak
            with guard:
                live += 1
                peak = max(peak, live)
            time.sleep(0.005)
            with guard:
                live -= 1
            client = MagicMock()
            client.assume_role.return_value = {
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            }
            return client

        base_session = MagicMock()
        base_session.region_name = "us-east-1"
        base_session.client.side_effect = construct

        threads = [
            threading.Thread(
                target=assume_role,
                args=("arn:aws:iam::111111111111:role/Headroom", "s", base_session),
            )
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert peak == 1


class TestSessionRetryConfiguration:
    """Test the retry behaviour every client inherits from the session."""

    def test_session_sets_standard_retry_mode(self) -> None:
        """
        Retries are configured on the session, so every client inherits them
        without a per-call-site Config.
        """
        with patch("headroom.aws.sessions.botocore.session.get_session") as mock_get:
            botocore_session = MagicMock()
            mock_get.return_value = botocore_session

            new_session()

        botocore_session.set_config_variable.assert_any_call("retry_mode", "standard")
        botocore_session.set_config_variable.assert_any_call(
            "max_attempts", RETRY_MAX_ATTEMPTS
        )

    def test_a_client_built_from_the_session_resolves_five_standard_attempts(
        self,
        hermetic_aws_env: None,
    ) -> None:
        """
        The resolved values, read off a real client rather than off the calls.

        The test above pins the two knob names, which is worth having -- both
        survive a rename attempt. It cannot pin either value: setting
        RETRY_MAX_ATTEMPTS to 1 left the whole suite green, and so did a
        second set_config_variable overriding the first, which assert_any_call
        has no way to see because it only asks whether a call ever happened.

        Five is asserted as a literal, and it is not an arbitrary one: legacy,
        the mode botocore uses by default, already allowed five attempts, and
        `standard` allows three, so this is the number that keeps the ceiling
        where it was while changing the retry predicate. `total_max_attempts`
        is botocore's own name for the count including the first try.
        """
        client = new_session(region_name="us-east-1").client("sts")

        # botocore populates Config.retries at runtime from OPTION_DEFAULTS;
        # the stubs do not declare it.
        resolved = client.meta.config.retries  # type: ignore[attr-defined]

        assert resolved == {"total_max_attempts": 5, "mode": "standard"}
