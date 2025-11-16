"""
Tests for headroom.aws.sessions module.

Tests for AWS session management and role assumption utilities.
"""

import pytest
from botocore.exceptions import ClientError
from unittest.mock import MagicMock, patch
from headroom.aws.sessions import assume_role


class TestAssumeRole:
    """Test assume_role function."""

    def test_assume_role_success(self) -> None:
        """Test successful role assumption."""
        mock_base_session = MagicMock()
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
                role_arn="arn:aws:iam::123456789012:role/TestRole",
                session_name="TestSession",
                base_session=mock_base_session
            )

            mock_sts_client.assume_role.assert_called_once_with(
                RoleArn="arn:aws:iam::123456789012:role/TestRole",
                RoleSessionName="TestSession"
            )

            mock_session_class.assert_called_once_with(
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
                role_arn="arn:aws:iam::123456789012:role/TestRole",
                session_name="TestSession"
            )

            mock_sts_client.assume_role.assert_called_once()
            assert result is not None

    def test_assume_role_client_error(self) -> None:
        """Test role assumption failure with ClientError."""
        mock_base_session = MagicMock()
        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client

        mock_sts_client.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}},
            "AssumeRole"
        )

        with pytest.raises(ClientError) as exc_info:
            assume_role(
                role_arn="arn:aws:iam::123456789012:role/TestRole",
                session_name="TestSession",
                base_session=mock_base_session
            )

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_assume_role_propagates_client_error_type(self) -> None:
        """Test that ClientError propagates with original error code."""
        mock_base_session = MagicMock()
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
                role_arn="arn:aws:iam::123456789012:role/TestRole",
                session_name="TestSession",
                base_session=mock_base_session
            )

            mock_session_class.assert_called_once_with(
                aws_access_key_id=expected_access_key,
                aws_secret_access_key=expected_secret_key,
                aws_session_token=expected_session_token
            )

            assert result == mock_new_session

    def test_assume_role_uses_base_session_for_sts_client(self) -> None:
        """Test that base session is used to create STS client."""
        mock_base_session = MagicMock()
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
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            session_name="TestSession",
            base_session=mock_base_session
        )

        mock_base_session.client.assert_called_once_with("sts")
