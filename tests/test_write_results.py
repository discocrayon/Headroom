"""
Tests for write_results module.

Tests the result writing functionality, ensuring proper file creation,
directory structure, and JSON formatting.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, cast
from unittest.mock import MagicMock, patch

import pytest

from headroom.write_results import (
    write_check_results,
    get_results_dir,
    get_results_path,
    results_exist,
    _redact_account_ids_from_arns,
)


class TestWriteCheckResults:
    """Test write_check_results function."""

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_creates_file(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that write_check_results creates the expected file."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {
                "summary": {
                    "account_name": account_name,
                    "account_id": account_id,
                    "check": check_name,
                    "total_instances": 5,
                    "violations": 2,
                    "exemptions": 1,
                    "compliant": 2,
                    "compliance_percentage": 60.0
                },
                "violations": [{"instance_id": "i-123"}],
                "exemptions": [{"instance_id": "i-456"}],
                "compliant_instances": [{"instance_id": "i-789"}, {"instance_id": "i-abc"}]
            }

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
            )

            expected_path = Path(temp_dir) / "scps" / check_name / f"{account_name}_{account_id}.json"
            assert expected_path.exists()

            with open(expected_path, 'r') as f:
                loaded_data = json.load(f)
                assert loaded_data == results_data

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_creates_directory(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that write_check_results creates necessary directories."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {"summary": {}}

            # Ensure check directory doesn't exist yet
            check_dir = Path(temp_dir) / "scps" / check_name
            assert not check_dir.exists()

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
            )

            assert check_dir.exists()
            assert check_dir.is_dir()

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_json_formatting(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that JSON is written with proper formatting."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {
                "summary": {"key": "value"},
                "violations": []
            }

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
            )

            expected_path = Path(temp_dir) / "scps" / check_name / f"{account_name}_{account_id}.json"
            with open(expected_path, 'r') as f:
                content = f.read()
                # Check that JSON is indented (formatted)
                assert "  " in content
                assert "{\n" in content

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_overwrites_existing(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that write_check_results overwrites existing files."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"

            # Write first version
            results_data_v1: Dict[str, Any] = {"summary": {"version": 1}}
            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data_v1,
                results_base_dir=temp_dir,
            )

            # Write second version
            results_data_v2: Dict[str, Any] = {"summary": {"version": 2}}
            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data_v2,
                results_base_dir=temp_dir,
            )

            expected_path = Path(temp_dir) / "scps" / check_name / f"{account_name}_{account_id}.json"
            with open(expected_path, 'r') as f:
                loaded_data = json.load(f)
                assert loaded_data["summary"]["version"] == 2

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_handles_special_characters(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that account names with special characters are handled correctly."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account-with-dashes"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {"summary": {}}

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
            )

            expected_path = Path(temp_dir) / "scps" / check_name / f"{account_name}_{account_id}.json"
            assert expected_path.exists()

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_raises_on_io_error(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that IOError is raised when file writing fails."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        check_name = "deny_imds_v1_ec2"
        account_name = "test-account"
        account_id = "111111111111"
        results_data: Dict[str, Any] = {"summary": {}}

        # Create a mock that raises IOError when write is called
        mock_file_handle = MagicMock()
        mock_file_handle.__enter__.return_value = mock_file_handle
        mock_file_handle.write.side_effect = IOError("Permission denied")

        with (
            patch("os.makedirs"),  # Mock makedirs to avoid actual directory creation
            patch("builtins.open", return_value=mock_file_handle),
            patch("json.dump", side_effect=IOError("Permission denied"))
        ):
            # Should raise IOError (fail fast, no catch-and-rethrow)
            with pytest.raises(IOError, match="Permission denied"):
                write_check_results(
                    check_name=check_name,
                    account_name=account_name,
                    account_id=account_id,
                    results_data=results_data,
                    results_base_dir="/some/dir",
                )

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_excludes_account_id_from_json(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that account_id is excluded from JSON when exclude_account_ids=True."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {
                "summary": {
                    "account_name": account_name,
                    "account_id": account_id,
                    "check": check_name,
                },
                "violations": []
            }

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
                exclude_account_ids=True,
            )

            expected_path = Path(temp_dir) / "scps" / check_name / f"{account_name}.json"
            assert expected_path.exists()

            with open(expected_path, 'r') as f:
                loaded_data = json.load(f)
                assert "account_id" not in loaded_data["summary"]
                assert loaded_data["summary"]["account_name"] == account_name

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_excludes_account_id_from_filename(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that filename excludes account_id when exclude_account_ids=True."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {"summary": {}}

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
                exclude_account_ids=True,
            )

            # Should create filename without account_id
            expected_path = Path(temp_dir) / "scps" / check_name / f"{account_name}.json"
            assert expected_path.exists()

            # Should NOT create filename with account_id
            unexpected_path = Path(temp_dir) / "scps" / check_name / f"{account_name}_{account_id}.json"
            assert not unexpected_path.exists()


class TestGetResultsDir:
    """Test get_results_dir function."""

    @patch('headroom.write_results.get_check_type_map')
    def test_get_results_dir_returns_correct_path(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that get_results_dir returns the correct directory path."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        check_name = "deny_imds_v1_ec2"
        results_base_dir = "/path/to/results"

        result = get_results_dir(check_name, results_base_dir)
        assert result == "/path/to/results/scps/deny_imds_v1_ec2"

    @patch('headroom.write_results.get_check_type_map')
    def test_get_results_dir_with_trailing_slash(self, mock_get_check_type_map: MagicMock) -> None:
        """Test get_results_dir handles trailing slashes."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        check_name = "deny_imds_v1_ec2"
        results_base_dir = "/path/to/results/"

        result = get_results_dir(check_name, results_base_dir)
        # Should still work (may have double slash but that's okay)
        assert check_name in result
        assert "scps" in result

    @patch('headroom.write_results.get_check_type_map')
    def test_get_results_dir_unknown_check_name(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that get_results_dir raises ValueError for unknown check names."""
        mock_get_check_type_map.return_value = {}
        check_name = "unknown_check"
        results_base_dir = "/path/to/results"

        with pytest.raises(ValueError, match="Unknown check name: unknown_check"):
            get_results_dir(check_name, results_base_dir)


class TestGetResultsPath:
    """Test get_results_path function."""

    @patch('headroom.write_results.get_check_type_map')
    def test_get_results_path_returns_correct_path(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that get_results_path returns the correct file path."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        check_name = "deny_imds_v1_ec2"
        account_name = "test-account"
        account_id = "111111111111"
        results_base_dir = "/path/to/results"

        result = get_results_path(check_name, account_name, account_id, results_base_dir)
        expected = Path("/path/to/results/scps/deny_imds_v1_ec2/test-account_111111111111.json")
        assert result == expected

    @patch('headroom.write_results.get_check_type_map')
    def test_get_results_path_returns_path_object(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that get_results_path returns a Path object."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        result = get_results_path("deny_imds_v1_ec2", "account", "123", "/base")
        assert isinstance(result, Path)

    @patch('headroom.write_results.get_check_type_map')
    def test_get_results_path_excludes_account_id_when_flag_set(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that get_results_path excludes account_id from filename when exclude_account_ids=True."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        check_name = "deny_imds_v1_ec2"
        account_name = "test-account"
        account_id = "111111111111"
        results_base_dir = "/path/to/results"

        result = get_results_path(
            check_name,
            account_name,
            account_id,
            results_base_dir,
            exclude_account_ids=True,
        )
        expected = Path("/path/to/results/scps/deny_imds_v1_ec2/test-account.json")
        assert result == expected


class TestResultsExist:
    """Test results_exist function."""

    @patch('headroom.write_results.get_check_type_map')
    def test_results_exist_returns_true_when_file_exists(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that results_exist returns True when file exists."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"

            # Create the file
            results_data: Dict[str, Any] = {"summary": {}}
            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
            )

            # Check if it exists
            assert results_exist(check_name, account_name, account_id, temp_dir) is True

    @patch('headroom.write_results.get_check_type_map')
    def test_results_exist_returns_false_when_file_missing(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that results_exist returns False when file doesn't exist."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"

            assert results_exist(check_name, account_name, account_id, temp_dir) is False

    @patch('headroom.write_results.get_check_type_map')
    def test_results_exist_returns_false_when_directory_missing(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that results_exist returns False when directory doesn't exist."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        check_name = "deny_imds_v1_ec2"
        account_name = "test-account"
        account_id = "111111111111"
        results_base_dir = "/nonexistent/directory"

        assert results_exist(check_name, account_name, account_id, results_base_dir) is False

    @patch('headroom.write_results.get_check_type_map')
    def test_results_exist_finds_file_without_account_id(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that results_exist finds files without account_id in filename."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"

            # Create file without account_id in filename
            results_data: Dict[str, Any] = {"summary": {}}
            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
                exclude_account_ids=True,
            )

            # Should find it when looking with exclude_account_ids=True
            assert results_exist(
                check_name,
                account_name,
                account_id,
                temp_dir,
                exclude_account_ids=True,
            ) is True

    @patch('headroom.write_results.get_check_type_map')
    def test_results_exist_backward_compatibility(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that results_exist finds old format files when using new format."""
        mock_get_check_type_map.return_value = {"deny_imds_v1_ec2": "scps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "deny_imds_v1_ec2"
            account_name = "test-account"
            account_id = "111111111111"

            # Create file with old format (account_id in filename)
            results_data: Dict[str, Any] = {"summary": {}}
            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
                exclude_account_ids=False,
            )

            # Should find it even when looking with exclude_account_ids=True
            assert results_exist(
                check_name,
                account_name,
                account_id,
                temp_dir,
                exclude_account_ids=True,
            ) is True


class TestRedactAccountIdsFromArns:
    """Test _redact_account_ids_from_arns function."""

    def test_redact_simple_arn_string(self) -> None:
        """Test redacting account ID from a simple ARN string."""
        arn = "arn:aws:iam::111111111111:role/MyRole"
        result = _redact_account_ids_from_arns(arn)
        assert result == "arn:aws:iam::REDACTED:role/MyRole"

    def test_redact_multiple_arns_in_string(self) -> None:
        """Test redacting multiple account IDs in a single string."""
        text = "arn:aws:iam::111111111111:role/Role1 and arn:aws:iam::222222222222:role/Role2"
        result = _redact_account_ids_from_arns(text)
        assert result == "arn:aws:iam::REDACTED:role/Role1 and arn:aws:iam::REDACTED:role/Role2"

    def test_redact_arns_in_dict(self) -> None:
        """Test redacting account IDs from ARNs in a dictionary."""
        data = {
            "role_name": "MyRole",
            "role_arn": "arn:aws:iam::111111111111:role/MyRole",
            "other_field": "no arn here"
        }
        result = cast(Dict[str, Any], _redact_account_ids_from_arns(data))
        assert result["role_arn"] == "arn:aws:iam::REDACTED:role/MyRole"
        assert result["role_name"] == "MyRole"
        assert result["other_field"] == "no arn here"

    def test_redact_arns_in_list(self) -> None:
        """Test redacting account IDs from ARNs in a list."""
        data = [
            "arn:aws:iam::111111111111:role/Role1",
            "arn:aws:iam::222222222222:role/Role2",
            "plain text"
        ]
        result = cast(List[Any], _redact_account_ids_from_arns(data))
        assert result[0] == "arn:aws:iam::REDACTED:role/Role1"
        assert result[1] == "arn:aws:iam::REDACTED:role/Role2"
        assert result[2] == "plain text"

    def test_redact_arns_in_nested_structure(self) -> None:
        """Test redacting account IDs from ARNs in nested data structures."""
        data = {
            "summary": {
                "account_name": "test-account",
                "account_id": "111111111111"
            },
            "roles": [
                {
                    "role_name": "Role1",
                    "role_arn": "arn:aws:iam::111111111111:role/Role1"
                },
                {
                    "role_name": "Role2",
                    "role_arn": "arn:aws:iam::222222222222:role/Role2"
                }
            ]
        }
        result = cast(Dict[str, Any], _redact_account_ids_from_arns(data))
        assert result["summary"]["account_id"] == "111111111111"
        assert result["roles"][0]["role_arn"] == "arn:aws:iam::REDACTED:role/Role1"
        assert result["roles"][1]["role_arn"] == "arn:aws:iam::REDACTED:role/Role2"

    def test_redact_preserves_non_string_types(self) -> None:
        """Test that non-string types are preserved unchanged."""
        data = {
            "count": 42,
            "percentage": 95.5,
            "enabled": True,
            "none_value": None
        }
        result = _redact_account_ids_from_arns(data)
        assert result == data

    def test_redact_handles_empty_structures(self) -> None:
        """Test that empty structures are handled correctly."""
        assert _redact_account_ids_from_arns({}) == {}
        assert _redact_account_ids_from_arns([]) == []
        assert _redact_account_ids_from_arns("") == ""

    def test_redact_different_aws_services(self) -> None:
        """Test redacting account IDs from ARNs of different AWS services."""
        data = {
            "iam_arn": "arn:aws:iam::111111111111:role/MyRole",
            "s3_arn": "arn:aws:s3::111111111111:bucket/MyBucket",
            "ec2_arn": "arn:aws:ec2::111111111111:instance/i-1234567890abcdef0"
        }
        result = cast(Dict[str, Any], _redact_account_ids_from_arns(data))
        assert result["iam_arn"] == "arn:aws:iam::REDACTED:role/MyRole"
        assert result["s3_arn"] == "arn:aws:s3::REDACTED:bucket/MyBucket"
        assert result["ec2_arn"] == "arn:aws:ec2::REDACTED:instance/i-1234567890abcdef0"

    def test_redact_arns_with_region(self) -> None:
        """Test redacting account IDs from ARNs with region field (e.g., RDS)."""
        data = {
            "rds_instance": "arn:aws:rds:us-east-1:111111111111:db:my-database",
            "rds_cluster": "arn:aws:rds:us-west-2:222222222222:cluster:my-cluster",
            "ec2_instance": "arn:aws:ec2:eu-west-1:333333333333:instance/i-1234567890"
        }
        result = cast(Dict[str, Any], _redact_account_ids_from_arns(data))
        assert result["rds_instance"] == "arn:aws:rds:us-east-1:REDACTED:db:my-database"
        assert result["rds_cluster"] == "arn:aws:rds:us-west-2:REDACTED:cluster:my-cluster"
        assert result["ec2_instance"] == "arn:aws:ec2:eu-west-1:REDACTED:instance/i-1234567890"

    def test_redact_does_not_affect_non_arn_numbers(self) -> None:
        """Test that non-ARN 12-digit numbers are not affected."""
        data = {
            "instance_id": "i-111111111111",
            "some_number": "111111111111",
            "role_arn": "arn:aws:iam::111111111111:role/MyRole"
        }
        result = cast(Dict[str, Any], _redact_account_ids_from_arns(data))
        assert result["instance_id"] == "i-111111111111"
        assert result["some_number"] == "111111111111"
        assert result["role_arn"] == "arn:aws:iam::REDACTED:role/MyRole"

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_redacts_arns_when_exclude_account_ids(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that ARNs are redacted when exclude_account_ids=True."""
        mock_get_check_type_map.return_value = {"third_party_assumerole": "rcps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "third_party_assumerole"
            account_name = "test-account"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {
                "summary": {
                    "account_name": account_name,
                    "account_id": account_id,
                    "check": check_name,
                },
                "roles_third_parties_can_access": [
                    {
                        "role_name": "ThirdPartyRole",
                        "role_arn": "arn:aws:iam::111111111111:role/ThirdPartyRole",
                        "third_party_account_ids": ["333333333333"]
                    }
                ]
            }

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
                exclude_account_ids=True,
            )

            expected_path = Path(temp_dir) / "rcps" / check_name / f"{account_name}.json"
            assert expected_path.exists()

            with open(expected_path, 'r') as f:
                loaded_data = json.load(f)
                assert "account_id" not in loaded_data["summary"]
                assert loaded_data["roles_third_parties_can_access"][0]["role_arn"] == "arn:aws:iam::REDACTED:role/ThirdPartyRole"

    @patch('headroom.write_results.get_check_type_map')
    def test_write_check_results_preserves_arns_when_exclude_account_ids_false(self, mock_get_check_type_map: MagicMock) -> None:
        """Test that ARNs are NOT redacted when exclude_account_ids=False."""
        mock_get_check_type_map.return_value = {"third_party_assumerole": "rcps"}
        with tempfile.TemporaryDirectory() as temp_dir:
            check_name = "third_party_assumerole"
            account_name = "test-account"
            account_id = "111111111111"
            results_data: Dict[str, Any] = {
                "summary": {
                    "account_name": account_name,
                    "account_id": account_id,
                    "check": check_name,
                },
                "roles_third_parties_can_access": [
                    {
                        "role_name": "ThirdPartyRole",
                        "role_arn": "arn:aws:iam::111111111111:role/ThirdPartyRole",
                        "third_party_account_ids": ["333333333333"]
                    }
                ]
            }

            write_check_results(
                check_name=check_name,
                account_name=account_name,
                account_id=account_id,
                results_data=results_data,
                results_base_dir=temp_dir,
                exclude_account_ids=False,
            )

            expected_path = Path(temp_dir) / "rcps" / check_name / f"{account_name}_{account_id}.json"
            assert expected_path.exists()

            with open(expected_path, 'r') as f:
                loaded_data = json.load(f)
                assert loaded_data["summary"]["account_id"] == account_id
                assert loaded_data["roles_third_parties_can_access"][0]["role_arn"] == "arn:aws:iam::111111111111:role/ThirdPartyRole"
