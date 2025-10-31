"""
Integration tests for the main function.

These tests verify the complete integration flow from CLI arguments through
configuration loading, merging, validation, and analysis execution.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from typing import Dict, Any, Generator
from headroom.main import main
from botocore.exceptions import ClientError  # type: ignore


class TestMainIntegration:
    """
    Integration tests for the main function.

    Tests the complete flow from CLI parsing through analysis execution,
    including error handling and edge cases.
    """

    # Test fixtures and setup
    @pytest.fixture
    def mock_cli_args(self) -> MagicMock:
        """Create mock CLI arguments for testing."""
        args = MagicMock()
        args.config = "test.yaml"
        return args

    @pytest.fixture
    def valid_yaml_config(self) -> Dict[str, Any]:
        """Create a valid YAML configuration for testing."""
        return {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }

    @pytest.fixture
    def complex_yaml_config(self) -> Dict[str, Any]:
        """Create a complex YAML configuration for testing edge cases."""
        return {
            "use_account_name_from_tags": True,
            "account_tag_layout": {
                "environment": "CustomEnv",
                "name": "CustomName",
                "owner": "CustomOwner"
            },
            "extra_field": "should_be_ignored",
            "nested": {
                "level1": {
                    "level2": "deep_value"
                }
            }
        }

    @pytest.fixture(autouse=True)
    def mock_dependencies(self) -> Generator[Dict[str, MagicMock], None, None]:
        """
        Automatically mock all external dependencies for all tests.

        This fixture eliminates the need for repetitive @patch decorators
        and provides clean access to all mocks through the test method.
        """
        with (
            patch('headroom.main.parse_cli_args') as mock_parse,
            patch('headroom.main.load_yaml_config') as mock_load,
            patch('headroom.main.merge_configs') as mock_merge,
            patch('headroom.main.perform_analysis') as mock_perform_analysis,
            patch('builtins.print') as mock_print,
            patch('sys.exit') as mock_exit,
        ):
            yield {
                'parse': mock_parse,
                'load': mock_load,
                'merge': mock_merge,
                'perform_analysis': mock_perform_analysis,
                'print': mock_print,
                'exit': mock_exit
            }

    # Success path tests
    def test_main_success_with_valid_config(
        self,
        mock_cli_args: MagicMock,
        valid_yaml_config: Dict[str, Any],
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with successful configuration processing.

        Verifies that all components are called correctly and in the right order
        when configuration is valid.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = valid_yaml_config

        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = valid_yaml_config
        mocks['merge'].return_value = mock_final_config

        # Act
        with patch('headroom.main.parse_results'), \
             patch('headroom.main.perform_analysis'), \
             patch('headroom.main.get_security_analysis_session'), \
             patch('headroom.main.analyze_organization_structure'):
            main()

        # Assert - Verify correct call sequence and parameters
        mocks['parse'].assert_called_once()
        mocks['load'].assert_called_once_with("test.yaml")
        mocks['merge'].assert_called_once_with(valid_yaml_config, mock_cli_args)

        # Verify success output
        expected_calls = [
            call("\n✅ Final Config:"),
            call(valid_yaml_config)
        ]
        mocks['print'].assert_has_calls(expected_calls, any_order=False)

        # Verify no error exit
        mocks['exit'].assert_not_called()

    def test_main_success_with_complex_config(
        self,
        mock_cli_args: MagicMock,
        complex_yaml_config: Dict[str, Any],
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with complex configuration including extra fields.

        Verifies that complex configurations with nested structures and
        extra fields are handled correctly.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = complex_yaml_config

        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = complex_yaml_config
        mocks['merge'].return_value = mock_final_config

        # Act
        with patch('headroom.main.parse_results'), \
             patch('headroom.main.perform_analysis'), \
             patch('headroom.main.get_security_analysis_session'), \
             patch('headroom.main.analyze_organization_structure'):
            main()

        # Assert
        mocks['parse'].assert_called_once()
        mocks['load'].assert_called_once_with("test.yaml")
        mocks['merge'].assert_called_once_with(complex_yaml_config, mock_cli_args)

        # Verify complex config output
        expected_calls = [
            call("\n✅ Final Config:"),
            call(complex_yaml_config)
        ]
        mocks['print'].assert_has_calls(expected_calls, any_order=False)
        mocks['exit'].assert_not_called()

    def test_main_success_with_empty_yaml_config(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with empty YAML configuration.

        Verifies that empty configurations are handled gracefully
        when CLI provides all required values.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = {}

        # Mock CLI args with all required fields
        mock_cli_args.use_account_name_from_tags = False
        mock_cli_args.account_tag_layout = {
            "environment": "Environment",
            "name": "Name",
            "owner": "Owner"
        }

        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = {}
        mocks['merge'].return_value = mock_final_config

        # Act
        with patch('headroom.main.parse_results'), \
             patch('headroom.main.perform_analysis'), \
             patch('headroom.main.get_security_analysis_session'), \
             patch('headroom.main.analyze_organization_structure'):
            main()

        # Assert
        mocks['parse'].assert_called_once()
        mocks['load'].assert_called_once_with("test.yaml")
        mocks['merge'].assert_called_once_with({}, mock_cli_args)
        mocks['exit'].assert_not_called()

    # Error handling tests
    def test_main_value_error_handling(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with ValueError (validation error).

        Verifies that configuration validation errors are caught and
        displayed with proper error formatting and exit code.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = {"invalid": "config"}
        mocks['merge'].side_effect = ValueError("Validation error: missing required fields")

        # Act & Assert - Should exit with SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Verify error handling
        expected_error_message = "\n🚨 Configuration Validation Error:\nValidation error: missing required fields\n"
        mocks['print'].assert_called_once_with(expected_error_message)
        assert exc_info.value.code == 1

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    def test_main_type_error_handling(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with TypeError (type conversion error).

        Verifies that type conversion errors are caught and
        displayed with proper error formatting and exit code.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = {"use_account_name_from_tags": "not_a_boolean"}
        mocks['merge'].side_effect = TypeError("Type error: expected bool, got str")

        # Act & Assert - Should exit with SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Verify error handling
        expected_error_message = "\n🚨 Configuration Type Error:\nType error: expected bool, got str\n"
        mocks['print'].assert_called_once_with(expected_error_message)
        assert exc_info.value.code == 1

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    def test_main_value_error_with_missing_required_fields(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with ValueError due to missing required fields.

        Verifies that missing required configuration fields are
        properly caught and reported.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = {}
        mocks['merge'].side_effect = ValueError("Missing required fields: account_tag_layout")

        # Act & Assert - Should exit with SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Verify error handling
        expected_error_message = "\n🚨 Configuration Validation Error:\nMissing required fields: account_tag_layout\n"
        mocks['print'].assert_called_once_with(expected_error_message)
        assert exc_info.value.code == 1

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    def test_main_value_error_with_invalid_account_tag_layout(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with ValueError due to invalid account tag layout.

        Verifies that invalid account tag layout configurations are
        properly caught and reported.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = {
            "account_tag_layout": {
                "environment": "",  # Empty string should cause validation error
                "name": "Name",
                "owner": "Owner"
            }
        }
        mocks['merge'].side_effect = ValueError("Invalid account tag layout: environment cannot be empty")

        # Act & Assert - Should exit with SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Verify error handling
        expected_error_message = "\n🚨 Configuration Validation Error:\nInvalid account tag layout: environment cannot be empty\n"
        mocks['print'].assert_called_once_with(expected_error_message)
        assert exc_info.value.code == 1

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    # Exception handling tests
    def test_main_unexpected_exception_propagation(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with unexpected exception (should not be caught).

        Verifies that unexpected exceptions are not caught by the main
        error handling and are properly propagated up.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = {"test": "config"}
        mocks['merge'].side_effect = RuntimeError("Unexpected runtime error")

        # Act & Assert - Should raise the exception
        with pytest.raises(RuntimeError, match="Unexpected runtime error"):
            main()

        # Verify no error handling was called
        mocks['exit'].assert_not_called()
        mocks['print'].assert_not_called()

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    def test_main_file_not_found_handling(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function when YAML file is not found.

        Verifies that missing YAML files are handled gracefully
        and result in appropriate validation errors.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = {}  # File not found returns empty dict
        mocks['merge'].side_effect = ValueError("Missing required fields: account_tag_layout")

        # Act & Assert - Should exit with SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Verify error handling
        expected_error_message = "\n🚨 Configuration Validation Error:\nMissing required fields: account_tag_layout\n"
        mocks['print'].assert_called_once_with(expected_error_message)
        assert exc_info.value.code == 1

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    def test_main_invalid_yaml_handling(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function when YAML file is invalid.

        Verifies that invalid YAML files result in exceptions
        that are not caught by the main error handling.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].side_effect = Exception("Invalid YAML syntax")

        # Act & Assert - Should raise the exception
        with pytest.raises(Exception, match="Invalid YAML syntax"):
            main()

        # Verify no error handling was called
        mocks['exit'].assert_not_called()
        mocks['print'].assert_not_called()

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    # Edge case tests
    def test_main_with_none_yaml_content(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with None YAML content.

        Verifies that None YAML content is handled correctly
        and results in appropriate validation errors.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = None  # YAML file with None content
        mocks['merge'].side_effect = ValueError("Configuration cannot be None")

        # Act & Assert - Should exit with SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Verify error handling
        expected_error_message = "\n🚨 Configuration Validation Error:\nConfiguration cannot be None\n"
        mocks['print'].assert_called_once_with(expected_error_message)
        assert exc_info.value.code == 1

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    def test_main_with_malformed_yaml_structure(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with malformed YAML structure.

        Verifies that malformed YAML structures are handled correctly
        and result in appropriate validation errors.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        malformed_config = {
            "account_tag_layout": "not_a_dict",  # Should be a dict
            "use_account_name_from_tags": "not_a_bool"  # Should be a bool
        }
        mocks['load'].return_value = malformed_config
        mocks['merge'].side_effect = ValueError("Invalid account tag layout: must be a dictionary")

        # Act & Assert - Should exit with SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Verify error handling
        expected_error_message = "\n🚨 Configuration Validation Error:\nInvalid account tag layout: must be a dictionary\n"
        mocks['print'].assert_called_once_with(expected_error_message)
        assert exc_info.value.code == 1

        # Verify analysis was NOT called due to error
        mocks['perform_analysis'].assert_not_called()

    # Performance and stress tests
    def test_main_with_large_yaml_config(
        self,
        mock_cli_args: MagicMock,
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function with large YAML configuration.

        Verifies that large configurations are processed correctly
        without performance degradation.
        """
        # Arrange - Create a large configuration
        large_config = {
            "use_account_name_from_tags": False,
            "account_tag_layout": {
                "environment": "Environment",
                "name": "Name",
                "owner": "Owner"
            }
        }

        # Add many extra fields to simulate large config
        for i in range(100):
            large_config[f"extra_field_{i}"] = f"value_{i}"

        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = large_config

        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = large_config
        mocks['merge'].return_value = mock_final_config

        # Act
        with patch('headroom.main.parse_results'), \
             patch('headroom.main.perform_analysis'), \
             patch('headroom.main.get_security_analysis_session'), \
             patch('headroom.main.analyze_organization_structure'):
            main()

        # Assert
        mocks['parse'].assert_called_once()
        mocks['load'].assert_called_once_with("test.yaml")
        mocks['merge'].assert_called_once_with(large_config, mock_cli_args)
        mocks['exit'].assert_not_called()

    # Integration flow verification tests
    def test_main_integration_flow_verification(
        self,
        mock_cli_args: MagicMock,
        valid_yaml_config: Dict[str, Any],
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """
        Test main function integration flow verification.

        Verifies the complete integration flow and ensures all
        components are called in the correct sequence with proper
        parameter passing.
        """
        # Arrange
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = valid_yaml_config

        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = valid_yaml_config
        mocks['merge'].return_value = mock_final_config

        # Act
        with patch('headroom.main.parse_results'), \
             patch('headroom.main.perform_analysis'), \
             patch('headroom.main.get_security_analysis_session'), \
             patch('headroom.main.analyze_organization_structure'):
            main()

        # Assert - Verify complete flow sequence
        # 1. Parse CLI arguments
        mocks['parse'].assert_called_once()

        # 2. Load YAML configuration
        mocks['load'].assert_called_once_with("test.yaml")

        # 3. Merge configurations
        mocks['merge'].assert_called_once_with(valid_yaml_config, mock_cli_args)

        # 4. Display final configuration
        expected_print_calls = [
            call("\n✅ Final Config:"),
            call(valid_yaml_config)
        ]
        mocks['print'].assert_has_calls(expected_print_calls, any_order=False)

        # 5. Perform analysis (mocked in test)

        # 6. No error exit
        mocks['exit'].assert_not_called()

        # Verify call count matches expected flow
        assert mocks['parse'].call_count == 1
        assert mocks['load'].call_count == 1
        assert mocks['merge'].call_count == 1
        assert mocks['print'].call_count == 2

    def test_main_early_return_when_no_recommendations(
        self,
        mock_cli_args: MagicMock,
        valid_yaml_config: Dict[str, Any],
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """Covers early return path when parse_results returns empty list."""
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = valid_yaml_config
        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = valid_yaml_config
        mocks['merge'].return_value = mock_final_config

        with (
            patch('headroom.main.parse_results', return_value=[]),
            patch('headroom.main.get_security_analysis_session') as mock_get_sess,
            patch('headroom.main.parse_rcp_result_files', return_value=({}, set())),
            patch('headroom.main.analyze_organization_structure')
        ):
            main()

        # get_security_analysis_session is now called even with no SCP recommendations
        # because we still check for RCP recommendations
        mock_get_sess.assert_called_once_with(mock_final_config)

    def test_main_early_return_when_no_management_account_id(
        self,
        mock_cli_args: MagicMock,
        valid_yaml_config: Dict[str, Any],
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """Covers early return path when management_account_id is missing."""
        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = valid_yaml_config
        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = valid_yaml_config
        mock_final_config.management_account_id = None
        mocks['merge'].return_value = mock_final_config

        with patch('headroom.main.parse_results', return_value=[MagicMock()]), \
             patch('headroom.main.get_security_analysis_session') as mock_get_sess:
            main()

        # We return before attempting to use the session if no management_account_id
        mock_get_sess.assert_called_once()

    def test_main_client_error_in_generation_is_handled(
        self,
        mock_cli_args: MagicMock,
        valid_yaml_config: Dict[str, Any],
        mock_dependencies: Dict[str, MagicMock]
    ) -> None:
        """Covers the ClientError exception handler branch (prints failure)."""

        mocks = mock_dependencies
        mocks['parse'].return_value = mock_cli_args
        mocks['load'].return_value = valid_yaml_config
        mock_final_config = MagicMock()
        mock_final_config.model_dump.return_value = valid_yaml_config
        mock_final_config.management_account_id = "111111111111"
        mocks['merge'].return_value = mock_final_config

        err = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "AssumeRole")

        with patch('headroom.main.parse_results', return_value=[MagicMock()]), \
             patch('headroom.main.get_security_analysis_session') as mock_get_sess, \
             patch('headroom.main.analyze_organization_structure') as mock_analyze:
            # cause sts.assume_role to raise
            mock_get_sess.return_value.client.return_value.assume_role.side_effect = err
            mock_analyze.return_value = None
            main()

        printed = [c.args[0] for c in mocks['print'].call_args_list]
        assert any("Failed to generate Terraform files:" in msg for msg in printed)
