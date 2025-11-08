"""Tests for the OutputHandler module."""

from unittest.mock import patch, call

from headroom.output import OutputHandler


class TestOutputHandler:
    """Test OutputHandler class methods."""

    def test_check_completed(self) -> None:
        """Test check_completed logs completion message."""
        with patch('headroom.output.logger.info') as mock_logger:
            OutputHandler.check_completed(
                "test_check",
                "account_123",
                {"violations": 5, "exemptions": 2, "compliant": 10}
            )

        mock_logger.assert_called_once_with(
            "test_check completed for account_123: "
            "5 violations, 2 exemptions, 10 compliant"
        )

    def test_check_completed_with_missing_keys(self) -> None:
        """Test check_completed handles missing keys with default 0."""
        with patch('headroom.output.logger.info') as mock_logger:
            OutputHandler.check_completed(
                "test_check",
                "account_123",
                {"violations": 3}
            )

        mock_logger.assert_called_once_with(
            "test_check completed for account_123: "
            "3 violations, 0 exemptions, 0 compliant"
        )

    def test_error(self) -> None:
        """Test error prints formatted error message."""
        with patch('builtins.print') as mock_print:
            test_error = ValueError("test error message")
            OutputHandler.error("Test Error", test_error)

        mock_print.assert_called_once_with(
            "\n🚨 Test Error:\ntest error message\n"
        )

    def test_success_with_dict_data(self) -> None:
        """Test success prints formatted message with JSON dict."""
        with patch('builtins.print') as mock_print:
            test_data = {"key1": "value1", "key2": "value2"}
            OutputHandler.success("Test Success", test_data)

        calls = mock_print.call_args_list
        assert len(calls) == 2
        assert calls[0] == call("\n✅ Test Success")
        assert '"key1": "value1"' in calls[1][0][0]
        assert '"key2": "value2"' in calls[1][0][0]

    def test_success_with_string_data(self) -> None:
        """Test success prints formatted message with string data."""
        with patch('builtins.print') as mock_print:
            OutputHandler.success("Test Success", "simple string data")

        expected_calls = [
            call("\n✅ Test Success"),
            call("simple string data")
        ]
        mock_print.assert_has_calls(expected_calls)

    def test_success_without_data(self) -> None:
        """Test success prints only title when no data provided."""
        with patch('builtins.print') as mock_print:
            OutputHandler.success("Test Success")

        mock_print.assert_called_once_with("\n✅ Test Success")

    def test_success_with_none_data(self) -> None:
        """Test success prints only title when data is None."""
        with patch('builtins.print') as mock_print:
            OutputHandler.success("Test Success", None)

        mock_print.assert_called_once_with("\n✅ Test Success")

    def test_section_header(self) -> None:
        """Test section_header prints formatted header."""
        with patch('builtins.print') as mock_print:
            OutputHandler.section_header("Test Section")

        expected_calls = [
            call("\n" + "=" * 80),
            call("Test Section"),
            call("=" * 80)
        ]
        mock_print.assert_has_calls(expected_calls)
