"""
Tests for headroom.utils, the general-purpose helpers shared across modules.
"""

from pathlib import Path

from headroom.utils import delete_and_rerun_remedy


def test_delete_and_rerun_remedy_names_the_file_and_the_check() -> None:
    result_file = Path("/results/rcps/deny_s3_third_party_access/test-account.json")

    message = delete_and_rerun_remedy(result_file, "deny_s3_third_party_access")

    assert message == (
        "Delete /results/rcps/deny_s3_third_party_access/test-account.json and "
        "re-run: the deny_s3_third_party_access check skips any account whose "
        "result file already exists, so re-running without deleting it changes "
        "nothing. The skip matches both filename formats, with and without the "
        "account ID, so if the account still skips, delete the other form of "
        "its name in /results/rcps/deny_s3_third_party_access too."
    )


def test_delete_and_rerun_remedy_points_at_the_other_filename_format() -> None:
    """
    ResultFilePathResolver.exists() accepts either filename format.

    An operator who deletes only the file the reader named still hits the
    skip when the other form of the same account's name is present, and
    re-runs into the identical error. The remedy has to name where that one
    is, or it sends them round the loop.
    """
    result_file = Path("/results/scps/deny_iam_user_creation/prod_111111111111.json")

    message = delete_and_rerun_remedy(result_file, "deny_iam_user_creation")

    assert "/results/scps/deny_iam_user_creation" in message
    assert "both filename formats" in message
