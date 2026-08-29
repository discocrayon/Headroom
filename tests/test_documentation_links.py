"""
Guard against broken relative links in the repository's Markdown files.

A relative link that points at a moved or deleted file sends a reader - or an
agent following the routing in CLAUDE.md - to nothing, and nothing else in the
test suite reads Markdown.
"""

from pathlib import Path

from tests.documentation_links import find_broken_links


def test_reports_a_link_whose_target_is_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("See [contributing](CONTRIBUTING.md).\n")

    assert find_broken_links(tmp_path) == ["README.md -> CONTRIBUTING.md"]


def test_ignores_links_that_leave_the_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "[docs](https://example.invalid/x)\n"
        "[plain](http://example.invalid/y)\n"
        "[mail](mailto:nobody@example.invalid)\n"
    )

    assert find_broken_links(tmp_path) == []


def test_ignores_an_anchor_into_the_same_document(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Jump to [setup](#setup).\n")

    assert find_broken_links(tmp_path) == []


def test_resolves_a_link_that_carries_an_anchor(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("[trust model](ARCHITECTURE.md#trust-model)\n")
    (tmp_path / "ARCHITECTURE.md").write_text("# Architecture\n")

    assert find_broken_links(tmp_path) == []


def test_resolves_a_link_against_the_file_that_holds_it(tmp_path: Path) -> None:
    (tmp_path / "documentation").mkdir()
    (tmp_path / "documentation" / "CHECKS.md").write_text("[how to](../HOW_TO_ADD_A_CHECK.md)\n")
    (tmp_path / "HOW_TO_ADD_A_CHECK.md").write_text("# How to\n")

    assert find_broken_links(tmp_path) == []


def test_skips_tool_directories(tmp_path: Path) -> None:
    vendored = tmp_path / ".tox" / "py313" / "site-packages" / "somedep"
    vendored.mkdir(parents=True)
    (vendored / "README.md").write_text("[changelog](CHANGELOG.md)\n")

    assert find_broken_links(tmp_path) == []


def test_every_relative_link_in_the_repository_resolves() -> None:
    repository_root = Path(__file__).resolve().parent.parent

    assert find_broken_links(repository_root) == []


def test_checks_markdown_in_dot_directories_that_are_not_tool_output(tmp_path: Path) -> None:
    cursor = tmp_path / ".cursor"
    cursor.mkdir()
    (cursor / "mental_model.md").write_text("[the guide](../CLAUDE.md)\n")

    assert find_broken_links(tmp_path) == [".cursor/mental_model.md -> ../CLAUDE.md"]
