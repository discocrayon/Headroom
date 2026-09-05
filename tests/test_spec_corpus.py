"""Tests for the specification corpus validator."""

from pathlib import Path

import pytest

from headroom.checks.registry import get_check_type_map
from tests.documentation_links import find_broken_links
from tests.spec_corpus import (
    CONFLICT_REGISTER_HEADING,
    REQUIRED_FIELDS,
    find_conflict_divergences,
    find_corpus_problems,
    find_missing_named_guards,
    find_corpus_wide_problems,
    invariant_ids,
    load_check_specifications,
    parse_frontmatter,
)

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SPEC_ROOT = REPOSITORY_ROOT / "spec"

# A document that satisfies every rule, used as the base for the failure cases.
GOOD_FRONTMATTER = """---
id: deny_ec2_public_ip
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_ec2_public_ip.py
depends_on:
  - INV-02
verification:
  - tests/test_checks_deny_ec2_public_ip.py
---

# deny_ec2_public_ip

## Objective

What the check is for.

## Enforced statement

The statement it generates.

## Evidence

What it reads.

## Decision table

A table.

## Failure behavior

What aborts.

## Result contract

What it writes.

## Placement and generated policy

Where it attaches.

## Accepted limitations

What it cannot see.

## Acceptance scenarios

A scenario.

## Referenced invariants

INV-02.

## Implementation

The module.
"""


def build_corpus(
    tmp_path: Path,
    document: str,
    name: str = "deny_ec2_public_ip.md",
    conflict_rows: str = ""
) -> Path:
    """
    Write a one-document corpus whose repository root holds the real files.

    The index carries the conflict register and nothing after it, so the
    register runs to end of file here and to the next heading in the real
    corpus.

    Args:
        tmp_path: pytest temporary directory
        document: Full text of the specification document
        name: Filename to write it under
        conflict_rows: Rows for the unresolved-conflict register table

    Returns:
        The spec root inside the temporary tree
    """
    repository_root = Path(__file__).resolve().parent.parent
    spec_root = tmp_path / "spec"
    (spec_root / "checks" / "scps").mkdir(parents=True)
    (spec_root / "checks" / "rcps").mkdir(parents=True)
    (spec_root / "checks" / "scps" / name).write_text(document)
    (spec_root / "checks" / "index.md").write_text(
        f"{CONFLICT_REGISTER_HEADING}\n\n| # | Where | Conflict |\n|---|---|---|\n{conflict_rows}"
    )
    (spec_root / "invariants.md").write_text(
        (repository_root / "spec" / "invariants.md").read_text()
    )
    # The validator resolves applies_to and verification against spec_root.parent,
    # so the temporary root needs the real files those fields name.
    (tmp_path / "headroom" / "checks" / "scps").mkdir(parents=True)
    (tmp_path / "headroom" / "checks" / "scps" / "deny_ec2_public_ip.py").touch()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_checks_deny_ec2_public_ip.py").touch()
    return spec_root


ONE_REGISTERED_CHECK = {"deny_ec2_public_ip": "scps"}


class TestTheRealCorpus:
    """The corpus in spec/ must agree with the registry."""

    def test_every_registered_check_has_exactly_one_specification(self) -> None:
        assert find_corpus_problems(SPEC_ROOT, get_check_type_map()) == []

    def test_the_corpus_covers_all_sixteen_checks(self) -> None:
        # An independent count: nine SCP modules and seven RCP modules ship
        # today, so a document added or dropped without a check shows up here.
        specifications = load_check_specifications(SPEC_ROOT)
        assert len(specifications) == 16

    def test_invariants_are_numbered_without_gaps(self) -> None:
        identifiers = invariant_ids(SPEC_ROOT)
        assert identifiers == [f"INV-{number:02d}" for number in range(1, len(identifiers) + 1)]

    def test_every_relative_link_in_the_corpus_resolves(self) -> None:
        assert find_broken_links(SPEC_ROOT) == []

    def test_the_conflict_register_and_the_check_documents_agree(self) -> None:
        assert find_conflict_divergences(SPEC_ROOT) == []

    def test_every_named_guard_resolves_to_a_real_test(self) -> None:
        # strategy.md says renaming a named guard without replacing it removes
        # an invariant's only enforcement. It named one that never existed.
        assert find_missing_named_guards(SPEC_ROOT, REPOSITORY_ROOT / "tests") == []


class TestFrontmatter:
    """Parsing the frontmatter block."""

    def test_a_leading_block_is_parsed(self) -> None:
        assert parse_frontmatter("---\nid: a\n---\n# Title\n") == {"id": "a"}

    def test_a_document_without_frontmatter_has_none(self) -> None:
        assert parse_frontmatter("# Title\n") is None

    def test_frontmatter_that_is_not_a_mapping_has_none(self) -> None:
        assert parse_frontmatter("---\n- one\n- two\n---\n") is None


class TestDocumentProblems:
    """One document at a time, against a one-check registry."""

    def test_a_good_document_has_no_problems(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, GOOD_FRONTMATTER)
        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == []

    @pytest.mark.parametrize("field", REQUIRED_FIELDS)
    def test_a_missing_required_field_is_reported(self, tmp_path: Path, field: str) -> None:
        document = "\n".join(
            line for line in GOOD_FRONTMATTER.splitlines() if not line.startswith(f"{field}:")
        )
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert problems == [f"deny_ec2_public_ip.md frontmatter is missing: {field}"]

    def test_an_id_that_does_not_match_the_filename_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("id: deny_ec2_public_ip", "id: something_else")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "declares id 'something_else', expected 'deny_ec2_public_ip'" in problems[0]

    def test_a_kind_that_does_not_match_the_directory_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("kind: scp", "kind: rcp")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert any("declares kind 'rcp' but sits in checks/scps/" in problem for problem in problems)

    def test_an_unknown_status_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("status: implemented", "status: mostly")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert any("declares status 'mostly'" in problem for problem in problems)

    def test_a_document_naming_no_registered_check_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("deny_ec2_public_ip", "deny_nothing")
        spec_root = build_corpus(tmp_path, document, name="deny_nothing.md")
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "deny_nothing.md names no registered scp check" in problems

    def test_an_undefined_invariant_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("- INV-02", "- INV-99")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "deny_ec2_public_ip.md cites INV-99, which invariants.md does not define" in problems

    def test_an_applies_to_path_that_does_not_exist_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "  - headroom/checks/scps/deny_ec2_public_ip.py",
            "  - headroom/checks/scps/gone.py",
        )
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert (
            "deny_ec2_public_ip.md applies_to names a missing path: "
            "headroom/checks/scps/gone.py"
        ) in problems

    def test_a_verification_path_that_does_not_exist_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "  - tests/test_checks_deny_ec2_public_ip.py",
            "  - tests/test_gone.py",
        )
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "deny_ec2_public_ip.md verification names a missing path: tests/test_gone.py" in problems


class TestCorpusWideProblems:
    """Problems that only appear across documents."""

    def test_a_registered_check_with_no_specification_is_reported(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, GOOD_FRONTMATTER)
        registry = {"deny_ec2_public_ip": "scps", "deny_rds_unencrypted": "scps"}
        problems = find_corpus_problems(spec_root, registry)
        assert problems == ["registered check deny_rds_unencrypted has no specification"]

    def test_two_documents_declaring_one_id_are_reported(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, GOOD_FRONTMATTER)
        (spec_root / "checks" / "scps" / "duplicate.md").write_text(GOOD_FRONTMATTER)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert (
            "id 'deny_ec2_public_ip' is declared by both "
            "deny_ec2_public_ip.md and duplicate.md"
        ) in problems

    def test_a_document_without_frontmatter_reports_every_field(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, "# No frontmatter at all\n")
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert problems[0] == (
            "deny_ec2_public_ip.md frontmatter is missing: "
            "id, kind, status, applies_to, depends_on, verification"
        )


class TestSectionContract:
    """Every per-check document must carry the eleven sections index.md states."""

    def test_a_document_missing_a_required_section_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Placement and generated policy\n\nWhere it attaches.\n\n", ""
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md is missing section: Placement and generated policy"
        ]

    def test_sections_out_of_order_are_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Evidence\n\nWhat it reads.\n\n## Decision table\n\nA table.\n",
            "## Decision table\n\nA table.\n\n## Evidence\n\nWhat it reads.\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md orders sections Decision table before Evidence"
        ]

    def test_an_unrecognized_section_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Implementation\n",
            "## Design notes\n\nNot part of the contract.\n\n## Implementation\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md has an unrecognized section: Design notes"
        ]

    def test_a_known_conflict_section_is_allowed_anywhere(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Accepted limitations\n",
            "## Known conflict: the summary omits violations\n\n"
            "**Status: unresolved.**\n\n"
            "## Accepted limitations\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == []

    def test_a_known_conflict_without_a_status_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Accepted limitations\n",
            "## Known conflict: the summary omits violations\n\n"
            "It reads zero for every account.\n\n"
            "## Accepted limitations\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md has a Known conflict section that "
            "does not say Status: unresolved"
        ]

    def test_an_empty_known_conflict_section_is_reported(self, tmp_path: Path) -> None:
        """
        The content rule reaches beyond the required eleven: a `Known
        conflict:` section is not one of them, and an empty one must be
        caught too.

        A second, well-formed conflict section carries the required status
        text elsewhere in the document, so the only problem this produces is
        the empty section itself: the status check scans the whole document,
        not each conflict section on its own.
        """
        document = GOOD_FRONTMATTER.replace(
            "## Accepted limitations\n",
            "## Known conflict: the summary omits violations\n\n"
            "**Status: unresolved.**\n\n"
            "## Known conflict: reads permissive by default\n\n"
            "## Accepted limitations\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md has an empty section: Known conflict: "
            "reads permissive by default"
        ]


def test_a_required_section_with_no_content_is_a_problem(tmp_path: Path) -> None:
    """
    A heading with nothing under it states nothing.

    The section contract is what makes a check document usable: Decision table
    and Acceptance scenarios are where a check's behavior is actually
    specified, and the tests that verify the check encode them. Eleven bare
    headings satisfy every rule the validator had, so a document could carry
    the shape of a specification and none of its content.
    """
    document = GOOD_FRONTMATTER.replace(
        "## Decision table\n\nA table.\n", "## Decision table\n\n"
    )
    spec_root = build_corpus(tmp_path, document)

    problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)

    assert problems == ["deny_ec2_public_ip.md has an empty section: Decision table"]


def test_a_duplicated_sections_empty_occurrence_is_still_reported(tmp_path: Path) -> None:
    """
    A dict keyed by heading lets a later, non-empty duplicate hide an earlier,
    empty one under the same name. Headings are not unique in an arbitrary
    document, so every occurrence must be checked on its own rather than
    collapsed by name.
    """
    document = GOOD_FRONTMATTER.replace(
        "## Implementation\n\nThe module.\n",
        "## Implementation\n\n## Implementation\n\nThe module.\n",
    )
    spec_root = build_corpus(tmp_path, document)

    problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)

    assert problems == ["deny_ec2_public_ip.md has an empty section: Implementation"]


def test_an_empty_section_anywhere_in_the_corpus_is_a_problem(tmp_path: Path) -> None:
    """
    The rule reached the sixteen check documents and none of the other thirteen.

    INV-01's entire body could be deleted with its heading kept and the
    suite stayed green, which makes the corpus's most-cited invariant a
    heading with nothing under it and no gate the wiser.
    """
    spec_root = build_corpus(tmp_path, GOOD_FRONTMATTER)
    (spec_root / "invariants.md").write_text(
        "# Global invariants\n\n## INV-01 — Absence of evidence\n\n## INV-02 — Something\n\nA body.\n"
    )

    problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)

    assert "invariants.md has an empty section: INV-01 — Absence of evidence" in problems


class TestMalformedFrontmatterValues:
    """A field of the wrong YAML type must report, not raise."""

    def test_a_scalar_where_a_list_belongs_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "depends_on:\n  - INV-02\n", "depends_on: INV-02\n"
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md depends_on must be a list, not a str"
        ]

    def test_an_empty_field_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "verification:\n  - tests/test_checks_deny_ec2_public_ip.py\n", "verification:\n"
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md verification must be a list, not a NoneType"
        ]


class TestConflictRegister:
    """The register and the check documents are two views of one set."""
    CONFLICT = (
        "## Known conflict: the summary omits violations\n\n"
        "**Status: unresolved.**\n\n"
    )

    def test_a_registered_check_with_no_conflict_section_is_reported(self, tmp_path: Path) -> None:
        spec_root = build_corpus(
            tmp_path,
            GOOD_FRONTMATTER,
            conflict_rows="| 1 | [`deny_ec2_public_ip`](scps/deny_ec2_public_ip.md) | It reads zero. |\n",
        )

        assert find_conflict_divergences(spec_root) == [
            "deny_ec2_public_ip is named in the conflict register with no "
            "'Known conflict:' section in its document"
        ]

    def test_a_conflict_section_the_register_omits_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("## Accepted limitations\n", self.CONFLICT + "## Accepted limitations\n")
        spec_root = build_corpus(tmp_path, document)

        assert find_conflict_divergences(spec_root) == [
            "deny_ec2_public_ip has a 'Known conflict:' section and the "
            "conflict register does not name it"
        ]

    def test_a_check_in_both_views_is_not_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("## Accepted limitations\n", self.CONFLICT + "## Accepted limitations\n")
        spec_root = build_corpus(
            tmp_path,
            document,
            conflict_rows="| 1 | [`deny_ec2_public_ip`](scps/deny_ec2_public_ip.md) | It reads zero. |\n",
        )

        assert find_conflict_divergences(spec_root) == []

    def test_a_link_outside_the_where_column_does_not_register_a_check(self, tmp_path: Path) -> None:
        # Row 4 contrasts itself with deny_s3_third_party_access in its prose,
        # which must not read as S3 carrying the conflict.
        spec_root = build_corpus(
            tmp_path,
            GOOD_FRONTMATTER,
            conflict_rows="| 1 | ECR | Unlike [`x`](rcps/deny_s3_third_party_access.md), it aborts. |\n",
        )

        assert find_conflict_divergences(spec_root) == []


def test_every_cited_invariant_is_defined_anywhere_in_the_corpus(
    tmp_path: Path
) -> None:
    """
    No document in the corpus may cite an invariant that does not exist —
    a per-check specification's own prose included, not only its frontmatter.

    Per-check frontmatter is validated against invariants.md, and nothing else
    is. A contract or an architecture document can cite INV-17 forever: the
    reader follows the citation to a heading that is not there, and concludes
    the rule was withdrawn rather than that the citation was wrong.
    """
    spec_root = tmp_path / "spec"
    (spec_root / "contracts").mkdir(parents=True)
    (spec_root / "invariants.md").write_text("# Global invariants\n\n## INV-01 — Something\n")
    (spec_root / "contracts" / "results.md").write_text(
        "# Contract: results\n\nThis is required by INV-99.\n"
    )

    problems = find_corpus_wide_problems(spec_root)

    assert problems == [
        "contracts/results.md cites INV-99, which invariants.md does not define"
    ]


def test_a_document_may_not_state_the_same_section_twice(tmp_path: Path) -> None:
    """
    A repeated heading is how a topic comes to be stated twice.

    spec/README.md forbids one topic in two places, and the corpus has drifted
    that way before - a second copy survives an edit to the first and then
    contradicts it. A duplicated heading inside one document is the cheapest
    instance to catch mechanically.
    """
    spec_root = tmp_path / "spec"
    spec_root.mkdir(parents=True)
    (spec_root / "invariants.md").write_text("# Global invariants\n")
    (spec_root / "product.md").write_text(
        "# Product\n\n## Scope\n\nOne.\n\n## Scope\n\nTwo.\n"
    )

    problems = find_corpus_wide_problems(spec_root)

    assert problems == ["product.md states the section 'Scope' twice"]


def test_the_real_corpus_has_no_corpus_wide_problems() -> None:
    """The rules above hold for spec/ as it stands."""
    assert find_corpus_wide_problems(SPEC_ROOT) == []


class TestNamedGuardResolution:
    """`find_missing_named_guards` over a corpus built for the case."""

    @staticmethod
    def _corpus(tmp_path: Path, table: str) -> tuple[Path, Path]:
        """
        Build the smallest tree the checker reads: one strategy.md, one test.

        Returns:
            The spec root and the tests root to hand the checker
        """
        spec_root = tmp_path / "spec"
        (spec_root / "verification").mkdir(parents=True)
        (spec_root / "verification" / "strategy.md").write_text(table)

        tests_root = tmp_path / "tests"
        tests_root.mkdir()
        (tests_root / "test_real.py").write_text("def test_a_guard_that_exists() -> None:\n    pass\n")
        return spec_root, tests_root

    def test_a_table_naming_only_real_tests_reports_nothing(self, tmp_path: Path) -> None:
        spec_root, tests_root = self._corpus(
            tmp_path,
            "## Named guard tests\n\n| `test_a_guard_that_exists` | pins something |\n",
        )

        assert find_missing_named_guards(spec_root, tests_root) == []

    def test_a_named_guard_no_test_defines_is_reported(self, tmp_path: Path) -> None:
        """The failure strategy.md's own table shipped with for months."""
        spec_root, tests_root = self._corpus(
            tmp_path,
            "## Named guard tests\n\n| `test_a_guard_nobody_wrote` | pins something |\n",
        )

        assert find_missing_named_guards(spec_root, tests_root) == [
            "named guard test_a_guard_nobody_wrote is defined by no test"
        ]

    def test_a_named_guard_file_that_does_not_exist_is_reported(self, tmp_path: Path) -> None:
        """Two rows name a whole file rather than one test, so both forms count."""
        spec_root, tests_root = self._corpus(
            tmp_path,
            "## Named guard tests\n\n| `tests/test_absent.py` | pins something |\n",
        )

        assert find_missing_named_guards(spec_root, tests_root) == [
            "named guard file tests/test_absent.py does not exist"
        ]

    def test_a_strategy_document_with_no_table_is_reported(self, tmp_path: Path) -> None:
        """
        A missing section is not an empty one.

        Dropping the heading would otherwise pass silently: the table it
        introduces would be read as empty, and a corpus naming no guards
        agrees with any suite at all.
        """
        spec_root, tests_root = self._corpus(tmp_path, "## Something else\n")

        problems = find_missing_named_guards(spec_root, tests_root)

        assert len(problems) == 1
        assert problems[0].endswith("no '## Named guard tests' section")

    def test_a_guard_named_outside_the_table_is_not_read(self, tmp_path: Path) -> None:
        """Only the table is the register; prose above it names tests freely."""
        spec_root, tests_root = self._corpus(
            tmp_path,
            "`test_mentioned_in_prose` is discussed here.\n\n"
            "## Named guard tests\n\n| `test_a_guard_that_exists` | pins something |\n",
        )

        assert find_missing_named_guards(spec_root, tests_root) == []
