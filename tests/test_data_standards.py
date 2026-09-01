"""
Enforce INV-15: committed AWS identifiers are obviously fake.

`test_environment/` is the one standing exception, and the invariant states its
size in prose. Nothing checked that prose against the directory, so it drifted:
the count was written once and the identifiers grew past it. These tests couple
the two, and pin the exception to the directory it is scoped to.

A twelve-digit number carries no evidence of being real, so the scan cannot
recognize a newly pasted account ID on sight. For that kind it enforces the two
properties that are decidable instead: the documented count matches what the
directory holds, and no identifier from the exception appears outside it. The
six other kinds are matched by a shape a plain number does not have - the `i-`,
`ami-`, `o-`, `ou-` and `r-` prefixes, and for a KMS key the hyphen groups of a
UUID - so those are read where they stand and must be fabricated everywhere.
The exception is granted for account IDs and covers no other kind, so
`test_environment/` is no shelter for them.

Fixtures standing in for a real identifier use the digits of pi, or the hex
bodies AWS's own examples print. A reader can see they are invented, while the
scanner reads them the way it reads a real one - which a placeholder-shaped
value could not exercise. The prefixed ones are spelled without their prefix and
composed in the assertion, so that this file does not commit the thing it looks
for.
"""

import re
from pathlib import Path
from typing import Dict, Set, Tuple

import pytest

from tests.data_standards import (
    IDENTIFIER_KINDS,
    account_ids_by_location,
    documented_exception_count,
    identifiers_by_location,
    identifiers_outside_the_exception,
    is_identifier_placeholder,
    is_placeholder,
    real_account_ids,
)

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

FABRICATED = "314159265358"

# Bodies that read as real, spelled without their prefix. Composing the
# identifier in the assertion keeps this file from committing the very thing
# the repository-wide scan below looks for; the account fixture above is the
# one that cannot be split that way, which is why that scan leaves the account
# kind to the exception-scoped gate.
AWS_DOCUMENTATION_AMI_BODY = "0abcdef1234567890"
NAMED_ORGANIZATION_BODY = "example12345"
OPAQUE_ORGANIZATIONAL_UNIT_BODY = "ab12-11111111"
OPAQUE_ROOT_BODIES = ("1a1b", "a1a9")

# One identifier per kind, held apart as the tuple of its own hyphen-separated
# parts and joined where it is used. Each is a shape AWS itself issues and
# prints in its documentation, so a matcher that has been mistyped cannot find
# its own kind. A KMS key ID carries no prefix, so spelling one in a single
# piece would commit exactly what the repository-wide scan below looks for;
# splitting every kind the same way keeps that from being a special case.
REALISTIC_IDENTIFIER_PARTS: Dict[str, Tuple[str, ...]] = {
    "account": (FABRICATED,),
    "ami": ("ami", AWS_DOCUMENTATION_AMI_BODY),
    "instance": ("i", "1234567890abcdef0"),
    "kms_key": ("1234abcd", "12ab", "34cd", "56ef", "1234567890ab"),
    "organization": ("o", "a1b2c3d4e5"),
    "organizational_unit": ("ou", "a1b2", "c3d4e5f6"),
    "root": ("r", "a1b9"),
}

# The same seven kinds in the form INV-15 fixes: real prefix, real length,
# body of one repeated character.
PLACEHOLDER_IDENTIFIER_PARTS: Dict[str, Tuple[str, ...]] = {
    "account": ("111111111111",),
    "ami": ("ami", "11111111111111111"),
    "instance": ("i", "11111111111111111"),
    "kms_key": ("11111111", "1111", "1111", "1111", "111111111111"),
    "organization": ("o", "1111111111"),
    "organizational_unit": ("ou", "1111", "11111111"),
    "root": ("r", "1111"),
}


@pytest.mark.parametrize("kind", sorted(IDENTIFIER_KINDS))
def test_every_matcher_reads_an_identifier_of_its_own_kind(kind: str, tmp_path: Path) -> None:
    """
    A matcher that can never match passes every other test in this file.

    Only two of the seven patterns were exercised. The other five were pinned
    by their key alone, so replacing any of them with a regex matching nothing
    left the whole suite green - which restores the hole the matchers were
    written to close while the guard still reports safe, and a guard believed
    for a property it does not hold is worse than no guard. Each pattern is
    handed an identifier of the shape AWS issues for its kind and has to find
    it.
    """
    identifier = "-".join(REALISTIC_IDENTIFIER_PARTS[kind])
    (tmp_path / "notes.md").write_text(f"the resource is {identifier}\n")

    assert identifiers_by_location(tmp_path)[kind] == {identifier: ["notes.md"]}


@pytest.mark.parametrize("kind", sorted(IDENTIFIER_KINDS))
def test_no_matcher_reports_the_placeholder_form_of_its_own_kind(kind: str, tmp_path: Path) -> None:
    """
    The form INV-15 prescribes passes the scan for all seven kinds.

    This is the other half of the pin above. On its own, the pin above is met
    by a pattern that matches far too much, and this one alone is met by a
    pattern that matches nothing; together they say each matcher reads its own
    kind and the placeholder rule then lets the fabricated form through.
    """
    identifier = "-".join(PLACEHOLDER_IDENTIFIER_PARTS[kind])
    (tmp_path / "notes.md").write_text(f"the resource is {identifier}\n")

    assert identifiers_by_location(tmp_path)[kind] == {}


def _kinds_inv_15_names(invariants_text: str) -> Set[str]:
    """
    Return the identifier kinds INV-15's own table names.

    Reading the invariant rather than a copy of it is the point: the
    assertion this replaced compared IDENTIFIER_KINDS against a hardcoded
    literal, so an eighth kind added to the invariant failed nothing.

    Args:
        invariants_text: The full text of spec/invariants.md

    Returns:
        The kind names in INV-15's table

    Raises:
        AssertionError: If the table cannot be found, which would otherwise
            make this return an empty set and pass by vacuity
    """
    section = invariants_text.split("## INV-15")[1].split("\n## ")[0]
    kinds = set(re.findall(r"^\| `([a-z_]+)` \|", section, re.MULTILINE))

    assert kinds, "INV-15's identifier-kind table is missing or unparseable"
    return kinds


def test_every_kind_inv_15_names_has_a_matcher() -> None:
    """
    INV-15 names seven kinds of identifier, and one regex scanned one of them.

    Six kinds went unscanned, so a real AMI ID or instance ID from a console
    screenshot could enter the repository and every gate would pass. This
    reads the invariant's own table rather than a literal copy of it: the
    assertion it replaced compared IDENTIFIER_KINDS against a hardcoded set,
    which is a copy of the constant checked against itself, so an eighth
    kind added to the invariant would have failed nothing.
    """
    invariants = (REPOSITORY_ROOT / "spec" / "invariants.md").read_text()

    assert _kinds_inv_15_names(invariants) == set(IDENTIFIER_KINDS)


def test_a_hex_body_that_reads_as_real_is_not_a_placeholder() -> None:
    """
    An AMI ID AWS's own documentation uses is not the canonical placeholder.

    INV-15 fixes the form as real prefix, real length, body of one repeated
    digit. AWS's example body has neither few enough distinct characters to
    read as deliberate nor a run that counts, so a reader cannot tell it from
    an identifier out of a real account.
    """
    assert is_identifier_placeholder("ami", "ami-11111111111111111") is True
    assert is_identifier_placeholder("ami", f"ami-{AWS_DOCUMENTATION_AMI_BODY}") is False


def test_a_named_fixture_body_is_a_placeholder() -> None:
    """
    A root or OU ID named for its fixture reads as fabricated.

    `r-root` and `ou-fake-payments` name the thing the test is about, which is
    what makes the hierarchy tests legible, and no real Organizations ID looks
    like either. The rule is named rather than achieved by leaving the kind
    unscanned. A word with digits welded onto it is not one of those names, so
    the organization ID this repository once used is still reported.
    """
    assert is_identifier_placeholder("organizational_unit", "ou-fake-payments") is True
    assert is_identifier_placeholder("organization", f"o-{NAMED_ORGANIZATION_BODY}") is False


def test_a_placeholder_segment_beside_a_named_one_is_a_placeholder() -> None:
    """
    An OU ID is two hand-written segments, and each stands on its own.

    A real OU ID repeats its root's suffix and appends an issued body, so the
    fixtures do too: `ou-aabb-workloads` sits under `r-aabb`. Judging the two
    segments as one run of characters would reject that pair while accepting
    nothing safer, and welding `aabb` into the fixture-word list would name
    something that is not a name.
    """
    assert is_identifier_placeholder("root", "r-aabb") is True
    assert is_identifier_placeholder("organizational_unit", "ou-aabb-workloads") is True
    assert is_identifier_placeholder("organizational_unit", f"ou-{OPAQUE_ORGANIZATIONAL_UNIT_BODY}") is False


def test_a_four_character_root_body_must_repeat_half_its_characters() -> None:
    """
    Three distinct characters out of four says almost nothing.

    A root ID's body is four characters, so a flat bound of three accepts
    15.8% of everything AWS could issue under `r-`: a real root ID pasted from
    a console would enter one time in six with the gate green, which is the
    class of miss this scan exists to close. Holding the bound to half the
    length drops that to 0.5% and costs the repository nothing.

    `r-root` shows why the whole rule matters rather than this clause alone.
    `root` holds three distinct characters in four and fails the count; it
    survives because it names its fixture.
    """
    assert is_identifier_placeholder("root", "r-1111") is True
    assert is_identifier_placeholder("root", "r-aabb") is True
    assert is_identifier_placeholder("root", "r-1234") is True
    assert is_identifier_placeholder("root", "r-root") is True
    for body in OPAQUE_ROOT_BODIES:
        assert is_identifier_placeholder("root", f"r-{body}") is False


def test_a_twelve_digit_account_id_is_long_enough_that_the_flat_bound_binds() -> None:
    """
    Scaling the bound with length leaves the account kind exactly as it was.

    Half of twelve is six, so the flat three is what an account ID is judged
    against, and 000011112222 - three distinct digits, the form the repository
    uses when several accounts must be told apart in one example - is still a
    placeholder.
    """
    assert is_placeholder("000011112222") is True
    assert is_placeholder(FABRICATED) is False


def test_a_body_of_one_repeated_digit_is_a_placeholder() -> None:
    assert is_placeholder("111111111111")


def test_digits_grouped_in_runs_are_a_placeholder() -> None:
    """Examples telling several accounts apart use this form."""
    assert is_placeholder("000011112222")


def test_counting_up_is_a_placeholder() -> None:
    assert is_placeholder("123456789012")


def test_counting_down_is_a_placeholder() -> None:
    assert is_placeholder("987654321098")


def test_a_body_of_many_digits_is_not_a_placeholder() -> None:
    assert not is_placeholder(FABRICATED)


def test_records_every_file_an_identifier_appears_in(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text(f'owner = "{FABRICATED}"\n')
    (tmp_path / "b.md").write_text(f"The account is {FABRICATED}.\n")

    assert account_ids_by_location(tmp_path) == {FABRICATED: ["a.tf", "b.md"]}


def test_ignores_placeholders(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text('owner = "111111111111"\n')

    assert account_ids_by_location(tmp_path) == {}


def test_ignores_a_longer_run_of_digits(tmp_path: Path) -> None:
    """A thirteen-digit number is not an account ID that happens to embed one."""
    (tmp_path / "a.md").write_text("checksum 3141592653589\n")

    assert account_ids_by_location(tmp_path) == {}


def test_skips_tool_directories(tmp_path: Path) -> None:
    vendored = tmp_path / ".tox" / "py313" / "site-packages" / "somedep"
    vendored.mkdir(parents=True)
    (vendored / "README.md").write_text(f"account {FABRICATED}\n")

    assert account_ids_by_location(tmp_path) == {}


@pytest.mark.parametrize("scratch", [
    ".superpowers/sdd/some-plan",
    "docs/superpowers/plans",
    "design-docs",
])
def test_skips_the_git_ignored_scratch_directories(scratch: str, tmp_path: Path) -> None:
    """
    A tree `.gitignore` excludes holds nothing this invariant can reach.

    `.superpowers/`, `docs/superpowers/`, and `design-docs/` are working
    scratch for a change in progress. No commit can carry a byte of them, so
    an identifier written there escapes to nobody - and the scan walks the
    filesystem rather than the index, so it read them anyway and failed
    `tox` on notes left over from an unrelated plan.
    """
    directory = tmp_path / scratch
    directory.mkdir(parents=True)
    (directory / "notes.md").write_text(f"the account was {FABRICATED}\n")

    assert account_ids_by_location(tmp_path) == {}


def test_skips_files_that_hold_no_readable_identifier(tmp_path: Path) -> None:
    (tmp_path / "logo.png").write_bytes(b"\x89PNG" + FABRICATED.encode())

    assert account_ids_by_location(tmp_path) == {}


def test_collects_identifiers_the_live_test_directory_commits(tmp_path: Path) -> None:
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text(f'vendor = "{FABRICATED}"\n')

    assert real_account_ids(tmp_path) == {FABRICATED}


def test_an_identifier_only_outside_the_sandbox_is_not_part_of_the_exception(tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text(f"account {FABRICATED}\n")

    assert real_account_ids(tmp_path) == set()


def test_reports_an_identifier_that_escaped_the_sandbox(tmp_path: Path) -> None:
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text(f'vendor = "{FABRICATED}"\n')
    (tmp_path / "headroom.py").write_text(f'DEFAULT = "{FABRICATED}"\n')

    assert identifiers_outside_the_exception(tmp_path) == {FABRICATED: ["headroom.py"]}


def test_an_identifier_confined_to_the_sandbox_is_not_reported(tmp_path: Path) -> None:
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text(f'vendor = "{FABRICATED}"\n')

    assert identifiers_outside_the_exception(tmp_path) == {}


def test_an_identifier_the_exception_never_held_is_not_reported(tmp_path: Path) -> None:
    """
    The check is scoped to the exception, not to every twelve-digit number.

    A fabricated identifier in a test fixture is not a leak, and reporting one
    would make the guard cry wolf until someone turned it off.
    """
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text('vendor = "111111111111"\n')
    (tmp_path / "test_thing.py").write_text(f'FIXTURE = "{FABRICATED}"\n')

    assert identifiers_outside_the_exception(tmp_path) == {}


def test_a_non_account_identifier_inside_the_sandbox_is_still_reported(tmp_path: Path) -> None:
    """
    The standing exception is granted for account IDs, and for nothing else.

    INV-15 scopes it to the real twelve-digit account IDs third-party vendors
    publish, which the live-test Terraform cannot fabricate without breaking
    the `terraform apply` it exists to run. Not a word of that reaches an AMI
    ID or an OU ID, so the directory launders neither: the scan reports one
    there exactly as it would anywhere else.
    """
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text(f'image = "ami-{AWS_DOCUMENTATION_AMI_BODY}"\n')

    found = identifiers_by_location(tmp_path)

    assert found["ami"] == {f"ami-{AWS_DOCUMENTATION_AMI_BODY}": ["test_environment/main.tf"]}


def test_reads_the_count_the_invariant_spells(tmp_path: Path) -> None:
    (tmp_path / "invariants.md").write_text(
        "`test_environment/` commits fourteen real\ntwelve-digit account IDs belonging to.\n"
    )

    assert documented_exception_count(tmp_path) == 14


def test_a_missing_count_sentence_reads_as_none(tmp_path: Path) -> None:
    (tmp_path / "invariants.md").write_text("## INV-15\n\nNothing about a count.\n")

    assert documented_exception_count(tmp_path) is None


def test_an_unmapped_number_word_reads_as_none(tmp_path: Path) -> None:
    (tmp_path / "invariants.md").write_text(
        "`test_environment/` commits several real\ntwelve-digit account IDs belonging to.\n"
    )

    assert documented_exception_count(tmp_path) is None


def test_the_documented_count_matches_what_the_live_test_directory_holds() -> None:
    documented = documented_exception_count(REPOSITORY_ROOT / "spec")

    assert documented == len(real_account_ids(REPOSITORY_ROOT))


def test_no_identifier_from_the_exception_appears_outside_it() -> None:
    assert identifiers_outside_the_exception(REPOSITORY_ROOT) == {}


def test_no_identifier_of_a_non_account_kind_reads_as_real_anywhere() -> None:
    """
    Every kind INV-15 names but the account ID is held to one standard.

    Six of the seven kinds had no matcher at all, so a real AMI ID or instance
    ID out of a console screenshot could enter the repository with every gate
    passing. Those six are checked everywhere, `test_environment/` included:
    the standing exception is granted, by INV-15's own words, for the real
    twelve-digit account IDs third-party vendors publish and for nothing else.
    An AMI ID or an OU ID gains nothing by sitting in that directory.

    The account kind is the one exception, and not because the sandbox earns
    it. A twelve-digit number carries no evidence of being real, so a fixture
    standing in for one - `FABRICATED` in this very file - is deliberately not
    a placeholder, and the account kind is pinned by the narrower gate above
    instead. Unifying the two therefore fails on the fixtures written to
    exercise the scan.
    """
    found = identifiers_by_location(REPOSITORY_ROOT)

    reads_as_real = {
        f"{kind}:{identifier}": paths
        for kind, matches in found.items()
        for identifier, paths in matches.items()
        if kind != "account"
    }

    assert reads_as_real == {}
