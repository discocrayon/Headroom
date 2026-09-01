"""Scan the repository for AWS identifiers, and separate placeholders from real ones."""

import re
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set

# The kinds INV-15 names. An ARN is not one of them: every ARN carries its
# account in a field the account matcher already reads, and the resource part
# is a name rather than an identifier AWS issued.
IDENTIFIER_KINDS: Dict[str, Pattern[str]] = {
    "account": re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])"),
    "ami": re.compile(r"\bami-[0-9a-f]{8}(?:[0-9a-f]{9})?\b"),
    "instance": re.compile(r"\bi-[0-9a-f]{8}(?:[0-9a-f]{9})?\b"),
    "kms_key": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    "organization": re.compile(r"\bo-[0-9a-z]{10,32}\b"),
    "organizational_unit": re.compile(r"\bou-[0-9a-z]{4,32}-[0-9a-z]{8,32}\b"),
    "root": re.compile(r"\br-[0-9a-z]{4,32}\b"),
}

# What AWS puts in front of each kind's body. An account ID and a KMS key ID
# carry nothing, so the whole identifier is the body. A kind added above with
# no entry here raises rather than being read as prefixless.
_IDENTIFIER_PREFIXES: Dict[str, str] = {
    "account": "",
    "ami": "ami-",
    "instance": "i-",
    "kms_key": "",
    "organization": "o-",
    "organizational_unit": "ou-",
    "root": "r-",
}

# Bodies that name the fixture they belong to. `r-root` and `ou-fake-payments`
# read as fabricated to any human and are what make the hierarchy tests
# legible; no Organizations ID AWS issues looks like either. Named here rather
# than achieved by leaving the kind unscanned, so that adding one is a
# deliberate edit.
_FIXTURE_WORDS = frozenset({
    "example",
    "fake",
    "payments",
    "production",
    "root",
    "sandbox",
    "test",
    "vanished",
    "workloads",
})

# INV-15 spells the standing exception's size in words rather than digits, so
# that the sentence reads. Only the counts the invariant could plausibly carry
# are mapped; an unmapped word is reported rather than guessed at.
_NUMBER_WORDS = {
    "one": 1,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}

_DOCUMENTED_COUNT = re.compile(
    r"commits\s+(\w+)\s+real\s+twelve-digit\s+account ID",
)

# Directories holding third-party or generated content, and the working scratch
# a change in progress leaves behind. .tox alone carries a site-packages tree
# that mentions account IDs in vendored documentation.
#
# The scratch trees are the three CONVENTIONS.md names and .gitignore excludes:
# .superpowers/, docs/superpowers/, and design-docs/. This scan walks the
# filesystem rather than the git index, so without them it reads notes no commit
# can ever carry and fails the suite on an unrelated plan's leftovers. Matching
# is by path component at any depth, so `docs/superpowers/` is named here by its
# own directory name.
_UNSCANNED_DIRECTORIES = frozenset({
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".superpowers",
    ".tox",
    "design-docs",
    "node_modules",
    "superpowers",
    "venv",
})

# Suffixes worth reading. A binary file cannot hold an identifier a reader or a
# search engine would ever surface. `.example` is here because a file that
# exists to be copied and filled in is exactly where someone pastes a real
# value: `test_environment/terraform.tfvars.example` is the one such file.
_SCANNED_SUFFIXES = frozenset({
    ".example",
    ".json",
    ".md",
    ".py",
    ".tf",
    ".tfvars",
    ".txt",
    ".yaml",
    ".yml",
})

TEST_ENVIRONMENT = "test_environment"

# A placeholder part is built from few enough distinct characters to read as
# deliberate: 111111111111 uses one, 000011112222 uses three, and the `aabb`
# that `r-aabb` and `ou-aabb-workloads` share uses two.
#
# The bound is also held to half the part's length, because a short body cannot
# carry enough characters for "few distinct" to mean anything. A root ID's body
# is four: a flat three accepts 15.8% of everything AWS could issue under `r-`,
# so a real root ID pasted from a console would enter one time in six with the
# gate green, while half the length accepts 0.5%. Twelve-digit account IDs are
# long enough that the flat bound is the one that binds, so they are unaffected.
_MAX_PLACEHOLDER_CHARACTERS = 3


def _is_sequential_over(body: str) -> bool:
    """
    Report whether a body counts up or down, wrapping past nine.

    Args:
        body: One hyphen-separated part of an identifier's body

    Returns:
        True for 123456789012 and 987654321098, false for a body holding any
        character that is not a digit
    """
    if not body.isdigit():
        return False

    digits = [int(digit) for digit in body]
    steps = {(later - earlier) % 10 for earlier, later in zip(digits, digits[1:])}

    return steps in ({1}, {9})


def _is_placeholder_part(part: str) -> bool:
    """
    Report whether one hyphen-separated part of a body reads as fabricated.

    Args:
        part: One part of an identifier's body

    Returns:
        True when the part uses few enough distinct characters to read as
        deliberate - at most half its length, and never more than
        _MAX_PLACEHOLDER_CHARACTERS - or counts plainly up or down, or names
        its fixture
    """
    allowed_characters = min(_MAX_PLACEHOLDER_CHARACTERS, len(part) // 2)
    few_enough_characters = len(set(part)) <= allowed_characters
    names_its_fixture = part in _FIXTURE_WORDS

    return few_enough_characters or _is_sequential_over(part) or names_its_fixture


def is_identifier_placeholder(kind: str, identifier: str) -> bool:
    """
    Report whether one identifier of one kind is an obvious placeholder.

    Every hyphen-separated part of the body is judged on its own, because an
    OU ID is two hand-written segments rather than one run of characters: it
    repeats its root's suffix and appends an issued body, and `ou-aabb-workloads`
    under `r-aabb` is fabricated in both halves.

    Args:
        kind: A key of IDENTIFIER_KINDS
        identifier: The matched identifier, prefix included

    Returns:
        True when the identifier reads as deliberately fabricated
    """
    body = identifier[len(_IDENTIFIER_PREFIXES[kind]):]

    return all(_is_placeholder_part(part) for part in body.split("-"))


def is_placeholder(account_id: str) -> bool:
    """
    Report whether an account ID is an obvious placeholder.

    INV-15 fixes the canonical form as a real length with a body of one
    repeated digit. The repository also uses two variants where several
    distinct accounts have to be told apart in one example: digits grouped in
    runs, and a plain count up or down.

    Args:
        account_id: Twelve-digit account ID

    Returns:
        True when the digits read as deliberately fabricated
    """
    return is_identifier_placeholder("account", account_id)


def identifiers_by_location(root: Path) -> Dict[str, Dict[str, List[str]]]:
    """
    Map every non-placeholder identifier under root to where it appears.

    Args:
        root: Directory to scan recursively

    Returns:
        Kind -> identifier -> sorted paths relative to root, one entry per file
    """
    locations: Dict[str, Dict[str, List[str]]] = {kind: {} for kind in IDENTIFIER_KINDS}

    for path in sorted(root.rglob("*")):
        if path.suffix not in _SCANNED_SUFFIXES:
            continue

        relative = path.relative_to(root)
        if not _UNSCANNED_DIRECTORIES.isdisjoint(relative.parts):
            continue

        text = path.read_text()
        for kind, pattern in IDENTIFIER_KINDS.items():
            found: List[str] = pattern.findall(text)
            for identifier in sorted(set(found)):
                if is_identifier_placeholder(kind, identifier):
                    continue
                locations[kind].setdefault(identifier, []).append(str(relative))

    return locations


def account_ids_by_location(root: Path) -> Dict[str, List[str]]:
    """
    Map every non-placeholder account ID under root to where it appears.

    Args:
        root: Directory to scan recursively

    Returns:
        Account ID -> sorted paths relative to root, one entry per file
    """
    return identifiers_by_location(root)["account"]


def real_account_ids(root: Path) -> Set[str]:
    """
    Return the real account IDs the live-test directory commits.

    Args:
        root: Repository root

    Returns:
        Account IDs appearing under test_environment/
    """
    return {
        account_id
        for account_id, paths in account_ids_by_location(root).items()
        if any(path.startswith(TEST_ENVIRONMENT) for path in paths)
    }


def identifiers_outside_the_exception(root: Path) -> Dict[str, List[str]]:
    """
    Report identifiers from the exception that appear outside it.

    INV-15 scopes the standing exception to `test_environment/` and nothing
    else, so one of its identifiers reaching code, tests, or documentation has
    left the sandbox the exception was granted for.

    Args:
        root: Repository root

    Returns:
        Account ID -> the offending paths, for each exception identifier seen
        outside test_environment/
    """
    leaked: Dict[str, List[str]] = {}
    exception = real_account_ids(root)

    for account_id, paths in account_ids_by_location(root).items():
        if account_id not in exception:
            continue
        outside = [path for path in paths if not path.startswith(TEST_ENVIRONMENT)]
        if outside:
            leaked[account_id] = outside

    return leaked


def documented_exception_count(spec_root: Path) -> Optional[int]:
    """
    Return the number of real identifiers INV-15 says the exception covers.

    Args:
        spec_root: The spec/ directory

    Returns:
        The documented count, or None if the sentence is missing or spells a
        number the word map does not carry
    """
    match = _DOCUMENTED_COUNT.search((spec_root / "invariants.md").read_text())
    if not match:
        return None

    return _NUMBER_WORDS.get(match.group(1).lower())
