"""Validate the specification corpus in spec/ against the check registry."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

# Frontmatter fields every per-check specification must carry.
REQUIRED_FIELDS = ("id", "kind", "status", "applies_to", "depends_on", "verification")

# Fields holding a list of repository-relative paths that must exist.
PATH_LIST_FIELDS = ("applies_to", "verification")

# Frontmatter `kind` -> the check type the registry records.
KIND_TO_CHECK_TYPE = {"scp": "scps", "rcp": "rcps"}

ALLOWED_STATUSES = frozenset({"implemented", "planned", "deprecated"})

# The sections spec/checks/index.md requires, in the order it requires them.
REQUIRED_SECTIONS = (
    "Objective",
    "Enforced statement",
    "Evidence",
    "Decision table",
    "Failure behavior",
    "Result contract",
    "Placement and generated policy",
    "Accepted limitations",
    "Acceptance scenarios",
    "Referenced invariants",
    "Implementation",
)

# A twelfth section is allowed where the implementation and the corpus disagree.
# It may sit anywhere, and index.md requires it to carry a status.
CONFLICT_SECTION_PREFIX = "Known conflict:"
CONFLICT_STATUS = "Status: unresolved"

# The register in checks/index.md that names every unresolved conflict.
CONFLICT_REGISTER_HEADING = "## Unresolved conflicts"

_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_NEXT_SECTION = re.compile(r"^## ", re.MULTILINE)
_CHECK_DOCUMENT_LINK = re.compile(r"\]\((?:scps|rcps)/([a-z0-9_]+)\.md\)")
_INVARIANT_HEADING = re.compile(r"^## (INV-\d+)\b", re.MULTILINE)
_SECTION_HEADING = re.compile(r"^## (.+)$", re.MULTILINE)
_INVARIANT_CITATION = re.compile(r"\bINV-\d+\b")

# A guard is cited in strategy.md as a backticked test name or test file.
_GUARD_NAME = re.compile(r"`(test_[a-z0-9_]+)`")
_GUARD_FILE = re.compile(r"`(tests/[a-z0-9_/]+\.py)`")
_TEST_DEFINITION = re.compile(r"^\s*def (test_[a-z0-9_]+)\(", re.MULTILINE)

# The heading the named-guard table lives under in strategy.md.
_GUARD_HEADING = "## Named guard tests"


@dataclass(frozen=True)
class CheckSpecification:
    """
    One per-check specification document.

    Attributes:
        path: Path to the document
        frontmatter: Parsed frontmatter mapping, empty if the document has none
        kind_directory: The checks/ subdirectory the document was found in
    """

    path: Path
    frontmatter: Dict[str, Any]
    kind_directory: str


def parse_frontmatter(text: str) -> Optional[Dict[str, Any]]:
    """
    Return a document's YAML frontmatter mapping.

    Args:
        text: Full document text

    Returns:
        The parsed mapping, or None if the document opens with no frontmatter
        block or the block does not parse to a mapping
    """
    match = _FRONTMATTER.match(text)
    if not match:
        return None

    parsed = yaml.safe_load(match.group(1))
    if not isinstance(parsed, dict):
        return None

    return parsed


def load_check_specifications(spec_root: Path) -> List[CheckSpecification]:
    """
    Load every per-check specification under spec/checks/.

    Args:
        spec_root: The spec/ directory

    Returns:
        Specifications, sorted by path
    """
    specifications: List[CheckSpecification] = []

    for kind_directory in sorted(KIND_TO_CHECK_TYPE):
        directory = spec_root / "checks" / f"{kind_directory}s"
        for path in sorted(directory.glob("*.md")):
            specifications.append(CheckSpecification(
                path=path,
                frontmatter=parse_frontmatter(path.read_text()) or {},
                kind_directory=kind_directory,
            ))

    return specifications


def invariant_ids(spec_root: Path) -> List[str]:
    """
    Return the invariant IDs invariants.md defines.

    Args:
        spec_root: The spec/ directory

    Returns:
        Invariant IDs, in document order
    """
    return _INVARIANT_HEADING.findall((spec_root / "invariants.md").read_text())


def corpus_documents(spec_root: Path) -> List[Path]:
    """
    Return every document in the corpus.

    Args:
        spec_root: The spec/ directory

    Returns:
        Every .md file under spec/, sorted by path
    """
    return sorted(spec_root.rglob("*.md"))


def find_corpus_wide_problems(spec_root: Path) -> List[str]:
    """
    Report the rules that hold for every document, not only the check ones.

    Per-check documents are validated against their frontmatter contract, and
    the other thirteen against nothing. These two rules need no frontmatter:
    a citation names an invariant that exists, and a document states each of
    its sections once.

    Args:
        spec_root: The spec/ directory

    Returns:
        Problem descriptions, sorted
    """
    defined = invariant_ids(spec_root)

    problems: List[str] = []
    for path in corpus_documents(spec_root):
        name = path.relative_to(spec_root).as_posix()
        text = path.read_text()

        for citation in sorted(set(_INVARIANT_CITATION.findall(text))):
            if citation in defined:
                continue
            problems.append(f"{name} cites {citation}, which invariants.md does not define")

        seen: Set[str] = set()
        for heading in _SECTION_HEADING.findall(text):
            if heading in seen:
                problems.append(f"{name} states the section '{heading}' twice")
                continue
            seen.add(heading)

    return sorted(problems)


def _document_problems(
    specification: CheckSpecification,
    spec_root: Path,
    check_types: Dict[str, str],
    defined_invariants: List[str],
) -> List[str]:
    """
    Report what is wrong with one specification document.

    Args:
        specification: The document to inspect
        spec_root: The spec/ directory, used to resolve repository paths
        check_types: Registered check name -> check type
        defined_invariants: Invariant IDs invariants.md defines

    Returns:
        Problem descriptions, one per finding
    """
    problems: List[str] = []
    name = specification.path.name
    frontmatter = specification.frontmatter

    missing = [field for field in REQUIRED_FIELDS if field not in frontmatter]
    if missing:
        problems.append(f"{name} frontmatter is missing: {', '.join(missing)}")
        return problems

    mistyped = [
        field for field in ("depends_on",) + PATH_LIST_FIELDS
        if not isinstance(frontmatter[field], list)
    ]
    if mistyped:
        return [
            f"{name} {field} must be a list, not a {type(frontmatter[field]).__name__}"
            for field in mistyped
        ]

    if frontmatter["id"] != specification.path.stem:
        problems.append(f"{name} declares id '{frontmatter['id']}', expected '{specification.path.stem}'")

    if frontmatter["kind"] != specification.kind_directory:
        problems.append(
            f"{name} declares kind '{frontmatter['kind']}' but sits in "
            f"checks/{specification.kind_directory}s/"
        )

    if frontmatter["status"] not in ALLOWED_STATUSES:
        problems.append(
            f"{name} declares status '{frontmatter['status']}', expected one of "
            f"{', '.join(sorted(ALLOWED_STATUSES))}"
        )

    if check_types.get(specification.path.stem) != KIND_TO_CHECK_TYPE[specification.kind_directory]:
        problems.append(f"{name} names no registered {specification.kind_directory} check")

    for invariant in frontmatter["depends_on"]:
        if invariant not in defined_invariants:
            problems.append(f"{name} cites {invariant}, which invariants.md does not define")

    repository_root = spec_root.parent
    for field in PATH_LIST_FIELDS:
        for relative_path in frontmatter[field]:
            if not (repository_root / relative_path).exists():
                problems.append(f"{name} {field} names a missing path: {relative_path}")

    problems.extend(_section_problems(name, specification.path.read_text()))

    return problems


def _section_bodies(text: str) -> List[Tuple[str, str]]:
    """
    Return each section's heading paired with its body, in document order.

    A body runs from the end of its heading line to the start of the next
    heading, or to end of file for the last one. Headings are not unique in
    an arbitrary document, so this returns every occurrence rather than a
    dict keyed by heading: a dict would let a later, non-empty duplicate
    silently hide an earlier, empty one under the same name.

    Args:
        text: Full document text

    Returns:
        (heading, body) pairs in document order, each body stripped
    """
    bodies: List[Tuple[str, str]] = []
    matches = list(_SECTION_HEADING.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        bodies.append((match.group(1), text[match.end():end].strip()))

    return bodies


def _section_problems(name: str, text: str) -> List[str]:
    """
    Report every way a document's sections depart from the index.md contract.

    Args:
        name: Document name for the problem descriptions
        text: Full document text

    Returns:
        Problem descriptions
    """
    problems: List[str] = []
    headings: List[str] = _SECTION_HEADING.findall(text)

    conflicts = [h for h in headings if h.startswith(CONFLICT_SECTION_PREFIX)]
    if conflicts and CONFLICT_STATUS not in text:
        problems.append(
            f"{name} has a Known conflict section that does not say {CONFLICT_STATUS}"
        )

    for heading in headings:
        if heading not in REQUIRED_SECTIONS and heading not in conflicts:
            problems.append(f"{name} has an unrecognized section: {heading}")

    present = [h for h in headings if h in REQUIRED_SECTIONS]
    for section in REQUIRED_SECTIONS:
        if section not in present:
            problems.append(f"{name} is missing section: {section}")

    expected_order = [s for s in REQUIRED_SECTIONS if s in present]
    for found, wanted in zip(present, expected_order):
        if found != wanted:
            problems.append(f"{name} orders sections {found} before {wanted}")
            break

    for heading, body in _section_bodies(text):
        if body:
            continue
        problems.append(f"{name} has an empty section: {heading}")

    return problems


def find_corpus_problems(spec_root: Path, check_types: Dict[str, str]) -> List[str]:
    """
    Report every way the corpus disagrees with the check registry.

    Args:
        spec_root: The spec/ directory
        check_types: Registered check name -> check type, from the registry

    Returns:
        Problem descriptions, sorted
    """
    specifications = load_check_specifications(spec_root)
    defined_invariants = invariant_ids(spec_root)

    problems: List[str] = []
    for specification in specifications:
        problems.extend(
            _document_problems(specification, spec_root, check_types, defined_invariants)
        )

    specification_paths = {specification.path for specification in specifications}
    for path in sorted(spec_root.rglob("*.md")):
        if path in specification_paths:
            continue
        for heading, body in _section_bodies(path.read_text()):
            if body:
                continue
            problems.append(f"{path.name} has an empty section: {heading}")

    seen: Dict[str, Path] = {}
    for specification in specifications:
        declared_id = specification.frontmatter.get("id")
        if not isinstance(declared_id, str):
            continue
        if declared_id in seen:
            problems.append(f"id '{declared_id}' is declared by both {seen[declared_id].name} and {specification.path.name}")
            continue
        seen[declared_id] = specification.path

    specified = {specification.path.stem for specification in specifications}
    for check_name in sorted(set(check_types) - specified):
        problems.append(f"registered check {check_name} has no specification")

    return sorted(problems)


def _conflict_register(spec_root: Path) -> str:
    """
    Return the body of the unresolved-conflict register.

    Args:
        spec_root: The spec/ directory

    Returns:
        Everything between the register heading and the next section heading
    """
    text = (spec_root / "checks" / "index.md").read_text()
    start = text.index(CONFLICT_REGISTER_HEADING) + len(CONFLICT_REGISTER_HEADING)
    next_section = _NEXT_SECTION.search(text, start)
    if not next_section:
        return text[start:]

    return text[start:next_section.start()]


def _registered_conflict_checks(spec_root: Path) -> Set[str]:
    """
    Return the checks the register's Where column names.

    Only that column counts. A conflict's prose routinely links a *different*
    check for contrast, and the paragraph below the table links the two gaps
    recorded elsewhere precisely because they are not conflicts.

    Args:
        spec_root: The spec/ directory

    Returns:
        Check names
    """
    names: Set[str] = set()
    for line in _conflict_register(spec_root).splitlines():
        if not line.startswith("|"):
            continue
        names.update(_CHECK_DOCUMENT_LINK.findall(line.split("|")[2]))

    return names


def _documented_conflict_checks(spec_root: Path) -> Set[str]:
    """
    Return the checks whose own document carries a conflict section.

    Args:
        spec_root: The spec/ directory

    Returns:
        Check names
    """
    names: Set[str] = set()
    for specification in load_check_specifications(spec_root):
        headings: List[str] = _SECTION_HEADING.findall(specification.path.read_text())
        if any(heading.startswith(CONFLICT_SECTION_PREFIX) for heading in headings):
            names.add(specification.path.stem)

    return names


def find_conflict_divergences(spec_root: Path) -> List[str]:
    """
    Report where the conflict register and the check documents disagree.

    The register and the per-check documents are two views of one set. A reader
    who opens a check document rather than the index must see the same
    conflicts, so a name may not appear in one view and be absent from the
    other. The section contract in `_section_problems` cannot catch this: it
    checks a conflict section it can see, and a document that simply has none
    passes it vacuously.

    Args:
        spec_root: The spec/ directory

    Returns:
        Problem descriptions, sorted
    """
    registered = _registered_conflict_checks(spec_root)
    documented = _documented_conflict_checks(spec_root)

    problems = [
        f"{name} is named in the conflict register with no '{CONFLICT_SECTION_PREFIX}' section in its document"
        for name in registered - documented
    ]
    problems.extend(
        f"{name} has a '{CONFLICT_SECTION_PREFIX}' section and the conflict register does not name it"
        for name in documented - registered
    )

    return sorted(problems)


def find_missing_named_guards(spec_root: Path, tests_root: Path) -> List[str]:
    """
    Report every guard `strategy.md` names that no test defines.

    The named-guard table is the corpus's record of which invariants have a
    mechanical pin, and `strategy.md` says renaming one without replacing it
    removes an invariant's only enforcement. Nothing enforced that claim: the
    table went on naming `test_only_the_aws_package_constructs_a_client` for
    as long as no such test existed, so the document asserted a guarantee the
    suite did not give.

    Args:
        spec_root: The `spec/` directory
        tests_root: The `tests/` directory

    Returns:
        One line per named guard that resolves to nothing, empty when the
        table and the suite agree
    """
    strategy = spec_root / "verification" / "strategy.md"
    text = strategy.read_text()
    if _GUARD_HEADING not in text:
        return [f"{strategy}: no {_GUARD_HEADING!r} section"]

    table = text.split(_GUARD_HEADING, 1)[1]
    defined = set()
    for path in sorted(tests_root.rglob("*.py")):
        defined.update(_TEST_DEFINITION.findall(path.read_text()))

    problems = []
    for name in sorted(set(_GUARD_NAME.findall(table))):
        if name not in defined:
            problems.append(f"named guard {name} is defined by no test")
    for relative in sorted(set(_GUARD_FILE.findall(table))):
        if not (tests_root.parent / relative).exists():
            problems.append(f"named guard file {relative} does not exist")
    return problems
