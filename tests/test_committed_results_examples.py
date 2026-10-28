"""
Every committed result file holds its evidence lists in the documented order.

`test_environment/headroom_results/` is committed as worked examples for a
person to read, the same way `test_environment/scps/` and `rcps/` are
committed Terraform. Nothing compared its ordering to the rule that produces
it, so two of the thirty-two drifted out of it unnoticed: a cluster's member
instance was captured ahead of the cluster it belongs to, once in one
account's `violations` and once in another's `compliant_instances`.
Reordering the two entries fixed the drift; this file is what stops it
recurring. A third file had drifted in a way the first version of this sweep
could not see: the S3 shared-account example held three account-keyed maps in
the order the buckets named the accounts, not key order. The sweep now walks
every record's map-valued and record-list-valued fields as well.

`entry_sort_key` is imported rather than restated, because what this file
checks is that the committed *data* agrees with the rule, not that the rule
itself is correct - `tests/test_checks_base.py` already pins the rule against
literals it does not derive from the code.
"""
import json
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, cast

from headroom.checks.base import entry_sort_key
from headroom.types import JsonDict

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
RESULTS_ROOT = REPOSITORY_ROOT / "test_environment" / "headroom_results"

# The base shape's three evidence lists, each sorted globally
# (`spec/contracts/results.md` § Document shape).
BASE_SHAPE_LISTS = ("violations", "exemptions", "compliant_instances")


def two_list_shape_pair(document: JsonDict) -> Optional[Tuple[str, str]]:
    """
    The two-list shape's `(wildcards_key, access_key)` pair, or None.

    `spec/contracts/results.md` fixes both suffixes: a key ending
    `_with_wildcards` holds `violations` alone, and the key sharing its
    prefix but ending `_third_parties_can_access` holds `violations +
    compliant` - or, for `deny_s3_third_party_access` and
    `deny_sqs_third_party_access`, which spare by ARN and produce no
    violations, `exemptions` alone and `exemptions + compliant`, the
    same two-segment shape. A document holding neither suffix takes the
    base shape instead - every SCP check, and `deny_service_confused_deputy`
    among the seven RCP checks.

    Args:
        document: One committed result file, parsed

    Returns:
        The two keys besides `summary`, or None for the base shape
    """
    wildcards_keys = [key for key in document if key.endswith("_with_wildcards")]
    if not wildcards_keys:
        return None

    (wildcards_key,) = wildcards_keys
    prefix = wildcards_key[:-len("_with_wildcards")]
    return wildcards_key, f"{prefix}_third_parties_can_access"


def unsorted_evidence_lists(document: JsonDict) -> List[str]:
    """
    Every key in `document` holding evidence out of `entry_sort_key` order.

    The base shape's three lists are each checked globally sorted. The
    two-list shape's `*_with_wildcards` is checked the same way; its
    `*_third_parties_can_access` counterpart is `violations + compliant`
    (`exemptions + compliant` for the two ARN-sparing checks), which
    `spec/contracts/results.md` sorts within each segment rather than
    across their join, so it is split at `len(*_with_wildcards)`: the
    prefix must be the `*_with_wildcards` list itself, since both are the
    same list, and the remainder is checked sorted on its own. A
    global check would fail the STS shared-account worked example, which is
    sorted exactly that way on purpose.

    Args:
        document: One committed result file, parsed

    Returns:
        Every key (or named half) holding entries out of order
    """
    pair = two_list_shape_pair(document)
    if pair is None:
        problems: List[str] = []
        for list_key in BASE_SHAPE_LISTS:
            entries = cast(List[JsonDict], document[list_key])
            if entries != sorted(entries, key=entry_sort_key):
                problems.append(list_key)
        return problems

    wildcards_key, access_key = pair
    wildcards = cast(List[JsonDict], document[wildcards_key])
    access = cast(List[JsonDict], document[access_key])
    split = len(wildcards)

    problems = []
    if wildcards != sorted(wildcards, key=entry_sort_key):
        problems.append(wildcards_key)
    if access[:split] != wildcards:
        problems.append(f"{access_key} wildcard segment")
    if access[split:] != sorted(access[split:], key=entry_sort_key):
        problems.append(f"{access_key} compliant segment")
    return problems


def is_record_list(value: object) -> bool:
    """
    Whether `value` is a non-empty list whose every element is a dict.

    Args:
        value: One field of a record

    Returns:
        True for a list of records, False for anything else
    """
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def records_in(path: str, record: JsonDict) -> Iterator[Tuple[str, JsonDict]]:
    """
    `record` and, recursively, every record in a record list nested inside it.

    `spec/contracts/results.md` names two kinds of record: `summary`, and one
    evidence entry, which may itself hold a list of records - a KMS key's
    `grants`. Each is yielded with a path naming where it was found, so a
    problem inside one is reported by position.

    Args:
        path: Where `record` sits in its document, for the report
        record: The record to walk

    Returns:
        Each record reached, paired with its path
    """
    yield path, record
    for field, value in record.items():
        if not is_record_list(value):
            continue
        for item in cast(List[JsonDict], value):
            yield from records_in(f"{path}.{field}[]", item)


def all_records(document: JsonDict) -> Iterator[Tuple[str, JsonDict]]:
    """
    Every record in `document`: `summary`, each evidence entry, and each
    record nested inside one.

    Args:
        document: One committed result file, parsed

    Returns:
        Each record paired with the path it was found at
    """
    yield from records_in("summary", cast(JsonDict, document["summary"]))
    for list_key, entries in document.items():
        if list_key == "summary":
            continue
        for entry in cast(List[JsonDict], entries):
            yield from records_in(list_key, entry)


def unsorted_maps_and_nested_lists(document: JsonDict) -> List[str]:
    """
    Every record field in `document` holding a map or a record list out of order.

    A record - `summary`, or one evidence entry - keeps its fields in the
    order they were written, and `spec/contracts/results.md` draws the line
    there: a dict that is the value of a record's field is a map keyed by an
    identifier, which sorts by key and, where its values are lists, by
    value; a list of records inside an entry sorts by `entry_sort_key`, the
    same rule as the list holding it. The record's own field order is the
    one thing here that must not be checked, and
    `test_a_records_own_field_order_is_not_checked` pins that it is not.

    Args:
        document: One committed result file, parsed

    Returns:
        Every map or nested record list out of order, named by its path
    """
    problems: List[str] = []
    for path, record in all_records(document):
        for field, value in record.items():
            if is_record_list(value) and value != sorted(cast(List[JsonDict], value), key=entry_sort_key):
                problems.append(f"{path}.{field}")
            if not isinstance(value, dict):
                continue
            if list(value) != sorted(value):
                problems.append(f"{path}.{field} keys")
            for key, values in value.items():
                if isinstance(values, list) and values != sorted(values):
                    problems.append(f"{path}.{field}[{key}] values")
    return problems


def ordering_problems(document: JsonDict) -> List[str]:
    """
    Everything in `document` out of the order `spec/contracts/results.md` states.

    Args:
        document: One committed result file, parsed

    Returns:
        The evidence lists, then the maps and nested record lists, out of order
    """
    return unsorted_evidence_lists(document) + unsorted_maps_and_nested_lists(document)


def test_every_committed_result_file_holds_its_evidence_in_sorted_order() -> None:
    """
    Every committed result file agrees with `spec/contracts/results.md` on its own data.

    Two of the thirty-two drifted before this test existed: a cluster's
    member instance was captured ahead of the cluster it belongs to, once in
    an account's `violations` and once in another's `compliant_instances`.
    A third drifted in its maps: the S3 shared-account example's three
    account-keyed maps were keyed in the order the buckets named the accounts.
    Reordering fixed each; this sweeps every committed file so a future
    hand-edit or stale capture cannot reintroduce either unnoticed.
    """
    result_files = sorted(RESULTS_ROOT.rglob("*.json"))
    assert result_files, "no committed result files found"

    documents: Dict[Path, JsonDict] = {
        result_file: json.loads(result_file.read_text())
        for result_file in result_files
    }
    problems = {
        str(result_file.relative_to(RESULTS_ROOT)): ordering_problems(document)
        for result_file, document in documents.items()
        if ordering_problems(document)
    }

    assert problems == {}


def test_the_sts_shared_account_example_is_sorted_within_each_segment_but_not_globally() -> None:
    """
    The STS shared-account example is the two-list shape's deliberately
    not-globally-sorted case, and the sweep above must pass it.

    Its `roles_third_parties_can_access` is one wildcard entry followed by
    ten compliant ones: each segment sorted on its own, the concatenation
    not, exactly as `spec/contracts/results.md` specifies. A test that
    demanded global sortedness here would fail this file and would
    contradict the specification it exists to enforce.
    """
    document: JsonDict = json.loads(
        (RESULTS_ROOT / "rcps" / "deny_sts_third_party_assumerole" / "shared-foo-bar.json").read_text()
    )

    wildcards = cast(List[JsonDict], document["roles_with_wildcards"])
    access = cast(List[JsonDict], document["roles_third_parties_can_access"])

    assert len(wildcards) == 1
    assert len(access) == 11
    assert access != sorted(access, key=entry_sort_key)
    assert access[:1] == wildcards
    assert access[1:] == sorted(access[1:], key=entry_sort_key)
    assert unsorted_evidence_lists(document) == []


def test_unsorted_evidence_lists_reports_a_base_shape_list_out_of_order() -> None:
    """
    A base-shape list holding an entry out of authored-field order names
    itself.

    Built rather than drawn from the corpus: after the two RDS examples
    were reordered, no committed base-shape file exercises this branch.
    """
    document: JsonDict = {
        "violations": [{"id": "b"}, {"id": "a"}],
        "exemptions": [],
        "compliant_instances": [{"id": "a"}, {"id": "b"}],
    }

    assert unsorted_evidence_lists(document) == ["violations"]


def test_unsorted_evidence_lists_reports_an_unsorted_with_wildcards_list_by_its_own_key() -> None:
    """
    A `*_with_wildcards` list out of order is named by its own key.

    Built rather than drawn from the corpus: every committed
    `*_with_wildcards` list is already sorted, so nothing there exercises
    this branch.
    """
    document: JsonDict = {
        "widgets_with_wildcards": [{"id": "b"}, {"id": "a"}],
        "widgets_third_parties_can_access": [{"id": "b"}, {"id": "a"}, {"id": "m"}],
    }

    assert unsorted_evidence_lists(document) == ["widgets_with_wildcards"]


def test_unsorted_evidence_lists_reports_the_access_lists_wildcard_segment_by_name() -> None:
    """
    The access list's first `len(*_with_wildcards)` entries must be that
    list, and a failure there names the segment.

    Built rather than drawn from the corpus: every committed access list's
    wildcard segment is already sorted, so nothing there exercises this
    branch.
    """
    document: JsonDict = {
        "widgets_with_wildcards": [{"id": "a"}, {"id": "b"}],
        "widgets_third_parties_can_access": [{"id": "z"}, {"id": "a"}, {"id": "m"}],
    }

    assert unsorted_evidence_lists(document) == ["widgets_third_parties_can_access wildcard segment"]


def test_unsorted_evidence_lists_reports_the_access_lists_compliant_segment_by_name() -> None:
    """
    The access list's remaining entries are checked as their own segment,
    and a failure there is named distinctly from the wildcard segment.

    Built rather than drawn from the corpus: every committed access list's
    compliant segment is already sorted, so nothing there exercises this
    branch.
    """
    document: JsonDict = {
        "widgets_with_wildcards": [{"id": "a"}],
        "widgets_third_parties_can_access": [{"id": "a"}, {"id": "z"}, {"id": "m"}],
    }

    assert unsorted_evidence_lists(document) == ["widgets_third_parties_can_access compliant segment"]


def test_unsorted_maps_reports_a_map_whose_keys_are_out_of_order() -> None:
    """
    An account-keyed map whose keys are not sorted is named by its path.

    Drawn from the corpus: the S3 shared-account example held three such
    maps - two in `summary`, one in an entry - before this function existed,
    and the evidence-list sweep alone passed it.
    """
    document: JsonDict = {
        "summary": {
            "actions_by_third_party_account": {
                "222222222222": ["s3:GetObject"],
                "111111111111": ["s3:GetObject"],
            },
        },
        "violations": [],
    }

    assert unsorted_maps_and_nested_lists(document) == ["summary.actions_by_third_party_account keys"]


def test_unsorted_maps_reports_a_maps_unsorted_values_by_key() -> None:
    """
    A map whose keys are in order but whose values under one key are not
    names that key.

    Built rather than drawn from the corpus: every committed map's values
    are already sorted, so nothing there exercises this branch.
    """
    document: JsonDict = {
        "summary": {},
        "violations": [
            {
                "bucket_name": "headroom-test-bucket",
                "actions_by_account": {"111111111111": ["s3:PutObject", "s3:GetObject"]},
            },
        ],
    }

    assert unsorted_maps_and_nested_lists(document) == ["violations.actions_by_account[111111111111] values"]


def test_unsorted_maps_reports_a_nested_record_list_out_of_entry_sort_key_order() -> None:
    """
    A list of records inside an entry that is not in `entry_sort_key` order
    is named by its path.

    Built rather than drawn from the corpus: no KMS result is committed, so
    no committed entry holds a nested record list.
    """
    document: JsonDict = {
        "summary": {},
        "violations": [
            {
                "key_id": "11111111-1111-1111-1111-111111111111",
                "grants": [{"grant_id": "b"}, {"grant_id": "a"}],
            },
        ],
    }

    assert unsorted_maps_and_nested_lists(document) == ["violations.grants"]


def test_a_records_own_field_order_is_not_checked() -> None:
    """
    A record's fields stay in authored order, and the sweep must not demand
    otherwise.

    `summary` and every entry below are written with their fields out of
    alphabetical order on purpose: that order is the record's, chosen to be
    read, and `spec/contracts/results.md` sorts maps and lists while leaving
    it alone. A sweep that sorted record fields would fail every committed
    file and contradict the contract it enforces.
    """
    document: JsonDict = {
        "summary": {"total_buckets_analyzed": 1, "account_name": "security-tooling"},
        "violations": [
            {
                "region": "us-east-1",
                "bucket_name": "headroom-test-bucket",
                "grants": [{"grant_id": "a", "operations": ["kms:Decrypt"]}],
            },
        ],
    }

    assert unsorted_maps_and_nested_lists(document) == []


def test_unsorted_evidence_lists_reports_a_sorted_wildcard_prefix_that_is_not_the_wildcards_list() -> None:
    """
    The access list's first `len(*_with_wildcards)` entries must be the
    `*_with_wildcards` list itself, not merely a sorted run.

    Both lists are built from the same `violations`, so equality is the
    rule, and it catches what sortedness of the slice cannot: a sorted
    prefix holding the wrong entries, and an access list shorter than the
    wildcards list, whose slice is short, sorted, and wrong.
    """
    wrong_entries: JsonDict = {
        "widgets_with_wildcards": [{"id": "a"}, {"id": "b"}],
        "widgets_third_parties_can_access": [{"id": "a"}, {"id": "c"}, {"id": "z"}],
    }
    too_short: JsonDict = {
        "widgets_with_wildcards": [{"id": "a"}, {"id": "b"}],
        "widgets_third_parties_can_access": [{"id": "a"}],
    }

    assert unsorted_evidence_lists(wrong_entries) == ["widgets_third_parties_can_access wildcard segment"]
    assert unsorted_evidence_lists(too_short) == ["widgets_third_parties_can_access wildcard segment"]
