# Parallel Account Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run account analysis concurrently and delete the redundant AWS calls, taking a
300-account run from roughly 4.9 hours to roughly 14 minutes.

**Architecture:** One `ThreadPoolExecutor` over accounts with cooperative abort, plus two
session-keyed memos that remove calls rather than merely running them in parallel. No
region-level, check-level, or resource-level threading. Output is unchanged: results are
written per account and per check, so worker scheduling cannot affect what lands on disk.

**Tech Stack:** Python 3.13, `concurrent.futures.ThreadPoolExecutor`, `threading.Event`,
`threading.Lock`, `weakref.WeakKeyDictionary`, boto3/botocore, Pydantic 2, pytest, mypy
strict, tox.

**Spec:** `design-docs/2026-08-21-parallel-account-analysis.md`

**Status:** Every task below is implemented. The checkboxes were never ticked,
so do not read them as work outstanding -- this is a finished plan kept for the
reasoning behind each step. See the spec's header for the two figures both
documents have since outlived.

## Global Constraints

Copied from the repository's rules. Every task's requirements include this section.

- **TDD, strictly.** Write the failing test, run it, watch it fail for the right reason,
  then implement. Never write production code first.
- **100% test coverage** on both `headroom/` and `tests/`. Enforced by tox.
- **mypy strict.** No untyped definitions. Every function annotated, including `-> None`.
- **Never use the type `Any`.** This forbids a single generic memo dictionary; see Task 1.
- **Never `except Exception`.** Catch the specific exception the code can raise.
- **No dynamic imports. No imports inside functions.** Top-level only.
- **No functions defined inside functions.** This forbids closures as memo builders.
- **No defensive fallbacks.** Never return an empty set, list, or `None` after a type
  check. Let it raise.
- **Do not overengineer.** No new type with one attribute, no new class with one function.
- **Config defaults are declared once**, in `headroom/config.py`, and never repeated.
- **CLI arguments must not carry defaults**; their default lives in `config.py` and the
  argparse default is `None` so `merge_configs` skips it.
- **Split docstrings over multiple lines** for PEP 257.
- **Wrap `with` statements in parentheses** with a newline after the paren, dedented body
  lines, and a trailing comma.
- **Use `continue` and `return`** to keep indentation shallow.
- **Never put a real AWS identifier** in code, tests, docs, or commit messages. Use
  obviously fake placeholders: real prefix, real length, body of one repeated digit, e.g.
  `111111111111`, `i-11111111111111111`, `ami-11111111111111111`.
- **Never commit without asking the repository owner first.**
- **Verify with `tox`, not the ambient venv.** The ambient venv carries stale boto3 stubs
  that produce false failures. Run `unset FORCE_COLOR` first. To run a single test file
  quickly, use `.tox/py313/bin/python -m pytest`.

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `headroom/aws/helpers.py` | Region discovery, pagination, region memo | 1 |
| `headroom/aws/ec2.py` | EC2 analysis, `Ec2Instance` projection, instance memo | 2 |
| `headroom/analysis.py` | Duplicate-name guard, worker pool, cooperative abort | 3, 6 |
| `headroom/log_context.py` | **New.** Thread-local account context for log records | 4 |
| `headroom/aws/sessions.py` | Client-construction lock, retry mode, STS pool sizing | 5 |
| `headroom/config.py` | `DEFAULT_ACCOUNT_WORKERS`, `MAX_ACCOUNT_WORKERS`, config field | 5, 6 |
| `headroom/usage.py` | `--max-account-workers` CLI flag | 6 |
| `headroom/main.py` | Install the logging filter | 4 |
| `tests/performance/test_call_counts.py` | **New.** Pin the saved calls as a contract | 7 |

Task order is chosen so every task leaves the tree green and is independently valuable.
Tasks 1-5 are each a standalone improvement; Task 6 is the payoff and depends on 3, 4,
and 5.

---

### Task 1: Memoize the region list

Eleven checks each call `get_all_regions`, and the answer cannot change within a run. Ten
of those eleven `describe_regions` calls are pure latency.

**Files:**
- Modify: `headroom/aws/helpers.py`
- Test: `tests/test_aws_helpers.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `get_all_regions(session: Session) -> List[str]`, unchanged signature, now
  memoized per session.

**Why two memos instead of one generic memo.** A single `WeakKeyDictionary[Session,
Dict[str, Any]]` would need `Any`, which the repository forbids. A generic helper taking a
builder callable would need a closure, and functions inside functions are also forbidden.
Two small independently-typed memos duplicate four lines of lock-check-set and break
neither rule. That is the right trade.

**Why the lock is released across the API call.** Holding it would serialize every worker
behind one account's `describe_regions`. Two threads cannot race to fill the same entry
because each session is used by exactly one worker; the lock exists only because the outer
`WeakKeyDictionary` is shared.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_aws_helpers.py`, inside `class TestGetAllRegions`:

```python
    def test_region_list_is_fetched_once_per_session(self) -> None:
        """
        Eleven checks ask for the region list; only the first reaches AWS.

        The other ten calls are pure latency, and the answer cannot change
        within a run.
        """
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

        first = get_all_regions(mock_session)
        second = get_all_regions(mock_session)

        assert first == second == ["us-east-1"]
        mock_ec2.describe_regions.assert_called_once_with()

    def test_each_session_gets_its_own_region_list(self) -> None:
        """
        Two sessions never share a memo entry.

        A memo keyed wrongly does not crash. It serves one account's region
        list to another account, and the resulting results look entirely
        plausible, so this is the failure mode worth pinning.
        """
        session_a, session_b = MagicMock(), MagicMock()
        ec2_a, ec2_b = MagicMock(), MagicMock()
        session_a.client.return_value = ec2_a
        session_b.client.return_value = ec2_b
        ec2_a.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        ec2_b.describe_regions.return_value = {"Regions": [{"RegionName": "eu-west-1"}]}

        assert get_all_regions(session_a) == ["us-east-1"]
        assert get_all_regions(session_b) == ["eu-west-1"]
        assert get_all_regions(session_a) == ["us-east-1"]

    def test_memo_entry_is_released_when_the_session_is_dropped(self) -> None:
        """
        An account's entry dies with its session, so a 300-account run does
        not accumulate 300 region lists.
        """
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

        get_all_regions(mock_session)
        assert len(_REGION_MEMO) == 1

        del mock_session
        gc.collect()

        assert len(_REGION_MEMO) == 0
```

Add to the imports at the top of the file:

```python
import gc

from headroom.aws.helpers import _REGION_MEMO, get_all_regions, paginate
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_aws_helpers.py -v
```

Expected: `ImportError: cannot import name '_REGION_MEMO'`. Fix nothing else until the
import exists; the other two tests cannot even be collected yet.

- [ ] **Step 3: Implement the memo**

In `headroom/aws/helpers.py`, add to the imports:

```python
from threading import Lock
from weakref import WeakKeyDictionary
```

Add above `get_all_regions`:

```python
_REGION_MEMO: WeakKeyDictionary[Session, list[str]] = WeakKeyDictionary()
_REGION_MEMO_LOCK = Lock()
```

Replace the body of `get_all_regions` (keep the existing docstring and append the new
paragraphs to it):

```python
def get_all_regions(session: Session) -> list[str]:
    """
    Return the AWS regions that are enabled for the account.

    `describe_regions` is deliberately called with no arguments. The default
    response contains only regions the account has enabled -- those with an
    OptInStatus of `opt-in-not-required` or `opted-in` -- and omits every
    `not-opted-in` region.

    Do not pass `AllRegions=True`. It adds disabled regions to the result, and
    since every caller builds a per-region client from this list, each disabled
    region would become a doomed API call against a region the account cannot
    use. Headroom has no interest in analyzing a region that cannot hold
    resources. `test_only_enabled_regions_are_requested` pins this.

    Note that an enabled region does not guarantee the service is available
    there; handling a missing regional endpoint is the caller's concern.

    The result is memoized per session. Eleven checks each ask for the region
    list and the answer cannot change within a run, so the other ten calls are
    pure latency.

    The memo is keyed on the session object itself, never on an account ID or
    name. That is what keeps one account's region list out of another account's
    results. Entries live in a WeakKeyDictionary, so an account's entry is
    released as soon as its worker drops the session and nothing accumulates
    across a 300-account run.

    The lock is released across the `describe_regions` call rather than held.
    Holding it would serialize every worker behind one account's region lookup.
    Two threads cannot race to fill the same entry because each session belongs
    to exactly one worker; the lock exists only because the outer
    WeakKeyDictionary is shared between workers.
    """
    with _REGION_MEMO_LOCK:
        cached = _REGION_MEMO.get(session)

    if cached is not None:
        return cached

    ec2_client: EC2Client = session.client("ec2")
    response = ec2_client.describe_regions()
    regions = [region["RegionName"] for region in response["Regions"]]

    with _REGION_MEMO_LOCK:
        _REGION_MEMO[session] = regions

    return regions
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_aws_helpers.py -v
```

Expected: PASS, including the three pre-existing tests. If
`test_only_enabled_regions_are_requested` now fails with a stale-memo error, the tests are
sharing a `MagicMock` session; each test must build its own.

- [ ] **Step 5: Run the full suite**

```bash
unset FORCE_COLOR && tox
```

Expected: all tests pass, 100% coverage, mypy clean.

- [ ] **Step 6: Ask the repository owner for permission to commit, then commit**

```bash
git add headroom/aws/helpers.py tests/test_aws_helpers.py
git commit -m "Memoize the region list per session"
```

---

### Task 2: Collect EC2 instances once per region

Four checks each run an unfiltered `describe_instances` across every region: the same call,
the same pages, four times. This task collapses them into one collection pass behind a
memo, and projects each instance down to the nine values the checks actually read.

**Files:**
- Modify: `headroom/aws/ec2.py`
- Test: `tests/test_aws_ec2.py`

**Interfaces:**
- Consumes: `paginate` from `headroom.aws.helpers` (already imported there is only
  `get_all_regions`; add `paginate`).
- Produces:
  - `Ec2Instance` dataclass with fields `instance_id: str`, `region: str`,
    `image_id: Optional[str]`, `owner_id: str`, `public_ip_address: Optional[str]`,
    `http_tokens: str`, `http_endpoint: str`, `hop_limit: int`, `tags: Dict[str, str]`
  - `get_instances(session: Session, region: str) -> List[Ec2Instance]`

**Behaviour change to confirm before starting.** The current code reads `OwnerId` off the
instance dictionary (`ec2.py`, in `get_ec2_public_ip_analysis`). The EC2 API puts `OwnerId`
on the **reservation**, not the instance — `mypy_boto3_ec2.type_defs.InstanceTypeDef` has no
such key. Against real AWS that expression always yields `""`, so every
`deny_ec2_public_ip` result carries a malformed ARN with an empty account field:
`arn:aws:ec2:us-east-1::instance/i-...`. The existing test passes only because its fixture
puts `OwnerId` on the instance.

This plan reads `OwnerId` from the reservation, which is correct, and updates the fixture.
**Do not start this task until the repository owner has confirmed that fix is wanted.** If
they prefer to preserve current behaviour, pass `""` for `owner_id` and raise the bug
separately.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_aws_ec2.py`:

```python
class TestGetInstances:
    """Test the shared per-region instance collector."""

    @staticmethod
    def _session(pages: List[Dict[str, Any]]) -> MagicMock:
        """Build a mock session whose regional EC2 client serves `pages`."""
        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = pages
        mock_regional_ec2.get_paginator.return_value = mock_paginator
        mock_session = MagicMock()
        mock_session.client.return_value = mock_regional_ec2
        return mock_session

    def test_projects_every_field_the_checks_read(self) -> None:
        """
        The projection carries exactly the values the four EC2 checks read.

        Anything else in a describe_instances entry -- BlockDeviceMappings,
        NetworkInterfaces, SecurityGroups, Placement -- is dropped, because
        holding it for an account's whole lifetime is what would make this
        memo expensive.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{
                    "InstanceId": "i-11111111111111111",
                    "ImageId": "ami-11111111111111111",
                    "PublicIpAddress": "203.0.113.10",
                    "State": {"Name": "running"},
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 2,
                    },
                    "Tags": [{"Key": "ExemptFromIMDSv2", "Value": "true"}],
                    "BlockDeviceMappings": [{"DeviceName": "/dev/sda1"}],
                }],
            }]
        }])

        instances = get_instances(session, "us-east-1")

        assert instances == [Ec2Instance(
            instance_id="i-11111111111111111",
            region="us-east-1",
            image_id="ami-11111111111111111",
            owner_id="111111111111",
            public_ip_address="203.0.113.10",
            http_tokens="required",
            http_endpoint="enabled",
            hop_limit=2,
            tags={"ExemptFromIMDSv2": "true"},
        )]

    def test_applies_the_aws_metadata_defaults(self) -> None:
        """
        An instance with no MetadataOptions gets the values AWS applies:
        IMDSv1 permitted, endpoint enabled, hop limit 1.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{
                    "InstanceId": "i-11111111111111111",
                    "State": {"Name": "running"},
                }],
            }]
        }])

        instance = get_instances(session, "us-east-1")[0]

        assert instance.http_tokens == "optional"
        assert instance.http_endpoint == "enabled"
        assert instance.hop_limit == 1
        assert instance.image_id is None
        assert instance.public_ip_address is None
        assert instance.tags == {}

    def test_terminated_instances_are_dropped_once_here(self) -> None:
        """
        The terminated filter lives in the collector.

        All four checks previously opened with the identical
        `if instance['State']['Name'] == 'terminated': continue`. Stating it
        once is the point of collecting once.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [
                    {"InstanceId": "i-11111111111111111", "State": {"Name": "terminated"}},
                    {"InstanceId": "i-22222222222222222", "State": {"Name": "running"}},
                ],
            }]
        }])

        instances = get_instances(session, "us-east-1")

        assert [i.instance_id for i in instances] == ["i-22222222222222222"]

    def test_owner_id_comes_from_the_reservation(self) -> None:
        """
        OwnerId lives on the reservation, not the instance.

        InstanceTypeDef has no OwnerId key, so reading it off the instance
        always produced an empty string against real AWS and yielded a
        malformed instance ARN with no account.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{
                    "InstanceId": "i-11111111111111111",
                    "State": {"Name": "running"},
                }],
            }]
        }])

        assert get_instances(session, "us-east-1")[0].owner_id == "111111111111"

    def test_a_region_is_described_once_per_session(self) -> None:
        """
        Four checks ask for one region's instances; only the first reaches AWS.

        This is 51 of the 68 describe_instances calls a 17-region account
        makes today.
        """
        session = self._session([{"Reservations": []}])

        for _ in range(4):
            get_instances(session, "us-east-1")

        session.client.return_value.get_paginator.assert_called_once_with("describe_instances")

    def test_each_region_is_described_separately(self) -> None:
        """Two regions are distinct memo entries, not one shared answer."""
        session = self._session([{"Reservations": []}])

        get_instances(session, "us-east-1")
        get_instances(session, "eu-west-1")

        assert session.client.call_count == 2

    def test_each_session_gets_its_own_instances(self) -> None:
        """
        Two sessions never share a memo entry.

        A memo keyed wrongly would report one account's instances as another
        account's, and the results would look entirely plausible.
        """
        session_a = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{"InstanceId": "i-11111111111111111", "State": {"Name": "running"}}],
            }]
        }])
        session_b = self._session([{
            "Reservations": [{
                "OwnerId": "222222222222",
                "Instances": [{"InstanceId": "i-22222222222222222", "State": {"Name": "running"}}],
            }]
        }])

        assert get_instances(session_a, "us-east-1")[0].instance_id == "i-11111111111111111"
        assert get_instances(session_b, "us-east-1")[0].instance_id == "i-22222222222222222"

    def test_memo_entry_is_released_when_the_session_is_dropped(self) -> None:
        """An account's instances die with its session."""
        session = self._session([{"Reservations": []}])

        get_instances(session, "us-east-1")
        assert len(_INSTANCE_MEMO) == 1

        del session
        gc.collect()

        assert len(_INSTANCE_MEMO) == 0

    def test_client_error_becomes_a_runtime_error_naming_the_region(self) -> None:
        """
        A failed describe_instances aborts the run with the region named.

        Headroom does not tolerate a partial scan: an account skipped for a
        transient error is indistinguishable in the results from an account
        with zero violations.
        """
        session = MagicMock()
        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeInstances",
        )
        mock_regional_ec2.get_paginator.return_value = mock_paginator
        session.client.return_value = mock_regional_ec2

        with pytest.raises(RuntimeError, match="us-east-1"):
            get_instances(session, "us-east-1")
```

Add to the test file's imports:

```python
import gc

from headroom.aws.ec2 import Ec2Instance, _INSTANCE_MEMO, get_instances
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_aws_ec2.py::TestGetInstances -v
```

Expected: `ImportError: cannot import name 'Ec2Instance'`.

- [ ] **Step 3: Implement the projection, the memo, and the collector**

In `headroom/aws/ec2.py`, extend the imports:

```python
from threading import Lock
from weakref import WeakKeyDictionary

from mypy_boto3_ec2.type_defs import ImageTypeDef, InstanceTypeDef

from .helpers import get_all_regions, paginate
```

Add after the existing dataclasses:

```python
@dataclass
class Ec2Instance:
    """
    The subset of a describe_instances entry that Headroom's EC2 checks read.

    Four checks previously swept every region independently for the same data.
    They now share one collection pass, and this is its output: the nine values
    those checks actually consume. Everything else in the API response --
    BlockDeviceMappings, NetworkInterfaces, SecurityGroups, Placement -- is
    dropped, because the memo holds this for an account's whole lifetime and
    the full entries are what would make that expensive.

    Attributes:
        instance_id: EC2 instance identifier
        region: AWS region the instance runs in
        image_id: AMI the instance was launched from, None if the API omits it
        owner_id: Account that owns the reservation
        public_ip_address: Public IP if one is assigned, None otherwise
        http_tokens: MetadataOptions HttpTokens; AWS defaults to 'optional'
        http_endpoint: MetadataOptions HttpEndpoint; AWS defaults to 'enabled'
        hop_limit: MetadataOptions HttpPutResponseHopLimit; AWS defaults to 1
        tags: Instance tags as a key to value mapping
    """
    instance_id: str
    region: str
    image_id: Optional[str]
    owner_id: str
    public_ip_address: Optional[str]
    http_tokens: str
    http_endpoint: str
    hop_limit: int
    tags: Dict[str, str]


_INSTANCE_MEMO: WeakKeyDictionary[Session, Dict[str, List[Ec2Instance]]] = WeakKeyDictionary()
_INSTANCE_MEMO_LOCK = Lock()


def _project_instance(
    instance: InstanceTypeDef,
    owner_id: str,
    region: str
) -> Ec2Instance:
    """
    Reduce one describe_instances entry to the values the checks read.

    Args:
        instance: Instance dictionary from describe_instances
        owner_id: Owner of the reservation the instance belongs to
        region: AWS region being collected

    Returns:
        The projected instance
    """
    metadata_options = instance.get('MetadataOptions', {})
    return Ec2Instance(
        instance_id=instance['InstanceId'],
        region=region,
        image_id=instance.get('ImageId'),
        owner_id=owner_id,
        public_ip_address=instance.get('PublicIpAddress'),
        http_tokens=metadata_options.get('HttpTokens', 'optional'),
        http_endpoint=metadata_options.get('HttpEndpoint', 'enabled'),
        hop_limit=metadata_options.get('HttpPutResponseHopLimit', 1),
        tags={tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
    )


def _describe_instances(session: Session, region: str) -> List[Ec2Instance]:
    """
    Read every non-terminated instance in one region and project it.

    The terminated filter lives here rather than in each check. All four EC2
    checks previously opened with the identical test, and collecting once is
    the opportunity to state it once.

    Args:
        session: boto3.Session for the target account
        region: AWS region to read

    Returns:
        Projected instances, terminated ones excluded

    Raises:
        RuntimeError: If describe_instances fails
    """
    regional_ec2: EC2Client = session.client('ec2', region_name=region)
    instances = []

    try:
        for page in paginate(regional_ec2, 'describe_instances'):
            for reservation in page['Reservations']:
                owner_id = reservation.get('OwnerId', '')
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'terminated':
                        continue
                    instances.append(_project_instance(instance, owner_id, region))
    except ClientError as e:
        raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

    return instances


def get_instances(session: Session, region: str) -> List[Ec2Instance]:
    """
    Return one region's non-terminated instances, reading AWS at most once.

    Four checks -- IMDSv1, AMI owner, public IP, and IMDS hop limit -- each
    need every instance in every region. Sweeping separately cost four
    identical describe_instances passes per region, 51 of the 68 calls a
    17-region account made.

    The memo is keyed on the session object itself, never on an account ID or
    name, which is what keeps one account's instances out of another account's
    results. Entries live in a WeakKeyDictionary and are released when the
    worker drops the session.

    The lock is released across the API call rather than held; see
    `get_all_regions` in helpers.py for why.

    Args:
        session: boto3.Session for the target account
        region: AWS region to read

    Returns:
        Projected instances for that region

    Raises:
        RuntimeError: If describe_instances fails
    """
    with _INSTANCE_MEMO_LOCK:
        by_region = _INSTANCE_MEMO.get(session)
        if by_region is None:
            by_region = {}
            _INSTANCE_MEMO[session] = by_region
        cached = by_region.get(region)

    if cached is not None:
        return cached

    instances = _describe_instances(session, region)

    with _INSTANCE_MEMO_LOCK:
        by_region[region] = instances

    return instances
```

- [ ] **Step 4: Run the new tests to verify they pass**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_aws_ec2.py::TestGetInstances -v
```

Expected: PASS.

- [ ] **Step 5: Rewrite the four analysis functions to consume the collector**

Each loses its paginator, its client construction, its terminated filter, and its
`try/except ClientError` — all of which now live in `_describe_instances`.

`get_ec2_imds_v1_analysis`:

```python
    results = []
    regions = get_all_regions(session)

    for region in regions:
        for instance in get_instances(session, region):
            # IMDSv1 is allowed when IMDS is enabled and tokens are optional;
            # it is blocked when HttpTokens is 'required' or IMDS is disabled.
            imdsv1_allowed = (
                instance.http_endpoint == 'enabled' and instance.http_tokens == 'optional'
            )
            exemption_tag_present = instance.tags.get('ExemptFromIMDSv2', '').lower() == 'true'

            results.append(DenyEc2ImdsV1(
                region=region,
                instance_id=instance.instance_id,
                imdsv1_allowed=imdsv1_allowed,
                exemption_tag_present=exemption_tag_present
            ))

    return results
```

`get_ec2_public_ip_analysis`:

```python
    results = []
    regions = get_all_regions(session)

    for region in regions:
        for instance in get_instances(session, region):
            instance_arn = (
                f"arn:aws:ec2:{region}:{instance.owner_id}:instance/{instance.instance_id}"
            )

            results.append(DenyEc2PublicIp(
                instance_id=instance.instance_id,
                region=region,
                public_ip_address=instance.public_ip_address,
                has_public_ip=instance.public_ip_address is not None,
                instance_arn=instance_arn
            ))

    return results
```

`get_ec2_imds_hop_limit_analysis`:

```python
    results = []
    regions = get_all_regions(session)

    for region in regions:
        for instance in get_instances(session, region):
            results.append(DenyEc2ImdsHopLimit(
                region=region,
                instance_id=instance.instance_id,
                hop_limit=instance.hop_limit,
                imds_enabled=instance.http_endpoint == 'enabled'
            ))

    return results
```

`get_ec2_ami_owner_analysis` keeps its own EC2 client, because `describe_images` needs one
and the collector returns no client:

```python
    results = []
    regions = get_all_regions(session)

    for region in regions:
        instances = get_instances(session, region)
        if not instances:
            continue

        regional_ec2: EC2Client = session.client('ec2', region_name=region)
        logger.debug(f"Analyzing EC2 AMI owners in {region}")
        ami_cache: Dict[str, _ResolvedAmi] = {}

        for instance in instances:
            if not instance.image_id:
                logger.warning(
                    f"Instance {instance.instance_id} in {region} has no AMI ID, skipping"
                )
                continue

            if instance.image_id not in ami_cache:
                ami_cache[instance.image_id] = _resolve_ami_owner(
                    regional_ec2, instance.image_id, region, instance.instance_id
                )

            resolved = ami_cache[instance.image_id]

            results.append(DenyEc2AmiOwner(
                instance_id=instance.instance_id,
                region=region,
                ami_id=instance.image_id,
                ami_owner=resolved.owner,
                ami_name=resolved.name,
                owner_unknown_reason=resolved.unknown_reason
            ))

    logger.info(
        f"Analyzed {len(results)} EC2 instances across {len(regions)} regions"
    )
    return results
```

The `if not instances: continue` guard is what keeps the AMI check from building a client
in an empty region, holding per-account EC2 clients at two per populated region rather
than two per enabled region.

- [ ] **Step 6: Run the four existing check test files unchanged**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest \
  tests/test_aws_ec2.py \
  tests/test_checks_deny_ec2_imds_v1.py \
  tests/test_checks_deny_ec2_ami_owner.py \
  tests/test_checks_deny_ec2_public_ip.py \
  tests/test_checks_deny_ec2_imds_hop_limit.py -v
```

This is the regression net. These files pin the four checks' behaviour and must pass
without modification, with one exception: fixtures that place `OwnerId` on the instance
dictionary must move it onto the reservation, because that is where the API puts it. If any
other assertion fails, the projection has changed behaviour and must be corrected — do not
edit the assertion.

- [ ] **Step 7: Run the full suite**

```bash
unset FORCE_COLOR && tox
```

Expected: all tests pass, 100% coverage, mypy clean. Coverage will flag the removed
`except ClientError` blocks in the three rewritten functions; confirm they are gone rather
than untested.

- [ ] **Step 8: Ask the repository owner for permission to commit, then commit**

```bash
git add headroom/aws/ec2.py tests/
git commit -m "Collect EC2 instances once per region instead of four times"
```

---

### Task 3: Guard against duplicate account names

With `exclude_account_ids` set, the result filename drops the account ID — the only
guaranteed-unique component — so two accounts named `prod` write the same path. Serially
that is a quiet last-writer-wins. Concurrently, two threads interleave `json.dump` output
into one file that then feeds policy generation.

**Files:**
- Modify: `headroom/analysis.py`
- Test: `tests/test_analysis.py`

**Interfaces:**
- Consumes: `AccountInfo`, `HeadroomConfig`.
- Produces: `_verify_no_duplicate_account_names(config: HeadroomConfig,
  account_infos: List[AccountInfo]) -> None`, called from `perform_analysis` after
  `get_relevant_subaccounts`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_analysis.py`:

```python
class TestDuplicateAccountNameGuard:
    """
    Test that duplicate account names abort before any result file is written.

    With exclude_account_ids set, the result filename is the account name
    alone, so two accounts sharing a name resolve to one path. Serially that
    is last-writer-wins; with a worker per account it interleaves two
    accounts' JSON into one file, which then feeds policy generation.
    """

    @staticmethod
    def _config(exclude_account_ids: bool) -> HeadroomConfig:
        """Build a config with the given redaction setting."""
        return HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Env", name="NameTag", owner="OwnerTag"
            ),
            exclude_account_ids=exclude_account_ids,
        )

    @staticmethod
    def _accounts(*names: str) -> List[AccountInfo]:
        """Build one AccountInfo per name, each with a distinct account ID."""
        return [
            AccountInfo(
                account_id=str(index + 1) * 12,
                environment="prod",
                name=name,
                owner="team",
            )
            for index, name in enumerate(names)
        ]

    def test_duplicate_names_abort_when_ids_are_excluded(self) -> None:
        """Two accounts sharing a name would write the same file, so abort."""
        with pytest.raises(RuntimeError, match="shared-name"):
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                self._accounts("shared-name", "unique", "shared-name"),
            )

    def test_the_abort_message_names_no_account_id(self) -> None:
        """
        The message names the duplicated name and the count, never the IDs.

        Printing the IDs would defeat exclude_account_ids, which is the
        setting that created the collision in the first place.
        """
        with pytest.raises(RuntimeError) as excinfo:
            _verify_no_duplicate_account_names(
                self._config(exclude_account_ids=True),
                self._accounts("shared-name", "shared-name"),
            )

        message = str(excinfo.value)
        assert "shared-name" in message
        assert "2" in message
        assert not re.search(r"\d{12}", message)

    def test_duplicate_names_are_allowed_when_ids_are_included(self) -> None:
        """
        With IDs in the filename, two accounts named alike do not collide.

        format_account_identifier appends the account ID, which is unique.
        """
        _verify_no_duplicate_account_names(
            self._config(exclude_account_ids=False),
            self._accounts("shared-name", "shared-name"),
        )

    def test_unique_names_pass(self) -> None:
        """Distinct names never collide, whatever the redaction setting."""
        _verify_no_duplicate_account_names(
            self._config(exclude_account_ids=True),
            self._accounts("one", "two", "three"),
        )
```

Add `import re` and `_verify_no_duplicate_account_names` to the file's imports.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_analysis.py::TestDuplicateAccountNameGuard -v
```

Expected: `ImportError: cannot import name '_verify_no_duplicate_account_names'`.

- [ ] **Step 3: Implement the guard**

Add to `headroom/analysis.py`, immediately before `perform_analysis`:

```python
def _verify_no_duplicate_account_names(
    config: HeadroomConfig,
    account_infos: List[AccountInfo]
) -> None:
    """
    Abort if two accounts would write to the same result file.

    With `exclude_account_ids` set, the result filename is the account name
    alone: `ResultFilePathResolver._build_filename` drops the account ID, which
    is the only guaranteed-unique component. Two accounts sharing a name then
    resolve to one path.

    Run serially that is a quiet last-writer-wins. Run with a worker per
    account it is two threads interleaving `json.dump` output into one file,
    producing either corrupt JSON or a valid file holding two accounts' results
    spliced together -- which then feeds policy generation.

    The message names the duplicated name and how many accounts carry it, never
    the account IDs. Printing those would defeat the setting that created the
    collision.

    Args:
        config: Headroom configuration
        account_infos: Accounts about to be analyzed

    Raises:
        RuntimeError: If `exclude_account_ids` is set and two accounts share a
            name
    """
    if not config.exclude_account_ids:
        return

    counts: Dict[str, int] = {}
    for account_info in account_infos:
        counts[account_info.name] = counts.get(account_info.name, 0) + 1

    collisions = sorted(name for name, count in counts.items() if count > 1)

    if not collisions:
        return

    breakdown = ", ".join(f"{name} ({counts[name]} accounts)" for name in collisions)
    raise RuntimeError(
        f"exclude_account_ids is set, so result files are named by account name "
        f"alone, but these names are not unique: {breakdown}. Every such account "
        "would write to the same file, and because accounts are analyzed "
        "concurrently the file would hold interleaved output from all of them. "
        "Rename the accounts, or unset exclude_account_ids so the account ID "
        "makes each filename unique."
    )
```

Call it from `perform_analysis`, immediately after `get_relevant_subaccounts`:

```python
    relevant_account_infos = get_relevant_subaccounts(account_infos)
    logger.info(f"Filtered to {len(relevant_account_infos)} relevant accounts for analysis")

    _verify_no_duplicate_account_names(config, relevant_account_infos)
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_analysis.py -v
```

Expected: PASS.

- [ ] **Step 5: Run the full suite**

```bash
unset FORCE_COLOR && tox
```

- [ ] **Step 6: Ask the repository owner for permission to commit, then commit**

```bash
git add headroom/analysis.py tests/test_analysis.py
git commit -m "Abort when redacted account names would collide"
```

---

### Task 4: Give log records their account

42 log calls in `headroom/aws/` name only a region or a resource. Eight of them fire per
region per account — roughly 40,000 lines at 300 accounts — and once accounts run
concurrently there is no way to tell which account a line belongs to.

**Files:**
- Create: `headroom/log_context.py`
- Modify: `headroom/main.py`, and the eight per-region `logger.info` calls in
  `headroom/aws/`
- Test: `tests/test_log_context.py` (new)

**Interfaces:**
- Produces:
  - `set_account(account_identifier: str) -> None`
  - `configure_logging() -> None`
  - `AccountContextFilter` (a `logging.Filter` subclass)

**Why a handler filter rather than a logger filter.** A filter attached to a logger only
sees records logged directly to it, not records propagated from child loggers — the classic
gotcha. Attached to the handler, it sees every record the handler formats, so
`%(account)s` is always populated.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_log_context.py`:

```python
"""
Tests for headroom.log_context module.
"""

import logging
import threading

from typing import List

from headroom.log_context import NO_ACCOUNT, AccountContextFilter, set_account


class TestAccountContextFilter:
    """Test that log records carry the account of the emitting thread."""

    @staticmethod
    def _record() -> logging.LogRecord:
        """Build a bare log record with no account attribute."""
        return logging.LogRecord(
            name="headroom.aws.sqs",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Analyzing SQS queues in eu-west-1",
            args=(),
            exc_info=None,
        )

    def test_record_carries_the_account_this_thread_set(self) -> None:
        """The filter stamps the record with this thread's account."""
        set_account("payments_111111111111")
        record = self._record()

        assert AccountContextFilter().filter(record) is True
        assert record.account == "payments_111111111111"

    def test_record_outside_a_worker_gets_a_placeholder(self) -> None:
        """
        Records emitted before any account is set still format.

        The formatter interpolates %(account)s unconditionally, so the
        attribute has to exist even for startup, configuration, and teardown
        records. The check runs on its own thread because thread-local context
        set by an earlier test would otherwise leak into it.
        """
        captured: List[str] = []

        def emit_without_context() -> None:
            record = self._record()
            AccountContextFilter().filter(record)
            captured.append(record.account)

        thread = threading.Thread(target=emit_without_context)
        thread.start()
        thread.join(timeout=5)

        assert captured == [NO_ACCOUNT]

    def test_each_thread_sees_only_its_own_account(self) -> None:
        """
        Context is thread-local, so concurrent workers do not overwrite
        each other's account.
        """
        seen: dict[str, str] = {}
        ready = threading.Barrier(2, timeout=5)

        def worker(identifier: str) -> None:
            set_account(identifier)
            ready.wait()
            record = self._record()
            AccountContextFilter().filter(record)
            seen[identifier] = record.account

        threads = [
            threading.Thread(target=worker, args=("a_111111111111",)),
            threading.Thread(target=worker, args=("b_222222222222",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        assert seen == {
            "a_111111111111": "a_111111111111",
            "b_222222222222": "b_222222222222",
        }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_log_context.py -v
```

Expected: `ModuleNotFoundError: No module named 'headroom.log_context'`.

- [ ] **Step 3: Create the module**

```python
"""
Thread-local account context for log records.

Headroom analyzes accounts concurrently, so records from different accounts
interleave in the output. Most of the log calls in `headroom/aws/` name only a
region or a resource, which is ambiguous the moment more than one account is in
flight. Rather than edit all of them, a filter stamps every record with the
account its thread is working on.
"""

import logging
import threading

__all__ = ["AccountContextFilter", "configure_logging", "set_account"]

# Shown for records emitted outside a worker: startup, configuration, teardown.
NO_ACCOUNT = "-"

LOG_FORMAT = "%(levelname)s:%(name)s:[%(account)s] %(message)s"

_CONTEXT = threading.local()


def set_account(account_identifier: str) -> None:
    """
    Record which account the calling thread is analyzing.

    Args:
        account_identifier: Formatted account identifier for log records
    """
    _CONTEXT.account = account_identifier


class AccountContextFilter(logging.Filter):
    """
    Stamp every log record with the account its thread is analyzing.

    Installed on the handler rather than on a logger. A logger's filters see
    only records logged directly to that logger, not records propagated up from
    child loggers, so a logger-level filter would leave most records without the
    attribute the formatter interpolates.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Add the calling thread's account to the record.

        Args:
            record: Record about to be formatted

        Returns:
            True, always: this filter annotates records, it never drops them
        """
        record.account = getattr(_CONTEXT, "account", NO_ACCOUNT)
        return True


def configure_logging() -> None:
    """
    Install the account filter and format on the root handler.

    Called once from `main`. `logging.basicConfig` has already run at import
    time in `analysis.py`, so the root handler exists by now.
    """
    for handler in logging.getLogger().handlers:
        handler.addFilter(AccountContextFilter())
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_log_context.py -v
```

- [ ] **Step 5: Call it from main and demote the eight per-region lines**

In `headroom/main.py`, add `from .log_context import configure_logging` to the imports and
make it the first statement of `main()`:

```python
def main() -> None:
    """Main entry point for Headroom security analysis."""
    configure_logging()
    cli_args = parse_cli_args()
```

Change `logger.info` to `logger.debug` at these eight sites, leaving the messages as they
are:

| File | Message |
| --- | --- |
| `headroom/aws/rds.py` | `Analyzing RDS resources in {region}` |
| `headroom/aws/sqs.py` | `Analyzing SQS queues in {region}` |
| `headroom/aws/eks.py` | `Analyzing EKS clusters in {region}` |
| `headroom/aws/ec2.py` | `Analyzing EC2 AMI owners in {region}` (already demoted in Task 2) |
| `headroom/aws/secretsmanager.py` | `Analyzing Secrets Manager in {region}` |
| `headroom/aws/ecr.py` | `Analyzing ECR repositories in {region}` |
| `headroom/aws/kms.py` | `Analyzing KMS keys in {region}` |
| `headroom/aws/lambda_functions.py` | `Analyzing Lambda functions in {region}` |

Confirm the exact set with:

```bash
grep -rn 'logger.info(f"Analyzing' headroom/aws/
```

If a listed message differs, follow the grep, not this table. Any test asserting on these
calls must switch from `mock_logger.info` to `mock_logger.debug`.

- [ ] **Step 6: Run the full suite**

```bash
unset FORCE_COLOR && tox
```

- [ ] **Step 7: Ask the repository owner for permission to commit, then commit**

```bash
git add headroom/log_context.py headroom/main.py headroom/aws/ tests/
git commit -m "Stamp log records with the account their thread is analyzing"
```

---

### Task 5: Harden sessions for concurrent use

Every worker calls `assume_role` with the same shared security session, so all of them
construct an STS client from one `Session` object simultaneously. This task adds the lock
that makes that safe, sizes the STS connection pool for the worker count, and turns on a
retry mode with throttling headroom.

**Files:**
- Modify: `headroom/aws/sessions.py`, `headroom/config.py`
- Test: `tests/test_aws_sessions.py`

**Interfaces:**
- Produces: `DEFAULT_ACCOUNT_WORKERS = 16` and `MAX_ACCOUNT_WORKERS = 32` in
  `headroom/config.py`, alongside the existing `DEFAULT_*_DIR` constants. Task 6 consumes
  both.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_aws_sessions.py`:

```python
class TestConcurrentClientConstruction:
    """Test that workers do not build STS clients from one session at once."""

    def test_client_construction_is_serialized(self) -> None:
        """
        Only one thread constructs a client from the shared session at a time.

        Every worker assumes a role using the one security-analysis session.
        Session.client() resolves the service model through the session's
        loader and mutates its component registry on first use, so concurrent
        first calls race. The lock covers construction only; the assume_role
        round trip stays outside it so workers still overlap.

        This probe can only ever false-pass, never false-fail.
        """
        live = 0
        peak = 0
        guard = threading.Lock()

        def construct(*args: object, **kwargs: object) -> MagicMock:
            nonlocal live, peak
            with guard:
                live += 1
                peak = max(peak, live)
            time.sleep(0.005)
            with guard:
                live -= 1
            client = MagicMock()
            client.assume_role.return_value = {
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            }
            return client

        base_session = MagicMock()
        base_session.region_name = "us-east-1"
        base_session.client.side_effect = construct

        threads = [
            threading.Thread(
                target=assume_role,
                args=("arn:aws:iam::111111111111:role/Headroom", "s", base_session),
            )
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert peak == 1


class TestSessionRetryConfiguration:
    """Test the retry behaviour every client inherits from the session."""

    def test_session_sets_standard_retry_mode(self) -> None:
        """
        Retries are configured on the session, so every client inherits them
        without a per-call-site Config.
        """
        with patch("headroom.aws.sessions.botocore.session.get_session") as mock_get:
            botocore_session = MagicMock()
            mock_get.return_value = botocore_session

            new_session()

        botocore_session.set_config_variable.assert_any_call("retry_mode", "standard")
        botocore_session.set_config_variable.assert_any_call(
            "max_attempts", RETRY_MAX_ATTEMPTS
        )

    def test_the_sts_client_pool_is_sized_to_the_worker_cap(self) -> None:
        """
        The STS client is built with the pool ceiling, not left at botocore's 10.

        The ceiling binds nothing today: assume_role builds a fresh client on
        every call and boto3 caches none, so each client gets its own
        PoolManager and serves exactly one AssumeRole request. This pins the
        wiring, not a live constraint, so the sizing survives until the client
        is built once per run and shared -- at which point it starts to matter.
        """
        base_session = MagicMock()
        base_session.region_name = "us-east-1"
        base_session.client.return_value.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }

        assume_role("arn:aws:iam::111111111111:role/Headroom", "s", base_session)

        config = base_session.client.call_args.kwargs["config"]
        assert config.max_pool_connections == MAX_ACCOUNT_WORKERS
```

Add to the imports: `import threading`, `import time`, and
`from headroom.aws.sessions import RETRY_MAX_ATTEMPTS, assume_role, new_session`, and
`from headroom.config import MAX_ACCOUNT_WORKERS`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_aws_sessions.py -v
```

Expected: `ImportError: cannot import name 'RETRY_MAX_ATTEMPTS'`, and once that exists,
`test_client_construction_is_serialized` failing with `assert 8 == 1`.

- [ ] **Step 3: Add the constants to config.py**

In `headroom/config.py`, below the existing directory defaults:

```python
# Accounts analyzed concurrently. Memory sets this, not the GIL: each worker
# holds its own botocore session carrying its own parsed service models, which
# measures at roughly 43 MB. Sixteen workers stay under a gigabyte.
DEFAULT_ACCOUNT_WORKERS = 16

# Upper bound on max_account_workers. At 32 workers resident memory passes
# 1.5 GB; wanting more is a signal to revisit the design rather than raise this.
# The shared session's STS connection pool is sized to this value, so the pool
# can serve every worker whatever the operator configures.
MAX_ACCOUNT_WORKERS = 32
```

- [ ] **Step 4: Implement the lock, the retry mode, and the pool size**

In `headroom/aws/sessions.py`, extend the imports:

```python
from threading import Lock

from botocore.config import Config

from ..config import MAX_ACCOUNT_WORKERS
```

Add below the imports:

```python
# Retry attempts every client inherits from the session. botocore's `standard`
# mode defaults to three; five gives throttling headroom now that many accounts
# are analyzed at once. `adaptive` is deliberately not used: it adds client-side
# rate limiting that throttles unpredictably, and workers are spread across
# separate accounts, which are separate rate-limit buckets.
RETRY_MAX_ATTEMPTS = 5

# Guards client construction on the shared security-analysis session. Every
# worker assumes a role through that one Session, and Session.client() resolves
# the service model through the session's loader and mutates its component
# registry on first use. Per-account sessions are not shared -- new_session()
# builds a fresh botocore session each time -- so this is the only site at risk.
_CLIENT_CONSTRUCTION_LOCK = Lock()

# Ceiling on the STS client's connection pool, imported rather than redeclared.
# It binds nothing today: assume_role builds a fresh client on every call and
# boto3 caches none, so each client gets its own PoolManager and serves exactly
# one AssumeRole request -- well inside botocore's default of 10. There is no
# shared STS pool to exhaust. Kept because it costs nothing and becomes
# load-bearing the day that client is built once per run and shared, which is
# also the change that would save one TLS handshake per account.
_STS_CLIENT_CONFIG = Config(max_pool_connections=MAX_ACCOUNT_WORKERS)
```

In `new_session`, after the existing `sts_regional_endpoints` line:

```python
    botocore_session.set_config_variable("retry_mode", "standard")
    botocore_session.set_config_variable("max_attempts", RETRY_MAX_ATTEMPTS)
```

In `assume_role`, replace the client construction:

```python
    with _CLIENT_CONSTRUCTION_LOCK:
        sts: STSClient = base_session.client(
            "sts",
            region_name=region,
            config=_STS_CLIENT_CONFIG,
        )

    resp: AssumeRoleResponseTypeDef = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )
```

The `assume_role` round trip stays outside the lock so workers still overlap; the lock
serializes about a millisecond of object construction.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_aws_sessions.py -v
```

- [ ] **Step 6: Run the full suite**

```bash
unset FORCE_COLOR && tox
```

- [ ] **Step 7: Ask the repository owner for permission to commit, then commit**

```bash
git add headroom/aws/sessions.py headroom/config.py tests/test_aws_sessions.py
git commit -m "Make session and client construction safe for concurrent workers"
```

---

### Task 6: Run accounts through a worker pool

The payoff. Depends on Tasks 3, 4, and 5.

**Files:**
- Modify: `headroom/analysis.py`, `headroom/config.py`, `headroom/usage.py`,
  `documentation/SETUP.md`, `sample_config.yaml`, `README.md`,
  `documentation/ARCHITECTURE.md`, `Headroom-Specification.md`
- Test: `tests/test_analysis.py`, `tests/test_config.py`

**Interfaces:**
- Consumes: `DEFAULT_ACCOUNT_WORKERS`, `MAX_ACCOUNT_WORKERS` (Task 5); `set_account`
  (Task 4).
- Produces: `HeadroomConfig.max_account_workers: int`; `abort: Event` threaded through
  `_run_checks_for_account(account_info, security_session, config, org_account_ids, abort)`
  and `run_checks_for_type(check_type, headroom_session, account_info, config,
  org_account_ids, abort)`.

- [ ] **Step 1: Write the failing config tests**

Add to `tests/test_config.py`, in `class TestHeadroomConfig`:

```python
    def test_max_account_workers_defaults_to_sixteen(self) -> None:
        """The default lives in config.py and nowhere else."""
        config = HeadroomConfig(
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Env", name="NameTag", owner="OwnerTag"
            ),
        )

        assert config.max_account_workers == DEFAULT_ACCOUNT_WORKERS == 16

    def test_max_account_workers_rejects_zero(self) -> None:
        """Zero workers would analyze nothing while appearing to succeed."""
        with pytest.raises(ValidationError):
            HeadroomConfig(
                use_account_name_from_tags=False,
                account_tag_layout=AccountTagLayout(
                    environment="Env", name="NameTag", owner="OwnerTag"
                ),
                max_account_workers=0,
            )

    def test_max_account_workers_rejects_above_the_cap(self) -> None:
        """
        Past the cap resident memory exceeds 1.5 GB, and the STS connection
        pool is sized to the cap, so a larger value would churn connections.
        """
        with pytest.raises(ValidationError):
            HeadroomConfig(
                use_account_name_from_tags=False,
                account_tag_layout=AccountTagLayout(
                    environment="Env", name="NameTag", owner="OwnerTag"
                ),
                max_account_workers=MAX_ACCOUNT_WORKERS + 1,
            )
```

- [ ] **Step 2: Write the failing pool tests**

Add to `tests/test_analysis.py`:

```python
class TestRunChecksPool:
    """Test the worker pool and its cooperative abort."""

    @staticmethod
    def _accounts(count: int) -> List[AccountInfo]:
        """Build `count` accounts with distinct names and IDs."""
        return [
            AccountInfo(
                account_id=str(index + 1) * 12,
                environment="prod",
                name=f"account-{index}",
                owner="team",
            )
            for index in range(count)
        ]

    @staticmethod
    def _config(max_account_workers: int) -> HeadroomConfig:
        """Build a config with the given pool size."""
        return HeadroomConfig(
            management_account_id="222222222222",
            security_analysis_account_id="111111111111",
            use_account_name_from_tags=False,
            account_tag_layout=AccountTagLayout(
                environment="Env", name="NameTag", owner="OwnerTag"
            ),
            max_account_workers=max_account_workers,
        )

    def test_every_pending_account_is_analyzed(self) -> None:
        """All accounts without results reach the worker."""
        seen: List[str] = []
        lock = threading.Lock()

        def record(account_info: AccountInfo, *args: object) -> None:
            with lock:
                seen.append(account_info.account_id)

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=record),
        ):
            run_checks(MagicMock(), self._accounts(5), self._config(4), set())

        assert sorted(seen) == sorted(a.account_id for a in self._accounts(5))

    def test_completed_accounts_never_reach_the_pool(self) -> None:
        """
        Accounts with all results present are filtered serially, up front.

        The filter is local filesystem I/O, so doing it before the pool starts
        keeps the "N accounts to scan" log line accurate.
        """
        worker = MagicMock()

        with (
            patch("headroom.analysis._all_checks_complete", return_value=True),
            patch("headroom.analysis._run_checks_for_account", worker),
        ):
            run_checks(MagicMock(), self._accounts(3), self._config(4), set())

        worker.assert_not_called()

    def test_accounts_are_analyzed_concurrently(self) -> None:
        """
        With four workers, four accounts are in flight at once.

        The barrier is the assertion: if fewer than four run simultaneously it
        times out and the test fails, which is how this pins parallelism
        rather than assuming it.
        """
        barrier = threading.Barrier(4, timeout=5)

        def wait_for_the_others(account_info: AccountInfo, *args: object) -> None:
            barrier.wait()

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=wait_for_the_others),
        ):
            run_checks(MagicMock(), self._accounts(4), self._config(4), set())

    def test_a_worker_failure_propagates_unchanged(self) -> None:
        """
        The first failure aborts the run rather than being logged and skipped.

        A partial run is more dangerous than no run: this output drives policy
        deployment, and an account skipped for a transient error looks exactly
        like an account with zero violations.
        """
        failure = RuntimeError("role assumption failed")

        with (
            patch("headroom.analysis._all_checks_complete", return_value=False),
            patch("headroom.analysis._run_checks_for_account", side_effect=failure),
            pytest.raises(RuntimeError, match="role assumption failed"),
        ):
            run_checks(MagicMock(), self._accounts(3), self._config(1), set())

    def test_a_worker_returns_immediately_when_abort_is_set(self) -> None:
        """
        An in-flight worker bails at its next checkpoint.

        Python cannot kill a running thread, so cancelling queued futures is
        not enough: without this check, shutdown would block until every
        in-flight account finished all its remaining checks.
        """
        abort = threading.Event()
        abort.set()

        with patch("headroom.analysis.get_headroom_session") as mock_session:
            _run_checks_for_account(
                self._accounts(1)[0], MagicMock(), self._config(1), set(), abort
            )

        mock_session.assert_not_called()

    def test_no_further_checks_run_once_abort_is_set(self) -> None:
        """`run_checks_for_type` stops before starting the next check."""
        abort = threading.Event()
        abort.set()

        with patch("headroom.analysis.get_all_check_classes") as mock_classes:
            mock_classes.return_value = [MagicMock()]
            run_checks_for_type(
                "scps", MagicMock(), self._accounts(1)[0], self._config(1), set(), abort
            )

        mock_classes.return_value[0].assert_not_called()
```

Add `import threading` and `run_checks_for_type`, `_run_checks_for_account` to the imports.

- [ ] **Step 3: Run the tests to verify they fail**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_config.py tests/test_analysis.py -v
```

Expected: `ValidationError` for the unknown `max_account_workers` field, and `TypeError`
for the extra `abort` argument.

- [ ] **Step 4: Add the config field and the CLI flag**

In `headroom/config.py`, add to `HeadroomConfig` and extend the import to
`from pydantic import BaseModel, Field`:

```python
    # Accounts analyzed concurrently. 1 runs them serially, on the same code
    # path, which is the escape hatch for debugging. See SETUP.md for the
    # memory cost per worker.
    max_account_workers: int = Field(
        default=DEFAULT_ACCOUNT_WORKERS,
        ge=1,
        le=MAX_ACCOUNT_WORKERS,
    )
```

In `headroom/usage.py`, add to `parse_cli_args` after the paths group:

```python
    parser.add_argument(
        '--max-account-workers',
        dest='max_account_workers',
        type=int,
        help='Accounts to analyze concurrently (1 runs them serially)'
    )
```

No default: `merge_configs` drops `None` values, so the default stays in `config.py` alone.

- [ ] **Step 5: Thread the abort event through the workers**

In `headroom/analysis.py`, extend the imports:

```python
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed

from .log_context import set_account
```

Add the `abort` parameter to `run_checks_for_type`, with the checkpoint at the top of the
loop:

```python
    check_classes = get_all_check_classes(check_type)

    for check_class in check_classes:
        if abort.is_set():
            return

        if results_exist(
```

Add the parameter and checkpoint to `_run_checks_for_account`, and set the log context
first so every record this worker emits carries the account:

```python
    account_identifier = _get_account_identifier(account_info)
    set_account(account_identifier)

    if abort.is_set():
        return

    logger.info(f"Running checks for account: {account_identifier}")

    headroom_session = get_headroom_session(config, security_session, account_info.account_id)

    scp_exist = all_check_results_exist("scps", account_info, config)
    if not scp_exist:
        run_checks_for_type("scps", headroom_session, account_info, config, org_account_ids, abort)

    rcp_exist = all_check_results_exist("rcps", account_info, config)
    if not rcp_exist:
        run_checks_for_type("rcps", headroom_session, account_info, config, org_account_ids, abort)

    logger.info(f"Checks completed for account: {account_identifier}")
```

- [ ] **Step 6: Replace the serial loop with the pool**

```python
    pending = []
    for account_info in relevant_account_infos:
        if _all_checks_complete(account_info, config):
            account_identifier = _get_account_identifier(account_info)
            logger.info(f"All results already exist for account {account_identifier}, skipping checks")
            continue
        pending.append(account_info)

    logger.info(
        f"Analyzing {len(pending)} account(s) with {config.max_account_workers} worker(s)"
    )

    abort = threading.Event()

    with ThreadPoolExecutor(max_workers=config.max_account_workers) as executor:
        futures: List[Future[None]] = [
            executor.submit(
                _run_checks_for_account,
                account_info,
                security_session,
                config,
                org_account_ids,
                abort,
            )
            for account_info in pending
        ]

        for future in as_completed(futures):
            error = future.exception()
            if error is None:
                continue

            abort.set()
            for outstanding in futures:
                outstanding.cancel()
            raise error
```

Replace the "Error handling is deliberately absent" paragraph in the `run_checks` docstring
with:

```
    Error handling is deliberately absent: the first failure aborts the entire
    run rather than being logged and skipped. A partial run is more dangerous
    than no run, because this output drives SCP and RCP deployment and an
    account skipped for a transient error is indistinguishable in the results
    from an account with zero violations, so swallowing the error could
    green-light a policy that breaks it. Accounts that cannot or should not be
    analyzed are excluded earlier, in `get_subaccount_information`: by lifecycle
    state, or by being named in `config.skip_account_ids`.

    Aborting takes two mechanisms because Python cannot kill a running thread.
    `Future.cancel` clears the queue but does nothing to accounts already in
    flight; the `abort` Event stops those at their next check boundary. Without
    it, leaving this `with` block would block until every in-flight account had
    run all its remaining checks.

    Leaving the block joins the in-flight workers before the exception reaches
    `main`, so no thread is still writing result files when the run gives up. A
    check already inside `execute()` finishes and writes its file, which is
    harmless: the file is complete and valid, and `results_exist` makes the run
    resumable at per-account, per-check granularity.

    "First" means first to complete with an exception, since `as_completed`
    yields in completion order. Workers that fail after the abort have their
    exceptions discarded unretrieved.
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/test_config.py tests/test_analysis.py -v
```

- [ ] **Step 8: Update the documentation**

`documentation/SETUP.md` — add to the configuration reference:

```markdown
- `max_account_workers`: how many accounts to analyze at once. Defaults to 16, and must be
  between 1 and 32.

### Tuning `max_account_workers`

Each worker holds its own boto3 session carrying its own parsed AWS service models, which
measures at roughly 43 MB. That is what bounds this setting, not CPU: analysis is
overwhelmingly network-bound, so the interpreter is idle most of the run.

| Workers | Resident memory | 300 accounts |
| --- | --- | --- |
| 1 | baseline | ~3.8 hours |
| 8 | ~0.4 GB | ~29 minutes |
| 16 (default) | ~0.8 GB | ~14 minutes |
| 32 (maximum) | ~1.5 GB | ~7 minutes |

Set it to `1` to analyze accounts one at a time. That runs the same code path as any other
value rather than a separate serial branch, so it is a safe way to get readable logs and a
simple stack trace while debugging.

A failure in any account aborts the whole run. Queued accounts never start, and accounts
already in flight stop after their current check. Nothing is lost: each check writes its own
result file as it completes, and a re-run skips the results already on disk.
```

`sample_config.yaml`:

```yaml
# Accounts to analyze at once. Default 16, maximum 32. Set to 1 for serial.
# Each worker costs roughly 43 MB. See documentation/SETUP.md.
# max_account_workers: 16
```

`README.md` — in the feature or performance section:

```markdown
Accounts are analyzed concurrently, 16 at a time by default. Combined with caching the
region list and the EC2 instance list per account, a 300-account organization goes from
roughly 4.9 hours to roughly 14 minutes.
```

`documentation/ARCHITECTURE.md` — add a section:

```markdown
## Concurrency model

One worker per account, from a single `ThreadPoolExecutor` sized by
`max_account_workers`. There is no region-level, check-level, or resource-level threading:
at 50-300 accounts the account pool already saturates the available network capacity, so a
second axis would multiply in-flight requests and throttling risk without going faster.

Within an account everything stays serial, which means each account's boto3 session is
touched by exactly one thread. Two caches rely on that: the region list and the projected
EC2 instance list are memoized in `WeakKeyDictionary` instances keyed on the session
object, so entries are released when a worker finishes and nothing accumulates across a
long run. Keying on the session rather than on an account ID is what keeps one account's
data out of another's results.

The one genuinely shared object is the security-analysis session, which every worker uses
to assume its target role. Client construction on that session is serialized by a lock in
`aws/sessions.py`; the `AssumeRole` round trip is not, so workers still overlap.

Failure aborts the run. The first worker exception cancels the queue, sets an abort
`Event` that in-flight workers check at each check boundary, joins them, and re-raises.
Because Python cannot kill a running thread, the Event is what makes the abort prompt.
```

`Headroom-Specification.md` — find the section describing the analysis loop as a serial
sweep over accounts and update it to describe the pool, citing `max_account_workers`.

- [ ] **Step 9: Run the full suite**

```bash
unset FORCE_COLOR && tox
```

- [ ] **Step 10: Ask the repository owner for permission to commit, then commit**

```bash
git add headroom/ tests/ documentation/ README.md sample_config.yaml Headroom-Specification.md
git commit -m "Analyze accounts concurrently with a cooperative abort"
```

---

### Task 7: Pin the saved calls as a contract

A test asserting "16 workers beat 1 worker" is a flake generator. The durable form asserts
call counts, which never flake and fail loudly the day someone reintroduces a redundant
sweep.

**Files:**
- Create: `tests/performance/__init__.py`, `tests/performance/test_call_counts.py`

- [ ] **Step 1: Write the tests**

`tests/performance/test_call_counts.py`:

```python
"""
Call-count contracts for the per-account memos.

These pin the savings from caching the region list and the EC2 instance list.
They assert counts rather than wall clock, so they cannot flake, and they fail
the day a new check reintroduces a redundant sweep.
"""

from typing import Any, Dict, List
from unittest.mock import MagicMock

from headroom.aws.ec2 import (
    get_ec2_ami_owner_analysis,
    get_ec2_imds_hop_limit_analysis,
    get_ec2_imds_v1_analysis,
    get_ec2_public_ip_analysis,
)
from headroom.aws.helpers import get_all_regions

REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-2"]


def _session(pages: List[Dict[str, Any]]) -> MagicMock:
    """Build a mock session serving `pages` from every region."""
    client = MagicMock()
    client.describe_regions.return_value = {
        "Regions": [{"RegionName": region} for region in REGIONS]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    client.get_paginator.return_value = paginator
    session = MagicMock()
    session.client.return_value = client
    return session


class TestCallCounts:
    """Pin the per-account AWS call counts the memos are there to reduce."""

    def test_region_list_costs_one_call_however_many_checks_ask(self) -> None:
        """
        Eleven checks ask for the region list; one describe_regions results.

        Before the memo this was eleven calls per account.
        """
        session = _session([{"Reservations": []}])

        for _ in range(11):
            get_all_regions(session)

        assert session.client.return_value.describe_regions.call_count == 1

    def test_four_ec2_checks_describe_each_region_once(self) -> None:
        """
        Four checks over three regions issue three describe_instances calls.

        Before the memo this was twelve: each check swept every region
        independently with an identical call.
        """
        session = _session([{"Reservations": []}])

        get_ec2_imds_v1_analysis(session)
        get_ec2_public_ip_analysis(session)
        get_ec2_imds_hop_limit_analysis(session)
        get_ec2_ami_owner_analysis(session)

        paginator = session.client.return_value.get_paginator
        describe_instances_calls = [
            call for call in paginator.call_args_list
            if call.args and call.args[0] == "describe_instances"
        ]
        assert len(describe_instances_calls) == len(REGIONS)
```

`tests/performance/__init__.py` is empty.

- [ ] **Step 2: Run them**

```bash
unset FORCE_COLOR && .tox/py313/bin/python -m pytest tests/performance/ -v
```

Expected: PASS, because Tasks 1 and 2 already implemented the memos. If either fails, a
memo regressed.

- [ ] **Step 3: Confirm tox collects the new directory**

```bash
unset FORCE_COLOR && tox
```

If `tests/performance/` is not collected, add it to the `testpaths` or `--cov` settings in
`pytest.ini` and `tox.ini`, and confirm the coverage gate still covers `tests/`.

- [ ] **Step 4: Ask the repository owner for permission to commit, then commit**

```bash
git add tests/performance/ pytest.ini tox.ini
git commit -m "Pin the memo call counts as a contract"
```

---

## Self-Review

**Spec coverage.** Every section of the spec maps to a task: §1 pool and cancellation →
Task 6; §2.1 shared session → Task 5; §2.2 duplicate names → Task 3; §2.3 log output →
Task 4; §3 memo layer → Tasks 1 and 2; §4 config and botocore → Tasks 5 and 6; §5.1-5.3
and 5.7 → Tasks 5 and 6; §5.4 cross-session isolation → Tasks 1 and 2; §5.5 EC2 regression
net → Task 2 Step 6; §5.6 performance tests → Task 7; documentation checklist → Task 6
Step 8.

**Gap found and closed.** The spec assumed the instance memo removed all 51 redundant EC2
client builds. It removes 34: `get_ec2_ami_owner_analysis` needs its own client for
`describe_images`. The spec was corrected in commit `3f163bf`; Task 2 Step 5 reflects it,
and adds an `if not instances: continue` guard so that client is never built in an empty
region.

**Open question raised in Task 2.** `OwnerId` is read from the instance dictionary today,
but the EC2 API puts it on the reservation, so the value is always empty against real AWS
and the resulting `instance_arn` is malformed. The plan fixes it. This must be confirmed
before Task 2 starts.

**Type consistency.** `abort: threading.Event` is the last positional parameter of both
`_run_checks_for_account` and `run_checks_for_type` throughout. `Ec2Instance` field names
are identical in the dataclass, `_project_instance`, the four rewritten analysis functions,
and the tests. `DEFAULT_ACCOUNT_WORKERS` and `MAX_ACCOUNT_WORKERS` are defined once in
Task 5 and consumed in Task 6.
