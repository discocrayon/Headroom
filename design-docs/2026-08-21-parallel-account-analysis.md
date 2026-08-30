# Parallel Account Analysis

**Date:** 2026-08-21
**Status:** Implemented -- historical record, not current behavior
**Scope:** `headroom/analysis.py`, `headroom/aws/sessions.py`, `headroom/aws/helpers.py`,
`headroom/aws/ec2.py`, the four EC2 checks, `headroom/config.py`, `headroom/usage.py`

> **Read this as history.** Code and tests define current behavior; this
> records what was decided on 2026-08-21 and why. Two things here have since
> been overtaken. A seventh RCP check, `deny_service_confused_deputy`, arrived
> after this was written and re-reads what four of the region-sweeping
> analyzers already read, taking the 187-probe baseline below to 255. A third
> session memo, `memoize_per_session` in `headroom/aws/helpers.py`, removes
> those 68 probes again -- so "the two memos" below is now three.

## Problem

A full run is serial at every level:

```
accounts -> checks (15) -> regions (~17) -> pages -> per-resource calls
```

Two properties of that loop dominate wall clock at the target scale of 50-300 accounts.

### An empty account still costs roughly a minute

Per account, before touching a single resource:

| Cost | Count | Cause |
| --- | --- | --- |
| `describe_regions` | 11 | Each region-looping check calls `get_all_regions` independently; `aws/ec2.py` alone calls it four times |
| Region probe calls | 187 | 11 region-looping checks x 17 enabled regions x at least one list call |
| Global check calls | 4 | s3, iam roles, iam users, iam saml |
| Fresh TLS handshakes | ~187 | boto3 does not cache clients; every check builds its own per-region client, so no connection is reused |

Assuming a 100 ms mean round-trip and two extra round-trips per new TLS connection, an
account holding nothing still costs:

```
203 requests + (192 handshakes x 2) = 587 round-trips ~= 58.7 s
```

Serially, 300 such accounts take about 4.9 hours.

### Four identical EC2 sweeps

`deny_ec2_imds_v1`, `deny_ec2_ami_owner`, `deny_ec2_public_ip`, and
`deny_ec2_imds_hop_limit` each run an unfiltered `describe_instances` across every region
-- the same call, the same pages, four times (`aws/ec2.py:105`, `:315`, `:386`, `:439`).
Of the 187 region probe calls, 51 are redundant EC2 sweeps: 27 percent of the floor.

### Measured CPU cost

Measured on a development machine with warm caches and no network:

| | Clients built per account | CPU |
| --- | --- | --- |
| Today | 187 | 542 ms |
| After the instance memo | 136 | 320 ms |

Building the session itself costs a further ~124 ms.

This yields a floor of **~0.45 s per account of GIL-bound Python** -- client
construction, model binding, JSON parsing -- or about 2.2 minutes across 300 accounts.

That floor is real but it does **not** bind: network wait after the memos is ~46 s per
account against ~0.45 s of CPU, a ratio near 100:1. Roughly 94 workers would be needed to
saturate one core, which is far past the point where other limits bite. The worker count
is set by memory instead (section 4), not by the GIL.

## Decisions

Four choices were made by the repository owner during design and are recorded here
because they constrain everything below.

| Decision | Choice | Consequence |
| --- | --- | --- |
| Bottleneck shape | Breadth: many accounts, most of them small | The empty-account floor dominates; deep per-resource N+1 elimination is deprioritised |
| Scale | 50-300 accounts | Account parallelism alone saturates available capacity; **no region-level threading** |
| Failure mode | Abort immediately on the first failure | Closest to today's documented fail-fast semantics; operator fixes and re-runs |
| Duplicate-name guard | In scope | See section 2 |

Because the organisation has 50-300 accounts, account parallelism and region parallelism
are substitutes rather than complements -- both fill the same pipe. Adding a region axis
on top of a saturated account pool would buy nothing but 17x the in-flight requests and
17x the ways to be throttled.

## Non-goals

| Deferred | Reason |
| --- | --- |
| Region-level threading | Redundant at 50-300 accounts (see above) |
| Per-resource threading inside a region | Targets the fat-account regime, which is not this organisation's |
| A per-account collection abstraction in the check framework | The instance memo achieves the same saving without touching `BaseCheck` |
| IAM Access Analyzer / AWS Config aggregator as a data source | A much larger change with org-wide prerequisites and coverage gaps; revisit if the org grows past ~1000 accounts |
| Multiprocessing | The GIL floor is ~2.2 minutes at 300 accounts and never binds; network wait dominates 94:1 |
| Sharing one botocore session across workers | Would cut the ~43 MB-per-worker cost and speed up session creation, but requires extending the client-construction lock to every client and reworking `new_session()`, which carries a pinned test and a deliberate STS-endpoint contract. This is the next lever to pull if memory becomes binding. |
| Refreshable credentials | The 60-minute static credential lifetime stops mattering once a run takes minutes |

## 1. Pool and cancellation

### Pre-filter outside the pool

`_all_checks_complete` is local filesystem I/O. It runs serially before the pool so that
the pool receives only real work and the "N accounts to scan" log line is accurate before
anything starts. Accounts whose results already exist are logged serially, exactly as
today.

### Structure

```python
def run_checks(security_session, relevant_account_infos, config, org_account_ids) -> None:
    pending = [a for a in relevant_account_infos if not _all_checks_complete(a, config)]
    # log the already-complete accounts here, serially, as today

    abort = threading.Event()

    with ThreadPoolExecutor(max_workers=config.max_account_workers) as executor:
        futures = [
            executor.submit(_run_checks_for_account, a, security_session,
                            config, org_account_ids, abort)
            for a in pending
        ]
        for future in as_completed(futures):
            error = future.exception()
            if error is None:
                continue
            abort.set()
            for f in futures:
                f.cancel()
            raise error
```

### Why both `cancel()` and the Event

`Future.cancel()` only succeeds on futures that have not started; it clears the queue and
does nothing to the accounts already running. Python cannot kill a running thread. The
`Event` is what stops in-flight workers: they test it at each check boundary and return.

Without the Event, `shutdown(wait=True)` would block process exit until every in-flight
account finished all of its remaining checks -- the opposite of an immediate abort.

### Why the `with` block matters

On exception the context manager calls `shutdown(wait=True)`, joining the in-flight
threads before the exception reaches `main()`. This is deliberate: the exception must not
propagate while 20 threads are still writing result files. With `abort` set, that join is
bounded by the duration of one check rather than one account.

### Checkpoint granularity: one check

`abort.is_set()` is tested at the top of `_run_checks_for_account` and before each check
in `run_checks_for_type`. Worst-case abort latency is therefore the longest single check.

Pushing granularity down to per-region would require threading `abort` through all 15
analysis functions and every region loop. That is a large amount of plumbing for a few
seconds of latency and fails the repository's "do not overengineer" rule.

A check already inside `execute()` finishes and writes its result file. This is harmless:
the file is complete and valid, and `results_exist` makes the run resumable at
per-account, per-check granularity.

### First failure

`as_completed` yields in completion order, so "first" means first to complete with an
exception, not first to occur. Workers that fail after `abort.set()` have their exceptions
discarded unretrieved; `concurrent.futures` does not warn about that, so no stray output
appears. This matches the chosen failure mode: report one failure, abort, let the operator
fix and re-run.

### Explicit Event

`abort` is passed as a parameter, never a module global. A global would break test
isolation and make the 100-percent-coverage tests order-dependent.

## 2. Thread-safety guards

### 2.1 The shared security session

Every worker calls `get_headroom_session` -> `assume_role(role_arn, name,
base_session=security_session)`, which does `base_session.client("sts",
region_name=region)` on the **single Session object shared by all workers**
(`aws/sessions.py:85`). `Session.client()` resolves the service model through the
session's loader and mutates its component registry on first use. Warm, this is benign; at
t=0 with 16 threads starting simultaneously, it is not.

Scope is narrow. Per-account sessions are **not** shared: `new_session()` calls
`botocore.session.get_session()`, which returns a fresh botocore session with its own
loader and registry, touched only by the worker that created it. The security session is
the only shared object.

The fix is one lock at one site, guarding client construction only:

```python
_CLIENT_CONSTRUCTION_LOCK = threading.Lock()

with _CLIENT_CONSTRUCTION_LOCK:
    sts: STSClient = base_session.client("sts", region_name=region)
sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)   # outside the lock
```

The network call stays outside the lock, so role assumptions still overlap. The lock
serializes roughly a millisecond of object construction.

### 2.2 Duplicate account names corrupt result files

`ResultFilePathResolver._build_filename` (`write_results.py:97`) returns
`{account_name}.json` when `exclude_account_ids` is set -- the account ID, the only
guaranteed-unique component, is deliberately dropped. Two accounts sharing a name write
the same path.

Serially this is already a bug, but a quiet one: last writer wins and the file remains
valid JSON. Concurrently, two threads `open(path, 'w')` and interleave `json.dump` output.
The result is a corrupt file, or a syntactically valid file containing two accounts'
results spliced together, which then feeds policy generation.

**Guard:** a pre-flight check in `perform_analysis` that aborts when `exclude_account_ids`
is set and two accounts in `relevant_account_infos` share a name.

The error message names the duplicated name and the count. It **must not** name the
account IDs -- printing them would defeat the setting that created the problem.

The rest of the write path is already safe: `os.makedirs(exist_ok=True)` handles the
`EEXIST` race, and distinct filenames in a shared directory do not conflict.

### 2.3 Log output

42 log calls in `headroom/aws/` carry no account context. Eight of them are
`logger.info(f"Analyzing ... in {region}")`, which fires per region per account: roughly
40,000 lines at 300 accounts, before threading scrambles the order. That output is already
unusable; concurrency only makes it obviously so.

Two complementary changes:

| Change | Effect |
| --- | --- |
| Demote the eight per-region `Analyzing ...` lines to `DEBUG` | Leaves INFO carrying only lines that already have account context: `Running checks for account:`, `Checks completed for account:`, and `OutputHandler.check_completed` |
| A `logging.Filter` backed by `threading.local`, set once per worker | Injects the account into every record, making `DEBUG` readable when enabled |

The filter fixes all 42 sites without editing any of them.

## 3. Memo layer

### Mechanism

Two memos, both keyed on the boto3 `Session`. The region memo lives in
`headroom/aws/helpers.py` alongside `get_all_regions` and `paginate`. The instance memo
lives in `headroom/aws/ec2.py` instead: its value type is `Ec2Instance`, which is defined
there, and `ec2.py` already imports `paginate` from `helpers.py`, so putting the memo in
`helpers.py` would need `Ec2Instance` back the other way and close an import cycle.

```python
_MEMO: WeakKeyDictionary[Session, dict] = WeakKeyDictionary()
_MEMO_LOCK = threading.Lock()
```

`WeakKeyDictionary` gives the correct lifetime for free: an entry dies when the account's
session goes out of scope at the end of its worker, so nothing accumulates across 300
accounts. The lock guards only the outer dictionary. Section 2.1 establishes that each
account session is touched by exactly one thread, so the inner per-session state needs no
lock.

Two alternatives were rejected. Setting an attribute on the `Session`
(`session._headroom_cache`) is simpler but mutates a third-party object and requires a
`type: ignore`. Threading an explicit cache object through the call chain is cleanest in
principle but impossible without changing `BaseCheck.analyze(session)` across all 15
checks, which is the framework change this design avoids.

### The two memos

| Memo | Type | Removes per account |
| --- | --- | --- |
| Region list | `WeakKeyDictionary[Session, list[str]]` | 10 of 11 `describe_regions` |
| Instances | `WeakKeyDictionary[Session, Dict[str, List[Ec2Instance]]]` | 51 of 68 `describe_instances`, 34 of 187 client builds and their TLS handshakes |

The instance memo nests the region inside a per-session dictionary rather than keying on a
`(session, region)` tuple. A tuple key is a strong reference to the session, which defeats
the `WeakKeyDictionary`: no entry would ever be collected, and a 300-account run would
retain every account's session and instance list to the end.

### Why there is no client memo

An earlier draft included a third memo caching one client per `(session, service, region)`.
It was dropped for two reasons.

It is **redundant**. EC2 is the only service any check uses more than once, so every
duplicated client build is an EC2 client, and the instance memo already removes 34 of the
51 by collapsing four sweeps into one.

It does not remove all 51 because `get_ec2_ami_owner_analysis` needs an EC2 client of its
own for `describe_images`, independent of the instance list. Per-region EC2 clients
therefore go from four to two: one built inside the collector on first access for that
region, and one the AMI check builds for image lookups. A client memo would recover the
last 17, which does not justify its cost.

It is **harmful**. Today a client is built inside the region loop and dropped at the end of
the iteration, so its connection pool is collected and its sockets close; peak usage is
about 2 file descriptors per worker. Memoizing clients for the account's lifetime would
keep roughly 136 pools alive at once -- 16 workers x 136 is about 2,200 sockets, against a
macOS default `ulimit -n` of 256.

### The instance memo caches a projection, not raw pages

Caching raw `describe_instances` output holds every instance dictionary for every region
for the account's whole lifetime. Most of that payload is `BlockDeviceMappings`,
`NetworkInterfaces`, `SecurityGroups`, and `Placement`, which no check reads. At 16
concurrent workers, one large account turns that into hundreds of megabytes.

The four checks read exactly seven fields:

```
ImageId, InstanceId, MetadataOptions, OwnerId, PublicIpAddress, State, Tags
  MetadataOptions -> HttpTokens, HttpEndpoint, HttpPutResponseHopLimit
  State           -> Name
  Tags            -> Key, Value
```

The memo therefore caches a frozen `Ec2Instance` dataclass carrying those fields, with
`tags` as a `Dict[str, str]` rather than the raw list. Converting the tag list to a
dictionary is behaviour-preserving because tag keys are unique per resource.

The projection is an order of magnitude smaller than the raw dictionaries and gives the
four checks a typed contract in place of four independent reaches into raw dicts.

It also replaces four copies of one rule with one: all four checks currently open with the
identical `if instance['State']['Name'] == 'terminated': continue`. That filter moves into
the collector, where it is stated once.

## 4. Configuration and botocore tuning

### New configuration field

| Field | Default | Bounds |
| --- | --- | --- |
| `max_account_workers: int` | 16 | `Field(ge=1, le=32)` |

A `--max-account-workers` CLI flag defaults to `None`, so the only default in the codebase
lives in `config.py`, per the repository rule that CLI defaults are declared once.
`merge_configs` already drops `None` CLI values, so `usage.py` needs no merge-logic change.

### Why 16

Memory sets this number, not the GIL. Each worker holds its own botocore session, and
because `new_session()` builds a fresh one per account, each carries its own parsed
service models. Measured resident growth, warm process:

| Concurrent sessions | Resident growth | Per session |
| --- | --- | --- |
| 1 | 4.5 MB | 4.5 MB |
| 4 | 140 MB | 35 MB |
| 8 | 322 MB | 40 MB |
| 16 | 689 MB | 43 MB |

Growth is linear at roughly 43 MB per worker. That gives:

| Workers | Resident | 300 accounts |
| --- | --- | --- |
| 1 | baseline | ~3.8 hours |
| 8 | ~0.4 GB | ~29 minutes |
| **16** | **~0.8 GB** | **~14 minutes** |
| 32 | ~1.5 GB | ~7 minutes |

Row 1 is the post-memo serial time; today's serial run is ~4.9 hours.

16 is a deliberately conservative default: under a gigabyte, comfortable on a laptop or a
small CI box, and a 21x improvement over today's serial run. The upper bound of 32 is where resident memory passes
1.5 GB; wanting more than that is a signal to revisit the design rather than turn a knob.

The flag exists precisely because the right value is environment-dependent. Raising it is
safe and effective well past 16 -- the GIL floor of ~2.2 minutes is the real ceiling and it
is a long way off.

`max_account_workers=1` means serial, on the same code path --
`ThreadPoolExecutor(max_workers=1)`, not an `if parallel:` branch. One path to test, and a
real escape hatch for debugging.

### Retries go on the session

`new_session()` already sets `sts_regional_endpoints`. Retry mode is settable the same way,
so every client inherits it with no call-site changes:

```python
botocore_session.set_config_variable("retry_mode", "standard")
botocore_session.set_config_variable("max_attempts", 5)
```

Five attempts rather than the `standard` default of three, for throttling headroom under
concurrency. `standard` rather than `adaptive`: adaptive adds client-side rate limiting
that throttles unpredictably, and 16 workers spread across 16 separate accounts sit in 16 separate
rate-limit buckets, so there is little to adapt to.

### One connection pool is sized, as a ceiling that binds nothing yet

`max_pool_connections` is not a botocore session config variable, only a
`botocore.config.Config` setting. One client receives one: the STS client in
`assume_role`, built from the shared security session, with a `Config` sized to the worker
cap that `sessions.py` imports from `config.py` rather than redeclaring.

**The original premise for that sizing was wrong and is corrected here.** There is no
single shared STS client "hit by all workers at t=0". `assume_role` calls
`base_session.client("sts", ...)` on every invocation and boto3 caches no clients, so a
300-account run builds 300 of them, each with its own `URLLib3Session` and its own
`PoolManager`, each serving exactly one `AssumeRole` request. Measured on two clients built
from one session: same client object `False`, same http session `False`, same `PoolManager`
`False`. Against a pool of one request, botocore's default of 10 was never going to be
exhausted, so nothing churned connections and nothing logged pool-full warnings.

The `Config` stays anyway. It costs nothing, it keeps the intended ceiling stated in one
place, and it becomes load-bearing the day the STS client is built once per run and shared
-- the change that would also save one TLS handshake per account and make this section's
original wording true. Filed rather than done here.

The lock in 2.1 is untouched by this correction and remains necessary: `Session.client()`
resolves the service model through the shared session's loader and mutates its component
registry, which is a hazard regardless of how many clients come back out.

Per-account clients stay on defaults. Each is used by a single thread and pools are lazy,
so the default of 10 costs nothing.

## 5. Testing

This introduces the first concurrency anywhere in the repository -- no `threading` import
exists in `headroom/` or `tests/` today. New tests follow the existing flat layout
(`test_analysis.py`, `test_aws_sessions.py`, `test_aws_helpers.py`, `test_aws_ec2.py`,
`test_config.py`), not the `tests/unit/` tree CLAUDE.md describes but the repository does
not use.

### Determinism policy

Synchronize with `threading.Barrier` and `Event`, never with `sleep`. Every barrier and
every `Event.wait` takes a timeout, so a broken implementation fails in seconds rather than
hanging CI. Section 5.3 records the one deliberate exception.

### 5.1 Cancellation

Testing "did the queued account really not start?" through a live pool is a race, and a
racy test is worse than no test. The contract is decomposed:

| Kind | Pins | Threads |
| --- | --- | --- |
| Unit | `_run_checks_for_account` returns without assuming a role when `abort` is already set | none |
| Unit | `run_checks_for_type` stops before the next check when `abort` is set | none |
| Unit | `run_checks` sets `abort` and calls `cancel()` on outstanding futures (spy) | none |
| Threaded | the worker's exception propagates out of `run_checks` unchanged | yes |

### 5.2 Parallelism actually happens

With `max_workers=N`, place a `threading.Barrier(N)` in the fake worker. If fewer than N
accounts run simultaneously the barrier times out and the test fails. This asserts
parallelism rather than assuming it.

### 5.3 The mutual-exclusion probe

For the STS lock, mock `client()` to increment a counter, sleep about 5 ms, decrement, and
record the maximum. Run eight threads through `assume_role` and assert the maximum observed
concurrency is 1.

Without the lock this fails reliably; with it, it passes. It can only false-pass, never
false-fail, which is the correct asymmetry for CI. This is the one place a sleep is
correct.

### 5.4 Cross-session isolation

A memo keyed wrongly does not crash. It silently serves one account's regions or instances
to another account, and the results look entirely plausible. Both memos therefore get an
explicit test that two distinct sessions never share an entry, plus a `gc.collect()` test
that an entry is released once its session is dropped.

### 5.5 The EC2 regression net

The highest-value test is one that does not need writing. The four EC2 checks already have
full behavioural test files, and the instance memo must leave every one of them passing
**unchanged**. If rerouting four independent sweeps through one projected collector alters
any check's output, those tests say so immediately.

New EC2 tests therefore cover only what is genuinely new:

- the seven-field projection
- `MetadataOptions` defaults: `HttpTokens` -> `optional`, `HttpEndpoint` -> `enabled`,
  hop limit -> 1 when absent
- the tag list to dictionary conversion
- the terminated filter now living in one place instead of four

### 5.6 Performance tests assert call counts

`tests/performance/` per the build documentation, but a test asserting "16 workers beat 1"
is a flake generator. The durable form pins the savings as a contract: a three-account run
issues exactly 3 `describe_regions` calls rather than 33, and exactly R
`describe_instances` per account rather than 4R. These never flake, and they fail loudly
the day someone reintroduces a redundant sweep.

### 5.7 Coverage

100 percent on both trees requires:

- the success path and the failure path through `as_completed`
- both bound rejections for `max_account_workers`
- all three states of the duplicate-name guard: duplicates with `exclude_account_ids` on,
  duplicates with it off, and no duplicates

The guard's message assertion checks that it names the duplicated name and contains **no**
account ID.

## Expected outcome

| Metric | Before | After (16 workers) |
| --- | --- | --- |
| Wall clock, 300 accounts | ~4.9 hours | ~14 minutes |
| Round-trips per empty account | 587 | 458 |
| `describe_regions` per account | 11 | 1 |
| `describe_instances` per account | 68 | 17 |
| Client builds per account | 187 | 153 |
| GIL-bound CPU per account | ~0.66 s | ~0.45 s |

Output is unchanged. Results are written per account and per check, so worker scheduling
cannot affect what lands on disk.

## Risks

| Risk | Mitigation |
| --- | --- |
| A memo keyed wrongly leaks one account's data into another's results | Explicit cross-session isolation tests (5.4); `WeakKeyDictionary` keyed on the session object itself, never on an account ID or name |
| Concurrent writes corrupt shared result filenames | Pre-flight duplicate-name guard (2.2) |
| Client construction races on the shared security session | Lock around the one shared construction site (2.1) |
| Throttling under concurrency | `standard` retry mode; workers spread across separate per-account rate-limit buckets |
| Flaky concurrency tests | Barriers and Events with timeouts, never sleeps, except the one probe in 5.3 |
| Abort latency of one check duration | Accepted; checks are seconds at this organisation's account sizes |

## Documentation to update at implementation time

Per the repository's two-phase documentation rule, these must be current before the
implementation commit:

| File | Change |
| --- | --- |
| `documentation/SETUP.md` | Document `max_account_workers`: what it does, the default of 16, the bounds, the ~43 MB-per-worker memory cost, and that 1 means serial |
| `sample_config.yaml` | Commented `max_account_workers` example pointing at SETUP.md |
| `README.md` | Note that accounts are analyzed concurrently, and the observed speedup |
| `documentation/ARCHITECTURE.md` | Record the concurrency model: one worker per account, cooperative abort, session-keyed memos |
| `Headroom-Specification.md` | Update the analysis-loop description, which currently describes a serial sweep |
