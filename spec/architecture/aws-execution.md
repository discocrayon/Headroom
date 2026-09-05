# Architecture: AWS execution

Owns how Headroom reaches AWS: the identities it assumes, the sessions it builds,
the regions it reads, and which accounts it treats as what.

Implementation: `headroom/aws/sessions.py`, `headroom/aws/helpers.py`,
`headroom/aws/organization.py`, `headroom/aws/organization_snapshot.py`,
`headroom/analysis.py`, `headroom/log_context.py`. Operator instructions for
creating these roles:
[`../../documentation/SETUP.md`](../../documentation/SETUP.md).

## Hub and spoke

Headroom runs from one account and reaches every other by assuming a role. It
never uses long-lived credentials in a member account.

```
Security Analysis Account  (the hub — where Headroom runs)
   ├─ OrgAndAccountInfoReader   in the management account   (organization structure)
   ├─ Headroom                  in member account 1         (resource scan)
   ├─ Headroom                  in member account 2         (resource scan)
   └─ Headroom                  in member account N         (resource scan)
```

Every role trusts the security analysis account as its principal.

## The role chain

| Step | Role | Assumed in | Session name | When |
|---|---|---|---|---|
| 0 | `OrganizationAccountAccessRole` | Security analysis account | `HeadroomSecurityAnalysisSession` | Only when `security_analysis_account_id` is configured |
| 1 | `OrgAndAccountInfoReader` | Management account | `HeadroomOrgAndAccountInfoReaderSession` | Always |
| 2 | `Headroom` | Each analyzable member account | `HeadroomAnalysisSession` | Per account |

Step 0 is skipped when Headroom is already running in the security analysis
account; the ambient credentials are used instead. Step 1 requires
`management_account_id` and raises without it; so does SCP placement, per
[`../contracts/configuration.md`](../contracts/configuration.md#management_account_id).
Step 2 chains from the security session, not from the management session.

Role names are fixed. They are not configurable.

## Sessions are minted regionally

Every session in the package is built by `headroom/aws/sessions.py`, with
`sts_regional_endpoints` set to `regional`, at every hop (INV-16).

botocore defaults that setting to `legacy`, which rewrites the STS endpoint to
the global `sts.amazonaws.com` whenever the session's region is one that predates
opt-in regions — `us-east-1` and `us-west-2` among them. Tokens the global
endpoint issues are valid only in regions enabled by default, so an assumed-role
credential minted there fails with `AuthFailure` the moment Headroom reads an
opt-in region. Headroom scans every enabled region of every account, so that is
the normal case rather than an edge case, and it cannot depend on the operator
having configured `regional` themselves.

An assumed session carries the region it was assumed from, so a chained
assumption keeps minting regionally at every hop. Assuming a role with no region
configured anywhere raises rather than guessing one.

## Regions

`get_all_regions` calls `describe_regions` with no arguments, returning only the
regions the account has enabled — `opt-in-not-required` and `opted-in`, never
`not-opted-in` (INV-16).

An enabled region does not guarantee the service is available there. Handling a
missing regional endpoint is each check's concern, and each check's document
states what it does. An absent endpoint raises botocore's
`EndpointConnectionError`, which is **not** a `ClientError` subclass, so an
`except ClientError` never catches it — the reason a region-loop that looks
defended can still abort the run.

## The three account projections

These are distinct and must stay distinct (INV-04). `discover_organization` in
`headroom/aws/organization_snapshot.py` builds all three in one pass and returns
them on a frozen `OrganizationSnapshot`, which every later stage reads and none
recomputes.

Freezing the outer dataclass is what makes INV-04 enforceable rather than
advisory: no stage can reassign `organization_id`, `member_account_ids`,
`analyzable_accounts`, or `hierarchy` to a projection it derived itself. Three
of the four are immutable the whole way down — a string, a frozenset, and a
tuple of frozen `AccountInfo` — so a stage holding a reference cannot edit an
entry in place either. `hierarchy` is the exception: `OrganizationHierarchy`
holds ordinary dicts and lists and its contents stay mutable, because
deep-freezing it would mean reworking every producer and consumer of those
collections. That is a known gap, not an oversight.

### Organization membership — `list_organization_accounts`

Every account ID the Organizations API reports, **unfiltered**. Deliberately
includes the management account, closed accounts, and accounts named in
`skip_account_ids`.

RCP checks use this set to tell an in-organization principal from a third party.
A closed account is still an organization member and still matches
`aws:PrincipalOrgID`, so filtering here would misclassify its principals as third
parties and inflate every allowlist.

Because it is the oracle the other two projections are measured against, this
listing indexes `Accounts` on each page rather than defaulting it, and
`_list_child_accounts` reads its sibling listing the same way. An organization
always holds at least the management account, so an empty page is never a true
answer, and nothing downstream would catch a short one. **Reading a page's
collection key** below owns the general rule.

### Analyzable accounts — `_select_analyzable_accounts`

The accounts that get scanned. Excludes, in this order:

1. The management account, because SCPs and RCPs do not restrict it.
2. Accounts named in `skip_account_ids`. Consulted **before** the lifecycle check
   so an account whose state cannot be classified can be excluded by
   configuration instead of aborting the run.
3. Every account not in the `ACTIVE` lifecycle state (INV-03).

An excluded account writes no results, and placement only sees accounts that
have results, so exclusion removes the account from the compliance picture
entirely rather than holding a policy back.

Each returned account carries its name, environment, and owner, read from account
tags per [`../contracts/configuration.md`](../contracts/configuration.md).
`ListTagsForResource` paginates, and every page is read: a tag that arrived on
page two would otherwise be indistinguishable from a tag the account does not
carry, and the account would silently take the fallback — the account ID in
place of its name, `unknown` for environment and owner.

### Hierarchy — `build_organization_hierarchy`

The OU tree placement walks: the root ID, every OU with its parent, children, and
accounts, and every account with its parent OU and path.

**Every listing is paginated.** `ListAccountsForParent` and
`ListOrganizationalUnitsForParent` cap a page at twenty, and AWS documents that
either can return fewer even when more remain, so a single response is never
evidence of a complete parent. This is load-bearing rather than tidy: the
OU-level RCP safety predicate in [`../contracts/placement.md`](../contracts/placement.md)
is evaluated against this hierarchy, not against the accounts that produced
results, so an account missing from a truncated page is an account whose
blockers no OU-level decision can see. A short read here is absence of evidence
presented as safety (INV-01).

`ListRoots` paginates too. An organization has one root today, but the paginator
is free to split any listing, and reading page one alone reported "No roots
found" for a root that arrived on page two. Two roots abort rather than
resolving to the first: which root came first is page order, and picking one
would traverse half the organization while reporting a complete hierarchy.

The walk reads each parent's children exactly once. A breadth-first worklist
replaces the earlier recursion, which listed every OU's children twice — once
entering the recursive call, once again to fill `child_ous` — and which matters
because Organizations is throttled tightly and pagination multiplies request
counts. Two observations abort rather than resolving quietly, because each means
the organization changed mid-read and neither has a safe reading: an account
under two parents, and a parent reached twice.

An account attached directly to the organization root has `parent_ou_id` of
`None` and an `ou_path` of `["Root"]`. It belongs to no OU and cannot be targeted
by an OU-level policy; the root ID is not a substitute.

## Partitions

**Headroom runs in the commercial `aws` partition only.** All three role ARNs in
`analysis.py` are built as `arn:aws:iam::<account>:role/<name>`, so the first
`sts:AssumeRole` against a GovCloud, China, or isolated-region account fails.
The partition is not configurable and is not derived from the caller.

This is a limitation, not a decision — nothing about the design depends on it,
and closing it means deriving the partition once from the caller's own identity
rather than threading a config field through. Elsewhere the code is already
partition-agnostic: the ARN pattern that extracts account IDs from policy
documents matches any partition ([`../contracts/policy-model.md`](../contracts/policy-model.md)),
and so does result redaction ([`../contracts/results.md`](../contracts/results.md)).
Two synthesized ARNs hardcode `aws` cosmetically, recorded at
[`deny_ec2_public_ip`](../checks/scps/deny_ec2_public_ip.md) and
[`deny_s3_third_party_access`](../checks/rcps/deny_s3_third_party_access.md).

## The account worker pool

The scan runs accounts concurrently. `run_checks` in `headroom/analysis.py`
filters out accounts whose results all exist — serially, before the pool — and
hands the rest to a `ThreadPoolExecutor` of `config.max_account_workers`
workers, one account per worker. Each worker assumes the `Headroom` role in its
account, runs every registered check, and writes that account's result files.

Setting `max_account_workers` to 1 runs the accounts serially **on the same code
path**, through the same executor. There is no separate serial branch to drift
out of step with the concurrent one, which is what makes 1 usable as a debugging
escape hatch rather than a different program.

The bound is memory, not the GIL. The work is almost entirely waiting on AWS, so
threads are the right shape; what costs is that each worker holds its own
botocore session with its own parsed service models, roughly 43 MB.
[`../contracts/configuration.md`](../contracts/configuration.md) carries the
default, the ceiling, and the arithmetic behind both.

### What the pool must not do

**A worker's failure must reach the operator, and the run must not drain.** A
`ThreadPoolExecutor`'s `__exit__` calls `shutdown(wait=True)`, which runs every
queued account to completion. On the way to reporting one account's failure that
would scan the whole organization first.

Three things prevent it, and each is load-bearing:

| Mechanism | Prevents |
|---|---|
| A `threading.Event` every worker checks at its own checkpoints | An in-flight worker continuing after the run has already failed |
| Cancelling every outstanding future before leaving the block | A queued account starting after the abort |
| Both handlers catching `BaseException` rather than `Exception` | An operator's Ctrl-C, and `SystemExit`, reaching `__exit__` uncaught — the two cases where draining is least wanted |

Submission sits inside the guarded block for the same reason. `executor.submit`
can itself raise `RuntimeError("can't start new thread")` on a host at its thread
limit, likeliest at the ceiling, and the futures map is bound before the block so
the handler always holds whatever the submit loop got through.

The Event covers a window the cancel loop cannot. CPython queues the work item
and only then starts a thread, so an item whose thread failed to start is queued
while its future was never returned: nothing can cancel it. An existing worker
picks it up, finds the abort set, and returns at its first checkpoint.

Failures are reported after the executor block, not inside it. A worker's
exception is not set on its future until `shutdown(wait=True)` has joined it, so
a handler inside the block would find nothing to report.

### Three things concurrency changes elsewhere

**Log records interleave.** Most log calls in `headroom/aws/` name a region or a
resource and not an account, which is unambiguous only while one account is in
flight. `headroom/log_context.py` stamps every record with the account its
thread is working on, from a `threading.local` set at the top of each worker,
through a filter installed on the handler. Records emitted outside a worker —
startup, configuration, teardown — carry `-`.

**Three memos are keyed on the session object.** Each covers a read that
several checks in one account would otherwise repeat: the enabled-region list,
which nearly every analyzer opens with; the EC2 instance sweep, which four EC2
checks each made a separate pass for; and the six resource-policy analyzers
wrapped by `memoize_per_session`, which have two callers apiece — their own
third-party-access check, and `deny_service_confused_deputy` re-reading the same
policies for source guards.

The key is the `Session` itself, never an account ID or name, and that is what
keeps one account's regions, instances, and resource policies out of another
account's results.

Entries live in a `WeakKeyDictionary`, so an account's entry is released when
its worker drops the session and nothing accumulates across a run of hundreds of
accounts. On the failure path the entry outlives the worker, because the
traceback pins the frame holding the session; what bounds that is how many
accounts are in flight, so `max_account_workers` rather than the size of the
organization.

**Client construction on the shared session is serialized.** Every worker
assumes its role through the one security-analysis `Session`, and boto3
documents a `Session` as unsafe to share across threads. That documented
contract is the whole justification for the lock in `headroom/aws/sessions.py`,
and it is deliberately not narrowed to a named unguarded mutation: botocore
guards the obvious candidate itself, and 32 threads making unlocked
`client("sts")` calls on one shared session raised nothing across four trials.
The lock is kept anyway, because a reader who checks one mechanism and finds it
safe would otherwise delete something that costs nothing and prevents a rare,
baffling failure. It covers construction only — the `AssumeRole` round trip
stays outside it, so workers still overlap. Per-account sessions are never
shared, so this is the one site at risk.

## Reading a page's collection key

Every paginated listing faces one choice: index the collection key, or default
it to the empty list. The choice is not stylistic. A check clears an account by
finding nothing, so a page silently read as empty is the most permissive answer
the run can give — INV-01's shape exactly. Indexing turns that into a `KeyError`,
which is neither `ClientError` nor `BotoCoreError` and so passes each listing's
own handler untouched and aborts.

**A key may be indexed only where its presence is guaranteed independently of
whether the answer is empty.** Nothing in the AWS toolchain answers that
question. Botocore's `required` metadata is a shape contract, not a wire
guarantee, and it marks the collection optional on almost every listing here —
including `organizations:ListAccounts` and `ec2:DescribeInstances`, both of
which this code indexes anyway on grounds the model knows nothing about.

`sqs:ListQueues` is the proof that guessing is not free. It omits `QueueUrls`
outright when the account holds no queues, rather than returning an empty list
([boto/boto3#2811](https://github.com/boto/boto3/issues/2811)). Indexing it
would abort every run against every region with no queues. Its `.get` is
load-bearing, not laxity, and a reader tidying it into a subscript breaks the
tool for the common case.

The same listing is the one whose pagination is opt-in. `sqs:ListQueues`
returns a `NextToken` only when the request set `MaxResults`; without it the
response holds at most 1000 queues and no token, so a paginator sending none
reads one page and stops as if the region held nothing more, with no error to
distinguish that from a region of 1000 queues. Botocore sends `MaxResults`
only when `PageSize` is configured, so `_analyze_queues_in_region` in
`headroom/aws/sqs.py` configures it, and it is the only paginator here that
must: every other listing this run issues returns its continuation marker
whether or not the request bounded the page.

| Listing | Key | Read as | Why |
|---|---|---|---|
| `organizations:ListAccounts`, `ListAccountsForParent` | `Accounts` | indexed | An organization always holds the management account, so empty is never a true answer, and this is the oracle nothing downstream re-checks |
| `iam:ListUsers`, `ListRoles` | `Users`, `Roles` | indexed | Botocore marks both required on the response; an account with none returns an empty list |
| `ec2:DescribeInstances` | `Reservations` | indexed | The empty account returns an empty `Reservations`, so a missing key is not the empty answer |
| `organizations:ListRoots` | `Roots` | defaulted | The function's own post-condition already raises on no root and on several, with a better message than a `KeyError` |
| `organizations:ListOrganizationalUnitsForParent` | `OrganizationalUnits` | defaulted | A dropped subtree makes the placement view disagree with membership, and the snapshot cross-check aborts on that |
| `sqs:ListQueues` | `QueueUrls` | defaulted, and must stay so | AWS omits the key on an account with no queues |
| `s3:ListBuckets`, `kms:ListKeys`, `ecr:DescribeRepositories`, `secretsmanager:ListSecrets`, `lambda:ListFunctions`, `lambda:ListFunctionUrlConfigs`, `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `eks:ListClusters` | `Buckets`, `Keys`, `repositories`, `SecretList`, `Functions`, `FunctionUrlConfigs`, `DBInstances`, `DBClusters`, `clusters` | defaulted | Unestablished. Neither AWS's reference nor botocore says whether the key survives an empty result |

That last row is a known gap rather than a settled design, and it is a smaller
one than it first reads. Work out what indexing would catch on a listing that
does return an empty list when the answer is empty. A page carrying items is
normal; a page carrying `[]` is normal; a page carrying neither is reachable
only if the service malfunctioned. **Indexing buys detection of that third case
and nothing else** — not any condition AWS documents. On a listing that omits
the key when empty, as `sqs:ListQueues` does, the second and third cases are the
same bytes, so indexing is not merely risky there but impossible: the
information needed to separate them is not on the wire.

So the row is not pending work with a known method, and should not be read as
one. An account holding none of that resource would show what a whole empty
result looks like, but not what an intermediate page carrying no items looks
like — a shape filtered pagination can produce and that indexing would abort a
healthy run over. Whoever revisits this decides whether detecting a malformed
AWS response is worth that cost; the answer so far has been no, on the grounds
that a region that errored, an API that denied permission, and a policy that
would not parse are the INV-01 exposures that actually occur, and each of those
already aborts.

## Failure policy

A failure anywhere in analysis aborts the whole run (INV-02). There is no
per-account error handling, by design.

Two deliberate exceptions, both narrow:

| Tolerated | Why |
|---|---|
| Any `ClientError` fetching an account's tags, in `_fetch_account_tags` in `headroom/aws/organization_snapshot.py` | Labels, not evidence. [`../contracts/configuration.md`](../contracts/configuration.md#tag-fallbacks) owns the fallbacks the account takes instead, the argument for tolerating the failure, and the record that the catch is wider than intended |
| Per-region and per-resource errors inside a check | Specified per check, and each such case is reported in that check's result rather than silently dropped. The last exception was [`deny_sqs_third_party_access`](../checks/rcps/deny_sqs_third_party_access.md), which dropped a queue naming an unrecognized principal key, then recorded it with nothing that check reads; it now aborts on that queue like the other five analyzers |

### What an aborted run tells the operator

One exception reaches `main`. Left at that, an operator missing the `Headroom`
role in forty accounts is told about one account, fixes it, re-runs, and is told
about the next. So the report has three parts, and each covers accounts the
others cannot see:

| Part | Covers |
|---|---|
| The propagating exception | The one account whose failure `as_completed` reported first |
| `_log_every_failure` | Every other account that failed. Their futures hold exceptions nobody asks for again, and `concurrent.futures.Future` has no `__del__` — unlike an asyncio future it is collected without even an "exception was never retrieved" warning, so these failures otherwise leave no trace at all |
| `_log_the_accounts_that_never_ran` | The accounts cancelled off the queue. They never ran, so they never logged, and they hold no exception to report — but their count is what says how much of the organization the results on disk actually cover |

Both reporters skip a future that is not `done()`. That branch is not dead: a
second Ctrl-C lands inside `shutdown(wait=True)` and reaches the handler with
workers still running, and blocking there to collect their failures is the
opposite of what an operator pressing Ctrl-C twice is asking for.

Accounts already in flight when the abort landed are counted in neither
reporter. They log their own `Checks aborted` at the checkpoint that stopped
them.

### What a policy document may and may not stop the run over

The RCP analyzers read policy documents an account's own operators wrote, so
they meet three kinds of trouble and answer them differently. The rule is
stated in full in
[`../contracts/policy-model.md`](../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run);
its consequence for this document is that only the first kind reaches INV-02:

| Kind | Example | Answer |
|---|---|---|
| A document AWS could not have stored | Unparseable JSON, a `Statement` that is neither object nor list, an `Allow` carrying neither `Principal` nor `NotPrincipal`, a principal key the policy type does not accept, an `Action` that is neither a string nor an array | **Aborts.** |
| A document AWS accepted that no allowlist can express | `Principal: "*"`, an `Allow` with `NotPrincipal`, and — in one of the five resource policies — a `Federated` or `CanonicalUser` principal | **Blocks the account** for that check. Recorded as a violation; the scan continues |
| A document AWS accepted that the check deliberately does not act on | A `Federated` principal in a role trust policy, paired with any grant of `sts:AssumeRole` other than that literal string | **Neither.** No finding is recorded and the account stays eligible |

A statement's `Condition` is the one element the first row does not reach. A
`Condition` that is not a mapping is as malformed as a `Statement` that is
neither object nor list, and `_read_principal_confinement` in
`headroom/aws/policy_documents.py` returns an empty confinement rather than
raising — as it does for a clause whose value is neither a string nor a
non-empty list of strings, and for an operator, a key, or a pairing of the two
nobody has modelled. No
bound is already the blocker answer, so there is nothing to abort for.
[`../contracts/policy-model.md`](../contracts/policy-model.md#condition-confined-wildcards)
owns that argument and the contrast with `_read_source_guards`, which does
raise on an operator it does not recognize because it is building an allowlist
out of what it reads. The `Principal` element of the same statement still
aborts by the first row: `read_statement_principals` reads it, through
`_read_principal`, before it reads the condition at all.

The second kind used to abort in four of the five resource-policy analyzers.
[`../contracts/policy-model.md`](../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run)
states what that cost and why the line falls where it does.

Which row a principal key lands in depends on the policy type reading it, so the
first row's set is not the four keys AWS documents. A `CanonicalUser` is a
blocker in the five resource policies and an abort in a role trust policy, which
does not accept the key.
[`../contracts/policy-model.md`](../contracts/policy-model.md) owns both sets and
why they differ.

A `Federated` principal reaches all three rows. In the five resource policies it
blocks the account. In a role trust policy it aborts when the statement grants
the literal `sts:AssumeRole`, raising `InvalidFederatedPrincipalError` in
`headroom/aws/iam/roles.py` — an abort no resource policy has. Written any other
way that still reaches `sts:AssumeRole` — `sts:*`, `sts:Assume*`, or
`STS:AssumeRole` in another case — it is deliberately tolerated: nothing records
it, `TrustPolicyAnalysis` carries no field for a principal with no account ID,
and the role is dropped.
[`../checks/rcps/deny_sts_third_party_assumerole.md`](../checks/rcps/deny_sts_third_party_assumerole.md)
owns that argument and that analyzer's full failure list.
`InvalidFederatedPrincipalError` and `UnknownPrincipalTypeError` are caught
nowhere, so each reaches INV-02 by the first row.

Once configuration has been validated, everything after it runs inside one of
three `_failures_reported` scopes, which between them cover the whole run:
organization discovery, the scan, and Terraform generation, the last of which
ends with reconciliation. Each scope catches `ValueError`, `RuntimeError`, and
`ClientError`, prints an error labeled with the phase that raised, exits
non-zero, and logs with `exc_info=True`, so the traceback still reaches the log
even though the operator sees only the label. None of them continues.

One reporter rather than one `try`, and one per phase rather than one for the
run, because the exception rarely names the phase itself: a `ClientError` says
which API refused and never says which phase called it, and a denied
`AssumeRole` is both discovery's first step and the scan's per-account one. The
scan sat outside the handler entirely at one point, so a `ClientError` in the
longest phase of the run aborted on an unhandled traceback instead of a labeled
message. INV-02 held either way, which is why it went unnoticed.

Any other exception type is caught nowhere and aborts on an unlabelled
traceback, with no log line at all: `MalformedPolicyError`,
`UnknownPrincipalTypeError`, `UnknownGranteeTypeError`,
`UnknownGrantPrincipalError`, `InvalidFederatedPrincipalError`, and
`MalformedStatementError` each subclass `Exception` directly, an `Action`
that is neither a string nor an array raises `TypeError`, and a KMS grant
carrying no `GrantId`, or neither `GranteeServicePrincipal` nor
`GranteePrincipal` while carrying any operation other than `RetireGrant`
alone, raises `KeyError`. A grant carrying only `RetireGrant` is skipped
before either grantee field is read, so a missing grantee cannot abort it;
its `GrantId` is read first and still can. Of row 1's four examples, only
unparseable JSON reaches a handler, because `json.JSONDecodeError` subclasses
`ValueError`.

That is not a defect to fix in `main`. INV-02 is met because the run aborts
whole, and INV-01 is met because the abort itself keeps a missing observation
from being read as clean — not because every message is equally informative.
All six classes name the resource whose policy or grant could not be read,
`UnknownGrantPrincipalError` since it was given the key ARN and the grant ID
alongside the grantee it could not classify — only the grantee, since a
grant's retiring principal is not read at all. Nor is the grantee ever an IAM
unique ID in the documented shape: a value the two patterns match is attributed
or recorded rather than raised on, whether or not an account comes out of it.
Both are for reasons
[`../checks/rcps/deny_kms_third_party_access.md`](../checks/rcps/deny_kms_third_party_access.md)
owns. The bare `TypeError` names only the value's Python type, and the
`KeyError` only the absent field. None of the eight lets the run finish and
report the account clean, which is the property that matters.

`UnknownPrincipalTypeError` was for a time the one type on that list with a
catch site: `headroom/aws/sqs.py` caught it and recorded the queue as a read
failure carrying nothing the queue's own check reads, so the abort INV-01
relies on here never happened for that queue and the account was cleared. The
catch is gone, and the exception aborts from all six analyzers.

A configuration error is caught earlier, and separately, in
`setup_configuration`: a `ValueError` or `TypeError` raised by `merge_configs`
prints a labeled error and exits before the `try` is ever entered.

A malformed check registration fails earlier still, and outside every handler.
`_validate_registration` in `headroom/checks/registry.py` raises `ValueError`
when the `@register_check` decorator runs, which is when `headroom.checks` is
imported — before `main` is entered, before any configuration is read, and
outside the three `_failures_reported` scopes — so the run aborts on an
unlabelled traceback naming the check and the rule it broke. That is the right
shape for this failure, not a gap to close in `main`: it is a developer's error
in the source tree rather than an operator's in the configuration or the
organization, no run on a tree that imports can meet it, and a handler labeling
it `Invalid configuration` would send the operator to the wrong file.
[`check-framework.md`](check-framework.md#discovery) owns the rules the
validator applies.

## Required permissions

The `Headroom` role needs read-only access to the services its checks call; each
check's document lists its APIs. The `OrgAndAccountInfoReader` role needs
`organizations:List*` and `organizations:Describe*` plus
`organizations:ListTagsForResource`.

Both roles must be exempt from any SCP that would deny their reads, or the scan
sees a distorted picture of the account.
[`../../documentation/SETUP.md`](../../documentation/SETUP.md) carries the
policy documents.
