---
id: deny_sqs_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_sqs_third_party_access.py
  - headroom/aws/sqs.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_sqs_third_party_access.py
  - tests/test_aws_sqs.py
  - tests/test_aws_policy_documents.py
---

# deny_sqs_third_party_access

## Objective

Deny SQS access by any principal outside the organization except the third-party
accounts that queue policies already grant.

### Scope

Queue access policies, in every enabled region.

### Non-goals

- Does not read the KMS key policy protecting an encrypted queue.
- Does not evaluate `Condition`, `Resource`/`NotResource`, or `NotAction`.
- Does not distinguish a dead-letter queue from any other.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenySQSThirdPartyAccess
Action: sqs:*
```

Pattern 5a, principal account allowlist
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).

Terraform variables: `deny_sqs_third_party_access` and
`sqs_third_party_access_account_ids_allowlist`.

## Evidence

Per enabled region: `sqs:ListQueues` (paginated), then `sqs:GetQueueAttributes`
requesting `Policy` and `QueueArn` per queue.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Action`.
The `Principal` element is read by `read_principal` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | A wildcard principal — literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | The queue has no policy | Not in the output |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Read failure | Unparseable policy JSON, or an unrecognized principal key | Recorded; the statement is withheld from the account |

## Failure behavior

| Situation | Behavior |
|---|---|
| `AWS.SimpleQueueService.NonExistentQueue` or `QueueDoesNotExist` | The queue was deleted mid-scan; skipped |
| No `Policy` attribute | Skipped; the queue grants nothing |
| Any other `ClientError` in any region | Logged and re-raised, aborting the run |
| `Statement` neither object nor list | `MalformedPolicyError`, aborting the run |
| `Principal` neither string, list, nor object | `MalformedPolicyError`, aborting the run |
| Unparseable policy JSON | `json.JSONDecodeError`, **caught and recorded as a read failure** |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, **caught and recorded as a read failure** |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

**This analyzer catches exactly two of the things a policy document can
raise, and records both.** It once skipped the queue instead, which cleared the
account on the strength of a queue nobody had read, against INV-01; and it once
raised on a `Federated` principal and stopped the whole run. Both are fixed: a
principal no allowlist can carry is now a violation like any other blocker, and
a document this analyzer cannot read is recorded as a read failure that
withholds the statement from the account. An `Action` that is neither a string
nor a list is the one policy-document error still uncaught here, and it aborts.
The rule is stated once in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md).

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `queues_third_parties_can_access` | Violations plus compliant |
| `queues_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_queues_analyzed`,
`queues_third_parties_can_access`, `queues_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`,
`actions_by_third_party_account`, `queues_by_third_party_account`.

Entry shape: `queue_url`, `queue_arn`, `region`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`.

`service_principal_sources` is **not** written. `analyze_sqs_queue_policies`
carries it on the in-memory analysis only, and
[`deny_service_confused_deputy`](deny_service_confused_deputy.md) reads it by
re-running that analyzer rather than by reading these files. That second call is
served from the analyzer's per-session memo and issues no AWS request;
[`../index.md`](../index.md) owns the accounting.

`actions_by_account` is filtered to third-party accounts, as it is in ECR, KMS,
S3, and Secrets Manager. The organization filter runs where an account is
admitted rather than over a set collected first, so the entry's account set and
its action map cannot disagree, and the summary's
`actions_by_third_party_account` and `queues_by_third_party_account` hold what
their names say.

`has_non_account_principals` carries the verdict rather than decorating it: it
is the field that makes a queue naming a `Federated` or `CanonicalUser`
principal a violation. It was dead while the analyzer raised instead of setting
it, and it came into use when the five analyzers converged on recording such a
principal. `_unreadable_queue` leaves it `false`, along with every other field
this check reads, which is what drops the entry from `analyze`'s filter.

`queues_with_wildcards` counts every violation, not only entries with a literal
wildcard principal. A `Federated` or `CanonicalUser` principal is now recorded
as a violation rather than aborting, so it is folded into the same field and the
name understates what the field holds. The same is true of
[`deny_secrets_manager_third_party_access`](deny_secrets_manager_third_party_access.md).

## Known conflict: an unreadable queue is recorded and then filtered out

Status: unresolved. Conflict 8 in
[`../index.md`](../index.md).

The Failure behavior section above says an unparseable document and an
undocumented principal key are each "caught and recorded as a read failure",
and that such a record "withholds the statement from the account". The Result
contract section says `_unreadable_queue` "leaves it `false`, along with every
other field this check reads, which is what drops the entry from `analyze`'s
filter". Both sentences describe the same queue, and they do not agree.

The code matches the second. `_unreadable_queue` in `headroom/aws/sqs.py`
returns an analysis whose `third_party_account_ids`, `has_wildcard_principal`,
and `has_non_account_principals` are all empty, and `analyze` filters on
exactly those three, so the queue never reaches `categorize_result`. The
statement that is withheld belongs to
[`deny_service_confused_deputy`](deny_service_confused_deputy.md), which reads
`service_principal_sources` and files the read failure as a violation. This
check reads none of it, and
`test_a_queue_kept_only_for_a_read_failure_is_not_reported` pins that.

What is unsettled is which behavior was intended here, and INV-01 is why it
matters rather than being a wording problem. A queue whose policy could not be
parsed may grant a third party. Dropped, it contributes no violation, this
check's account is cleared, and the generated Deny is attached against an
allowlist computed without it — a missing observation read as evidence of
safety. The sibling check reaches the opposite verdict from the same record,
for that stated reason.

Against that: the analyzer's catch is deliberate and well argued. It replaced
an abort that cost every other account's results and dropped a source account
the confused-deputy allowlist depended on. Whatever settles this must keep the
run completing.

Not fixed here, because the fix is not a prose change. Making this check see
the read failure would alter which accounts are blocked and which RCPs deploy,
and [`../../README.md`](../../README.md) requires reporting a conflict rather
than guessing which side is right.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. A queue whose policy or principal could not be read contributes no source
   guard, only the knowledge that the read failed; see Failure behavior.
2. `Condition`, `Resource`, and `NotAction` are not evaluated.
3. The queue-level filter for third-party or wildcard findings lives in the
   check's `analyze`, not in the analyzer, which appends every queue that has a
   policy.
4. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a queue policy may grant nothing at all. It is still
   counted as a blocker, because whether the grant is live is not readable from
   the document and INV-01 forbids assuming it is not.

## Acceptance scenarios

1. A queue policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded anywhere:
   neither in `third_party_account_ids` nor in `actions_by_account`.
3. A queue policy with `Principal: "*"` → violation; the account is blocked for
   SQS only.
4. A queue with no `Policy` attribute → skipped.
5. A queue deleted between listing and reading → skipped.
6. `AccessDenied` in one region → the run aborts.
7. A queue whose policy is not valid JSON → recorded as a read failure; the
   queue is withheld from the account, and the remaining queues are still read.
8. A queue naming a principal key AWS does not document → recorded as a read
   failure, on the same grounds.
9. A queue naming a `Federated` principal → the account is blocked for SQS;
   the run continues.
10. A queue naming a `CanonicalUser` principal → the account is blocked, on the same
    grounds.

## Referenced invariants

INV-01 (see Failure behavior), INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_sqs_third_party_access.py`
- `headroom/aws/sqs.py` — `analyze_sqs_queue_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_sqs_third_party_access.py`,
  `tests/test_aws_sqs.py`, `tests/test_aws_policy_documents.py`
