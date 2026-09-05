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
- Evaluates `Condition` only for a bound on the statement's principals, under
  the rule
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
  owns. A condition that narrows the grant rather than the principal set is
  unread, and so are `Resource`/`NotResource` and `NotAction`.
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

Every `ListQueues` request sets `MaxResults` to 1000, the largest value the
API accepts. SQS returns a `NextToken` only when the request set `MaxResults`,
so a paginator that sends none reads one page of at most 1000 queues and stops
as if the region held no more. Queue 1001 would then never be read: a partner
granted there would be left out of the allowlist and denied on deploy, and a
wildcard there would let the statement deploy where it should be withheld
(INV-01). `LIST_QUEUES_PAGE_SIZE` in `headroom/aws/sqs.py` holds the value;
[`../../architecture/aws-execution.md`](../../architecture/aws-execution.md#reading-a-pages-collection-key)
records why this listing alone needs it.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Condition`,
`Action`. The statement is read by `read_statement_principals` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`, which reads the `Principal` element with
`_read_principal` and, where that element is a wildcard, asks the `Condition`
whether it bounds what the wildcard reaches
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)).

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | An unconfined wildcard principal — a literal `*` whose statement carries no bound the reader can prove, or an `Allow` with `NotPrincipal`, which is never confined | `VIOLATION` |
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the queue `COMPLIANT` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | The queue has no policy | Not in the output |
| Not recorded | Only in-organization principals or AWS services | Not in the output |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Violation | An ARN naming no account, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run) owns | `VIOLATION` |

## Failure behavior

| Situation | Behavior |
|---|---|
| `AWS.SimpleQueueService.NonExistentQueue` or `QueueDoesNotExist` | The queue was deleted mid-scan; skipped |
| No `Policy` attribute | Skipped; the queue grants nothing |
| Any other `ClientError` in any region | Logged and re-raised, aborting the run |
| `Statement` neither object nor list | `MalformedPolicyError`, aborting the run |
| `Principal` neither string, list, nor object | `MalformedPolicyError`, aborting the run |
| An `Allow` carrying neither `Principal` nor `NotPrincipal` | `MalformedPolicyError`, aborting the run — AWS stores no such statement, so it is a document misread rather than a grant to nobody |
| Unparseable policy JSON | `json.JSONDecodeError`, aborting the run |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

**This analyzer catches nothing a policy document can raise.** Unparseable
JSON and an undocumented principal key abort the run here as they do from the
other five resource-policy analyzers. They did not always: this analyzer once
skipped such a queue on a warning, and then recorded it with every field this
check reads left empty. Either way the queue contributed no violation, the
account was cleared for this check on the strength of a queue nobody had read,
and the generated Deny was attached against an allowlist computed without it,
which is INV-01's case. A `Federated` or `CanonicalUser` principal is the
opposite correction: it once aborted the run and is now a violation like any
other blocker. The rule is stated once in
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

`total_queues_analyzed` counts the queues that produced an entry — violations,
exemptions, and compliant together — not the queues `ListQueues` returned. A
queue with no policy, or one naming only in-organization principals, is never
entered and is not counted; limitation 2 owns where the second is dropped.

Entry shape: `queue_url`, `queue_arn`, `region`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`,
`confined_by`.

`confined_by` holds the condition keys, lower-cased, that each bounded one of
this policy's statements on their own, unioned across the policy. A key is
recorded whether or not the queue still blocks — one bounded statement beside
one unbounded one reports both the key and the violation — but only for a statement whose `Principal` was a wildcard. The reader
consults a `Condition` for nothing else, so a bound beside a `Principal`
that already names its callers is neither read nor recorded.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
owns which keys can appear and what each proves. The field is additive: a
result file written before it existed lacks the key, and no reader requires
anything outside `summary`
([`../../contracts/results.md`](../../contracts/results.md#summary-keys-a-reader-requires)).

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
principal.

`queues_with_wildcards` counts every violation, not only entries with a literal
wildcard principal. A `Federated` or `CanonicalUser` principal is now recorded
as a violation rather than aborting, so it is folded into the same field and the
name understates what the field holds. The same is true of
[`deny_secrets_manager_third_party_access`](deny_secrets_manager_third_party_access.md).

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. `Resource` and `NotAction` are not evaluated, and neither is a `Condition`
   that narrows the grant rather than the statement's principals — so a grant
   confined by `aws:SourceVpce` still contributes its account at full width
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
2. The queue-level filter for third-party or wildcard findings lives in the
   check's `analyze`, not in the analyzer, which appends every queue that has a
   policy.
3. AWS documents federated principals only for role trust policies, so a
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
7. A queue whose policy is not valid JSON → the run aborts.
8. A queue naming a principal key AWS does not document → the run aborts, on
   the same grounds.
9. A queue naming a `Federated` principal → the account is blocked for SQS;
   the run continues.
10. A queue naming a `CanonicalUser` principal → the account is blocked, on the same
    grounds.
11. A region holding more queues than one `ListQueues` page → every page is
    read, because each request sets `MaxResults`.
12. A queue policy with `Principal: "*"` narrowed by `ArnLike aws:SourceArn`
    to an SNS topic, AWS's documented cross-account subscription → still a
    violation here. `aws:SourceArn` is not a principal key: it names the
    resource that originated a call rather than the caller that made it, so no
    account of its ever reaches this allowlist and it bounds nothing this
    reader can act on
    ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)
    carries the argument, including the near-miss case for reading it as a
    bound and where that case fails). The topic's account reaches the allowlist
    of [`deny_service_confused_deputy`](deny_service_confused_deputy.md)
    through `service_principal_sources`, so that statement stays deployable.
13. That same policy grants `sqs:SendMessage` twice: once to
    `Principal: {"Service": "sns.amazonaws.com"}` under `ArnEquals
    aws:SourceArn`, and once to the wildcard of scenario 12 under `ArnLike`.
    The two are separate documented shapes rather than one statement written
    twice — the first names the service and the second does not, so only the
    second is a wildcard for this check to block. Neither puts its topic's
    account in this check's allowlist.
14. A queue policy with `Principal: "*"` under `StringEquals
    aws:PrincipalAccount` naming `333333333333`, outside the organization →
    compliant rather than a violation; that account enters the allowlist with
    the statement's actions.
15. Two statements on one queue, one wildcard bounded by `StringEquals
    aws:PrincipalAccount` and one bare → violation. Confinement is decided per
    statement and the queue's verdict is the union, so the bounded statement's
    account still enters `third_party_account_ids` and `confined_by` still
    records `aws:principalaccount`, beside the wildcard the other statement
    leaves standing.
16. A `Principal: "*"` under `StringEquals kms:CallerAccount` naming
    `333333333333` → still a violation. No Amazon SQS request carries that key,
    so the clause admits nobody and the statement grants nobody anything; it is
    a bound in a KMS key policy and nowhere else.

## Referenced invariants

INV-01 (see Failure behavior), INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_sqs_third_party_access.py`
- `headroom/aws/sqs.py` — `analyze_sqs_queue_policies`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_sqs_third_party_access.py`,
  `tests/test_aws_sqs.py`, `tests/test_aws_policy_documents.py`
