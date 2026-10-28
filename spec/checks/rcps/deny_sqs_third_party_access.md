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
  - INV-07
  - INV-13
  - INV-16
verification:
  - tests/test_terraform_module_plans.py
  - tests/test_checks_deny_sqs_third_party_access.py
  - tests/test_aws_sqs.py
  - tests/test_aws_policy_documents.py
  - tests/test_generate_rcps.py
---

# deny_sqs_third_party_access

## Objective

Deny SQS access by any principal outside the organization except the
third-party accounts that queue policies already grant, and except on the
queues whose grants no account list can express — a wildcard, an `Allow` with
`NotPrincipal`, a `Federated` or `CanonicalUser` principal — which the
statement spares by ARN. A queue policy edit cannot quietly expose a queue to
a new external account, and no queue the organization already exposes stops
working.

### Scope

Queue access policies, in every enabled region.

### Non-goals

- Does not judge whether an exempt queue *should* be public or should trust a
  federated identity. Every such queue found is spared and recorded as an
  exemption so it stays visible.
- Does not read the KMS key policy protecting an encrypted queue.
- Evaluates `Condition` only for a bound on the statement's principals, under
  the rule
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
  owns. A condition that narrows the grant rather than the principal set is
  unread, and so are `Resource`/`NotResource` and `NotAction`.
- Does not distinguish a dead-letter queue from any other.

## Enforced statement

The standard RCP allowlist statement, with `Action: sqs:*`, composed with a
resource ARN allowlist:

```
Sid:         DenySQSThirdPartyAccess
Effect:      Deny
Principal:   "*"
Action:      sqs:*
NotResource: <each exempt queue ARN>   (Resource: "*" when the list is empty)
Condition:   StringNotEqualsIfExists  aws:PrincipalOrgID   = <this organization>
             StringNotEqualsIfExists  aws:PrincipalAccount = <sqs_third_party_access_account_ids_allowlist>   (omitted when empty)
             BoolIfExists             aws:PrincipalIsAWSService = "false"
```

Pattern 6, the composition of the principal account allowlist every
third-party-access check renders (5a) with a resource ARN allowlist (5b)
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)). The 5a
clause is the one every third-party-access check shares, and is specified once
there. The 5b clause is this check's own: `NotResource` lifts the deny from the
queues whose grants an account list cannot carry, so a request against one of
them is authorized by the queue's own policy exactly as today, and every other
queue in the organization is denied to every principal outside it.

RCPs accept `NotResource` and reject `NotPrincipal` and `NotAction`, so
sparing by resource is the one shape available;
[`deny_s3_third_party_access`](deny_s3_third_party_access.md) takes it for
buckets and carries the argument. A queue contributes one entry, its ARN as the
scan recorded it: SQS has no sub-resource, and every `sqs:*` action authorizes
against the queue ARN itself, where S3 needs a second entry for the objects
under a bucket. When no covered account holds an exempt queue the statement
carries `Resource: "*"` instead: a resource array must hold at least one value,
and an empty `NotResource` would be rejected as malformed (INV-06). This is the
third shape INV-06 names, not the second — the empty list does not turn the
statement off, because a statement with nothing to spare is the strongest form
of the deny, not a broken one.

The module builds the resource clause from two conditionals merged into the
statement rather than one, because Terraform requires both arms of a
conditional to share a type and objects keyed `NotResource` and `Resource` do
not. `terraform validate` does not check that, `terraform plan` does, and the
module's `tests/plan.tftest.hcl` is that plan, run under `tox` by
`tests/test_terraform_module_plans.py`.

Terraform variables: `deny_sqs_third_party_access`,
`sqs_third_party_access_account_ids_allowlist`, and
`sqs_third_party_access_exempt_queue_arns`.

## Evidence

Per enabled region: `sqs:ListQueues` (paginated), then `sqs:GetQueueAttributes`
requesting `Policy` and `QueueArn` per queue.

Every `ListQueues` request sets `MaxResults` to 1000, the largest value the
API accepts. SQS returns a `NextToken` only when the request set `MaxResults`,
so a paginator that sends none reads one page of at most 1000 queues and stops
as if the region held no more. Queue 1001 would then never be read: a partner
granted there would be left out of the allowlist and denied on deploy, and a
wildcard there would leave its queue out of the exempt list and denied on
deploy too (INV-01). `LIST_QUEUES_PAGE_SIZE` in `headroom/aws/sqs.py` holds the
value;
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
| Exemption | An unconfined wildcard principal — a literal `*` whose statement carries no bound the reader can prove, or an `Allow` with `NotPrincipal`, which is never confined; the queue ARN is allowlisted | `EXEMPTION` |
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the queue `COMPLIANT` |
| Exemption | A `Federated` or `CanonicalUser` principal; the queue ARN is allowlisted | `EXEMPTION` |
| Exemption | An ARN naming no account, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run) owns; the queue ARN is allowlisted | `EXEMPTION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Violation | — | **Never produced** |
| Not recorded | The queue has no policy | Not in the output |
| Not recorded | Only in-organization principals or AWS services | Not in the output |

These grants carry no account ID, so no `aws:PrincipalAccount` list can
express them, and until this check spared them by ARN they blocked the account
exactly as an unconfined wildcard did. They are exemptions rather than
violations because the statement now spares the queue: its ARN is in
`NotResource`, so the deny never matches a request against it, and it must not
count against deployability
([`../../architecture/check-framework.md`](../../architecture/check-framework.md#the-three-categories)).
This is the direct form of the claim `EXEMPTION` is reserved for — the scan
reads the very ARN the statement names — as `deny_lambda_auth_type_none` and
`deny_s3_third_party_access` do. A wildcard or a non-account principal bounded
by `Condition` to accounts is read as those accounts instead, and the queue is
compliant, because an account list *can* express that grant.

This check can never report a violation, so every account is always safe for
it, and it always places at root when any account produced a result. The
safety argument therefore rests on the exempt list being complete, which is
why INV-07 applies and why the round trip below is specified end to end.

The shape this most often spares is AWS's own documented cross-account
SNS-to-SQS queue policy: `Principal: "*"` under `ArnEquals` or `ArnLike
aws:SourceArn` naming the topic. `aws:SourceArn` is not a principal key, so the
reader leaves the wildcard unconfined and the queue is exempt; before this
check spared by ARN, that queue blocked its account, and
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)
owns why the key will not be read as a bound. The SNS delivery itself is a
service call, spared by the `aws:PrincipalIsAWSService` clause whether or not
the queue is exempt. The exemption spares whoever else the wildcard reaches,
which is what the reader could not rule out.

## Failure behavior

| Situation | Behavior |
|---|---|
| `AWS.SimpleQueueService.NonExistentQueue` or `QueueDoesNotExist` | The queue was deleted mid-scan; skipped |
| No `Policy` attribute | Skipped; the queue grants nothing |
| Any other `ClientError` in any region | Logged and re-raised, aborting the run |
| `Statement` neither object nor list, or a list holding anything but objects | `MalformedPolicyError`, aborting the run |
| `Principal` neither string, list, nor object | `MalformedPolicyError`, aborting the run |
| An `Allow` carrying neither `Principal` nor `NotPrincipal` | `MalformedPolicyError`, aborting the run — AWS stores no such statement, so it is a document misread rather than a grant to nobody |
| Unparseable policy JSON | `json.JSONDecodeError`, aborting the run |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

**This analyzer catches nothing a policy document can raise.** Unparseable
JSON and an undocumented principal key abort the run here as they do from the
other five resource-policy analyzers. They did not always: this analyzer once
skipped such a queue on a warning, and then recorded it with every field this
check reads left empty. Either way the queue contributed no finding, the
account was cleared for this check on the strength of a queue nobody had read,
and the generated Deny was attached against an allowlist computed without it,
which is INV-01's case. A `Federated` or `CanonicalUser` principal is the
opposite correction: it once aborted the run, then blocked the account as a
violation, and is now an exemption like every other grant no account list can
express. The rule is stated once in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md).

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `queues_third_parties_can_access` | Exemptions plus compliant |
| `queues_with_wildcards` | Exemptions only |

Summary fields beyond the common three: `total_queues_analyzed`,
`queues_third_parties_can_access`, `queues_with_wildcards`, `violations`,
`exemptions`, `unique_third_party_accounts`, `third_party_account_count`,
`exempt_queue_arns`, `actions_by_third_party_account`,
`queues_by_third_party_account`.

`violations` is structurally zero: `categorize_result` never returns
`VIOLATION`. It is written anyway, because a reader cannot tell an absent key
from a genuine zero and RCP parsing refuses to guess
([`../../contracts/results.md`](../../contracts/results.md)).
`queues_with_wildcards` in the summary is the exemption count;
`queues_third_parties_can_access` counts the exemptions that also carry a
third-party account ID, plus the compliant queues, so a public queue that
grants no named account is not counted as third-party access.

`exempt_queue_arns` is a sorted list of queue ARN **strings**, one per
exempted queue, and is the second allowlist this check declares. A queue ARN
carries the account between the region and the queue name, so
`exclude_account_ids` writes it as `REDACTED`, and the declaration sets
`restores_account_ids`: parsing puts the file's account back, and rendering
rewrites the field to the account's generated local. It is the first RCP
allowlist to set the flag; `deny_iam_user_creation` and
`deny_lambda_auth_type_none` set it on the SCP side.

**Result files written before `exempt_queue_arns` existed do not parse.** RCP
parsing aborts by name on a summary missing a declared key, because an absent
key cannot be told from an account that observed nothing (INV-01), and its
error says which file to delete and re-scan.

`total_queues_analyzed` counts the queues that produced an entry — violations,
exemptions, and compliant together — not the queues `ListQueues` returned. A
queue with no policy, or one naming only in-organization principals, is never
entered and is not counted; limitation 2 owns where the second is dropped.

Entry shape: `queue_url`, `queue_arn`, `region`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`,
`confined_by`.

`confined_by` holds the condition keys, lower-cased, that each bounded one of
this policy's statements on their own, unioned across the policy. A key is
recorded whether or not the queue is still exempt — one bounded statement
beside one unbounded one reports both the key and the exemption — but only for
a statement whose `Principal` was a wildcard. The reader consults a `Condition`
for nothing else, so a bound beside a `Principal` that already names its
callers is neither read nor recorded.
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
principal an exemption. It was dead while the analyzer raised instead of
setting it, and it came into use when the five analyzers converged on recording
such a principal.

`queues_with_wildcards` holds every exemption, not only entries with a literal
wildcard principal. A `Federated` or `CanonicalUser` principal is folded into
the same field, so the name understates what it holds. The equivalent field on
[`deny_ecr_third_party_access`](deny_ecr_third_party_access.md),
[`deny_kms_third_party_access`](deny_kms_third_party_access.md), and
[`deny_secrets_manager_third_party_access`](deny_secrets_manager_third_party_access.md)
understates the same way, holding their violations; on
[`deny_s3_third_party_access`](deny_s3_third_party_access.md) it holds
exemptions, as here.

## Placement and generated policy

Every account is safe, so placement lands at root; there is no blocker this
check can raise. The principal allowlist is the union of
`unique_third_party_accounts` across covered accounts, as for every RCP.

The exempt-queue round trip (INV-07):

1. `summary.exempt_queue_arns` — queue ARNs, with the account ID replaced by
   `REDACTED` when `exclude_account_ids` is set. A queue ARN carries the
   account between the region and the queue name, and the redaction reads that
   field whatever the service.
2. RCP parsing reads it as the second declared allowlist, by the same reader
   that reads `unique_third_party_accounts`, aborts on a file lacking it, and
   restores the account ID into each ARN once the account is identified,
   because this check's `Allowlist` sets `restores_account_ids`.
3. `RCPCheckResult.allowlist_values["exempt_queue_arns"]`.
4. The sorted union across the accounts a placement covers.
5. `RCPPlacementRecommendations.allowlist_values["exempt_queue_arns"]`.
6. The `sqs_third_party_access_exempt_queue_arns` Terraform variable, rendered
   after the principal allowlist whenever the boolean is true, `[]` included,
   with each ARN's account field rewritten to `${local.<account_name>_account_id}`
   where the account is in the hierarchy. An ARN naming an account the
   hierarchy does not have is emitted literally.

The module validates each entry as `arn:aws:sqs:` followed by a region, a
12-digit account ID, and a queue name drawn from letters, digits, hyphens and
underscores with an optional `.fifo` suffix. Terraform resolves the account
local before the validation runs, so a rewritten entry passes it.

**An empty exempt list leaves the policy on.** With no queue to spare the
module renders `Resource: "*"` in place of `NotResource`, and the statement
denies every out-of-organization principal on every queue, which is the good
case rather than a broken run. This is the third INV-06 shape, alongside the
omitted `aws:PrincipalAccount` clause; the declaration therefore sets no
`empty_allowlist_comment`.

## Accepted limitations

1. `Resource` and `NotAction` are not evaluated, and neither is a `Condition`
   that narrows the grant rather than the statement's principals — so a grant
   confined by `aws:SourceVpce` still contributes its account at full width
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
2. The queue-level filter for third-party or wildcard findings lives in the
   check's `analyze`, not in the analyzer, which appends every queue that has a
   policy.
3. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a queue policy may grant nothing at all. The queue
   is still spared, because whether the grant is live is not readable from the
   document and INV-01 forbids assuming it is not.
4. An exempt queue is spared for **every** principal and every `sqs:*` action,
   not only the grant that made it exempt. A queue public for `SendMessage` is
   also reachable by any third-party account its policy names for anything
   else, and a later edit to that queue's policy is not caught by this
   statement. The queue's own policy remains the only control on it.
5. A queue made public, or granted to a federated identity, between the scan
   and the apply is absent from the exempt list; its next cross-organization
   request is denied.
6. A queue deleted after the scan stays in the list, which is harmless: the
   `NotResource` entry matches nothing. A queue name is unique only within its
   account and region, so a queue re-created under the same name in the same
   account is spared too, until the next scan; unlike a bucket name, it cannot
   be taken by another account.
7. Every exempt queue ARN, region and account included, competes for the
   module's 5,120-character RCP budget. An organization with many public
   queues can exceed it at the root; the module fails at plan time with the
   character count rather than attaching a truncated policy.
8. An account excluded from analysis — one in `skip_account_ids`, in a
   non-ACTIVE lifecycle state, or created between the scan and the apply —
   contributes no exempt queue, and the root placement this check always
   produces reaches it anyway. The management account is not part of this gap,
   since no RCP reaches it
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#scp-versus-rcp)).
   [`../../contracts/placement.md`](../../contracts/placement.md#rcp-placement)
   records the general case as "excluded from analysis" and calls it open and
   deliberate. A queue already public in such an account is denied on the next
   cross-organization request, while the check itself reports every analyzed
   account compliant.
9. A queue whose only external grant is the documented SNS-to-SQS wildcard is
   spared whole, though the reader could not tell it from a public queue.
   Reading `aws:SourceArn` as a bound is settled against
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read));
   what not reading it costs moved from blocking the account to sparing the
   queue for every principal.

## Acceptance scenarios

1. A queue policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded anywhere:
   neither in `third_party_account_ids` nor in `actions_by_account`.
3. A queue policy with `Principal: "*"` → exemption; `summary.exempt_queue_arns`
   holds the queue ARN, and the account is not blocked.
4. A queue with no `Policy` attribute → skipped.
5. A queue deleted between listing and reading → skipped.
6. `AccessDenied` in one region → the run aborts.
7. A queue whose policy is not valid JSON → the run aborts.
8. A queue naming a principal key AWS does not document → the run aborts, on
   the same grounds.
9. A queue naming a `Federated` principal → exemption, recorded rather than
   raised, and the queue ARN is exempt; the run continues.
10. A queue naming a `CanonicalUser` principal → exemption, on the same
    grounds.
11. A region holding more queues than one `ListQueues` page → every page is
    read, because each request sets `MaxResults`.
12. A queue policy with `Principal: "*"` narrowed by `ArnLike aws:SourceArn`
    to an SNS topic, AWS's documented cross-account subscription → exemption;
    the queue is spared by ARN rather than the account blocked. `aws:SourceArn`
    is not a principal key: it names the resource that originated a call rather
    than the caller that made it, so no account of its ever reaches this
    allowlist and it bounds nothing this reader can act on
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
    second is a wildcard this check spares the queue for. Neither puts its
    topic's account in this check's allowlist.
14. A queue policy with `Principal: "*"` under `StringEquals
    aws:PrincipalAccount` naming `333333333333`, outside the organization →
    compliant rather than an exemption; that account enters the allowlist with
    the statement's actions.
15. Two statements on one queue, one wildcard bounded by `StringEquals
    aws:PrincipalAccount` and one bare → exemption. Confinement is decided per
    statement and the queue's verdict is the union, so the bounded statement's
    account still enters `third_party_account_ids` and `confined_by` still
    records `aws:principalaccount`, beside the wildcard the other statement
    leaves standing.
16. A `Principal: "*"` under `StringEquals kms:CallerAccount` naming
    `333333333333` → still an exemption. No Amazon SQS request carries that
    key, so the clause admits nobody and the statement grants nobody anything;
    it is a bound in a KMS key policy and nowhere else, and the wildcard is
    read as unconfined.
17. An account with no exempt queue → `violations: 0`, `exemptions: 0`, and
    `exempt_queue_arns: []`, present rather than absent; a module covering
    only such accounts renders `sqs_third_party_access_exempt_queue_arns = []`
    and the statement carries `Resource: "*"`
    (`empty_exempt_lists_render_resource_star` in the module's
    `tests/plan.tftest.hcl`; `populated_exempt_lists_render_not_resource`
    there pins the queue ARN under `NotResource`).
18. Two accounts, one with an exempt queue and one without → the root
    recommendation carries that one ARN, and the module call renders it with
    the account field as that account's generated local
    (`tests/test_generate_rcps.py` drives this end to end).
19. A result file written with `exclude_account_ids`, carrying `REDACTED` in
    the queue ARN's account field → RCP parsing restores the file's account
    into the ARN.
20. A result file written before `exempt_queue_arns` existed → RCP parsing
    aborts naming the file, the key, and the check, and prescribes deleting
    the file and re-running. The reader is generic;
    `tests/test_generate_rcps.py` pins the abort for
    `deny_s3_third_party_access`.
21. An entry that is not a queue ARN — a bucket ARN, a queue ARN with no
    account field, or one carrying `/` → the module's variable validation
    rejects the plan with a message naming the variable and the required form
    (`queue_arn_without_account_is_rejected` in
    `test_environment/modules/rcps/tests/plan.tftest.hcl`, run under `tox` by
    `tests/test_terraform_module_plans.py`; the other two forms were exercised
    against the regex outside the suite).

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-07, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_sqs_third_party_access.py`
- `headroom/aws/sqs.py` — `analyze_sqs_queue_policies`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `headroom/parse_results.py` — `_read_declared_allowlist`,
  `union_allowlist_values`
- `headroom/write_results.py` — `restore_account_id_in_arns`
- `headroom/terraform/parameters.py` — `_replace_account_id_in_arn`
- `test_environment/modules/rcps/locals.tf`
- `test_environment/modules/rcps/variables.tf`
- Tests: `tests/test_checks_deny_sqs_third_party_access.py`,
  `tests/test_aws_sqs.py`, `tests/test_aws_policy_documents.py`,
  `tests/test_generate_rcps.py`
