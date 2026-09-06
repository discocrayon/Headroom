---
id: deny_service_confused_deputy
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_service_confused_deputy.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-06
  - INV-10
  - INV-13
verification:
  - tests/test_checks_deny_service_confused_deputy.py
  - tests/test_aws_helpers.py
  - tests/test_aws_policy_documents.py
---

# deny_service_confused_deputy

## Objective

Narrow the AWS service exemption the other six RCP statements grant.

A service call carries no `aws:PrincipalOrgID`, so each of those statements must
exempt service principals or it would deny every service integration in the
organization. That exemption is a hole: a service acting on an out-of-organization
caller's behalf reaches organization resources through it. This statement closes
the hole for calls that say who they are acting for.

### Scope

Service calls that populate `aws:SourceAccount`, across the six services the
other statements cover.

### Non-goals

- Does not reach a call populating only `aws:SourceArn`, or no source key at
  all. `Null` on `aws:SourceAccount` scopes the deny to calls carrying that one
  key.
- Does not simulate whether a `Condition` would match a request at runtime,
  and does not read `Resource` or `NotAction`. No RCP check simulates. All
  seven read a `Condition` structurally, and what separates this one is which
  keys it reads and what it does with them: this check reads the four source
  keys
  ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#source-guards))
  to build an allowlist out of the accounts a service acted for, and the six
  third-party-access checks read the principal keys
  ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards))
  to bound how far a statement's principals reach. That difference decides
  what an unreadable clause costs — here it makes the recorded set incomplete
  and poisons the whole block, there it can only fail to prove its own key's
  bound — and that document owns the argument.
- Does not report a service principal trusted with no source guard at all. See
  limitation 1, which is this check's principal deployment risk.
- Does not count the resources or sources the six analyzers read. Five of the
  six drop a resource that produced nothing reportable before returning, and
  SQS keeps every queue that carries a policy, so a tally taken in this check
  would be exhaustive for queues and incidental for the other five, seeing
  only the unguarded sources that sit on a resource kept for another reason.
  A plausible-looking wrong number is worse than no number, so this check
  writes no count of what was read. `resources_with_actionable_source` counts
  the resources that reached it; the Result contract states what that
  population is and why it is complete.

## Enforced statement

```
Effect:    Deny
Principal: *
Action:    ecr:*, kms:*, s3:*, secretsmanager:*, sqs:*, sts:AssumeRole
Resource:  *
Condition: StringNotEqualsIfExists
             aws:SourceOrgID  = <this organization>
             aws:SourceAccount = <allowlist>     (only when non-empty)
           Null
             aws:SourceAccount = "false"
           Bool
             aws:PrincipalIsAWSService = "true"
```

Pattern 6, composition — the only one, and not 5a because the allowlisted
account is not the principal.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md) owns that
argument.

`StringNotEqualsIfExists` on `aws:SourceOrgID` catches sources in standalone
accounts, which belong to no organization and so carry no organization ID.

The `aws:SourceAccount` key is merged in only when the allowlist is non-empty
(INV-06): rendered empty it would deny every source rather than none.

`Bool aws:PrincipalIsAWSService = "true"` is the clause that scopes the whole
statement to service calls at all. The Objective above is to narrow the AWS
service exemption the other six statements grant through `BoolIfExists
aws:PrincipalIsAWSService = "false"`; this clause is what names the principals
that exemption applies to, so that this statement narrows it rather than
denying on the source keys alone for every principal, service or not.

## Evidence

The check issues no AWS call directly. It re-runs the six analyzers the other
six RCP checks use and reads `service_principal_sources` off each analysis.
Each of the six is memoized on the account's session, so re-running them costs
no AWS request when the other check has already run in that account — and pays
for the reads once when it has not. [`../index.md`](../index.md) lists the calls
and owns the accounting.

| Analyzer | Resource identifier | Region |
|---|---|---|
| `analyze_ecr_policies` | Repository ARN, or `"registry"` for a registry policy, which no ARN can equal | Yes |
| `analyze_kms_key_policies` | Key ID | Yes |
| `analyze_s3_bucket_policies` | Bucket name | No — global |
| `analyze_secrets_manager_policies` | Secret name | Yes |
| `analyze_sqs_queue_policies` | Queue ARN | Yes |
| `analyze_iam_roles_trust_policies` | Role name | No — global |

`read_service_principal_sources` in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md) is the one
rule all six read a source guard by. They hand it `Allow` statements only; a
`Deny` is never read, which is the second half of limitation 1.

A source is a `Service` principal, or a wildcard principal — `*` or
`{"AWS": "*"}` — narrowed by one of the four source keys. Only a service call
carries a source key, so such a statement is a grant to whichever service
delivers for those sources, and the guard names who it is for even though the
`Principal` element does not. AWS's own cross-account SNS-to-SQS queue policy
is written that way. A wildcard under no source key is not a source here; it is
the plain wildcard the six third-party-access checks block the account for,
unless a confining key bounds it
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)).
The same wildcard under a guard this check cannot read is a `read_failure`, by
the same rules a `Service` principal's guard is read by.

A finding is kept only when it names out-of-organization source accounts, names
a source no allowlist can enumerate, or could not be read. Everything else is
dropped before categorization.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | `has_wildcard_source` — the guard names sources no allowlist can enumerate | `VIOLATION` |
| Violation | `has_wildcard_source` — an `...IfExists` operator guards a key other than `aws:SourceAccount`; the guard names its sources precisely, but also matches a request naming none | `VIOLATION` |
| Violation | `read_failure` is set — the source guard could not be read | `VIOLATION` |
| Compliant | The guard names out-of-organization accounts, all enumerable | `COMPLIANT` |
| Compliant | A wildcard principal — `*` or `{"AWS": "*"}` — narrowed by such a guard; `service_principal` is `*` | `COMPLIANT` |
| Not recorded | An unguarded service principal, a wildcard principal under no source key, or a guard naming only organization sources | Dropped before categorization |

A failed read is a violation for the same reason a wildcard source is: the
account's allowlist cannot be computed, so the statement must be withheld rather
than deployed against a guess (INV-01).

`aws:SourceAccount` is excepted from the second row because this statement's
own `Null` clause makes an `...IfExists` guard on that one key safe — see
[`../../contracts/policy-model.md`](../../contracts/policy-model.md) for why.

## Failure behavior

| Failure | Behavior |
|---|---|
| Any `ClientError` from the six analyzers | Propagates, aborting the run (INV-02) |
| Any other abort one of the six analyzers raises — `MalformedPolicyError`, `UnknownPrincipalTypeError`, `UnknownGranteeTypeError`, `UnknownGrantPrincipalError`, `InvalidFederatedPrincipalError`, a `TypeError` on an `Action`, or a `KeyError` on a KMS grant missing its ID or its grantee | Propagates, aborting the run. This check re-runs the analyzers, so it inherits every abort they have; each analyzer's own specification owns when it raises |
| A source key under an operator that does not pin it, an `aws:SourceAccount` value that is neither an account ID nor a wildcard, or an unreadable organization scope | Recorded as `read_failure` on the finding, which makes it a violation |

The third row is deliberate and is the one place this check does not abort. The
reader sits inside all six analyzers, and six pre-existing checks share them
without ever reading a source guard, so raising would take
`deny_s3_third_party_access` and its five siblings down with it. Recording the
failure withholds this statement from the account without disturbing theirs.

## Result contract

Base document shape. Entry fields: `resource_type` (`ecr`, `kms`, `s3`,
`secretsmanager`, `sqs`, or `iam`), `resource_identifier`, `region` (null for a
global resource), `service_principal` (`*` for a wildcard principal narrowed by
a source key; null when the read failed, whatever principals the statement
named), `source_account_ids`, `has_source_condition`, `has_wildcard_source`,
`read_failure`.

For a Secrets Manager finding, `region` is what separates the replicas of one
secret, which share a name: `resource_identifier` is the secret name, so two
replicas differ in no other identity field.

Two entry fields changed after the check first shipped, and both are additive: a
Secrets Manager entry written before the analysis recorded its region carries
`region: null` though the secret is regional, and an ECR entry written before
the identifier became the repository ARN carries the repository name. No reader
requires anything outside `summary`
([`../../contracts/results.md`](../../contracts/results.md#summary-keys-a-reader-requires)).

A multi-Region KMS key is the same shape as a replicated secret: its replicas
share one `mrk-` key ID and differ only in `region`, so they are two resources.

Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `resources_with_actionable_source` | Distinct resources, keyed by `resource_type`, `resource_identifier`, and `region`, that produced at least one entry. Not the resources the analyzers read |
| `violations` | Count. **This is the field placement reads.** |
| `sources_with_wildcard_source` | Violations with `has_wildcard_source`: the guard names sources no allowlist can enumerate — a wildcard account, an accountless ARN, or another organization — or an `...IfExists` operator on a key other than `aws:SourceAccount` lets a request omit the key. Both `has_wildcard_source` rows of the Decision table |
| `sources_with_failed_read` | Violations whose source guard could not be read |
| `unique_third_party_accounts` | The statement's `aws:SourceAccount` allowlist |
| `third_party_account_count` | Its length |

`sources_with_wildcard_source` and `sources_with_failed_read` sum to
`violations`. `_violation_cause` in the check module is the one rule for why an
entry is a violation: it names a failed read first, because the guard is unknown
and nothing a wildcard flag says can add to that, and a wildcard source
otherwise. `categorize_result` reads it to decide the category and
`build_summary_fields` to count by cause, so the two counts partition
`violations` by construction rather than by the convention that
`unreadable_service_principal_source`, the one constructor of a failed read,
never sets `has_wildcard_source`. The two do not count the same unit. A readable
statement yields one entry per service principal it names; an unreadable one
yields one entry for the statement, because `read_service_principal_sources`
catches the error at statement scope and returns a single entry, discarding
whatever principals it had already resolved. A statement trusting three
services counts three under a guard no allowlist can express and one when its
guard cannot be read. Together they are the summary-level signal for which
cause a violation came from; without them, `violations: 1` sends the reader
through every entry to learn which. This is the shape
[`deny_kms_third_party_access`](deny_kms_third_party_access.md) gives
`keys_with_unresolved_grants`.

`resources_with_actionable_source`, `sources_with_wildcard_source`, and
`sources_with_failed_read` are additive in the same way: a result file written
before they existed lacks the keys, and no reader requires anything outside
`summary`.

A source is actionable when this check keeps it: it names out-of-organization
source accounts, names a source no allowlist can enumerate, or could not be
read. `resources_with_actionable_source` is complete over that population, which
is the sources the six analyzers produce: a statement an analyzer's own gate
rejects, an `Effect: Deny`, a role trust granting no `sts:AssumeRole`, or a key
policy statement granting only `kms:RetireGrant`, never becomes a source. Every
analyzer retains a resource carrying an actionable source, five by naming
`has_actionable_service_principal_source` in their retention test and SQS by
retaining every queue that carries a policy, and this check filters each source
through `is_actionable_service_principal_source`, the per-source rule
`has_actionable_service_principal_source` applies with `any`. So every resource
carrying one reaches the check, and the distinct count over its entries is the
whole actionable population. A resource whose sources are all unguarded is
neither entered nor counted, and an AWS-managed KMS key is skipped
before analysis
([`deny_kms_third_party_access`](deny_kms_third_party_access.md#result-contract)).

The six third-party-access checks each write a `total_*_analyzed` by the rule
[`../../contracts/results.md`](../../contracts/results.md#the-two-list-shape)
states, and this field counts by the same rule. It is not named as a total
because, as that section says, this check scans six resource types and has
nothing single to name a key for, and because one total spanning all six would
nonetheless read as the count of what was scanned, which is the tally the
Non-goals decline to write.

## Placement and generated policy

| | |
|---|---|
| Terraform variable | `deny_service_confused_deputy` |
| Allowlist variable | `service_confused_deputy_source_account_ids_allowlist` |
| Allowlist round trip | `unique_third_party_accounts` → `third_party_accounts` → placement union → module parameter (INV-07) |
| Placement input | `summary.violations` |

The allowlist variable carries `source_` before `account_ids`, unlike its six
siblings, because the list holds the accounts a service acted **for** rather
than the calling principals. The naming pattern would predict
`service_confused_deputy_account_ids_allowlist`. Do not normalize it; the
Terraform module defines it this way.

Its `TerraformSection` is `SERVICE_CONFUSED_DEPUTY`, declared last in
`headroom/enums.py`, so it renders after the alphabetical run of the six
services rather than inside it, because it names no single service.

## Accepted limitations

1. **A service principal trusted with no source guard is dropped, not
   reported.** Every service role trust policy and every log bucket in an
   account carries one, and listing them would bury the sources that matter.
   Dropping them is not the same as their being safe: `aws:SourceAccount` is
   populated by the calling service from the resource that drove the call, so an
   unguarded trust driven by an out-of-organization account is within the
   statement's reach and will be denied on deploy. **This is the check's
   principal deployment risk.**

   Some of those policies do name the driver, and this check does not read
   it. One idiom for the confused-deputy guard keeps the `Allow Service:...`
   statement unguarded and pins the source in a companion `Deny` written
   `StringNotEquals aws:SourceAccount <account>`, or `ArnNotEquals
   aws:SourceArn`. Every adapter reads `Principal` and `Condition` under
   `Effect: Allow` only, so the `Deny` is skipped, the `Allow` beside it is
   an unguarded source, and the account the pair permits is not recorded:
   the statement deploys and denies the driver the policy named. Where the
   pin is absent from `Allow` and `Deny` alike, the driver is truly unnamed
   and only CloudTrail finds it.

   Reading the pin off the `Deny` is standing intent. It is not the mirror
   image of the `Allow` read. It must accept only the negated operators —
   `StringNotEquals`, `ArnNotEquals`, and their `...IfExists` forms — on
   `aws:SourceAccount` and `aws:SourceArn`; take only exact account IDs from
   them, since a wildcard or an organization scope under a negated operator
   permits nothing enumerable; ignore rather than raise on anything else
   under `Deny`, where an unreadable condition withholds nothing; not match
   the `Deny`'s `Action` or `Resource` against the `Allow`'s, which this
   analysis never reads; and move the source read above the `Effect` gate in
   all six adapters. An account the policy names can only lengthen the
   allowlist, never withhold a statement, so every account the check clears
   today it would still clear. Until then no adapter reads a `Condition`
   under `Deny` for any purpose, and scenario 11 pins the idiom as not
   recorded.
2. **One statement covers six services**, so one verdict gates all of them
   (INV-10 holds only because the statement is single). A violation found on one
   SQS queue withholds the statement protecting ECR, KMS, S3, Secrets Manager,
   and STS in that account too.
3. Organization scopes are compared exactly, with no wildcard expansion.
4. A call populating only `aws:SourceArn` is outside the statement, so a service
   integration guarded that way is neither measured nor protected.
5. **Treating an `...IfExists` guard on `aws:SourceArn`, `aws:SourceOrgID`, or
   `aws:SourceOrgPaths` as a wildcard is a change to this analysis, not to any
   committed artifact.** Result artifacts are written by a scan and read back by
   a later, separate stage
   ([`../../architecture/overview.md`](../../architecture/overview.md)); only
   the scan reads AWS. An account this rule now marks a violation keeps its
   prior result — and whatever that placed — until the next live run re-reads
   its policies and a new result supersedes the old one.

### Rollout

Before enabling this statement for a target:

1. Review CloudTrail for calls into that target's accounts where
   `aws:PrincipalIsAWSService` is true and `aws:SourceAccount` falls outside the
   organization. Those are the drivers discovery cannot see, because the
   resource policy names no account for it to record. Add the legitimate ones to
   the allowlist, or pin them in the resource policy so the next run finds them.
2. Deploy to a test OU with the discovered allowlist and watch for denials
   before going organization-wide.

`unique_third_party_accounts` measures the sources a resource policy already
pins. It is not a measurement of the estate's out-of-organization
service-mediated access, and reading it as one is what makes step 1 necessary.

Rolling back a deployed statement is not specific to this check:
[`../../contracts/terraform.md`](../../contracts/terraform.md#rollback) owns
that procedure.

## Acceptance scenarios

1. An S3 bucket policy trusting `logging.s3.amazonaws.com` with
   `aws:SourceAccount` naming an out-of-organization account → compliant, and
   that account reaches `unique_third_party_accounts`.
2. The same guard naming only organization accounts → not recorded at all.
3. A guard whose `aws:SourceAccount` is a wildcard → violation, and the account
   is not cleared.
4. A guard naming `aws:SourceOrgID` for a different organization → violation:
   that organization's accounts are not enumerable, so the guard is a wildcard
   source and `summary.sources_with_wildcard_source` counts it.
5. A statement whose source guard cannot be read → violation with `read_failure`
   set and counted in `summary.sources_with_failed_read`, and the other six
   checks still complete.
6. A queue trusting `sns.amazonaws.com` with no source guard → not recorded
   (limitation 1).
7. An account matching scenario 3 → `summary.violations` is 1,
   `summary.sources_with_wildcard_source` is 1, and placement does not clear it.
8. A guard on `aws:SourceArn` written with `ArnEqualsIfExists` → violation, and
   the account is not cleared, even though the guard names an account, and
   `summary.sources_with_wildcard_source` counts it.
9. A queue policy with `Principal: "*"` narrowed by `ArnEquals aws:SourceArn`
   to a topic in an out-of-organization account, AWS's documented cross-account
   SNS subscription → compliant, with `service_principal` `*`, and the topic's
   account reaches `unique_third_party_accounts`. The queue is separately a
   wildcard violation for
   [`deny_sqs_third_party_access`](deny_sqs_third_party_access.md):
   `aws:SourceArn` names the resource that originated the call and not the
   caller that made it, so it bounds no principal set and the wildcard stands
   there
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
10. The same `Principal: "*"` under `aws:PrincipalOrgID` naming this
    organization → not recorded here; no source key, no source. That other
    check no longer records it either: an organization scope naming **this**
    organization bounds the wildcard to callers the deployed statement already
    spares
    ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)),
    so the shape now clears both. One naming **another** organization bounds it
    to a set no account allowlist can enumerate, which confines nothing, so the
    queue stays a violation there.
11. A queue policy whose `Allow` trusts `sns.amazonaws.com` with no guard,
    beside a `Deny` on the same action written `StringNotEquals
    aws:SourceAccount` naming an out-of-organization account → not recorded;
    the account does not reach `unique_third_party_accounts`, and on deploy the
    statement denies the driver the policy named (limitation 1).
12. A secret replicated to two regions, each replica's policy trusting a
    service under a guard naming an out-of-organization account → two
    compliant entries sharing `resource_identifier` and separated by
    `region`, and `summary.resources_with_actionable_source` is 2.

## Referenced invariants

INV-01, INV-02, INV-06, INV-10, INV-13.

## Implementation

- `headroom/checks/rcps/deny_service_confused_deputy.py` — class
  `DenyServiceConfusedDeputyCheck`, dataclass `ServicePrincipalSourceFinding`,
  `_violation_cause`
- `headroom/aws/policy_documents.py` — `read_service_principal_sources`,
  `has_actionable_service_principal_source`,
  `is_actionable_service_principal_source`,
  `unreadable_service_principal_source`
- `headroom/terraform/parameters.py` — `render_check_parameters`
- `test_environment/modules/rcps/locals.tf` — the rendered statement
- Tests: `tests/test_checks_deny_service_confused_deputy.py`,
  `tests/test_aws_policy_documents.py`, `tests/test_aws_helpers.py`
