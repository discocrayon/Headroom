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
- Does not evaluate `Condition`, `Resource`, or `NotAction` — no RCP check
  simulates whether a condition would match a request at runtime. That is
  different from not reading `Condition` at all, which is true of the six
  third-party-access checks
  ([`../../contracts/policy-model.md`](../../contracts/policy-model.md)) but
  not of this one: it reads the block structurally, for the four source keys
  named in that document's Source guards section.
- Does not report a service principal trusted with no source guard at all. See
  limitation 1, which is this check's principal deployment risk.

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
| `analyze_ecr_policies` | Repository name, the template's prefix for a creation template policy, or `"registry"` for a registry policy | Yes |
| `analyze_kms_key_policies` | Key ID | Yes |
| `analyze_s3_bucket_policies` | Bucket name | No — global |
| `analyze_secrets_manager_policies` | Secret name | No |
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
the plain wildcard the six third-party-access checks block the account for. The
same wildcard under a guard this check cannot read is a `read_failure`, by the
same rules a `Service` principal's guard is read by.

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
| A source key under an operator that does not pin it, an `aws:SourceAccount` value that is neither an account ID nor a wildcard, or an unreadable organization scope | Recorded as `read_failure` on the finding, which makes it a violation |

The second row is deliberate and is the one place this check does not abort. The
reader sits inside all six analyzers, and six pre-existing checks share them
without ever reading a source guard, so raising would take
`deny_s3_third_party_access` and its five siblings down with it. Recording the
failure withholds this statement from the account without disturbing theirs.

## Result contract

Base document shape. Entry fields: `resource_type` (`ecr`, `kms`, `s3`,
`secretsmanager`, `sqs`, or `iam`), `resource_identifier`, `region` (null for a
global resource), `service_principal` (`*` for a wildcard principal narrowed
by a source key; null when the read failed before any principal resolved),
`source_account_ids`, `has_source_condition`,
`has_wildcard_source`, `read_failure`.

Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `violations` | Count. **This is the field placement reads.** |
| `unique_third_party_accounts` | The statement's `aws:SourceAccount` allowlist |
| `third_party_account_count` | Its length |

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
4. A guard naming `aws:SourceOrgID` for a different organization → the source is
   out of organization and is recorded.
5. A statement whose source guard cannot be read → violation with `read_failure`
   set, and the other six checks still complete.
6. A queue trusting `sns.amazonaws.com` with no source guard → not recorded
   (limitation 1).
7. An account matching scenario 3 → `summary.violations` is 1 and placement does
   not clear it.
8. A guard on `aws:SourceArn` written with `ArnEqualsIfExists` → violation, and
   the account is not cleared, even though the guard names an account.
9. A queue policy with `Principal: "*"` narrowed by `ArnEquals aws:SourceArn`
   to a topic in an out-of-organization account, AWS's documented cross-account
   SNS subscription → compliant, with `service_principal` `*`, and the topic's
   account reaches `unique_third_party_accounts`. The queue is separately a
   wildcard violation for
   [`deny_sqs_third_party_access`](deny_sqs_third_party_access.md), which does
   not read `Condition`.
10. The same `Principal: "*"` under `aws:PrincipalOrgID` alone → not recorded
    here; the wildcard is that other check's to block.
11. A queue policy whose `Allow` trusts `sns.amazonaws.com` with no guard,
    beside a `Deny` on the same action written `StringNotEquals
    aws:SourceAccount` naming an out-of-organization account → not recorded;
    the account does not reach `unique_third_party_accounts`, and on deploy the
    statement denies the driver the policy named (limitation 1).

## Referenced invariants

INV-01, INV-02, INV-06, INV-10, INV-13.

## Implementation

- `headroom/checks/rcps/deny_service_confused_deputy.py` — class
  `DenyServiceConfusedDeputyCheck`, dataclass `ServicePrincipalSourceFinding`
- `headroom/aws/policy_documents.py` — `read_service_principal_sources`,
  `has_actionable_service_principal_source`, `unreadable_service_principal_source`
- `headroom/terraform/parameters.py` — `render_check_parameters`
- `test_environment/modules/rcps/locals.tf` — the rendered statement
- Tests: `tests/test_checks_deny_service_confused_deputy.py`,
  `tests/test_aws_policy_documents.py`
