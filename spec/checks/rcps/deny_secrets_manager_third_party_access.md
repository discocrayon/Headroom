---
id: deny_secrets_manager_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_secrets_manager_third_party_access.py
  - headroom/aws/secretsmanager.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_secrets_manager_third_party_access.py
  - tests/test_aws_secretsmanager.py
  - tests/test_aws_policy_documents.py
---

# deny_secrets_manager_third_party_access

## Objective

Deny Secrets Manager access by any principal outside the organization except the
third-party accounts that secret resource policies already grant.

### Scope

Secret resource policies, in every enabled region.

### Non-goals

- Does not read the KMS key policy protecting a secret. Access to the secret and
  access to its key are separate grants;
  [`deny_kms_third_party_access`](deny_kms_third_party_access.md) covers the
  second.
- Evaluates `Condition` only for a bound on the statement's principals, under
  the rule
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
  owns. A condition that narrows the grant rather than the principal set is
  unread, and so are `Resource`/`NotResource` and `NotAction`.
- Does not read rotation Lambda permissions.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenySecretsManagerThirdPartyAccess
Action: secretsmanager:*
```

Pattern 5a, principal account allowlist
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).

Terraform variables: `deny_secrets_manager_third_party_access` and
`secrets_manager_third_party_account_ids_allowlist`.

**That allowlist variable's name departs from the RCP naming rule.**
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#the-rcp-allowlist-statement)
owns the naming rule, both departures from it, and why this one is not a typo to
fix in Python.

## Evidence

Per enabled region: `secretsmanager:ListSecrets` (paginated), then
`secretsmanager:GetResourcePolicy` per secret.

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
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the secret `COMPLIANT` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Violation | An ARN naming no account, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run) owns | `VIOLATION` |
| Aborts | A principal key AWS does not document | The run aborts |

## Failure behavior

| Situation | Behavior |
|---|---|
| `ResourceNotFoundException` on one secret | The secret is skipped; it has no policy |
| An empty policy string | The secret is skipped |
| Any other `ClientError` on one secret | Logged and re-raised, aborting the run |
| `ClientError` listing secrets in any region | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| `Principal` neither string, list, nor object | `MalformedPolicyError` |
| An `Allow` carrying neither `Principal` nor `NotPrincipal` | `MalformedPolicyError` — AWS stores no such statement, so it is a document misread rather than a grant to nobody |
| A `Federated` or `CanonicalUser` principal, or an ARN naming no account | Recorded as `has_non_account_principals`; the account is blocked |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

A `Federated` or `CanonicalUser` principal used to raise
`UnsupportedPrincipalTypeError` here and stop the whole run. This check
reached it one principal type further than ECR and KMS did, because it
tested for both types before extracting account IDs. All three now record the
principal as a violation instead, under the rule
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run)
owns.

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `secrets_third_parties_can_access` | Violations plus compliant |
| `secrets_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_secrets_analyzed`,
`secrets_third_parties_can_access`, `secrets_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`,
`actions_by_third_party_account`, `secrets_by_third_party_account`.

`total_secrets_analyzed` counts the secrets that produced an entry — violations,
exemptions, and compliant together — not the secrets `ListSecrets` returned. A
secret whose policy is absent or empty, or names only in-organization
principals, is never entered and is not counted.

Entry shape: `secret_name`, `secret_arn`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`,
`confined_by`.

`confined_by` holds the condition keys, lower-cased, that each bounded one of
this policy's statements on their own, unioned across the policy. A key is
recorded whether or not the secret still blocks — one bounded statement beside
one unbounded one reports both the key and the violation — but only for a statement whose `Principal` was a wildcard. The reader
consults a `Condition` for nothing else, so a bound beside a `Principal`
that already names its callers is neither read nor recorded.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
owns which keys can appear and what each proves. The field is additive: a
result file written before it existed lacks the key, and no reader requires
anything outside `summary`
([`../../contracts/results.md`](../../contracts/results.md#summary-keys-a-reader-requires)).

`service_principal_sources` is **not** written. `analyze_secrets_manager_policies`
carries it on the in-memory analysis only, and
[`deny_service_confused_deputy`](deny_service_confused_deputy.md) reads it by
re-running that analyzer rather than by reading these files. That second call is
served from the analyzer's per-session memo and issues no AWS request;
[`../index.md`](../index.md) owns the accounting.

`has_non_account_principals` carries the verdict rather than decorating it: it
is the field that makes a secret naming a `Federated` or `CanonicalUser`
principal a violation. It was dead while the analyzer raised instead of setting
it, and it came into use when the five analyzers converged on recording such a
principal.

`secrets_with_wildcards` counts every violation, not only entries with a
literal wildcard principal. A `Federated` or `CanonicalUser` principal is now
recorded as a violation rather than aborting, so it is folded into the same
field and the name understates what the field holds. The same is true of the
equivalent
field.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a secret's resource policy may grant nothing at all.
   It is still counted as a blocker, because whether the grant is live is not
   readable from the document and INV-01 forbids assuming it is not.
2. `Resource` and `NotAction` are not evaluated, and neither is a `Condition`
   that narrows the grant rather than the statement's principals — so a grant
   confined by `aws:SourceVpce` still contributes its account at full width
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
3. A replica secret is enumerated separately in each region it replicates to, so
   one logical secret can produce several findings.
4. This check's class is the only RCP check whose `__init__` does not accept
   `**kwargs`, so it is coupled to the exact keyword set `run_checks_for_type`
   passes. Adding a construction argument breaks this check first.

## Acceptance scenarios

1. A secret policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A secret policy with `Principal: "*"` → violation; the account is blocked for
   Secrets Manager only.
4. A secret with no resource policy → skipped.
5. A secret with an empty policy string → skipped.
6. A secret policy with a `Federated` principal → violation, recorded rather
   than aborting.
7. A secret policy with a `CanonicalUser` principal → violation, on the same
   grounds.
8. A secret policy naming a principal key AWS does not document → the run
   aborts.
9. A secret policy with `Principal: {"AWS": "*"}` under `StringEquals
   aws:PrincipalAccount` naming `333333333333`, outside the organization →
   compliant rather than a violation; that account enters the allowlist and
   `confined_by` records `aws:principalaccount`.
10. The same wildcard under `ArnLikeIfExists aws:PrincipalArn` → still a
    violation. An `...IfExists` operator is satisfied by a request that
    presents no principal ARN, so it proves no bound.
11. The same wildcard under `StringEquals kms:CallerAccount` naming
    `333333333333` → still a violation. No Secrets Manager request carries that key,
    so the clause admits nobody and the statement grants nobody anything; it is
    a bound in a KMS key policy and nowhere else.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_secrets_manager_third_party_access.py`
- `headroom/aws/secretsmanager.py` — `analyze_secrets_manager_policies`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `headroom/terraform/parameters.py` — `render_check_parameters`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_secrets_manager_third_party_access.py`,
  `tests/test_aws_secretsmanager.py`, `tests/test_aws_policy_documents.py`
