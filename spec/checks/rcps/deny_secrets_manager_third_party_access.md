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
- Does not evaluate `Condition`, `Resource`/`NotResource`, or `NotAction`.
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

Entry shape: `secret_name`, `secret_arn`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`.

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
2. `Condition`, `Resource`, and `NotAction` are not evaluated.
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

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_secrets_manager_third_party_access.py`
- `headroom/aws/secretsmanager.py` — `analyze_secrets_manager_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `headroom/terraform/parameters.py` — `render_check_parameters`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_secrets_manager_third_party_access.py`,
  `tests/test_aws_secretsmanager.py`, `tests/test_aws_policy_documents.py`
