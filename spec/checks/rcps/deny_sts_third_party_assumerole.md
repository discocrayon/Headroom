---
id: deny_sts_third_party_assumerole
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_sts_third_party_assumerole.py
  - headroom/aws/iam/roles.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
verification:
  - tests/test_checks_deny_sts_third_party_assumerole.py
  - tests/test_aws_iam.py
  - tests/test_aws_policy_documents.py
---

# deny_sts_third_party_assumerole

## Objective

Deny `sts:AssumeRole` by any principal outside the organization except the
third-party accounts that already assume a role here, so a trust policy edit
cannot quietly hand a new external account a foothold.

### Scope

IAM role trust policies, and only their `sts:AssumeRole` grants.

### Non-goals

- Does not gate `sts:AssumeRoleWithSAML`, `sts:AssumeRoleWithWebIdentity`,
  `sts:TagSession`, or `sts:SetSourceIdentity`. They are neither scanned nor
  denied.
- Does not evaluate `Condition`, so an `sts:ExternalId`-gated grant contributes
  its account at full width. See
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md).
- Does not consult CloudTrail to find which accounts actually assume a role.

## Enforced statement

The standard RCP allowlist statement
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)), with:

```
Sid:    DenySTSThirdPartyAssumeRole
Action: sts:AssumeRole
```

Pattern 5a, principal account allowlist.

Terraform variables: `deny_sts_third_party_assumerole` and
`sts_third_party_assumerole_account_ids_allowlist`.

## Evidence

`iam:ListRoles`, paginated. Global — no region iteration. Nothing else is
called.

The trust policy arrives as a dict, or as a URL-encoded JSON string which is
unquoted and parsed.

For each statement, gated on `Effect == "Allow"` **and** on the statement
granting `sts:AssumeRole`:

| Read | Used for |
|---|---|
| `Action` / `NotAction` | Whether the statement grants `sts:AssumeRole` |
| `NotPrincipal` presence | Read as a wildcard |
| `Principal` | Third-party account IDs, or a wildcard |

### Action matching is IAM-faithful

This is the only analyzer that gates on actions, and it matches the way IAM
matches: case-insensitively, with `*` and `?` expanding anywhere in the pattern.
`sts:*`, `sts:Assume*`, and `STS:AssumeRole` all grant.

`NotAction` inverts: a statement whose `NotAction` excludes `sts:AssumeRole`
does not grant it; one whose `NotAction` names something else does.

Exactly one of `Action` and `NotAction` must be present. Both, or neither, raises
`MalformedStatementError` — IAM requires exactly one, so a statement with the
wrong shape is not something to guess at.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | The role has a wildcard principal on a statement granting `sts:AssumeRole` — a literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Compliant | The role names third-party account IDs an allowlist can express | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | The role names only in-organization principals or AWS services | Not in the output |

A violation is a **blocker**: it makes the whole account ineligible for this
RCP, because no allowlist can express a wildcard
([`../../contracts/placement.md`](../../contracts/placement.md)).

Account IDs are extracted with the partition- and service-agnostic ARN pattern,
so an STS session ARN and a GovCloud or China ARN all resolve. Organization
membership is the unfiltered projection (INV-04), so a closed member account's
principal is not a third party.

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` from `ListRoles` | Logged and re-raised, aborting the run |
| Unparseable trust policy JSON | Logged and re-raised, aborting the run |
| `Statement` neither object nor list | `MalformedPolicyError` |
| `Principal` neither string, list, nor object | `MalformedPolicyError` |
| Both or neither of `Action`/`NotAction` on an `Allow` | `MalformedStatementError` |
| An `Action` or `NotAction` that is neither a string nor a list | `TypeError`, aborting the run, matching the five resource-policy analyzers |
| A `Federated` principal granted the literal `sts:AssumeRole` | `InvalidFederatedPrincipalError`, aborting the run |
| A principal key outside `TRUST_POLICY_PRINCIPAL_TYPES` — `CanonicalUser` included | `UnknownPrincipalTypeError`, aborting the run |

The `Federated` check is an exact-membership test on the declared actions, not a
wildcard match. That is deliberate: it fires only on the unambiguous case rather
than on every `sts:*` grant to a federated principal.

### Why a `Federated` principal is otherwise no finding here

The five resource-policy analyzers count a `Federated` principal as a blocker,
because it carries no account ID and their RCPs deny a whole service. This one
denies `sts:AssumeRole` alone, and a federated identity cannot call it — AWS
routes federation through `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity`.
So the grant this RCP could break is not one a `Federated` principal holds, and
`read_principal` reports the fact while this analyzer alone ignores it.

`CanonicalUser` is a different matter: it is an Amazon S3 identifier and cannot
name who may assume a role, so `TRUST_POLICY_PRINCIPAL_TYPES` does not accept
the key and it aborts as an undocumented one. See
[`../../contracts/policy-model.md`](../../contracts/policy-model.md).

## Result contract

`_build_results_data` is **overridden**. There is no `violations`,
`exemptions`, or `compliant_instances` key.

| Key | Holds |
|---|---|
| `roles_third_parties_can_access` | Violations plus compliant |
| `roles_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_roles_analyzed`,
`roles_third_parties_can_access`, `roles_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`.

Entry shape: `role_name`, `role_arn`, `third_party_account_ids`,
`has_wildcard_principal`.

`service_principal_sources` is **not** written. `analyze_iam_roles_trust_policies`
carries it on the in-memory analysis only, and
[`deny_service_confused_deputy`](deny_service_confused_deputy.md) reads it by
re-running that analyzer rather than by reading these files. That second call is
served from the analyzer's per-session memo and issues no AWS request;
[`../index.md`](../index.md) owns the accounting.

`summary.violations` and `summary.unique_third_party_accounts` are both required
on read (INV-01): the first decides whether the account can take the RCP, and an
absent second is not the same answer as an empty one.

This is the only RCP check with **no action tracking** in its output, because the
statement denies exactly one action.

## Placement and generated policy

RCP placement ([`../../contracts/placement.md`](../../contracts/placement.md)):
an account is blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across the accounts a placement covers.

## Accepted limitations

1. **Only `sts:AssumeRole` is gated.** A trust policy granting
   `sts:AssumeRoleWithWebIdentity` to a third party is neither reported nor
   denied.
2. `Condition` is not evaluated, so an externally-ID-gated grant still widens the
   allowlist.
3. A `CanonicalUser` principal aborts the run rather than being recorded as a
   blocker, unlike [`deny_s3_third_party_access`](deny_s3_third_party_access.md).
   A trust policy does not accept the key, so the case should not arise; if it
   does, the document is one AWS should not have stored.

## Acceptance scenarios

1. A role trusting `arn:aws:iam::111111111111:root`, where that account is not in
   the organization → compliant, and `111111111111` enters the allowlist.
2. The same role where the account **is** in the organization → not recorded.
3. A role with `Principal: "*"` and `Action: "sts:AssumeRole"` → violation; the
   account is blocked for this check only.
4. A role with `Principal: "*"` and `Action: "s3:GetObject"` → not recorded; the
   statement does not grant `sts:AssumeRole`.
5. A role with `Action: "sts:*"` and a third-party principal → compliant; the
   wildcard action matches.
6. A role with `NotAction: "sts:AssumeRole"` and a wildcard principal → not a
   grant of `sts:AssumeRole`, so not recorded.
7. An `Allow` with `NotPrincipal` on an `sts:AssumeRole` statement → violation.
8. A `Deny` with `NotPrincipal` → not recorded.
9. A statement with both `Action` and `NotAction` → the run aborts.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13.

## Implementation

- `headroom/checks/rcps/deny_sts_third_party_assumerole.py` — class
  `ThirdPartyAssumeRoleCheck`
- `headroom/aws/iam/roles.py` — `analyze_iam_roles_trust_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `headroom/constants.py` — `AWS_ARN_ACCOUNT_ID_PATTERN`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_sts_third_party_assumerole.py`,
  `tests/test_aws_iam.py`, `tests/test_aws_policy_documents.py`
