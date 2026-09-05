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
- Evaluates `Condition` only for a bound on the statement's principals, under
  the rule
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
  owns. `sts:ExternalId` bounds no principal set — it is a shared secret the
  caller presents, not a name for who the caller is — so an
  `sts:ExternalId`-gated grant still contributes its account at full width.
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
| `Principal` | Third-party account IDs, or a wildcard, and the principal-type keys the `Federated` check asks after — all read off `read_statement_principals`'s reading, never off the element |
| `Condition` | Whether a bound on the statement's principals clears that wildcard, and which accounts the bound enumerates |

### Action matching is IAM-faithful

This is one of the two analyzers that gate on actions —
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#actions)
owns the count and names the other, `aws/kms.py`'s skip of a key policy
statement whose only action is `kms:RetireGrant`. This gate matches the way IAM
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
| Violation | The role has an unconfined wildcard principal on a statement granting `sts:AssumeRole` — a literal `*` whose statement carries no bound the reader can prove, or an `Allow` with `NotPrincipal`, which is never confined | `VIOLATION` |
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the role `COMPLIANT` |
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
| An `Allow` granting `sts:AssumeRole` and carrying neither `Principal` nor `NotPrincipal` | `MalformedPolicyError` — AWS stores no such statement, so it is a document misread rather than a grant to nobody |
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
`_read_principal` reports the fact while this analyzer alone ignores it.

A `Condition` opens a second route to an entry on such a role, and it does not
go through that fact. A role whose only principal is `{"Federated": …}` under
`StringEquals aws:PrincipalAccount` carries the account the clause names in
`third_party_account_ids` and so passes this check's reporting gate, where read
for its `Principal` alone it named no account, raised no wildcard, and produced
no entry at all. The account is recorded because the `Condition` enumerates it,
not because the `Principal` does, and the allowlist entry is over-wide by one
account — the direction that breaks nothing.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run)
owns why the two are not the same population.

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

`total_roles_analyzed` counts the roles that produced an entry — violations,
exemptions, and compliant together — not the roles `ListRoles` returned. A role
whose trust policy grants `sts:AssumeRole` only to in-organization principals,
or not at all, is never entered and is not counted.

Entry shape: `role_name`, `role_arn`, `third_party_account_ids`,
`has_wildcard_principal`, `confined_by`.

`confined_by` holds the condition keys, lower-cased, that each bounded one of
the trust policy's `sts:AssumeRole` statements on their own, unioned across
them. A key is recorded whether or not the role still blocks — one bounded
statement beside one unbounded one reports both the key and the violation — but only for a statement whose `Principal` was a wildcard. The reader
consults a `Condition` for nothing else, so a bound beside a `Principal`
that already names its callers is neither read nor recorded.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
owns which keys can appear and what each proves; `kms:CallerAccount` is not
among them here, because it is read in a KMS key policy and nowhere else. The
field is additive: a result file written before it existed lacks the key, and
no reader requires anything outside `summary`
([`../../contracts/results.md`](../../contracts/results.md#summary-keys-a-reader-requires)).

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
2. A `Condition` that narrows the grant rather than the statement's principals
   is not evaluated, so an `sts:ExternalId`-gated grant still widens the
   allowlist
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
3. A `CanonicalUser` principal aborts the run rather than being recorded as a
   blocker, unlike [`deny_s3_third_party_access`](deny_s3_third_party_access.md).
   A trust policy does not accept the key, so the case should not arise; if it
   does, the document is one AWS should not have stored.
4. This check's tests cannot pin a "not recorded" verdict the way the other
   five can. A trust policy rides inside the `ListRoles` response and the
   reader is inline in `analyze_iam_roles_trust_policies`, so there is neither
   a per-role fetch to assert nor a reader a test can call directly, and an
   empty page is indistinguishable from a document read to no findings.
   [`../../verification/strategy.md`](../../verification/strategy.md#a-nothing-was-reported-assertion-needs-a-positive-control)
   owns the rule and names the extraction that would close it.

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
10. A role with `Principal: {"AWS": "*"}`, `Action: "sts:AssumeRole"`, and
    `StringEquals aws:PrincipalAccount` naming `333333333333`, outside the
    organization → compliant rather than a violation; that account enters the
    allowlist and `confined_by` records `aws:principalaccount`.
11. The same wildcard under `StringEquals aws:PrincipalOrgID` naming this
    organization → not recorded and not counted; the bound admits only callers
    the deployed statement already spares.
12. The same wildcard under `StringEquals kms:CallerAccount` naming
    `333333333333` → still a violation. No STS request carries that key, so
    the clause admits nobody and bounds nothing; it is a bound in a KMS key
    policy and nowhere else.
13. A role whose only principal is
    `{"Federated": "arn:aws:iam::444444444444:saml-provider/ExampleIdP"}` under
    `Action: "sts:*"` and `StringEquals aws:PrincipalAccount` naming
    `333333333333` → **not recorded**; neither account reaches the allowlist.
    `444444444444` stays out because the provider ARN's twelve digits name the
    account hosting the provider, not the caller. `333333333333` stays out
    because the `Principal` is not a wildcard, so its `Condition` is never
    consulted — and consulting it would be wrong anyway: a federated session
    reports the provider's account, so the clause and the element admit nobody
    between them. `sts:*` is the shape that clears the `sts:AssumeRole` gate
    while missing the literal `Federated` check in Failure behavior, so this is
    a live path rather than a hypothetical.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13.

## Implementation

- `headroom/checks/rcps/deny_sts_third_party_assumerole.py` — class
  `ThirdPartyAssumeRoleCheck`
- `headroom/aws/iam/roles.py` — `analyze_iam_roles_trust_policies`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `headroom/constants.py` — `AWS_ARN_ACCOUNT_ID_PATTERN`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_sts_third_party_assumerole.py`,
  `tests/test_aws_iam.py`, `tests/test_aws_policy_documents.py`
