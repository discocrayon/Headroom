---
id: deny_kms_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_kms_third_party_access.py
  - headroom/aws/kms.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_kms_third_party_access.py
  - tests/test_aws_kms.py
  - tests/test_aws_policy_documents.py
---

# deny_kms_third_party_access

## Objective

Deny KMS access by any principal outside the organization except the third-party
accounts that key policies already grant, so an external account cannot be handed
the ability to decrypt.

### Scope

The `default` key policy **and the grants** of every customer-managed key
`kms:ListKeys` returns, in every enabled region. That listing is unfiltered, so
each key is described first and an AWS-managed key is skipped before its
policy or grants are read; the Decision table owns why.

### Non-goals

- Does not read a key policy stored under a name other than `default`.
- Does not evaluate `Condition`, `Resource`/`NotResource`, or `NotAction`.
- Does not read an AWS-managed key at all, not even to confirm that its policy
  has the documented shape. RCPs do not apply to such a key, so nothing its
  policy says can change what this check's statement does.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenyKMSThirdPartyAccess
Action: kms:*
```

Pattern 5a, principal account allowlist
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).

Terraform variables: `deny_kms_third_party_access` and
`kms_third_party_access_account_ids_allowlist`.

## Evidence

Per enabled region: `kms:ListKeys` (paginated), then per key `kms:DescribeKey`,
and for a customer-managed key `kms:GetKeyPolicy` with `PolicyName="default"`
and `kms:ListGrants` (paginated).

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
| Not recorded | An AWS-managed key: `KeyManager` is `AWS` on `DescribeKey` | Not in the output; neither its policy nor its grants are read |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Violation | An ARN naming no account, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run) owns | `VIOLATION` |
| Aborts | A principal key AWS does not document | The run aborts |

Every KMS key policy names its own account's root principal, which is an
in-organization principal and so is never recorded.

An AWS-managed key is skipped on `KeyManager` alone. AWS states that resource
control policies do not apply to AWS managed keys, in both the
[KMS key concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-key)
and the
[RCP documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#actions-not-restricted-by-rcps),
so no statement this check gates can reach one; and such a key can be used only
by principals in the account that holds it, so there is no third party to
preserve either. Its default policy grants `Principal: {"AWS": "*"}` narrowed
by `kms:CallerAccount` to the key's own account, the idiom AWS documents for
"all identities in one account" because the `Principal` element has no syntax
for it. `read_principal` reads that as a wildcard, so before the skip every
account holding an AWS-managed key was blocked for this RCP by a policy its
operator cannot change. The skip reads the key type, not the `Condition`
block: `kms:CallerAccount` is not evaluated, and a customer-managed key written
the same way is still a violation
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
`DescribeKey` is the identification AWS documents as definitive; the `aws/`
alias prefix is the informal one.

## Failure behavior

| Situation | Behavior |
|---|---|
| `NotFoundException` from `GetKeyPolicy` on one key | The key has no policy, so no statement is read. Its grants are still listed, and the key reaches the results list if one of them names an account outside the organization |
| `ClientError` from `DescribeKey` on one key | Re-raised, aborting the run. The key's type is unknown, and either guess is wrong: reading the policy could block the account over an AWS-managed key, and skipping could drop a customer-managed key that grants a third party |
| Any other `ClientError` on one key | Re-raised, aborting the run |
| A grant naming a principal that is neither an ARN nor an AWS service principal | `UnknownGrantPrincipalError`, aborting the run. The message names the key ARN, the grant ID, and which of `GranteePrincipal` and `RetiringPrincipal` carried it, since either raises and the run stops before anything records the key |
| A grant carrying no `GrantId` | `KeyError`, aborting the run. `ListGrants` returns the ID `RetireGrant` takes, so its absence is a response Headroom has misread; recording the grant with a blank ID would report access through a grant nobody can name |
| `ClientError` in any region | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| `Principal` neither string, list, nor object | `MalformedPolicyError` |
| A `Federated` or `CanonicalUser` principal, or an ARN naming no account | Recorded as `has_non_account_principals`; the account is blocked |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

A `Federated` or `CanonicalUser` principal used to raise here and stop the whole
run — the same divergence as
[`deny_ecr_third_party_access`](deny_ecr_third_party_access.md), resolved the
same way: it is recorded as a violation, under the rule
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run)
owns.

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `keys_third_parties_can_access` | Violations plus compliant |
| `keys_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_keys_analyzed`,
`keys_third_parties_can_access`, `keys_with_wildcards`,
`keys_with_third_party_grants`, `violations`, `unique_third_party_accounts`,
`third_party_account_count`, `actions_by_account`.

`total_keys_analyzed` counts the keys that produced an entry — violations,
exemptions, and compliant together — not the keys `ListKeys` returned. An
AWS-managed key, or a customer-managed key whose policy and grants name only
in-organization principals, is never entered and is not counted.

`keys_with_third_party_grants` counts the entries whose `grants` list is
non-empty, and it is the only summary-level signal that the grant surface found
anything. Without it a key with a clean policy and a third-party grant is
indistinguishable in `summary` from one found through its policy.

Entry shape: `key_id`, `key_arn`, `region`, `third_party_account_ids`,
`actions_by_account`, `has_wildcard_principal`, `has_non_account_principals`,
`grants`.

`grants` holds one object per grant reaching outside the organization —
`grant_id`, `grantee_account_id`, `retiring_principal_account_id`,
`operations`, `has_constraints` — and is an empty list on a key whose only
third-party access is in its policy. This is the only one of the six entry
shapes with a field of its own for a second surface;
[`deny_s3_third_party_access`](deny_s3_third_party_access.md) reads two surfaces
as well and merges the ACL's verdict into `has_wildcard_principal` and
`has_non_account_principals` rather than reporting it separately.

`service_principal_sources` is **not** written. `analyze_kms_key_policies`
carries it on the in-memory analysis only, and
[`deny_service_confused_deputy`](deny_service_confused_deputy.md) reads it by
re-running that analyzer rather than by reading these files. That second call is
served from the analyzer's per-session memo and issues no AWS request;
[`../index.md`](../index.md) owns the accounting.

`actions_by_account` is filtered to third-party accounts.

`keys_with_wildcards` counts every violation, not only entries with a literal
wildcard principal. A `Federated` or `CanonicalUser` principal is now recorded
as a violation rather than aborting, so it is folded into the same field and the
name understates what the field holds. The same is true of the
equivalent
field.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. Only the `default` key policy is read, so access granted by a named
   non-default policy is invisible.
2. `Condition`, `Resource`, and `NotAction` are not evaluated.
3. **A grant's `Constraints` are recorded as a boolean and not read.** A grant
   narrowed to one encryption context is reported exactly as an unrestricted
   grant to the same account, so the allowlist it feeds is wider than the access
   that exists.
4. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a key policy may grant nothing at all. It is still
   counted as a blocker, because whether the grant is live is not readable from
   the document and INV-01 forbids assuming it is not.

## Acceptance scenarios

1. A key policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. A key policy naming only its own account's root → not recorded.
3. A key policy with `Principal: "*"` → violation; the account is blocked for KMS
   only.
4. A key whose `GetKeyPolicy` returns `NotFoundException`, with no grant
   reaching outside the organization → not recorded. The missing policy does
   not stop `kms:ListGrants` from being called for that key.
5. A key whose only external access is a grant → compliant, and the grantee
   enters the allowlist. A grant narrowed by `Constraints` does the same, which
   is limitation 3.
6. A key policy with a `Federated` or `CanonicalUser` principal → violation; the
   account is blocked for KMS, and the remaining keys are still read.
7. A key policy naming a principal key AWS does not document → the run aborts.
8. An AWS-managed key, `KeyManager` = `AWS`, whose default policy grants
   `Principal: {"AWS": "*"}` under `kms:CallerAccount` → not recorded, and
   neither `GetKeyPolicy` nor `ListGrants` is called for it.
9. A customer-managed key with that same policy → violation, as in scenario 3.
10. `AccessDenied` from `DescribeKey` on one key → the run aborts.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_kms_third_party_access.py`
- `headroom/aws/kms.py` — `analyze_kms_key_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_kms_third_party_access.py`,
  `tests/test_aws_kms.py`, `tests/test_aws_policy_documents.py`
