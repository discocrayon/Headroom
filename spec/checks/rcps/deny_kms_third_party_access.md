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

For each grant: `GrantId`, `GranteeServicePrincipal`, `GranteePrincipal`,
`Operations`, `Constraints` presence. `RetiringPrincipal`,
`RetiringServicePrincipal`, and `IssuingAccount` are not read; the Decision
table owns why.

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
| Compliant | A grant whose `GranteePrincipal` is an ordinary ARN outside the organization, with any operation other than `RetireGrant` alone, or with no `Operations` | `COMPLIANT`; the grantee's account enters the allowlist |
| Not recorded | A grant listed with `GranteeServicePrincipal`, or whose `GranteePrincipal` is an AWS service principal | Not in the output; the RCP exempts services with `aws:PrincipalIsAWSService`. When the typed field is present the display `GranteePrincipal` beside it is not read |
| Not recorded | A policy statement or a grant naming a service-linked role, in any partition, identified by the reserved `role/aws-service-role/` path | Not in the output, whichever account holds the role; RCPs do not impact service-linked roles. [`../../contracts/policy-model.md`](../../contracts/policy-model.md#principals) owns the rule, and both surfaces read it |
| Not recorded | A grant whose nonempty `Operations` is only `RetireGrant`, or a policy statement whose only action is the literal `kms:RetireGrant` | Not in the output; RCPs do not impact `kms:RetireGrant`, and the permission is not effective in a key policy at all. Such a statement is skipped whole, so `Principal: "*"` or `NotPrincipal` on it is not a blocker either |
| Not read | `RetiringPrincipal` and `RetiringServicePrincipal`, whatever they hold | Never classified, allowlisted, or failed on |
| Aborts | A `GranteePrincipal` that is neither an ARN nor an AWS service principal, on a grant with no `GranteeServicePrincipal` | The run aborts |

Every KMS key policy names its own account's root principal, which is an
in-organization principal and so is never recorded.

A grant's retiring principal is irrelevant to RCP safety. It can call
`kms:RetireGrant` and nothing else, and AWS states in the
[RCP documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#actions-not-restricted-by-rcps)
that RCPs do not impact that permission, and in the
[grant lifecycle documentation](https://docs.aws.amazon.com/kms/latest/developerguide/grant-delete.html)
that the grant itself authorizes retirement and the permission is not
effective in a key policy or an RCP. So the statement this check generates
cannot deny a retiring principal, and an allowlist entry for its account would
open `kms:*` to an account the RCP was never going to block. The field is
ignored categorically rather than by value: a service-created grant lists an
opaque display value such as `AWS Internal` there, and reading it through the
grantee's classifier aborted the whole organization scan over a value that
bears on nothing the RCP does. The same reasoning drops a grant whose only
operation is `RetireGrant`, since the grantee then holds nothing the RCP can
deny, and a key policy statement whose only action is `kms:RetireGrant`, which
AWS documents as not effective in a key policy and so authorizes nothing to
anyone — the statement is skipped before its principal is read, so a wildcard
on it blocks nothing. The action is matched literally, as every action in this
corpus is: `kms:retiregrant` in another case, or `kms:Retire*`, is read as an
ordinary statement and errs toward recording. Neither exemption is a statement
about `kms:RetireGrant` in general — an SCP or an identity policy can deny it —
only about this check's RCP.

A service-linked role is exempt on both surfaces by the one rule
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#principals)
owns: the reserved `aws-service-role/` path, in any partition, and never the
name. A role named `AWSServiceRoleForExample` outside that path is an ordinary
role anyone can create and is classified by its account like any other. A
service-linked role in another account is still not a third party, since the
RCP cannot deny it.

A grant with no `Operations` is not one carrying only `RetireGrant`. Nothing in
it says what it authorizes, and INV-01 forbids reading that silence as safe,
so its external grantee is recorded with an empty operations list.

Grantee identity is read from `GranteeServicePrincipal` and `GranteePrincipal`
only. `IssuingAccount`, the key's own account, and the retiring fields say
nothing about who the grantee is and are not consulted.

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
| A grant whose `GranteePrincipal` is neither an ARN nor an AWS service principal, with no `GranteeServicePrincipal` beside it | `UnknownGrantPrincipalError`, aborting the run. The message names the key ARN and the grant ID, and the run stops before anything records the key. `AWS Internal` as the grantee raises like any other opaque value: the grantee holds access the RCP would deny, and nothing authoritative says which account it belongs to |
| A grant whose `RetiringPrincipal` or `RetiringServicePrincipal` is opaque, `AWS Internal` included | Nothing. The field is not read, so no value in it can raise |
| A grant with no `Operations` | Recorded with an empty operations list when its grantee is outside the organization, not dropped as `RetireGrant`-only |
| A grant carrying no `GrantId` | `KeyError`, aborting the run. `ListGrants` returns the ID `RetireGrant` takes, so its absence is a response Headroom has misread; recording the grant with a blank ID would report access through a grant nobody can name |
| A grant carrying neither `GranteeServicePrincipal` nor `GranteePrincipal` | `KeyError`, aborting the run. Every grant is listed with one of the two, so a grant with neither is a response Headroom has misread, and dropping it would read a missing grantee as no grantee (INV-01) |
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
third-party access is in its policy. `grantee_account_id` is always set on an
entry, since a grantee outside the organization is what makes one.
`retiring_principal_account_id` is always `null` on a newly analyzed entry: the
retiring principal is no longer read, for the reason the Decision table gives,
and the field is kept only so persisted results keep their shape (INV-14). A
result file written before that change may carry an account there, and both
readers still read it. This is the only one of the six entry
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
11. A grant to an in-organization service-linked role with
    `RetiringPrincipal: "AWS Internal"` → not recorded, and the run continues.
12. A grant to an in-organization role whose `RetiringPrincipal` is a role in
    `999999999999`, outside the organization → not recorded; that account
    enters neither the results nor the allowlist.
13. A grant to a service-linked role in `999999999999`, under the
    `role/aws-service-role/` path → not recorded.
14. A grant listed with `GranteeServicePrincipal`, whatever `GranteePrincipal`
    says beside it → not recorded.
15. A grant to an ordinary role in `999999999999` whose `Operations` is only
    `RetireGrant` → not recorded.
16. A grant to an ordinary role in `999999999999` whose `Operations` is
    `RetireGrant` and `Decrypt` → compliant; the account enters the allowlist
    with both operations recorded.
17. A grant to an ordinary role in `999999999999` with no `Operations` →
    compliant, recorded with an empty operations list.
18. A grant to an ordinary role in `999999999999` named
    `AWSServiceRoleForExample`, outside the reserved path → compliant; the
    name does not make it a service-linked role.
19. A grant whose `GranteePrincipal` is `AWS Internal`, with no
    `GranteeServicePrincipal` → the run aborts, naming the key ARN and the
    grant ID.
20. A grant with neither `GranteeServicePrincipal` nor `GranteePrincipal` →
    the run aborts with `KeyError`.
21. A key policy statement granting `kms:Decrypt` to a service-linked role in
    `999999999999` → not recorded, as the same role would be as a grantee.
22. A key policy statement granting only `kms:RetireGrant` to an ordinary role
    in `999999999999` → not recorded.
23. A key policy statement granting only `kms:RetireGrant` to `Principal: "*"`
    → not recorded, and not a violation.
24. A grant to an ordinary role in `999999999999` with
    `RetiringPrincipal: "AWS Internal"` → compliant; the grantee's account
    enters the allowlist and `retiring_principal_account_id` is `null`.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_kms_third_party_access.py`
- `headroom/aws/kms.py` — `analyze_kms_key_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_kms_third_party_access.py`,
  `tests/test_aws_kms.py`, `tests/test_aws_policy_documents.py`
