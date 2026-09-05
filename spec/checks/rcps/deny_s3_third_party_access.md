---
id: deny_s3_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_s3_third_party_access.py
  - headroom/aws/s3.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
verification:
  - tests/test_checks_deny_s3_third_party_access.py
  - tests/test_aws_s3.py
  - tests/test_aws_policy_documents.py
---

# deny_s3_third_party_access

## Objective

Deny S3 access by any principal outside the organization except the third-party
accounts that bucket policies already grant, so a bucket policy edit cannot
quietly expose data to a new external account.

### Scope

Bucket policies **and bucket ACLs**, the two surfaces an S3 bucket authorizes
through.

### Non-goals

- Does not read S3 Access Points, Multi-Region Access Points, or Object Lambda
  access point policies. Bucket ACLs **are** read — they are the second surface
  named in Scope above; it is *object* ACLs that are not, under limitation 5.
- Evaluates `Condition` only for a bound on the statement's principals, under
  the rule
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
  owns. A condition that narrows the grant rather than the principal set is
  unread, and so are `Resource`/`NotResource`.
- Does not read Block Public Access settings.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenyS3ThirdPartyAccess
Action: s3:*
```

Pattern 5a, principal account allowlist
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).

`Action` is rendered as a bare string here rather than a one-element list,
unlike its five siblings. The semantics are identical.

Terraform variables: `deny_s3_third_party_access` and
`s3_third_party_access_account_ids_allowlist`.

## Evidence

`s3:ListAllMyBuckets` (paginated), then `s3:GetBucketAcl` and
`s3:GetBucketPolicy` per bucket. **Global** — S3 buckets are listed once, not
per region. The listing permission is named for the IAM action, which is
`s3:ListAllMyBuckets`; the API operation it authorizes is `ListBuckets`.

The ACL is read before the policy, because a bucket that shares only by ACL
carries no policy at all and abandoning it for want of one would skip the grant
most likely to be the only grant on it. A `CanonicalUser` grantee other than the
bucket owner carries no account ID, so no allowlist can preserve it and it
blocks the account — this is the ACL surface rather than the `Principal`
element, so the grantee never reaches `_read_principal` and no API resolves a
canonical user ID to an account. The `AllUsers` and `AuthenticatedUsers` group
URIs are read as a wildcard; the `LogDelivery` group URI is ignored. Any other
grantee type or group URI raises `UnknownGranteeTypeError`.

`AmazonCustomerByEmail` is among them, and deliberately. AWS resolves an
email grantee to its canonical user ID when the grant is written, so a
`GetBucketAcl` response returns `CanonicalUser`; a response carrying the
email type is one AWS does not produce. The analyzer treated it as a
non-account grantee for a time, proved only by a fixture AWS could not have
returned.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Condition`,
`Action`. The bucket ARN is synthesized as `arn:aws:s3:::<name>`.

The statement is read by `read_statement_principals` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`, which reads the `Principal` element with
`_read_principal` and, where that element is a wildcard, asks the `Condition`
whether it bounds what the wildcard reaches
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)).
S3 is the service AWS documents `CanonicalUser` for, and it is why that key is
in the resource-policy set at all.

The ACL is a separate surface and no `Condition` reaches it. A bucket whose
every statement is bounded is still public when the `AllUsers` group holds an
ACL grant, and the bound is recorded beside that verdict rather than in place
of it.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | An unconfined wildcard principal — a literal `*` whose statement carries no bound the reader can prove, or an `Allow` with `NotPrincipal`, which is never confined | `VIOLATION` |
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the bucket `COMPLIANT` |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Violation | A CloudFront origin access identity — an ARN naming no account | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |

S3 was the only check that recorded `Federated` and `CanonicalUser` principals
as findings rather than aborting, and it was right: they carry no account ID, so
no allowlist can express them, and they block the account exactly as an
**unconfined** wildcard does. No `Condition` rescues them the way one rescues a
wildcard: confinement bounds reach, and these are claims about identity type.
The other four resource-policy analyzers raised instead. They have converged on
this behavior, and the rule now lives in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md) rather than
here.

An origin access identity is the same verdict for the same reason. Its user
ARN carries `cloudfront` where an account ID would be, so no allowlist can
preserve it, and the deployed statement denies every request the distribution
makes; AWS's
[data perimeter guidance](https://github.com/aws-samples/data-perimeter-policy-examples/blob/main/resource_control_policies/README.md)
names this break and recommends migrating to origin access control, which
calls as the `cloudfront.amazonaws.com` service principal and is outside this
check. Before the rule in `_read_principal` that ARN named nothing at all, so a
bucket granting only an OAI was never recorded and its account cleared.

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` from `ListBuckets`, on any page | Logged and re-raised, aborting the run. The listing is materialized before any bucket is read, so a failure part-way through paging is reported as the listing failure it is rather than reaching the bucket-policy handler |
| `NoSuchBucketPolicy` on one bucket | The bucket has no policy, so no statement is read. Its ACL was read first and its verdict stands: the bucket reaches the results list when the ACL alone names a public group URI or a canonical user other than the owner |
| Any other `ClientError` on one bucket, `AccessDenied` included | Logged and re-raised, aborting the run |
| An ACL grant whose grantee type is neither `CanonicalUser` nor `Group`, or whose group URI is none of `AllUsers`, `AuthenticatedUsers`, and `LogDelivery` | `UnknownGranteeTypeError`, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| `Principal` neither string, list, nor object | `MalformedPolicyError` |
| An `Allow` carrying neither `Principal` nor `NotPrincipal` | `MalformedPolicyError` — AWS stores no such statement, so it is a document misread rather than a grant to nobody |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

`UnsupportedPrincipalTypeError` was declared in this module and never raised —
the mechanism the other four analyzers used and S3 deliberately did not. None of
the five raises it now, and the class is gone from all of them.

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `buckets_third_parties_can_access` | Violations plus compliant |
| `buckets_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_buckets_analyzed`,
`buckets_third_parties_can_access`, `buckets_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`,
`actions_by_third_party_account`, `buckets_by_third_party_account`.

`total_buckets_analyzed` counts the buckets that produced an entry — violations,
exemptions, and compliant together — not the buckets `ListBuckets` returned. A
bucket whose policy names only in-organization principals, and whose ACL grants
only to its owner or the `LogDelivery` group, is never entered and is not
counted.

Entry shape: `bucket_name`, `bucket_arn`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`,
`confined_by`.

`confined_by` holds the condition keys, lower-cased, that each bounded one of
the bucket policy's statements on their own, unioned across the policy. A key
is recorded whether or not the bucket still blocks — one bounded statement
beside one unbounded one, or beside a public ACL grant, reports both the key
and the violation — but only for a statement whose `Principal` was a wildcard. The reader
consults a `Condition` for nothing else, so a bound beside a `Principal`
that already names its callers is neither read nor recorded.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
owns which keys can appear and what each proves. The field is additive: a
result file written before it existed lacks the key, and no reader requires
anything outside `summary`
([`../../contracts/results.md`](../../contracts/results.md#summary-keys-a-reader-requires)).

`service_principal_sources` is **not** written. `analyze_s3_bucket_policies`
carries it on the in-memory analysis only, and
[`deny_service_confused_deputy`](deny_service_confused_deputy.md) reads it by
re-running that analyzer rather than by reading these files. That second call is
served from the analyzer's per-session memo and issues no AWS request;
[`../index.md`](../index.md) owns the accounting.

`buckets_with_wildcards` counts every violation, not only entries with a literal
wildcard principal. A `Federated` or `CanonicalUser` principal is recorded as a
violation, so it is folded into the same field and the name understates what the
field holds. That has been true here for longer than it has anywhere else: this
was the check the other four converged on, so the field was already carrying
non-wildcard violations before they stopped aborting. The same is true of
[`deny_ecr_third_party_access`](deny_ecr_third_party_access.md),
[`deny_kms_third_party_access`](deny_kms_third_party_access.md),
[`deny_secrets_manager_third_party_access`](deny_secrets_manager_third_party_access.md),
and [`deny_sqs_third_party_access`](deny_sqs_third_party_access.md).

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. The synthesized bucket ARN hardcodes the `aws` partition.
2. Access Points are unread, so cross-account access delivered through one is
   invisible.
3. An ACL grantee's permission is not read, only that the grant exists. A
   grantee holding `READ_ACP` alone counts the same as one holding `FULL_CONTROL`.
4. A bucket whose Object Ownership is `BucketOwnerEnforced` has ACLs disabled,
   and the ACL read still happens.
5. Object ACLs are not read. Under `ObjectWriter` object ownership an object
   uploaded by an external account is owned by that account and can carry its
   own ACL, as can log objects delivered under `TargetGrants`. Enumerating them
   costs one call per object, so an object ACL granting a third party is
   invisible to this check.
6. `Resource` is not evaluated, and neither is a `Condition` that narrows the
   grant rather than the statement's principals — so a grant confined by
   `s3:prefix` or `aws:SourceVpce` still contributes its account at full width
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).

## Acceptance scenarios

1. A bucket policy granting `arn:aws:iam::111111111111:root`, outside the
   organization → compliant, and `111111111111` enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A bucket policy with `Principal: "*"` → violation; the account is blocked for
   S3 only.
4. A bucket policy with a `Federated` principal → violation, recorded rather than
   raised.
5. A bucket policy with a `CanonicalUser` principal → violation.
6. A bucket with no policy → skipped.
7. `AccessDenied` reading one bucket's policy → the run aborts.
8. A `Principal: "*"` narrowed by `StringEquals aws:PrincipalOrgID` naming
   this organization → not a violation, and the bucket is not recorded at all:
   the bound admits only callers the deployed statement already spares, so
   there is no account to allowlist and nothing left for an RCP to break. The
   same wildcard bounded by `StringEquals aws:PrincipalAccount` to an
   out-of-organization account is compliant and that account enters the
   allowlist.
9. A bucket policy granting a CloudFront origin access identity → violation;
   the account is blocked for S3 until the distribution moves to origin access
   control.
10. A `Principal: "*"` under `StringEquals kms:CallerAccount` naming
    `333333333333` → still a violation. No Amazon S3 request carries that key,
    so the clause admits nobody and the statement grants nobody anything; it is
    a bound in a KMS key policy and nowhere else.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13.

## Implementation

- `headroom/checks/rcps/deny_s3_third_party_access.py`
- `headroom/aws/s3.py` — `analyze_s3_bucket_policies`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_s3_third_party_access.py`,
  `tests/test_aws_s3.py`, `tests/test_aws_policy_documents.py`
