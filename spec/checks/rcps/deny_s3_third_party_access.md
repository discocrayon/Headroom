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

- Does not read S3 Access Points, Multi-Region Access Points, bucket ACLs, or
  Object Lambda access point policies.
- Does not evaluate `Condition` or `Resource`/`NotResource`. See
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md).
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
element, so the grantee never reaches `read_principal` and no API resolves a
canonical user ID to an account. The `AllUsers` and `AuthenticatedUsers` group
URIs are read as a wildcard; the `LogDelivery` group URI is ignored. Any other
grantee type or group URI raises `UnknownGranteeTypeError`.

`AmazonCustomerByEmail` is among them, and deliberately. AWS resolves an
email grantee to its canonical user ID when the grant is written, so a
`GetBucketAcl` response returns `CanonicalUser`; a response carrying the
email type is one AWS does not produce. The analyzer treated it as a
non-account grantee for a time, proved only by a fixture AWS could not have
returned.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Action`. The
bucket ARN is synthesized as `arn:aws:s3:::<name>`.

The `Principal` element is read by `read_principal` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)). S3 is the
service AWS documents `CanonicalUser` for, and it is why that key is in the
resource-policy set at all.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | A wildcard principal — literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Violation | A CloudFront origin access identity — an ARN naming no account | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |

S3 was the only check that recorded `Federated` and `CanonicalUser` principals
as findings rather than aborting, and it was right: they carry no account ID, so
no allowlist can express them, and they block the account exactly as a wildcard
does. The other four resource-policy analyzers raised instead. They have
converged on this behavior, and the rule now lives in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md) rather than
here.

An origin access identity is the same verdict for the same reason. Its user
ARN carries `cloudfront` where an account ID would be, so no allowlist can
preserve it, and the deployed statement denies every request the distribution
makes; AWS's
[data perimeter guidance](https://github.com/aws-samples/data-perimeter-policy-examples/blob/main/resource_control_policies/README.md)
names this break and recommends migrating to origin access control, which
calls as the `cloudfront.amazonaws.com` service principal and is outside this
check. Before the rule in `read_principal` that ARN named nothing at all, so a
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

Entry shape: `bucket_name`, `bucket_arn`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`.

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
6. `Condition` and `Resource` are not evaluated.

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
8. A `Principal: "*"` narrowed by `aws:PrincipalOrgID` → still a violation; see
   the condition limitation.
9. A bucket policy granting a CloudFront origin access identity → violation;
   the account is blocked for S3 until the distribution moves to origin access
   control.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13.

## Implementation

- `headroom/checks/rcps/deny_s3_third_party_access.py`
- `headroom/aws/s3.py` — `analyze_s3_bucket_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_s3_third_party_access.py`,
  `tests/test_aws_s3.py`, `tests/test_aws_policy_documents.py`
