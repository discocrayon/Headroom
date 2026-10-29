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
  - INV-07
  - INV-13
verification:
  - tests/test_terraform_module_plans.py
  - tests/test_checks_deny_s3_third_party_access.py
  - tests/test_aws_s3.py
  - tests/test_aws_policy_documents.py
  - tests/test_generate_rcps.py
---

# deny_s3_third_party_access

## Objective

Deny S3 access by any principal outside the organization except the
third-party accounts that bucket policies already grant, and except on the
buckets whose grants no account list can express — a wildcard, a `Federated`
or `CanonicalUser` principal, a CloudFront origin access identity, a public
ACL — which the statement spares by ARN. A bucket policy edit cannot quietly
expose data to a new external account, and no bucket the organization already
exposes stops working on its bucket or object ARN. Limitation 2 names the
access-point path those two ARNs do not spare.

### Scope

Bucket policies **and bucket ACLs**, the two surfaces an S3 bucket authorizes
through.

### Non-goals

- Does not judge whether an exempt bucket *should* be public or should trust a
  federated identity. Every such bucket found is spared and recorded as an
  exemption so it stays visible.
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

The standard RCP allowlist statement, with `Action: s3:*`, composed with a
resource ARN allowlist:

```
Sid:         DenyS3ThirdPartyAccess
Effect:      Deny
Principal:   "*"
Action:      s3:*
NotResource: <each exempt bucket ARN, and that ARN + "/*">   (Resource: "*" when the list is empty)
Condition:   StringNotEqualsIfExists  aws:PrincipalOrgID   = <this organization>
             StringNotEqualsIfExists  aws:PrincipalAccount = <s3_third_party_access_account_ids_allowlist>   (omitted when empty)
             BoolIfExists             aws:PrincipalIsAWSService = "false"
```

Pattern 6, the composition of the principal account allowlist every
third-party-access check renders (5a) with a resource ARN allowlist (5b)
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)). The 5a
clause is the one every third-party-access check shares, and is specified once
there. The 5b clause is this check's own: `NotResource` lifts the deny from the
buckets whose grants an account list cannot carry, so a request against one of
them is authorized by the bucket's own policy and ACL exactly as today, and
every other bucket in the organization is denied to every principal outside it.

RCPs accept `NotResource` — AWS documents it as "the AWS resources that are
exempt from the RCP, used instead of the `Resource` element" — and reject
`NotPrincipal` and `NotAction`, so sparing by resource is the one shape
available. Each bucket contributes two entries because S3 authorizes bucket
actions against `arn:aws:s3:::name` and object actions against
`arn:aws:s3:::name/key`; an entry for the bucket alone would spare
`ListBucket` and still deny every `GetObject`. When no covered account holds
an exempt bucket the statement carries `Resource: "*"` instead: a resource
array must hold at least one value, and an empty `NotResource` would be
rejected as malformed (INV-06). This is the third shape INV-06 names, not the
second — the empty list does not turn the statement off, because a statement
with nothing to spare is the strongest form of the deny, not a broken one.

The module builds the resource clause from two conditionals merged into the
statement rather than one, because Terraform requires both arms of a
conditional to share a type and objects keyed `NotResource` and `Resource` do
not. A single conditional passes `terraform validate`, where the list is
unknown and `flatten()` leaves its arm untyped, and fails `terraform plan`,
where the list is known — so a plan, not a validate, is what proves this
clause renders, and the module's `tests/plan.tftest.hcl` is that plan, run
under `tox` by `tests/test_terraform_module_plans.py`.

`Action` is rendered as a bare string here rather than a one-element list,
unlike its five siblings. The semantics are identical.

Terraform variables: `deny_s3_third_party_access`,
`s3_third_party_access_account_ids_allowlist`, and
`s3_third_party_access_exempt_bucket_arns`.

## Evidence

`s3:ListAllMyBuckets` (paginated), then `s3:GetBucketAcl` and
`s3:GetBucketPolicy` per bucket. **Global** — S3 buckets are listed once, not
per region. The listing permission is named for the IAM action, which is
`s3:ListAllMyBuckets`; the API operation it authorizes is `ListBuckets`.

The ACL is read before the policy, because a bucket that shares only by ACL
carries no policy at all and abandoning it for want of one would skip the grant
most likely to be the only grant on it. A `CanonicalUser` grantee other than
the bucket owner carries no account ID, so no account allowlist can preserve it
and the bucket becomes an exemption spared by ARN — this is the ACL surface
rather than the `Principal` element, so the grantee never reaches
`_read_principal` and no API resolves a canonical user ID to an account. The
`AllUsers` and `AuthenticatedUsers` group URIs are read as a wildcard; the
`LogDelivery` group URI is ignored. Any other grantee type or group URI raises
`UnknownGranteeTypeError`.

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
| Exemption | An unconfined wildcard principal — a literal `*` whose statement carries no bound the reader can prove, or an `Allow` with `NotPrincipal`, which is never confined — or a public ACL group; the bucket ARN is allowlisted | `EXEMPTION` |
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the bucket `COMPLIANT` |
| Exemption | A `Federated` or `CanonicalUser` principal, or an ACL grant to a canonical user other than the owner; the bucket ARN is allowlisted | `EXEMPTION` |
| Exemption | A CloudFront origin access identity — an ARN naming no account; the bucket ARN is allowlisted | `EXEMPTION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Violation | — | **Never produced** |
| Not recorded | Only in-organization principals or AWS services | Not in the output |

These grants carry no account ID, so no `aws:PrincipalAccount` list can
express them, and until this check spared them by ARN they blocked the
account exactly as an unconfined wildcard did. They are exemptions rather than
violations because the statement now spares the bucket: its ARN is in
`NotResource`, so the deny never matches a request against it, and it must not
count against deployability
([`../../architecture/check-framework.md`](../../architecture/check-framework.md#the-three-categories)).
This is the direct form of the claim `EXEMPTION` is reserved for — the scan
reads the very ARN the statement names — as `deny_lambda_auth_type_none` does,
where `deny_ec2_imds_v1` reads a proxy. A wildcard or a non-account principal
bounded by `Condition` to accounts is read as those accounts instead, and the
bucket is compliant, because an account list *can* express that grant.

This check can never report a violation, so every account is always safe for
it, and it always places at root when any account produced a result. The
safety argument therefore rests on the exempt list being complete, which is
why INV-07 applies and why the round trip below is specified end to end.

An origin access identity is spared for the same reason. Its user ARN carries
`cloudfront` where an account ID would be, so no allowlist can preserve it, and
without the exemption the deployed statement would deny every request the
distribution makes; AWS's
[data perimeter guidance](https://github.com/aws-samples/data-perimeter-policy-examples/blob/main/resource_control_policies/README.md)
names this break and recommends migrating to origin access control, which
calls as the `cloudfront.amazonaws.com` service principal and is outside this
check. Before the rule in `_read_principal` that ARN named nothing at all, so a
bucket granting only an OAI was never recorded and its account cleared with the
bucket unspared.

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` from `ListBuckets`, on any page | Logged and re-raised, aborting the run. The listing is materialized before any bucket is read, so a failure part-way through paging is reported as the listing failure it is rather than reaching the bucket-policy handler |
| `NoSuchBucketPolicy` on one bucket | The bucket has no policy, so no statement is read. Its ACL was read first and its verdict stands: the bucket reaches the results list when the ACL alone names a public group URI or a canonical user other than the owner |
| Any other `ClientError` on one bucket, `AccessDenied` included | Logged and re-raised, aborting the run |
| An ACL grant whose grantee type is neither `CanonicalUser` nor `Group`, or whose group URI is none of `AllUsers`, `AuthenticatedUsers`, and `LogDelivery` | `UnknownGranteeTypeError`, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list, or a list holding anything but objects | `MalformedPolicyError` |
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
| `buckets_third_parties_can_access` | Exemptions plus compliant |
| `buckets_with_wildcards` | Exemptions only |

Summary fields beyond the common three: `total_buckets_analyzed`,
`buckets_third_parties_can_access`, `buckets_with_wildcards`, `violations`,
`exemptions`, `unique_third_party_accounts`, `third_party_account_count`,
`exempt_bucket_arns`, `actions_by_third_party_account`,
`buckets_by_third_party_account`.

`violations` is structurally zero: `categorize_result` never returns
`VIOLATION`. It is written anyway, because a reader cannot tell an absent key
from a genuine zero and RCP parsing refuses to guess
([`../../contracts/results.md`](../../contracts/results.md)).
`buckets_with_wildcards` in the summary is the exemption count;
`buckets_third_parties_can_access` counts the exemptions that also carry a
third-party account ID, plus the compliant buckets, so a public bucket that
grants no named account is not counted as third-party access.

`exempt_bucket_arns` is a sorted list of bucket ARN **strings**, one per
exempted bucket, and is the second allowlist this check declares. A bucket ARN
carries no account field, so `exclude_account_ids` leaves it alone and the
declaration does not set `restores_account_ids`.

**Result files written before `exempt_bucket_arns` existed do not parse.** RCP
parsing aborts by name on a summary missing a declared key, because an absent
key cannot be told from an account that observed nothing (INV-01), and its
error says which file to delete and re-scan.

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

`buckets_with_wildcards` holds every exemption, not only entries with a
literal wildcard principal. A `Federated` or `CanonicalUser` principal and a
CloudFront OAI are folded into the same field, so the name understates what it
holds. The equivalent field on
[`deny_ecr_third_party_access`](deny_ecr_third_party_access.md),
[`deny_kms_third_party_access`](deny_kms_third_party_access.md),
and [`deny_secrets_manager_third_party_access`](deny_secrets_manager_third_party_access.md)
understates the same way, holding their violations; on
[`deny_sqs_third_party_access`](deny_sqs_third_party_access.md) it holds
exemptions, as here.

## Placement and generated policy

Every account is safe, so placement lands at root; there is no blocker this
check can raise. The principal allowlist is the union of
`unique_third_party_accounts` across covered accounts, as for every RCP.

The exempt-bucket round trip (INV-07):

1. `summary.exempt_bucket_arns` — bucket ARNs, untouched by
   `exclude_account_ids` because a bucket ARN has no account field.
2. RCP parsing reads it as the second declared allowlist, by the same reader
   that reads `unique_third_party_accounts`, and aborts on a file lacking it.
3. `RCPCheckResult.allowlist_values["exempt_bucket_arns"]`.
4. The sorted union across the accounts a placement covers.
5. `RCPPlacementRecommendations.allowlist_values["exempt_bucket_arns"]`.
6. The `s3_third_party_access_exempt_bucket_arns` Terraform variable, rendered
   after the principal allowlist whenever the boolean is true, `[]` included.
   The module expands each entry to the bucket and its objects.

The module validates each entry as `arn:aws:s3:::` followed by a name with no
`/` — the ARN prefix and the absence of an object key, not a bucket-name
regex, because a bucket created in us-east-1 before March 2018 may carry
uppercase letters and underscores.

**An empty exempt list leaves the policy on.** With no bucket to spare the
module renders `Resource: "*"` in place of `NotResource`, and the statement
denies every out-of-organization principal on every bucket, which is the good
case rather than a broken run. This is the third INV-06 shape, alongside the
omitted `aws:PrincipalAccount` clause; the declaration therefore sets no
`empty_allowlist_comment`.

## Accepted limitations

1. The synthesized bucket ARN hardcodes the `aws` partition.
2. Access Points are unread, and a spared bucket is spared on its bucket and
   object ARNs only. A request through an access point is authorized against
   the access-point object ARN,
   `arn:aws:s3:REGION:111111111111:accesspoint/NAME/object/KEY`, which neither
   `NotResource` entry matches, so a third party reading an exempt bucket
   through an access point in the same account is expected to be denied once
   the statement lands. This is AWS's recommended delegation pattern, not an
   edge case: a bucket policy granting `Principal: "*"` under
   `StringEquals s3:DataAccessPointAccount` reads as an unconfined wildcard,
   because that key bounds no principal
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)),
   so the bucket is exempt and the account is not blocked. An access point
   owned by an account outside the organization is expected to be unaffected:
   that resource is outside the statement's reach, and the bucket-side
   authorization is spared. Neither expectation has been verified against a
   live organization.
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
7. An exempt bucket is spared for **every** principal and every `s3:*` action,
   not only the grant that made it exempt. A bucket public for `GetObject` on
   one prefix is also reachable by any third-party account its policy names
   for anything else, and a later edit to that bucket's policy is not caught
   by this statement. The bucket's own policy and ACL remain the only control
   on it.
8. A bucket made public, or granted to a federated identity, between the scan
   and the apply is absent from the exempt list; its next cross-organization
   request is denied.
9. A bucket deleted after the scan stays in the list, which is harmless: the
   `NotResource` entries match nothing. A bucket name is global, so a new
   bucket created under the same name by another account is spared too, until
   the next scan.
10. Two ARNs per exempt bucket compete for the module's 5,120-character RCP
    budget. An organization with many public buckets can exceed it at the
    root; the module fails at plan time with the character count rather than
    attaching a truncated policy.
11. An account excluded from analysis — one in `skip_account_ids`, in a
    non-ACTIVE lifecycle state, or created between the scan and the apply —
    contributes no exempt bucket, and the root placement this check always
    produces reaches it anyway. The management account is not part of this
    gap, since no RCP reaches it
    ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#scp-versus-rcp)).
    [`../../contracts/placement.md`](../../contracts/placement.md#rcp-placement)
    records the general case as "excluded from analysis" and calls it open
    and deliberate. A bucket already public in such an account is denied on
    the next cross-organization request, while the check itself reports
    every analyzed account compliant.

## Acceptance scenarios

1. A bucket policy granting `arn:aws:iam::111111111111:root`, outside the
   organization → compliant, and `111111111111` enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A bucket policy with `Principal: "*"` → exemption; `summary.exempt_bucket_arns`
   holds the bucket ARN, and the account is not blocked.
4. A bucket policy with a `Federated` principal → exemption, recorded rather
   than raised, and the bucket ARN is exempt.
5. A bucket policy with a `CanonicalUser` principal → exemption, and the
   bucket ARN is exempt.
6. A bucket with no policy → skipped.
7. `AccessDenied` reading one bucket's policy → the run aborts.
8. A `Principal: "*"` narrowed by `StringEquals aws:PrincipalOrgID` naming
   this organization → not a violation, and the bucket is not recorded at all:
   the bound admits only callers the deployed statement already spares, so
   there is no account to allowlist and nothing left for an RCP to break. The
   same wildcard bounded by `StringEquals aws:PrincipalAccount` to an
   out-of-organization account is compliant and that account enters the
   allowlist.
9. A bucket policy granting a CloudFront origin access identity → exemption;
   the distribution keeps working, and the recorded ARN says which bucket
   should move to origin access control.
10. A `Principal: "*"` under `StringEquals kms:CallerAccount` naming
    `333333333333` → still an exemption. No Amazon S3 request carries that
    key, so the clause admits nobody and the statement grants nobody anything;
    it is a bound in a KMS key policy and nowhere else, and the wildcard is
    read as unconfined.
11. A bucket whose ACL grants the `AllUsers` group and whose policy names only
    in-organization principals → exemption from the ACL surface; the bucket
    ARN is exempt.
12. A bucket with `Principal: "*"` that also names `arn:aws:iam::111111111111:root`
    → exemption, and `111111111111` still enters the principal allowlist:
    `buckets_third_parties_can_access` counts it, `buckets_with_wildcards`
    counts it, and both lists in the body hold it.
13. An account with no exempt bucket → `violations: 0`, `exemptions: 0`, and
    `exempt_bucket_arns: []`, present rather than absent; a module covering
    only such accounts renders `s3_third_party_access_exempt_bucket_arns = []`
    and the statement carries `Resource: "*"`
    (`empty_exempt_lists_render_resource_star` in the module's
    `tests/plan.tftest.hcl`).
14. Two accounts, one with an exempt bucket and one without → the root
    recommendation carries that one ARN, and the module renders it as the
    bucket ARN and the bucket ARN with `/*` appended under `NotResource`
    (`populated_exempt_lists_render_not_resource` in the module's
    `tests/plan.tftest.hcl`).
15. A result file written before `exempt_bucket_arns` existed → RCP parsing
    aborts naming the file, the key, and the check, and prescribes deleting
    the file and re-running.
16. An exempt-bucket entry carrying `/` → the module's variable validation
    rejects the plan with a message naming the variable and the required form
    (`bucket_arn_with_object_key_is_rejected` in
    `test_environment/modules/rcps/tests/plan.tftest.hcl`, run under `tox` by
    `tests/test_terraform_module_plans.py`).

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-07, INV-13.

## Implementation

- `headroom/checks/rcps/deny_s3_third_party_access.py`
- `headroom/aws/s3.py` — `analyze_s3_bucket_policies`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `headroom/parse_results.py` — `_read_declared_allowlist`,
  `union_allowlist_values`
- `test_environment/modules/rcps/locals.tf`
- `test_environment/modules/rcps/variables.tf`
- Tests: `tests/test_checks_deny_s3_third_party_access.py`,
  `tests/test_aws_s3.py`, `tests/test_aws_policy_documents.py`
