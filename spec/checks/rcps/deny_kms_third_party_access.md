---
id: deny_kms_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_kms_third_party_access.py
  - headroom/aws/kms.py
  - headroom/aws/iam_unique_ids.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-14
  - INV-16
verification:
  - tests/test_checks_deny_kms_third_party_access.py
  - tests/test_aws_kms.py
  - tests/test_aws_iam_unique_ids.py
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
- Evaluates `Condition` only for a bound on the statement's principals, under
  the rule
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
  owns. A condition that narrows the grant rather than the principal set is
  unread, and so are `Resource`/`NotResource` and `NotAction`.
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

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Condition`,
`Action`. The statement is read by `read_statement_principals` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`, which reads the `Principal` element with
`_read_principal` and, where that element is a wildcard, asks the `Condition`
whether it bounds what the wildcard reaches
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)).
This is the one policy type where `kms:CallerAccount` can prove such a bound;
that document owns why it is read here and nowhere else.

For each grant: `GrantId`, `GranteeServicePrincipal`, `GranteePrincipal`,
`Operations`, `Constraints` presence. `RetiringPrincipal`,
`RetiringServicePrincipal`, and `IssuingAccount` are not read; the Decision
table owns why.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | An unconfined wildcard principal — a literal `*` whose statement carries no bound the reader can prove, or an `Allow` with `NotPrincipal`, which is never confined | `VIOLATION` |
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, `kms:CallerAccount` included, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the key `COMPLIANT` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |
| Not recorded | An AWS-managed key: `KeyManager` is `AWS` on `DescribeKey` | Not in the output; neither its policy nor its grants are read |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Violation | An ARN naming no account, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run) owns | `VIOLATION` |
| Aborts | A principal key AWS does not document | The run aborts |
| Compliant | A grant whose `GranteePrincipal` is an ordinary ARN outside the organization, with any operation other than `RetireGrant` alone, or with no `Operations` | `COMPLIANT`; the grantee's account enters the allowlist |
| Not recorded | A grant listed with `GranteeServicePrincipal`, or whose `GranteePrincipal` is an AWS service principal | Not in the output; the RCP exempts services with `aws:PrincipalIsAWSService`. When the typed field is present the display `GranteePrincipal` beside it is not read |
| Not recorded | A policy statement or a grant naming a service-linked role, in any partition, identified by the reserved `role/aws-service-role/` path | Not in the output, whichever account holds the role; RCPs do not impact service-linked roles. [`../../contracts/policy-model.md`](../../contracts/policy-model.md#principals) owns the rule, and both surfaces read it. The rule matches a path, so it reaches a role named by ARN only: a service-linked role a grant names by a decodable unique ID carries no path to match and is allowlisted like any other grantee, which exempts every principal in its account and not the role alone (limitation 7) |
| Not recorded | A grant whose nonempty `Operations` is only `RetireGrant`, or a policy statement whose only action is the literal `kms:RetireGrant` | Not in the output; RCPs do not impact `kms:RetireGrant`, and the permission is not effective in a key policy at all. Such a statement is skipped whole, so `Principal: "*"` or `NotPrincipal` on it is not a blocker either, and such a grant is skipped before its `GranteePrincipal` is read, so an opaque grantee on it is not an abort either |
| Not read | `RetiringPrincipal` and `RetiringServicePrincipal`, whatever they hold | Never classified, allowlisted, or failed on |
| Compliant | A `GranteePrincipal` that is an IAM unique ID — `AROA` or `AIDA` followed by exactly seventeen characters from `A-Z2-7` and nothing else — decoding to an account outside the organization, on a grant with no `GranteeServicePrincipal`, with any operation other than `RetireGrant` alone, or with no `Operations` | `COMPLIANT`; the decoded account enters the allowlist, and the entry records `grantee_account_id_source: iam_unique_id` so the reading that produced it is auditable |
| Not recorded | The same shape, decoding to an account the organization already holds | Not in the output; an in-organization grantee is not a third party, whichever form named it. Logged at `DEBUG` with the identifier and the account it decoded to: this is the one grant the results themselves cannot account for, so the log is all an operator asking after it has |
| Violation | The same shape, which the encoding cannot resolve — below the offset, which is the legacy random format, or decoding to `000000000000` or past `999999999999` | `VIOLATION`; recorded under the entry's `unresolved_grants` with the complete identifier. The grantee holds access the RCP would deny and names no account, so nothing enters the allowlist and the account is blocked for KMS. The run continues |
| Aborts | A `GranteePrincipal` that is neither an ARN, an AWS service principal, nor an IAM unique ID in the documented shape, on a grant with no `GranteeServicePrincipal`, with any operation other than `RetireGrant` alone, or with no `Operations` | The run aborts. The shape alone spares the abort: an identifier matching it is read or recorded by one of the three rows above, whether or not an account comes out of it |

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

A service-linked role named by ARN is exempt on both surfaces by the one rule
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

The two surfaces read a bare IAM unique ID differently. In a policy's
`Principal` element it names nothing at all
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#principals));
as a grant's `GranteePrincipal` it names the account the identifier encodes,
and blocks the key's account only when the encoding cannot resolve it. The
surfaces differ in recognition and not only in verdict: the grant surface
matches the shape against `^AROA[A-Z2-7]{17}$` and its `AIDA` twin, while
`_read_principal` carries no unique ID pattern at all and reads a bare
identifier as nothing only because it is a non-ARN string naming no account —
so a lowercase copy, a session suffix, and `AROA11111111111111111` are each
nothing in a policy and each abort the run as a grantee. The two readings
differ because the guarantees differ. For a policy, IAM documents the
mechanism: a `Principal` ARN is stored as the entity's unique ID and displayed
as the ARN while the entity exists, and once the entity is deleted the bare ID
is what the policy shows, because "the policy no longer applies, even if you
recreate the role because the new role has a new principal ID"
([IAM role principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-roles)).
A unique ID read back from a policy is therefore a dead entry. For a grant,
[`ListGrants`](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListGrants.html)
documents `GranteePrincipal` as usually containing "the user or role
designated as the grantee principal in the grant", and otherwise as containing
a service principal when the grantee is an AWS service. It says nothing about
what the field holds once that user or role is deleted, whether the grant still
authorizes anything, or whether KMS performs the transformation IAM documents
for policies. A grant is a separate authorization object, not a policy, and
nothing AWS publishes extends the policy guarantee to it. INV-01 settles the
rest: the grantee holds access the RCP would deny, so the analyzer reads the
account out of the identifier where it can, and where it cannot it records the
grant rather than reading the silence as safe. The unresolved verdict is the
one a `Federated` principal receives, reached on the grant surface, and it is
recorded rather than raised because the identifier is regular enough to be
recognized and reported. Sibling grants are not consulted to guess whose role
it was, and no IAM call is made to find out.

The classifier is strict: the prefix must be `AROA` or `AIDA` and the body
exactly seventeen characters from `A-Z2-7`, anchored at both ends, so nothing
may precede or follow
([IAM identifiers reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids)).
The character class is the AWS Base32 alphabet, which omits `0`, `1`, `8`, and
`9`; a body carrying one of those four is not an identifier AWS could have
issued, whatever else is right about it. A lowercase copy, a wrong length, or a
session suffix such as `AROA6RVFFB77QAAAAAAAA:session-name` is likewise not a
unique ID, and each still aborts the run rather than being decoded or recorded.

The account is read out of the identifier and out of nothing else, by
`headroom/aws/iam_unique_ids.py`. The eight characters after the prefix spell a
forty-bit number in that alphabet, most significant first. A number below
`QAAAAAAA`, which is two to the thirty-ninth — the top bit of that field, and a
format flag rather than a threshold — is the legacy random format and carries
no account. At or above it, the account is twice what is left once the flag is
cleared, plus one when the character at index 12, the ninth after the prefix,
ranks at or above `Q`: the account's lowest bit is displaced out of the
eight-character field and into that character as its own highest. A result
above `999999999999` is larger than any account AWS can issue and is rejected,
and so is `000000000000`, which no account holds either. The rejection stops
there: AWS publishes no smallest issued account, so a floor anywhere above zero
would be a guess at where accounts start, and zero is the one result inside the
twelve digits that needs no guess. So `AROA6RVFFB77QAAAAAAAA` decodes to
`999999999999` and `AROAQAAAAAAAQAAAAAAAA` to `000000000001`, while
`AROAAAAAAAAAAAAAAAAAA` sits below the offset, `AROA77777777777777777` decodes
past the top of the range, and `AROAQAAAAAAAAAAAAAAAA` arrives at the zero
account, none of the last three resolving to anything.

That encoding is reverse-engineered from published research rather than an
AWS-supported contract
([AWS access key ID formats](https://awsteele.com/blog/2020/09/26/aws-access-key-format.html)),
and that research documents the `AKIA` and `ASIA` access key IDs. That a
principal unique ID is encoded the same way is an inference from the one
published `AROA` whose account is also on record, and
`tests/test_aws_iam_unique_ids.py` pins both halves. Which is why every
validation failure stays fail-closed: a shape the patterns
do not match aborts the run, and a shape they match but the encoding cannot
resolve blocks the account. The guarantee runs one way only. A `None` result
says the encoding does not resolve the identifier, not that the identifier is
legacy: a value decoding past `999999999999` is neither legacy nor resolvable.
An account handed back is evidence that the identifier is in the current format
rather than proof of it, because the format is marked by that one bit and a
legacy identifier carrying it set would decode to a plausible, wrong account.

An AWS-managed key is skipped on `KeyManager` alone. AWS states that resource
control policies do not apply to AWS managed keys, in both the
[KMS key concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-key)
and the
[RCP documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#actions-not-restricted-by-rcps),
so no statement this check gates can reach one; and such a key can be used only
by principals in the account that holds it, so there is no third party to
preserve either. Reading the policy could only reach a verdict on a key this
RCP cannot govern, and skipping ahead of `GetKeyPolicy` and `ListGrants` saves
those two calls per key.

The skip rests on the key type and on nothing the document says, which is why
it survives every change to how the document is read
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
It was once the only thing between one shape and a blocked account. The
default policy of an AWS-managed key grants `Principal: {"AWS": "*"}` narrowed
by `kms:CallerAccount` to the key's own account — the idiom AWS documents for
"all identities in one account", because the `Principal` element has no syntax
for it — and read for its `Principal` element alone that is a wildcard, so
before the skip every account holding such a key was blocked for this RCP by a
policy its operator cannot change. The skip is no longer what catches that
shape on its own: `kms:CallerAccount` names the account of the calling
principal, so in a KMS key policy it enumerates who the wildcard reaches, and a
customer-managed key written the same way is bounded to the account the clause
names rather than blocking on the wildcard
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)).
`kms:ViaService`, which sits beside it in that same default policy, is not a
bound: it names the service a call came through and not the principal that made
it. `DescribeKey` is the identification AWS documents as definitive; the `aws/`
alias prefix is the informal one.

## Failure behavior

| Situation | Behavior |
|---|---|
| `NotFoundException` from `GetKeyPolicy` on one key | The key has no policy, so no statement is read. Its grants are still listed, and the key reaches the results list if one of them names an account outside the organization, or names an IAM unique ID the encoding cannot resolve - which names no account at all and makes the key a violation |
| `ClientError` from `DescribeKey` on one key | Re-raised, aborting the run. The key's type is unknown, and either guess is wrong: reading the policy could block the account over an AWS-managed key, and skipping could drop a customer-managed key that grants a third party |
| Any other `ClientError` on one key | Re-raised, aborting the run |
| A grant whose `GranteePrincipal` is neither an ARN, an AWS service principal, nor a value the two unique ID patterns match, with no `GranteeServicePrincipal` beside it and any operation other than `RetireGrant` alone, or with no `Operations` | `UnknownGrantPrincipalError`, aborting the run. The message names the key ARN and the grant ID, and the run stops before anything records the key. `AWS Internal` as the grantee raises like any other opaque value, and so does a near miss the patterns reject — a lowercase copy, a wrong length, a session suffix, a body carrying `0`, `1`, `8`, or `9`: the grantee holds access the RCP would deny, and nothing authoritative says which account it belongs to |
| A grant whose `GranteePrincipal` is an IAM unique ID the patterns match but the encoding cannot resolve, with no `GranteeServicePrincipal` beside it and any operation other than `RetireGrant` alone, or with no `Operations` | Recorded under the entry's `unresolved_grants` with the complete identifier, and logged at `WARNING` with the key ARN and grant ID. The key is a `VIOLATION`, the account is blocked for KMS, and the run continues. No account is inferred for it |
| A grant whose `GranteePrincipal` is an IAM unique ID decoding to an account outside the organization | Not a failure. Nothing is logged above `DEBUG`, the decoded account enters the allowlist, and the run is unaffected. The account is read out of the identifier alone; no IAM call is made and no other field is consulted |
| A grant whose nonempty `Operations` is only `RetireGrant`, whatever its `GranteePrincipal` | Skipped before the grantee is read, so an opaque or unique-ID grantee on it neither raises nor records, and no unique ID on it is decoded |
| A grant whose `RetiringPrincipal` or `RetiringServicePrincipal` is opaque, `AWS Internal` included | Nothing. The field is not read, so no value in it can raise |
| A grant with no `Operations` | Recorded with an empty operations list when its grantee is outside the organization, not dropped as `RetireGrant`-only |
| A grant carrying no `GrantId` | `KeyError`, aborting the run. `ListGrants` returns the ID `RetireGrant` takes, so its absence is a response Headroom has misread; recording the grant with a blank ID would report access through a grant nobody can name |
| A grant carrying neither `GranteeServicePrincipal` nor `GranteePrincipal`, with any operation other than `RetireGrant` alone, or with no `Operations` | `KeyError`, aborting the run. Every grant is listed with one of the two, so a grant with neither is a response Headroom has misread, and dropping it would read a missing grantee as no grantee (INV-01). A `RetireGrant`-only grant is skipped before either field is read, so it cannot raise this |
| `ClientError` in any region | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| `Principal` neither string, list, nor object | `MalformedPolicyError` |
| An `Allow` carrying neither `Principal` nor `NotPrincipal` | `MalformedPolicyError` — AWS stores no such statement, so it is a document misread rather than a grant to nobody |
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
`keys_with_third_party_grants`, `keys_with_unresolved_grants`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`,
`actions_by_account`.

`total_keys_analyzed` counts the keys that produced an entry — violations,
exemptions, and compliant together — not the keys `ListKeys` returned. An
AWS-managed key, or a customer-managed key whose policy and grants name only
in-organization principals, is never entered and is not counted.

`keys_with_third_party_grants` counts the entries whose `grants` list is
non-empty. It and `keys_with_unresolved_grants` are the only summary-level
signals that the grant surface found anything. Without them a key with a clean
policy and a grant is indistinguishable in `summary` from one found through its
policy.

`keys_with_unresolved_grants` counts the entries whose `unresolved_grants` list
is non-empty. It is the summary-level signal that a violation came from a
grantee the analyzer could not attribute rather than from a wildcard; without
it, `violations: 1` sends the reader through every entry to learn which.

Entry shape: `key_id`, `key_arn`, `region`, `third_party_account_ids`,
`actions_by_account`, `has_wildcard_principal`, `has_non_account_principals`,
`grants`, `unresolved_grants`, `confined_by`.

`confined_by` holds the condition keys, lower-cased, that each bounded one of
the key policy's statements on their own, unioned across the policy. A key is
recorded whether or not the KMS key still blocks — one bounded statement
beside one unbounded one, or beside an unresolvable grant, reports both the
condition key and the violation — but only for a statement whose `Principal` was a wildcard. The reader
consults a `Condition` for nothing else, so a bound beside a `Principal`
that already names its callers is neither read nor recorded.
It reports the policy surface alone; a grant carries no `Condition`.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
owns which keys can appear and what each proves. The field is additive: a
result file written before it existed lacks the key, and both readers read only
`summary` (INV-14).

`grants` holds one object per grant reaching outside the organization —
`grant_id`, `grantee_account_id`, `grantee_principal`,
`grantee_account_id_source`, `retiring_principal_account_id`, `operations`,
`has_constraints` — and is an empty list on a key whose only third-party access
is in its policy. `grantee_account_id` is always set on an entry, since a
grantee outside the organization is what makes one.

`grantee_principal` is the complete `GranteePrincipal` exactly as `ListGrants`
returned it, and `grantee_account_id_source` says which reading produced the
account beside it: `arn` when the `GranteePrincipal` spelled the account out,
`iam_unique_id` when it was decoded from a bare identifier. The two are not
worth the same to a reader auditing an allowlist — one is what AWS returned,
the other is arithmetic on a reverse-engineered encoding (limitation 6) — so
the distinction is written down rather than left to be re-derived from the
string. The pair is additive: a result file written before the two fields
existed lacks both keys, and both readers read only `summary` (INV-14).

With `--exclude-account-ids` set, `grantee_principal` is subject to the same
redaction every other string in the document is: the account field of an ARN
becomes `REDACTED`
([`../../contracts/results.md`](../../contracts/results.md#redaction)). So an
ARN-backed grant is written as `arn:aws:iam::REDACTED:role/VendorRole` while
`grantee_account_id` beside it keeps the account, and the two fields read as
disagreeing. That is the global rule and not something this check does, and it
leaves the decoded case untouched, because a bare unique ID is not ARN-shaped
and has no account field to blank — so the provenance survives on both, and
the identifier survives wherever it is the only handle there is.

`deny_kms_third_party_access` is the only one of the six third-party-access
checks whose entry shape carries a field of its own for a second surface.
[`deny_s3_third_party_access`](deny_s3_third_party_access.md) reads two
surfaces as well and merges the ACL's verdict into `has_wildcard_principal`
and `has_non_account_principals` rather than reporting it separately.

`retiring_principal_account_id` is always `null` on a newly analyzed entry: the
retiring principal is no longer read, for the reason the Decision table gives,
and the field is kept only so persisted results keep their shape (INV-14). A
result file written before that change may carry an account there, and both
readers still read it.

`unresolved_grants` holds one object per grant whose `GranteePrincipal` is an
IAM unique ID the encoding cannot resolve — `grant_id`, `grantee_principal`,
`principal_kind`, `operations`, `has_constraints` — and is an empty list on
every other entry. `grantee_principal` is the complete identifier exactly as
`ListGrants` returned it, never truncated, because it is the one handle an
operator has on the grant, and redaction leaves it alone for the reason above.
`principal_kind` is `iam_role_unique_id` for an `AROA` prefix and
`iam_user_unique_id` for `AIDA`; `operations` is `kms:`-prefixed and sorted
like a `grants` entry's, and empty when the grant listed none.
`has_non_account_principals` stays `False`: it reports the policy surface, and
the grant surface reports itself through this field. The field is additive: a
result file written before it existed lacks the key, and both readers read only
`summary` (INV-14).

`service_principal_sources` is **not** written. `analyze_kms_key_policies`
carries it on the in-memory analysis only, and
[`deny_service_confused_deputy`](deny_service_confused_deputy.md) reads it by
re-running that analyzer rather than by reading these files. That second call is
served from the analyzer's per-session memo and issues no AWS request;
[`../index.md`](../index.md) owns the accounting.

`actions_by_account` is filtered to third-party accounts.

`keys_with_wildcards` counts every violation, not only entries with a literal
wildcard principal. A `Federated` or `CanonicalUser` principal is recorded as a
violation rather than aborting, and so is a key whose only finding is a grant to
an unresolvable unique ID - which has no policy principal behind it at all, and
no wildcard anywhere. Both are folded into the same field, so the name
understates what it holds by more than the one route it was named for.
`keys_with_unresolved_grants` is what separates the second route back out. The
same understatement applies to the equivalent field on all five resource-policy
checks, for the `Federated` and `CanonicalUser` route they share.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts. Blocking is not local
to the blocked account: it costs the organization root-level placement for this
RCP and every OU above the account the OU level, for which
[`../../contracts/placement.md`](../../contracts/placement.md) owns the two
predicates.

## Accepted limitations

1. Only the `default` key policy is read, so access granted by a named
   non-default policy is invisible.
2. `Resource` and `NotAction` are not evaluated, and neither is a `Condition`
   that narrows the grant rather than the statement's principals — so a grant
   confined by `kms:ViaService` still contributes its account at full width
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
3. **A grant's `Constraints` are recorded as a boolean and not read.** A grant
   narrowed to one encryption context is reported exactly as an unrestricted
   grant to the same account, so the allowlist it feeds is wider than the access
   that exists.
4. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a key policy may grant nothing at all. It is still
   counted as a blocker, because whether the grant is live is not readable from
   the document and INV-01 forbids assuming it is not.
5. A grant to an IAM unique ID withholds the RCP from the account with no
   allowlist escape **when the encoding cannot resolve the identifier**, since
   there is then no account to allowlist. A grant to an identifier that does
   decode costs nothing: its account joins the allowlist and the key stays
   compliant. For the unresolved case the operator's only route to placement is
   to retire or revoke the grant
   ([KMS grant deletion](https://docs.aws.amazon.com/kms/latest/developerguide/grant-delete.html)),
   which Headroom does not do for them: it reads.
6. **The account encoding is reverse-engineered and carries no checksum.** A
   legacy identifier is random, and one whose character at index 4 happens to
   rank at or above `Q` sets the one bit the format test reads, so it passes
   that test and decodes to an account that is simply wrong. The one legacy
   identifier on record carries `J` there, rank 9, so this is unobserved;
   nothing in the format certifies it, and a single value is an observation
   and not a property. Which way the wrong account falls decides whether
   anyone can see it. Outside the organization, the grant is recorded and
   `grantee_account_id_source` says a decoding rather than an ARN produced the
   account, so the RCP allowlists an account nothing granted while the real
   grantee stays denied - wrong, but visible in the results. Inside it, the
   grant is dropped as internal: no `grants` entry and no `unresolved_grants`
   entry, and the only trace is the `DEBUG` line naming the identifier and
   the account it decoded to, so the RCP ships denying a grantee nobody
   reading the results knows about. That direction is the one this check
   cannot show its reader.

   The two directions are ranked above by visibility, not by likelihood,
   and those run opposite. Half of legacy identifiers set the format bit,
   and around nine values in ten above it land inside twelve digits, so a
   mis-decode falls outside the organization - the visible direction -
   almost every time it happens at all. Falling inside additionally
   requires the arithmetic to collide with one of the organization's own
   accounts out of a twelve-digit space, which is rarer by many orders of
   magnitude. The wrong allowlist entry is the outcome to plan for; the
   silent drop is the one that is hard to see, not the one that is
   likely.
7. **A service-linked role a grant names by a unique ID is read as an ordinary
   principal.** The exemption keys on the reserved `role/aws-service-role/`
   path, and nothing in a bare unique ID distinguishes a service-linked role
   from any other principal — so the same role is exempt when the grant names
   it by ARN and is not when the grant names it by unique ID. This is inherent
   to decoding rather than a defect in it, and both forms of the identifier
   cost something. A decodable one puts the role's account on the allowlist,
   and the allowlist renders as `aws:PrincipalAccount`, which is
   account-granular: naming an account for the sake of one service-linked role
   exempts every principal in that account from this RCP's KMS deny, not the
   role alone. An undecodable one is recorded under `unresolved_grants` and
   blocks the key's account, withholding the RCP over a role it could not have
   denied.

## Acceptance scenarios

1. A key policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. A key policy naming only its own account's root → not recorded.
3. A key policy with `Principal: "*"` → violation; the account is blocked for KMS
   only.
4. A key whose `GetKeyPolicy` returns `NotFoundException`, with no grant
   reaching outside the organization and none naming an unresolvable unique ID
   → not recorded. The missing policy does not stop `kms:ListGrants` from being
   called for that key. The same key with one unresolvable grantee is recorded
   and is a violation, on the grant surface alone.
5. A key whose only external access is a grant → compliant, and the grantee
   enters the allowlist. A grant narrowed by `Constraints` does the same, which
   is limitation 3.
6. A key policy with a `Federated` or `CanonicalUser` principal → violation; the
   account is blocked for KMS, and the remaining keys are still read.
7. A key policy naming a principal key AWS does not document → the run aborts.
8. An AWS-managed key, `KeyManager` = `AWS`, whose default policy grants
   `Principal: {"AWS": "*"}` under `kms:CallerAccount` → not recorded, and
   neither `GetKeyPolicy` nor `ListGrants` is called for it.
9. A customer-managed key with that same policy → not recorded, and not a
   violation. `kms:CallerAccount` names the key's own account, which is in the
   organization, so the bound leaves nobody the RCP would deny; the
   `kms:ViaService` clause beside it proves nothing and the account clause is
   what bounds the statement. The key-type skip in scenario 8 was once the
   only thing that kept this shape from blocking the account.
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
20. A grant with neither `GranteeServicePrincipal` nor `GranteePrincipal`,
    carrying any operation other than `RetireGrant` alone → the run aborts with
    `KeyError`. The same grant carrying only `RetireGrant` is skipped before
    either field is read, so it does not abort.
21. A key policy statement granting `kms:Decrypt` to a service-linked role in
    `999999999999` → not recorded, as the same role would be as a grantee.
22. A key policy statement granting only `kms:RetireGrant` to an ordinary role
    in `999999999999` → not recorded.
23. A key policy statement granting only `kms:RetireGrant` to `Principal: "*"`
    → not recorded, and not a violation.
24. A grant to an ordinary role in `999999999999` with
    `RetiringPrincipal: "AWS Internal"` → compliant; the grantee's account
    enters the allowlist and `retiring_principal_account_id` is `null`.
25. A grant whose `GranteePrincipal` is `AROAAAAAAAAAAAAAAAAAA`, which sits
    below the offset, with `Operations: ["Decrypt"]` and `IssuingAccount`
    naming `999999999999` → violation; `unresolved_grants` holds the grant with
    `principal_kind: iam_role_unique_id`, `999999999999` enters neither the
    results nor the allowlist, and the run continues.
26. The same grant with `GranteePrincipal: AIDAAAAAAAAAAAAAAAAAA` → violation,
    `principal_kind: iam_user_unique_id`.
27. `AROAAAAAAAAAAAAAAAAAA` as grantee with no `Operations` → violation,
    recorded with an empty operations list.
28. `AROAAAAAAAAAAAAAAAAAA` as grantee with `Operations: ["RetireGrant"]` →
    not recorded.
29. `AROAAAAAAAAAAAAAAAAAA` as grantee with
    `Operations: ["RetireGrant", "Decrypt"]` → violation, both operations
    recorded.
30. A grant listed with `GranteeServicePrincipal` and
    `GranteePrincipal: AROAAAAAAAAAAAAAAAAAA` → not recorded; the display
    value is not read.
31. `aroa6rvffb77qaaaaaaaa`, `AROA6RVFFB77QAAAAAAA`,
    `AROA6RVFFB77QAAAAAAAA:session-name`, or `AROA11111111111111111`, whose
    body carries a digit the alphabet omits, as grantee with `Decrypt` → the
    run aborts, as any opaque value does. None of the four is decoded, and
    none is recorded as unresolved.
32. `AWS Internal` as grantee with `Operations: ["RetireGrant"]` → not
    recorded; the grant is skipped before the grantee is read.
33. Two accounts, one holding a key with an unresolved grant and the other
    clean → the first is blocked for the KMS RCP; the second is placed at
    account level with its own allowlist.
34. `AROA6RVFFB77QAAAAAAAA` as grantee with `Operations: ["Decrypt"]`,
    decoding to `999999999999`, outside the organization → compliant;
    `999999999999` enters `third_party_account_ids` and the allowlist, and the
    `grants` entry carries the identifier with
    `grantee_account_id_source: iam_unique_id`.
35. `AROATHPL2AOHAAAAAAAAA` as grantee with `Operations: ["Decrypt"]`,
    decoding to `222222222222`, an account the organization holds → not
    recorded at all: no `grants` entry, no `unresolved_grants` entry, and
    nothing in the allowlist. An in-organization grantee is not a third party,
    whichever form names it.
36. `AROAAAAAAAAAAAAAAAAAA` as grantee with `Operations: ["Decrypt"]`, whose
    eight characters after the prefix fall below the `QAAAAAAA` offset and so
    are the legacy random format → violation, recorded under
    `unresolved_grants`; the account is blocked for KMS and no account is
    inferred.
37. `AROA77777777777777777` as grantee with `Operations: ["Decrypt"]`, decoding
    past `999999999999` → violation, recorded under `unresolved_grants`
    exactly as scenario 36 is. A decoding no account can hold is no account.
38. `AROAQAAAAAAAAAAAAAAAA` as grantee with `Operations: ["Decrypt"]`, the first
    identifier the format flag admits, arriving at `000000000000` → violation,
    recorded under `unresolved_grants` by the rule scenario 37 states, since no
    account holds that number either. `AROAQAAAAAAAQAAAAAAAA`, one rank up the
    displaced low bit, is compliant and allowlists `000000000001`: the
    rejection covers the zero account and nothing above it.
39. `AROA6RVFFB77QAAAAAAAA` as grantee with `Operations: ["RetireGrant"]` →
    not recorded, and not decoded either. The `RetireGrant`-only skip runs
    before the grantee is read, so the outcome does not depend on what the
    identifier would have decoded to.
40. `AROA6RVFFB77QAAAAAAAA` as grantee with `Operations: ["Decrypt"]`, on a key
    in `111111111111`, whose `IssuingAccount` names `333333333333` → compliant,
    attributed to `999999999999`, the decoded account; `333333333333` enters
    neither the results nor the allowlist, because `IssuingAccount` names who
    created the grant and not who holds it.
41. One key with two grants, one to `arn:aws:iam::999999999999:role/VendorRole`
    and one to `AROA6RVFFB77QAAAAAAAA`, both with `Operations: ["Decrypt"]` →
    compliant, with two `grants` objects, one carrying
    `grantee_account_id_source: arn` and the other `iam_unique_id`, while
    `third_party_account_ids` and the allowlist each carry `999999999999` once.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-14, INV-16.

## Implementation

- `headroom/checks/rcps/deny_kms_third_party_access.py`
- `headroom/aws/kms.py` — `analyze_kms_key_policies`
- `headroom/aws/iam_unique_ids.py` — `iam_unique_id_kind`, `decode_account_id`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_kms_third_party_access.py`,
  `tests/test_aws_kms.py`, `tests/test_aws_iam_unique_ids.py`,
  `tests/test_aws_policy_documents.py`
