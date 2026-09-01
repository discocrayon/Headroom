# Contract: policy model

Owns the vocabulary every check is written in: what an SCP and an RCP each
control, the patterns a generated statement can take, and the grammar by which
Headroom reads an existing policy document.

A per-check specification names the pattern it implements rather than restating
what the pattern is.

Implementation: `headroom/aws/policy_documents.py` (shared grammar, including
the principal types and the one function that reads a `Principal` element),
`headroom/constants.py` (ARN pattern), and every service adapter that reads a
policy document — `aws/ecr.py`, `aws/kms.py`, `aws/s3.py`,
`aws/secretsmanager.py`, `aws/sqs.py`, `aws/iam/roles.py`. A change to how a
statement is read is a change to all of them.

## SCP versus RCP

| | SCP | RCP |
|---|---|---|
| Bounds | What principals **in** the account may do | Who may act **on** resources in the account |
| Evaluated against | Requests made by principals in the account | Requests made against resources in the account, including by principals outside the organization |
| Applies to the management account | No | No |
| Headroom's evidence | Resource configuration in the account | Resource policies and trust policies in the account |
| Headroom's blocking question | Does any resource already violate the statement? | Does any resource name a principal no allowlist can express? |
| Allowlist source | Values observed in the account | Third-party account IDs observed in the account's policies |

Both are Deny-only in Headroom. Nothing generated here grants access; a
statement either denies or is omitted.

## The generated patterns

Every statement Headroom generates is one of these. The taxonomy exists so a new
check declares its shape rather than inventing one.

| # | Pattern | Mechanism | Example check |
|---|---|---|---|
| 1 | **Absolute deny** | `Deny` with no condition | `deny_iam_saml_provider_not_aws_sso` |
| 2 | **Conditional deny** | `Deny` unless a condition key holds the required value | `deny_ec2_public_ip`, `deny_rds_unencrypted` |
| 3 | **Paved road** | `Deny` unless a request tag marks the blessed path | `deny_eks_create_cluster_without_tag` |
| 4 | **Exception tag** | `Deny` unless an exemption tag is present on the request | `deny_ec2_imds_v1` |
| 5a | **Principal account allowlist** | `Deny` unless `aws:PrincipalAccount` is allowlisted | the six third-party-access RCP checks |
| 5b | **Resource ARN allowlist** | `Deny` with `NotResource` naming approved ARNs | `deny_iam_user_creation` |
| 5c | **Condition value allowlist** | `Deny` unless a condition key's value is allowlisted | `deny_ec2_ami_owner` |
| 6 | **Composition** | Two or more of the above in one statement | `deny_service_confused_deputy` |

Pattern 6 is `deny_service_confused_deputy`, the only composition. It is not
5a because the allowlisted account is not the principal: the principal is the
AWS service, and the account allowlisted is the one that configured it. The
statement composes a conditional deny — the `Null` and `Bool` gates — with a
condition value allowlist on `aws:SourceAccount`. What it renders is specified
in [`../checks/rcps/deny_service_confused_deputy.md`](../checks/rcps/deny_service_confused_deputy.md).

### Pattern 3 versus pattern 4

Both condition on a tag; they mean opposite things.

| | 3 — paved road | 4 — exception tag |
|---|---|---|
| Says | "You did it the blessed way" | "You need an exception" |
| Lifecycle | Permanent | Temporary, and should be revisited |
| Audit stance | Encouraged | Scrutinized |
| Example tag | `PavedRoad=true` | `ExemptFromIMDSv2=true` |

Prefer 3. Reach for 4 only when there is a real workload that cannot take the
paved road, and name the tag for what it exempts — `ExemptFromIMDSv2`, never
`special` — so an audit can tell what the exception buys.

The retired taxonomy carried three further design principles that are
deliberately not restated here. "Start with least privilege, then allowlist"
describes designing a statement, which Headroom does not do — it decides whether
a statement someone else wrote is deployable, and two shipped checks are
deny-the-bad-behavior by construction. "Combine patterns for defense in depth"
is pattern 6 in the table above — a shape a check declares, not advice to
repeat. "Document the why" is now the eleven-section contract in
[`../checks/index.md`](../checks/index.md), enforced by
`tests/test_spec_corpus.py` rather than asked for in prose.

The exception-tag principle did survive, as the table above, but one clause of it
did not: the requirement that an exemption record a business justification. That
asks whoever grants an exemption to say why, and Headroom reads exemption tags
off resources it did not create and cannot amend. The tag name carries what is
exempted, which a scan can see; why it was granted lives wherever the tag was
applied.

### Pattern 5 variants

| | 5a | 5b | 5c |
|---|---|---|---|
| Constrains | **Who** — the principal | **What** — the resource | **Which value** — a condition key |
| Construct | `aws:PrincipalAccount` | `NotResource` | `Condition` value list |
| Granularity | Account | Resource ARN | Attribute |

No 5-family statement renders an empty allowlist as `[]` (INV-06), but the
remedy differs by shape: a 5b or 5c check whose covered accounts observed no
values leaves its policy off, while a 5a check omits its `aws:PrincipalAccount`
clause and still renders.
[`../invariants.md`](../invariants.md#inv-06--an-empty-allowlist-is-never-rendered-as-an-empty-list)
owns the rule and why each shape earns the remedy it gets, and
[the section below](#the-rcp-allowlist-statement) states what the 5a omission
costs.

## The RCP allowlist statement

The six third-party-access RCP checks generate the same shape, differing only
in `Action` and in which allowlist variable feeds them:

```
Effect:    Deny
Principal: "*"
Action:    <the service's actions>
Resource:  "*"
Condition: StringNotEqualsIfExists  aws:PrincipalOrgID   = <this organization>
           StringNotEqualsIfExists  aws:PrincipalAccount = <allowlist>   (omitted when empty)
           BoolIfExists             aws:PrincipalIsAWSService = "false"
```

Three consequences follow, and they are the same for all six:

- **In-organization principals are never denied**, whatever the allowlist holds,
  because `aws:PrincipalOrgID` matches organization *membership* — which by
  INV-04 includes closed accounts and skipped accounts.
- **AWS service principals are never denied**, so a service acting on the
  resource on your behalf is unaffected.
- **The `aws:PrincipalAccount` clause is omitted entirely when the allowlist is
  empty**, rather than rendered as an empty list. With it omitted, the statement
  still denies every out-of-organization principal; rendered empty, the semantics
  would differ.

`deny_service_confused_deputy`, the seventh registered RCP check, is pattern 6
above and generates a different statement. It shares `Effect`, `Principal`, and
`Resource` with the shape here and differs in `Action` and `Condition`, so
neither the shape nor these three consequences describe it — most sharply the
second, since it targets the service principals the six exempt.
[`../checks/rcps/deny_service_confused_deputy.md`](../checks/rcps/deny_service_confused_deputy.md)
specifies what it generates.

Terraform variables, for all seven registered RCP checks:

| Check | Enable variable | Allowlist variable |
|---|---|---|
| `deny_ecr_third_party_access` | `deny_ecr_third_party_access` | `ecr_third_party_access_account_ids_allowlist` |
| `deny_kms_third_party_access` | `deny_kms_third_party_access` | `kms_third_party_access_account_ids_allowlist` |
| `deny_s3_third_party_access` | `deny_s3_third_party_access` | `s3_third_party_access_account_ids_allowlist` |
| `deny_secrets_manager_third_party_access` | `deny_secrets_manager_third_party_access` | `secrets_manager_third_party_account_ids_allowlist` |
| `deny_sqs_third_party_access` | `deny_sqs_third_party_access` | `sqs_third_party_access_account_ids_allowlist` |
| `deny_sts_third_party_assumerole` | `deny_sts_third_party_assumerole` | `sts_third_party_assumerole_account_ids_allowlist` |
| `deny_service_confused_deputy` | `deny_service_confused_deputy` | `service_confused_deputy_source_account_ids_allowlist` |

Five of the seven allowlist variables are the check name without `deny_`, plus
`_account_ids_allowlist`. Two are not. Secrets Manager's drops the `_access_`
segment its check name carries — the Terraform module defines it that way, and
it is not a typo to fix in Python: the Python table matches the module, and
normalizing the name there would emit a module call assigning a variable the
module never declares, which `terraform plan` refuses.
`deny_service_confused_deputy`'s inserts `source_`, because the list holds the
accounts a service acted **for** rather than calling principals.
[`../checks/rcps/deny_service_confused_deputy.md`](../checks/rcps/deny_service_confused_deputy.md)
owns that reason.

## Reading an existing policy document

This grammar is shared. A check does not re-derive it.

### Statements

`Statement` may be a lone object where a one-element list would do; IAM accepts
both, so both reach the analyzers and both are read as a list.

Anything else — a string, a number, `null` — raises `MalformedPolicyError`.
Reading it as no statements would report the resource as granting nothing, which
is not a safe guess (INV-01).

### Principals

| Form | Read as |
|---|---|
| `Principal: "*"` or `{"AWS": "*"}` | Wildcard — a blocker |
| `Allow` with `NotPrincipal` | Wildcard — grants to everyone except a short list, the same reach |
| `Deny` with `NotPrincipal` | Nothing — it restricts rather than grants, and a resource policy's Deny hands access to nobody |
| An account ID or an ARN | The 12-digit account ID it names |
| `Service` | Not an account principal, and not a blocker |
| `Federated` | Carries no account ID — a blocker. A SAML provider ARN does contain twelve digits, but they name the provider's host account, not the caller's. |
| `CanonicalUser` | An opaque identifier that maps to an account only through an API call the scan does not make — a blocker |
| Any other key | `UnknownPrincipalTypeError` |
| Not a string, a list, or an object | `MalformedPolicyError` — the element is not a Principal at all |

The reader raises; what that costs is the caller's. Five of the six analyzers
let it abort the run. `aws/sqs.py` is the one that catches it and records the
queue as a read failure, which withholds the confused-deputy statement from the
account rather than dropping the queue from the scan;
[`../checks/rcps/deny_sqs_third_party_access.md`](../checks/rcps/deny_sqs_third_party_access.md)
owns that departure and
[`../architecture/aws-execution.md`](../architecture/aws-execution.md) places it
against INV-02.

Callers must apply their own `Effect` gate **before** consulting `NotPrincipal`.
A statement carrying both `Principal` and `NotPrincipal` is not valid IAM and
cannot be stored; were one to arrive, it is treated as a wildcard rather than
letting the `Principal` half stand in for a broader grant.

The account ID is extracted from an ARN with a deliberately loose pattern: the
service segment is unconstrained, because a resource-policy principal can be an
STS session ARN as readily as an IAM one, and the partition is matched the same
way so GovCloud and China ARNs resolve.

### One reader, six analyzers

`read_principal` in `headroom/aws/policy_documents.py` is the only place a
`Principal` element is interpreted. It returns three facts and nothing else: the
account IDs the element names, whether it reaches principals the analyzer cannot
enumerate, and whether it names a principal type that carries no account ID.

A bare string carries no principal-type key, so it names none of the
non-account types — the third fact is `False` whether the string resolves to
an account ID, an ARN, or the wildcard. Pinned by
`test_a_bare_string_principal_names_no_non_account_type`, since nothing else
in the suite reads that branch's value for the third fact.

The permitted keys are a parameter, because the two policy types differ in one
key and only one:

| Set | Keys | Used by |
|---|---|---|
| `RESOURCE_POLICY_PRINCIPAL_TYPES` | `AWS`, `CanonicalUser`, `Federated`, `Service` | `aws/ecr.py`, `aws/kms.py`, `aws/s3.py`, `aws/secretsmanager.py`, `aws/sqs.py` |
| `TRUST_POLICY_PRINCIPAL_TYPES` | `AWS`, `Federated`, `Service` | `aws/iam/roles.py` |

A canonical user ID is an Amazon S3 identifier, so it cannot name who may assume
a role and a trust policy does not accept the key. The resource-policy set is
the **union** of what resource policies accept rather than a list per service:
S3 is the service that documents `CanonicalUser`, and admitting the key
everywhere costs a branch that never fires if AWS rejects it elsewhere, where
excluding it would abort a whole organization's scan over one queue.

### A blocker stops the account; a document Headroom cannot read stops the run

Both a wildcard and a principal carrying no account ID mean the same thing: the
RCP would deny a grant that exists today, because an allowlist keyed on
`aws:PrincipalAccount` cannot carry it. That is **one verdict, recorded** — the
resource becomes a violation, the account is blocked for that check, and the
scan continues. Which of the two it was is reported and not acted on
differently.

An undocumented principal key is the separate case and **aborts**. AWS validates
the `Principal` element when it stores a policy, so a key outside the documented
four means Headroom misread the document or AWS has added a principal type
nobody has modelled here. Recording it as a finding would state a verdict on a
grant this code cannot read.

The dividing line is the same one that governs unparseable JSON and a malformed
`Statement`: **a document AWS could not have stored aborts the run; a document
AWS accepted that no allowlist can express blocks the account.** Aborting
protects the account at the cost of every other account's results and puts the
finding in a stack trace instead of the report, so it is reserved for the case
where continuing would mean guessing.

[`deny_sts_third_party_assumerole`](../checks/rcps/deny_sts_third_party_assumerole.md#why-a-federated-principal-is-otherwise-no-finding-here)
reads the same three facts and acts on two of them: it is the one place the
third fact is read and deliberately ignored, and it owns the argument for
ignoring it.

### Actions

Only [`deny_sts_third_party_assumerole`](../checks/rcps/deny_sts_third_party_assumerole.md)
**gates** on actions: a trust-policy statement counts only if its actions cover
`sts:AssumeRole`. The other five analyzers read every `Allow` statement whatever
it grants, and keep the action list for reporting alone.

`normalize_actions` in `headroom/aws/policy_documents.py` is the only place an
`Action` element is read, for the same reason `read_principal` is the only place
a `Principal` element is. Both claims are enforced rather than
asserted: `test_only_policy_documents_reads_a_statement_principal` and
`test_only_policy_documents_normalizes_a_statement_action` walk the package and
fail on a second reader. A divergent copy fails no other test, because each
analyzer's suite passes against its own reader — which is how the drift survived
four rounds. It answers the actions the element names and **raises
`TypeError`** for anything that is neither a string nor an array: IAM stores an
`Action` in one of those two shapes and nothing else, so a third shape is a
document AWS could not have stored, on the aborting side of the line above. Five
copies of that reader disagreed four ways before it was shared — an empty set, an
object's keys read as though they were IAM actions, and a raise — which is the
drift the `Principal` walk had.

Where an action is matched, it is matched the way IAM matches it —
case-insensitively, honoring `*` wildcards, and honoring `NotAction`. String
comparison misses `sts:*`, `sts:Assume*`, `STS:AssumeRole`, and every
`NotAction`.

Prefer not gating at all. Gating narrows what the scan sees, which is the unsafe
direction: an action the gate rejects is a grant the scan did not count and the
RCP will still deny.

### Source guards

[`deny_service_confused_deputy`](../checks/rcps/deny_service_confused_deputy.md)
is the one RCP check that reads a `Condition` block, and only for the four
keys AWS populates when a service acts on a resource's behalf:
`aws:SourceAccount`, `aws:SourceArn`, `aws:SourceOrgID`, and
`aws:SourceOrgPaths`. `_read_source_guards` in
`headroom/aws/policy_documents.py` is the one place they are read; each of the
six analyzers named in that check's Evidence table reaches it through
`read_service_principal_sources`.

Reading an operator as a guard takes three parts. `SOURCE_GUARD_OPERATORS`
whitelists the eight base operators that constrain one of these keys to a
value — `ArnEquals`, `ArnLike`, `StringEquals`, `StringLike`, and their four
`...IfExists` forms. `aws:SourceOrgPaths` is multivalued, so AWS requires one
of the two set operators it defines on it; `SOURCE_GUARD_SET_OPERATORS`
whitelists both, `ForAnyValue` and `ForAllValues`, read as the prefix on a
base operator written `ForAllValues:StringLike` rather than bare. `Null` is
neither: it pins no value, so a `Null <key> = "false"` clause is read only as
an assertion that `<key>` is present, never as a source to record. Anything
else does not constrain the key — a negated operator such as
`StringNotEquals` excludes rather than permits, and a set operator AWS does
not define, such as `ForSomeValues`, is not one this parser recognizes — and
reading either as a guard would put the wrong account in the allowlist, so
both raise `UnknownSourceConditionError` instead.

The `...IfExists` forms are not a milder way to constrain a key. AWS's
condition-operator reference (see References) states that appending
`IfExists` means "if the key is not present, evaluate the condition element as
true," and that with a negated operator under `"Effect": "Deny"`, such as
`StringNotEqualsIfExists`, "the request is still denied even if the condition
key is not present." A guard written with one therefore also matches a request
that omits the key outright, tracked as `SOURCE_GUARD_IF_EXISTS_OPERATORS`:

| Key | Plain operator | `...IfExists` operator |
|---|---|---|
| `aws:SourceAccount` | guard | guard — the one exception |
| `aws:SourceArn` | guard | wildcard |
| `aws:SourceOrgID` | guard | wildcard |
| `aws:SourceOrgPaths` | guard | wildcard |

`aws:SourceAccount` is the exception because the deployed statement pairs the
guard with `Null aws:SourceAccount = "false"`
([`../checks/rcps/deny_service_confused_deputy.md`](../checks/rcps/deny_service_confused_deputy.md)),
which scopes the deny to calls that populate that key. The key-absent case an
`...IfExists` guard additionally admits already falls outside the deny, so the
resource policy and the deployed RCP agree. No such clause exists for
`aws:SourceArn`, `aws:SourceOrgID`, or `aws:SourceOrgPaths`, so on those three
keys an `...IfExists` guard permits a call the deployed RCP still denies. No
allowlist can express that, so `_read_service_principal_sources` records
`has_wildcard_source` instead, and the statement is withheld from the account
rather than deployed against a guess (INV-01).

`ForAllValues` opens the same kind of hole for a different reason: a set
operator is satisfied when the request carries no values for the key at all,
so `ForAllValues:StringLike` on `aws:SourceOrgPaths` matches a request that
omits it outright. That is why AWS's own published examples pair the
operator with `Null aws:SourceOrgPaths = "false"` — the presence assertion
that closes the empty case. `_keys_asserted_present` reads which keys carry
that assertion, and `_read_source_guards` treats a `ForAllValues` guard as
permitting the key's absence unless the assertion names that same key, with
the same `aws:SourceAccount` carve-out the `...IfExists` forms get and for
the same reason: the deployed statement's own `Null aws:SourceAccount =
"false"` clause already puts a sourceless request outside its reach.
`ForAnyValue` needs no such companion, because it is false outright on a key
that carries no values.

Three spellings of that companion are read, because IAM stores all three. The
grammar makes quotation marks optional on a Boolean value and defines a
condition value as a list whose brackets may be dropped when it holds one
entry, so `"false"`, `false`, and `["false"]` are one assertion written three
ways — and generators do emit the unquoted and bracketed forms. `Null` is the
one operator no set-operator prefix and no `...IfExists` suffix may be attached
to, so `ForAllValues:Null` and `NullIfExists` are not policies AWS will store
and are read as no assertion. So is a capitalised `"False"`: `Null` defines no
case-insensitive variant, and inventing one would clear an account on a
spelling AWS may reject. `_asserts_key_present` in
`headroom/aws/policy_documents.py` owns the list.

The verdict is scoped to the whole `Condition` block, not to the individual
key: a plain `StringEquals` guard on `aws:SourceAccount` does not rescue the
block from a wildcard verdict an `...IfExists` guard on `aws:SourceArn`,
`aws:SourceOrgID`, or `aws:SourceOrgPaths` sets elsewhere in it, even though
the account itself is still pinned. That is the same posture
`_read_service_principal_sources` already takes toward an accountless
`aws:SourceArn` beside a same-organization scope — erring toward withholding a
statement this analysis cannot fully clear, rather than deploying it against a
guess.

### What is deliberately not read

The six third-party-access checks read `Effect`, `Principal`, and — for STS
alone — `Action`. They read neither `Condition` nor `Resource`/`NotResource`.
`deny_service_confused_deputy` is the exception for `Condition` alone: the
Source guards section above names exactly which four keys it reads, and no
others. It reads no `Resource` or `NotResource` either, so that omission is the
one all seven share.

Both omissions **widen** what the six third-party-access checks see, and
widening is the safe direction:

- A `Principal: "*"` narrowed by `aws:PrincipalOrgID` grants nothing outside the
  organization — it is the pattern AWS recommends for organization-wide bucket
  access — but is counted as a violation and blocks that account from the check's
  RCP.
- A grant narrowed by `s3:prefix`, `aws:SourceVpce`, or a lapsed `DateLessThan`
  still contributes its account to the allowlist at full width, so the account
  keeps a broader RCP allowance than it needs.
- A statement scoped away from the resource by `Resource`/`NotResource` still
  contributes its principals.

A condition or a resource scope can only ever narrow a grant, so neither can hide
a third party the scan should have found. No RCP generated under this limitation
breaks access a condition-aware scan would have preserved. The cost is coverage,
not safety, which is what makes it a roadmap item rather than a defect. See
[`../../ROADMAP.md`](../../ROADMAP.md).

## References

- [IAM policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html)
- [Global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) - the `aws:`-prefixed keys, including `aws:PrincipalAccount` and the request-tag keys patterns 3 and 4 read
- [IAM condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IfExists) - the `...IfExists` forms are satisfied when the condition key is absent, a negated operator under `Effect: Deny` still denies when the key is absent, and the `ForAllValues` set operator "returns true if there are no context keys in the request or if the context key value resolves to a null dataset"
- [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) - per-service actions, and the condition keys each action supports. Evidence of what AWS has documented, not of what IAM does; see `deny_rds_unencrypted` for a key that works and is not listed
- [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [Organizations limits](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)
