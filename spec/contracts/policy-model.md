# Contract: policy model

Owns the vocabulary every check is written in: what an SCP and an RCP each
control, the patterns a generated statement can take, and the grammar by which
Headroom reads an existing policy document.

A per-check specification names the pattern it implements rather than restating
what the pattern is.

Implementation: `headroom/aws/policy_documents.py` (shared grammar, including
the principal types, the one function that reads a `Principal` element, and the
one function that reads a statement's `Principal` against its `Condition`),
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
| `Principal: "*"` or `{"AWS": "*"}` | Wildcard — a blocker, unless the statement's `Condition` confines it ([below](#condition-confined-wildcards)) |
| `Allow` with `NotPrincipal` | Wildcard — grants to everyone except a short list, the same reach, and no `Condition` confines it |
| `Deny` with `NotPrincipal` | Nothing — it restricts rather than grants, and a resource policy's Deny hands access to nobody |
| An account ID or an ARN | The 12-digit account ID it names |
| An ARN whose account field is not twelve digits | Carries no account ID — a blocker. CloudFront's origin access identity user, `arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity <id>`, is the documented case |
| A bare unique ID, `AROA…` or `AIDA…` | Nothing. AWS writes it in place of a deleted user's or role's ARN and documents that the entry then grants no one access, so it is neither an account nor a blocker |
| A service-linked role ARN — a resource under `role/aws-service-role/`, in any partition | Nothing. RCPs do not impact the permissions of any service-linked role, so no statement Headroom generates can deny one and it is neither an account nor a blocker. IAM reserves that path to AWS services, so the path identifies the role and its name is not consulted |
| `Service` | Not an account principal, and not a blocker |
| `Federated` | Carries no account ID — a blocker. A SAML provider ARN does contain twelve digits, but they name the provider's host account, not the caller's. |
| `CanonicalUser` | An opaque identifier that maps to an account only through an API call the scan does not make — a blocker |
| Any other key | `UnknownPrincipalTypeError` |
| Not a string, a list, or an object | `MalformedPolicyError` — the element is not a Principal at all |

The reader raises, and no analyzer catches it: all six let
`UnknownPrincipalTypeError` and `MalformedPolicyError` abort the run.
`aws/sqs.py` once caught the former and recorded the queue as a read failure,
which withheld the confused-deputy statement from the account but left the
queue's own check nothing to read, so that check cleared the account on a
queue nobody had read.
[`../architecture/aws-execution.md`](../architecture/aws-execution.md) places
the abort against INV-02.

Callers must apply their own `Effect` gate **before** consulting `NotPrincipal`.
A statement carrying both `Principal` and `NotPrincipal` is not valid IAM and
cannot be stored; were one to arrive, it is treated as a wildcard rather than
letting the `Principal` half stand in for a broader grant.

A service-linked role ARN is the other account-less string that is not a
blocker, and the one ARN that does name an account without that account being
recorded. AWS states in the
[RCP documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#actions-not-restricted-by-rcps)
that RCPs do not impact the effective permissions of any service-linked role,
so a statement granting one is never denied by anything Headroom generates and
its account has no business in an allowlist. `is_service_linked_role_arn` in
`headroom/aws/policy_documents.py` is the one rule, read by `_read_principal`
for a `Principal` element and by `headroom/aws/kms.py` for a grant's
`GranteePrincipal`, so a policy and a grant agree on what a service-linked
role is — wherever one is named by ARN. The rule matches a path and a bare IAM
unique ID carries none, so a grant naming a service-linked role that way is
classified by the account the identifier decodes to, like any other grantee;
[`../checks/rcps/deny_kms_third_party_access.md`](../checks/rcps/deny_kms_third_party_access.md)
records that as an accepted limitation of decoding. Pinned by
`test_a_service_linked_role_names_no_account_and_blocks_nothing` and
`test_a_role_named_like_a_service_role_outside_the_path_is_an_account`.

The account ID is extracted from an ARN with a deliberately loose pattern: the
service segment is unconstrained, because a resource-policy principal can be an
STS session ARN as readily as an IAM one, and the partition is matched the same
way so GovCloud and China ARNs resolve.

### Condition-confined wildcards

A wildcard is a claim about how far a statement reaches, and a `Condition` can
bound that reach to a set an allowlist can carry.

A bound is recognized only when it can be proven. Every operator, key, and
value this reader does not fully understand leaves the wildcard standing. The
asymmetry is deliberate and governs every rule below: a bound missed costs
coverage — the RCP is withheld from an account that could have taken it —
while a bound read wrongly clears the account, generates the RCP, and breaks
the access the analysis exists to preserve.

`read_statement_principals` in `headroom/aws/policy_documents.py` is the one
rule by which a statement's `Principal` is read against its `Condition`. It
composes `_read_principal`, which stays the element reader and is unchanged:
the element still reports a wildcard, and the statement reader decides whether
that wildcard is bounded. All six third-party-access analyzers call it —
`aws/ecr.py`, `aws/kms.py`, `aws/s3.py`, `aws/secretsmanager.py`,
`aws/sqs.py`, and `aws/iam/roles.py` — so a trust policy is read by the same
rule as a resource policy. Confining a wildcard in five of the six and leaving
the sixth to read it raw would recreate the divergence six copies of the
principal walk once had, this time held together by documentation instead of
by a shared function.

`read_service_principal_sources` is the one reader that deliberately does not
compose it and keeps probing the **raw** wildcard, because a wildcard narrowed
by a source key is exactly the shape `deny_service_confused_deputy` records;
that split is permanent.

Five condition keys can prove a bound. Four are cross-service —
`aws:PrincipalAccount`, `aws:PrincipalArn`, `aws:PrincipalOrgID`, and
`aws:PrincipalOrgPaths` — and `kms:CallerAccount` is the fifth, in a KMS key
policy alone. Condition **keys** are matched case-insensitively, because IAM
matches them that way, so `aws:principalaccount` and `aws:PrincipalAccount` are
one key and `confined_by` records the lower-cased spelling. The fold is
ASCII-only: a key carrying any other character is not IAM's, and is dropped
before its case is touched. Neither rule belongs to this reader. Splitting an
operator at its last colon into a set-operator prefix and a base operator,
folding the key, and dropping a non-ASCII key are the grammar of a `Condition`
block rather than a verdict about one, and `_condition_clauses` in
`headroom/aws/policy_documents.py` performs all three once, for every reader
of the block — this one, the [source guards](#source-guards) reader, and its
`Null` pre-pass — so a rule about what a clause *is* cannot land in one reader
and miss another. **Operators** are
matched case-sensitively: IAM defines each operator's spelling, and one written
any other way is an operator this reader does not recognize, which proves no
bound rather than being guessed at.

The `Condition` is read only for a statement whose `Principal` is a wildcard.
Narrowing a wildcard is the only thing a bound is read for: `Condition` clauses
AND with the `Principal` element, so a bound can never reach a caller the
element does not already name. A statement whose `Principal` names its callers
outright is therefore returned as `_read_principal` read it, with an empty
`confined_by` — joining an account its `Condition` enumerates would write an
allowlist entry exempting an account from the Deny that no grant reaches, and
`aws:PrincipalAccount` beside a `Federated` principal is exactly that shape:
a federated session reports the identity provider's account, so the clause and
the element admit nobody between them.

Which statements reach this reader is every `Allow` that clears the analyzer's
own gates: the `Effect` gate, the `NotPrincipal` gate, `aws/kms.py`'s skip of
a statement whose only action is `kms:RetireGrant`, and a trust policy's
`sts:AssumeRole` gate. No analyzer skips a statement for want of a
`Principal`: one carrying neither `Principal` nor `NotPrincipal` reaches this
reader and aborts the run, under the
[rule below](#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run).

Each row below reads one clause, and the pairing of operator with key is the
unit: an operator confines nothing on a key it cannot compare, whichever other
key it would confine. Clauses AND, so a clause that enumerates nobody leaves
what another clause proved intact rather than unproving it; where two clauses
on one key each enumerate accounts, the union is taken, which is over-wide by
at most an allowlist entry and never short of one. A wildcard that no clause
confines is a blocker; the two statement-level rows are marked as such.
"A string operator" below means `StringEquals` or `StringLike`, and "an ARN
operator" means `ArnEquals` or `ArnLike`; `CONFINING_OPERATORS_BY_KEY` in
`headroom/aws/policy_documents.py` is the pairing in code.

| Shape | Read as |
|---|---|
| Wildcard, no `Condition` | **Blocker** |
| A `Principal` that is not a wildcard, whatever its `Condition` | Read as `_read_principal` reads the element; the `Condition` is not consulted and `confined_by` is empty |
| Two clauses on one key, one enumerable and one not | Confined by the enumerable one. Clauses AND, so the second cannot widen past the first |
| A string operator on `aws:PrincipalAccount`, every value twelve digits | Confined. Each value outside the organization becomes a third-party account; in-organization values contribute nothing |
| A string operator on `aws:PrincipalAccount`, any value not twelve digits or carrying `*` or `?` | Does not confine. Twelve digits means twelve ASCII digits: AWS validates no condition value, and a fullwidth digit run reaching the allowlist fails the module's own `^[0-9]{12}$` check, taking the whole plan down rather than one account's RCP |
| A string operator on `aws:PrincipalOrgID` naming **this** organization | Confined; contributes no third party |
| A string operator on `aws:PrincipalOrgID` naming **another** organization | Does not confine — bounded, but to a set no account allowlist can enumerate |
| A string operator on `aws:PrincipalOrgPaths`, every value's first path segment exactly this organization's ID | Confined; contributes no third party. A trailing `*` after that segment is AWS's own recommended shape and stays inside the organization |
| A string operator on `aws:PrincipalOrgPaths` whose first segment is not exactly this organization's ID, a wildcard included | Does not confine |
| `ArnEquals` on `aws:PrincipalArn` naming a service-linked role | Confined; contributes nothing — RCPs do not impact a service-linked role |
| `ArnEquals` on `aws:PrincipalArn` whose account field is twelve digits | Confined; an account outside the organization becomes a third party. Twelve ASCII digits, by the same rule as `aws:PrincipalAccount` |
| `ArnLike` on `aws:PrincipalArn` whose account field is twelve digits | Confined, on the account field alone — the only segment consulted, so a wildcard in the service, region, or resource segment changes nothing. The partition is the exception: it is matched as `aws` followed by lower-case letters, digits, and hyphens, so a wildcard there pins no account and the key confines nothing |
| `ArnLike` on `aws:PrincipalArn` whose account field is `*` or carries `*` or `?` | Does not confine |
| `ArnEquals` or `ArnLike` on `aws:PrincipalArn` naming no account | Does not confine — the CloudFront origin access identity shape |
| Any operator on `aws:PrincipalArn` whose value is an assumed-role session ARN, `arn:<partition>:sts::<account>:assumed-role/...` | Does not confine — for a role session the key holds the role's ARN, never the session's, and AWS documents that the session ARN must not be written as its value, so the clause matches nobody. A `federated-user/` session ARN under the same service segment is a real bound: the key does hold that ARN |
| `StringLike` on `aws:PrincipalArn` | Read exactly as `ArnLike` is. The key holds an ARN whichever operator names it, and `StringLike aws:PrincipalArn arn:aws:iam::111111111111:role/vendor-*` is the ordinary way it is written |
| `StringEquals` on `aws:PrincipalArn`, no value carrying `*` or `?` | Read exactly as `ArnEquals` is |
| `StringEquals` on `aws:PrincipalArn`, any value carrying `*` or `?` | Does not confine — `StringEquals` matches exactly, so the star is literal and no ARN carries one. The clause matches nobody; the author meant `StringLike`, and the standing wildcard is what says so |
| An ARN operator on `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, or `kms:CallerAccount` | Does not confine — an ARN operator compares six colon-delimited components and none of those keys holds an ARN. What IAM makes of the pairing is not guessed at |
| A string operator on `kms:CallerAccount` **in a KMS key policy**, every value twelve digits | Confined. An in-organization value contributes nothing; an out-of-organization value becomes a third-party account |
| `kms:CallerAccount` in a policy for any other service | Does not confine — the key is not in that service's table |
| Any `...IfExists` operator | Does not confine — it is true when the key is absent |
| Any negated operator: `StringNotEquals`, `StringNotLike`, `ArnNotEquals`, `ArnNotLike` | Does not confine — it excludes rather than bounds |
| A `ForAnyValue:` prefix on `StringEquals`, `StringLike`, `ArnEquals`, or `ArnLike` | Read exactly as the bare operator: `ForAnyValue:` is satisfied by one matching value and is false outright on a key carrying no values, so it opens no absent-key hole. AWS requires a set operator on the multivalued `aws:PrincipalOrgPaths`, so its own recommended guard arrives prefixed |
| Any `ForAllValues:` set operator | Does not confine — it is true when the key carries no values |
| `Null`, `Bool`, a date operator, or any other operator on a confining key | Does not confine |
| A condition key carrying a non-ASCII character | Does not confine — IAM has no such key, so the clause matches nobody. The key is checked before its case is folded: Python folds the Kelvin sign U+212A to `k`, which would otherwise read a key IAM never populates as `kms:CallerAccount` |
| `s3:prefix`, `aws:SourceVpce`, `kms:ViaService`, `kms:GrantIsForAWSResource`, or `aws:CurrentTime` | Does not confine — each narrows the grant, not the principal set |
| Any other key, `aws:SourceAccount`, `aws:SourceArn`, `aws:SourceOrgID`, and `aws:SourceOrgPaths` among them | Does not confine |
| `Allow` with `NotPrincipal`, whatever its `Condition` | **Blocker** — never confined |

The accepted operators are therefore `StringEquals`, `StringLike`, `ArnEquals`,
and `ArnLike`, each optionally prefixed `ForAnyValue:`. `ForAllValues:` never
confines and no `Null` clause rescues it: a set operator is true when the key
carries no values, so the guard also matches a request presenting none.
`_read_source_guards` does rescue that case when a `Null <key> = "false"` clause
asserts the key present, and this reader does not, because no observed shape
pairs `ForAllValues:` with a principal key and adding the rescue would widen the
reading with no evidence behind it.

Two decisions are shared rather than reimplemented. `_names_this_organization`
decides both organization keys exactly as it decides `aws:SourceOrgID` and
`aws:SourceOrgPaths`, comparing the first `/` segment with no wildcard
expansion, so `o-11111111111*` reads as foreign. `is_service_linked_role_arn`
decides the service-linked role case, so a `Principal` element and an
`aws:PrincipalArn` value agree on what a service-linked role is.

Four rules compose those verdicts:

- **Condition keys AND**, so one confining key settles the verdict. A clause
  this reader cannot read, sitting beside one it can, admits nobody the
  readable clause excludes, so it cannot widen past a bound already proven.
- **Values under one key OR**, so every value must be enumerable or the key
  bounds nothing. One value this reader cannot pin reaches principals the rest
  do not.
- **Statements OR**, so one unconfined wildcard blocks the resource whatever
  sits beside it. Confinement is decided per statement and each analyzer
  accumulates the wildcard verdict across the document. The confining keys are
  a union across statements and are recorded even then: a resource reporting
  both a confining key and a violation is reporting the true state, that some
  statements were bounded and one was not.
- **Two confining keys contribute the union of their accounts, never the
  intersection.** The verdict ANDs, as above; the accounts recorded alongside
  it do not. A block pinning both `aws:PrincipalAccount = ["444444444444"]` and
  `aws:PrincipalArn = "arn:aws:iam::555555555555:role/example"` grants to
  nobody, and both accounts are recorded. That is over-wide by construction and
  never under-wide, which is the error worth making: an allowlist entry nobody
  uses costs nothing, and a missing one is an outage. It is the same widening
  this grammar already accepts when a statement names an account and a
  condition excludes it.

Confinement rescues the wildcard verdict and nothing else. A principal carrying
no account ID is never rescued, however tightly the `Condition` bounds the
statement, though the accounts a bound enumerates are still recorded alongside
the blocker verdict. A wildcard is a claim about **reach**, which an enumerable
condition can bound; a `Federated` or `CanonicalUser` principal is a claim
about **identity type**, and whether such a caller presents an
`aws:PrincipalAccount` an allowlist could carry is not something the document
shows.

An `Allow` with `NotPrincipal` is never confined, and that is an omission rather
than a gap. Every analyzer applies its `NotPrincipal` gate before it reads a
principal at all, so no condition on such a statement is ever consulted and the
statement stays a blocker whatever its `Condition` carries. Intersecting an
exclusion with a bound is reasoning this analysis will not do: AWS advises
against `NotPrincipal` in a resource policy, the shape is rare, and an
intersection computed wrongly widens an allowlist rather than narrowing one.

The `Condition` reading never raises. A `Condition` that is not a mapping, a
clause whose value is neither a string nor a non-empty list of strings, and an
operator or key nobody has modelled all prove no bound — and no bound is the
blocker answer, so there is nothing to abort for. `read_statement_principals`
itself does raise, because it reads the `Principal` element first and
`_read_principal` aborts on a malformed or undocumented one; the abort belongs
to the element and never to the condition. Conditions are freeform and an
unknown key is an ordinary thing to find in a policy AWS accepted, which is
what separates this from the `Principal` element, where an undocumented key is
a document AWS could not have stored. It separates it from
`_read_source_guards` too, which raises `UnknownSourceConditionError` on an
operator it does not recognize: that reader is building an allowlist out of
what it reads, so a misread there puts a wrong account in the allowlist, while
a misread here costs coverage and withholds the RCP.

`kms:CallerAccount` is read because it names the account of the calling
principal — exactly what `aws:PrincipalAccount` names, and enumerable in
exactly the same way — and because it is the idiom AWS documents for granting
to every identity in one account, which the `Principal` element has no syntax
for. It is read in a KMS key policy and nowhere else. A service-scoped key is
valid only on its own service, so a `kms:CallerAccount` clause in a bucket
policy names a key no request carries: that statement grants nobody anything,
and reading it as a bound would put an account in the S3 allowlist that no
policy granted. `SERVICE_SCOPED_ACCOUNT_CONDITION_KEYS` in
`headroom/aws/policy_documents.py` holds the one row, keyed by the
`PolicyService` member each adapter passes, so the service dimension lives in a
table rather than in a branch; a service with no row recognizes no
service-scoped key, which is the answer for ECR, S3, Secrets Manager, SQS, and
STS and not an oversight.

`kms:ViaService` is **not** a bound: it names the service a call came through,
not the principal that made it, so a customer-managed key granting
`Principal: "*"` under `kms:ViaService` alone stays a blocker. AWS pairs the
two keys in the default policy of an AWS-managed key, which is the shape the
guard is best known in, but those keys never reach this reader
([below](#what-is-deliberately-not-read)) — so the policy the rule actually
decides is a customer-managed key's.

### One reader, six analyzers

`_read_principal` in `headroom/aws/policy_documents.py` is the only place a
`Principal` element is interpreted. It answers four questions and nothing
else: which account IDs the element names, whether it reaches principals the
analyzer cannot enumerate, whether it names a principal type that carries no
account ID, and which principal-type keys — `AWS`, `Service`, `Federated`,
`CanonicalUser` — it carries at all, none for a bare string. The fourth is
`principal_types`, a fact about the element rather than a verdict on it, and
it exists so that the one analyzer with a question about a type —
[`deny_sts_third_party_assumerole`](../checks/rcps/deny_sts_third_party_assumerole.md)'s
`Federated` check — asks the reading and never the element. The reading
carries a fifth field, `confined_by` — the condition keys that bounded the
statement — which this reader always leaves empty: an element carries no
`Condition`, so only `read_statement_principals` fills it. Every
third-party-access check writes it into each result entry and nothing
mechanical reads it back, which is the standing of every entry field outside
`summary` ([`results.md`](results.md#document-shape)). It is there for the
operator: a confined wildcard writes `has_wildcard_principal: false` against a
policy whose `Principal` is literally `*`, and `confined_by` is the one thing
in the artifact that says why that verdict is right. The accounts the bound
admitted sit beside it in `third_party_account_ids`, read exactly as a named
principal's would be.

A bare string carries no principal-type key, so the third fact is `False` for
an account ID, for an ARN naming one, and for the wildcard — and `True` for an
ARN that names no account. CloudFront's origin access identity user is that
case: its account field holds the service's name, no allowlist keyed on
`aws:PrincipalAccount` can carry it, and the deployed statement denies it.
Before this rule the ARN named nothing at all, so a bucket granting only an
OAI was never recorded and its account cleared for the S3 statement, which
then denied every request the distribution made. Pinned by
`test_a_bare_string_principal_names_no_non_account_type` and
`test_an_arn_naming_no_account_blocks_the_account`, since nothing else in the
suite reads that branch's value for the third fact.

A bare unique ID is the one account-less string that is not a blocker. AWS
writes it in place of a deleted user's or role's ARN, and documents that the
entry then grants no one access — a replacement with the same name gets a new
ID — so nothing lives behind it for an RCP to deny, and reading it as naming
nothing is the reading, not a gap. Pinned by
`test_a_unique_id_names_nothing_and_blocks_nothing`.

That reading is for a `Principal` element, and rests on the transformation IAM
documents for policies. A KMS grant's `GranteePrincipal` is read by
`headroom/aws/kms.py`, not by `_read_principal`, and the same bare unique ID
there names something rather than nothing: `ListGrants` documents no such
transformation for a grant, so nothing says the entry is dead, and INV-01
forbids assuming it. Three outcomes follow there instead of one. The eight
characters after the prefix carry an owning account where the encoding resolves
them, and that account decides: one outside the organization is an ordinary
third party and enters the allowlist, and one inside it is not recorded at all.
Where the encoding resolves nothing the grant is a blocker, recorded under the
entry's `unresolved_grants`, because access exists that the RCP would deny and
no allowlist entry can preserve it.
[`../checks/rcps/deny_kms_third_party_access.md`](../checks/rcps/deny_kms_third_party_access.md)
owns the argument, the strict classifier, and what a decoding is worth.

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

Both an unconfined wildcard and a principal carrying no account ID mean the
same thing: the RCP would deny a grant that exists today, because an allowlist
keyed on `aws:PrincipalAccount` cannot carry it. That is **one verdict,
recorded** — the resource becomes a violation, the account is blocked for that
check, and the scan continues. Which of the two it was is reported and not
acted on differently.

An undocumented principal key is the separate case and **aborts**. AWS validates
the `Principal` element when it stores a policy, so a key outside the documented
four means Headroom misread the document or AWS has added a principal type
nobody has modelled here. Recording it as a finding would state a verdict on a
grant this code cannot read.

An `Allow` carrying neither `Principal` nor `NotPrincipal` aborts by the same
reasoning. AWS requires one of the two in every resource-policy and
trust-policy statement it stores, so a statement with neither is a document
Headroom has misread, and `read_statement_principals` raises
`MalformedPolicyError` on it, naming the resource. The six analyzers once
skipped such a statement, each with a read of the element of its own. That
skip was the one raw `Principal` read outside this module, and reading the
statement as granting nothing was a guess (INV-01).

A `Principal` that is present but empty — `{}`, `[]`, or `""` — is not the
absent case. It is read as naming nobody: no account, no wildcard, no type,
and no service principal for the source-guard reader to record, which is the
outcome the skip used to produce for it. `null` is neither empty nor absent,
and aborts as a `Principal` that is neither a string, a list, nor an object.

The dividing line is the same one that governs unparseable JSON and a malformed
`Statement`: **a document AWS could not have stored aborts the run; a document
AWS accepted that no allowlist can express blocks the account.** Aborting
protects the account at the cost of every other account's results and puts the
finding in a stack trace instead of the report, so it is reserved for the case
where continuing would mean guessing.

[`deny_sts_third_party_assumerole`](../checks/rcps/deny_sts_third_party_assumerole.md#why-a-federated-principal-is-otherwise-no-finding-here)
reads all five and acts on every one but the third: it is the one place the
third fact is read and deliberately ignored, and it owns the argument for
ignoring it. It is also the one place the fourth is read at all.

Reading the `Condition` opens a second path to a finding on a role that the
third fact alone would have cleared. A role whose only principal is
`{"Federated": …}` under `StringEquals aws:PrincipalAccount` carries that
account in `third_party_account_ids` and passes the check's reporting gate;
read for its `Principal` alone, the role named no account, raised no wildcard,
and produced no entry at all. The account is recorded because the `Condition`
enumerates it and not because the `Principal` does, and the two are not the same
population: AWS includes `aws:PrincipalAccount` in the request context of a
signed request alone, and `AssumeRoleWithSAML` is unsigned. The allowlist entry
is therefore over-wide by one account — the RCP spares an account it need not
have spared, which is the direction that breaks nothing.

### Actions

Two analyzers **gate** on actions.
[`deny_sts_third_party_assumerole`](../checks/rcps/deny_sts_third_party_assumerole.md)
counts a trust-policy statement only if its actions cover `sts:AssumeRole`, and
`aws/kms.py` skips a key policy statement whose only action is
`kms:RetireGrant`, which authorizes nothing in a key policy whoever it names;
[`../checks/rcps/deny_kms_third_party_access.md`](../checks/rcps/deny_kms_third_party_access.md)
owns that rule. The other four analyzers read every `Allow` statement whatever
it grants. The five resource-policy analyzers keep the action list for
reporting; `aws/iam/roles.py` records none.

`normalize_actions` in `headroom/aws/policy_documents.py` is the only place an
`Action` element is read, for the same reason `_read_principal` is the only place
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
is the one RCP check that reads a `Condition` block for the accounts its
allowlist must carry, and only for the four keys AWS populates when a service
acts on a resource's behalf:
`aws:SourceAccount`, `aws:SourceArn`, `aws:SourceOrgID`, and
`aws:SourceOrgPaths`. `_read_source_guards` in
`headroom/aws/policy_documents.py` is the one place they are read; each of the
six analyzers named in that check's Evidence table reaches it through
`read_service_principal_sources`.

That reader looks at a statement's `Condition` only when its `Principal` names
a `Service`, or is a wildcard — `*` or `{"AWS": "*"}` — as `_read_principal`
reads it. Every adapter has already read the `Principal` against its own type
set, through `read_statement_principals`, before handing the statement to this
reader, so a malformed or undocumented principal is reported by the adapter,
under the adapter's own description and against the type set that policy holds
to; the wildcard read inside this reader cannot raise. Only a service call carries a source key, so a wildcard narrowed by
one is a grant to whichever service delivers for those sources; AWS's own
cross-account SNS-to-SQS queue policy is written that way, `Principal: "*"`
under `ArnEquals aws:SourceArn`. Such a statement is recorded with
`service_principal` `*`. A wildcard under no source key is not read here at
all; it is the plain wildcard the six third-party-access checks block the
account for, unless a confining key bounds it
([above](#condition-confined-wildcards)). A `Principal` naming accounts and no
service is never read here, whatever its `Condition` carries.

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

[Principal confinement](#condition-confined-wildcards) scopes its verdict the
other way, per key rather than per block. The two readers walk the same
`Condition` through the same parse — `_condition_clauses` owns what a clause
is and nothing about what it proves — and ask different questions of it:

| | Source guards | Principal confinement |
|---|---|---|
| Question | Which accounts must the allowlist carry? | Is the statement's reach bounded at all? |
| A hole elsewhere in the block | Makes the recorded set **incomplete**, so it poisons the block | Cannot widen past an ANDed clause that already bounds the reach |
| Verdict scope | Whole block | Per key |

An `ArnLikeIfExists` clause sitting beside a `StringEquals
aws:PrincipalAccount` clause cannot admit a caller the account clause excludes,
so it does not poison the bound the way it would poison a source guard's
recorded set.

### What is deliberately not read

The six third-party-access checks read `Effect`, `Principal`, `Condition`, and
`Action`. `deny_service_confused_deputy` reads the `Condition` too, for a
different set of keys: the Source guards section above names exactly which
four, and no others. None of the seven reads `Resource` or `NotResource`,
so that omission is the one they all share.

Reading a `Condition` for a bound on the statement's principals is not reading
it for everything it says. A condition that narrows the grant rather than the
principal set is still unread, and so is a resource scope. Both omissions
**widen** what the checks see, and widening is the safe direction:

- A grant narrowed by `s3:prefix`, `aws:SourceVpce`, or a lapsed `DateLessThan`
  still contributes its account to the allowlist at full width, so the account
  keeps a broader RCP allowance than it needs.
- A statement scoped away from the resource by `Resource`/`NotResource` still
  contributes its principals.

One policy shape is not read narrowly — it is not read at all: an AWS-managed
KMS key's default policy, its `kms:ViaService` guard included. Those keys are
skipped on `KeyManager`, before either the policy or the grants are read,
because RCPs do not apply to them at all;
[`../checks/rcps/deny_kms_third_party_access.md`](../checks/rcps/deny_kms_third_party_access.md)
owns that skip.

One limitation survives on the confining side: `aws:SourceArn`. A
`Principal: "*"` guarded by `ArnLike aws:SourceArn` — the legacy console form
of a cross-account SNS-to-SQS queue policy — still blocks its account.

Not reading it is a decision rather than unfinished work, and the two are
easily confused because the coverage it costs is on the roadmap. What is
settled is that this reader will not un-block on the key: the argument for
doing so fails, below, and acting on it anyway risks an outage. What is open
is whether some other signal — CloudTrail evidence of who actually called, or
a `Bool aws:PrincipalIsAWSService` clause pinning the caller to a service —
could close the gap without inverting the safety direction. `ROADMAP.md`
carries the second question; it does not reopen the first.

There is a near-miss argument for reading that guard as a bound. The generated
5a statement carries `BoolIfExists aws:PrincipalIsAWSService = "false"`, so it
never denies an AWS service principal; AWS's confused-deputy guidance says the
source keys carry their information for requests made by AWS service principals,
and AWS's own recommended confused-deputy RCP pairs them with `Bool
aws:PrincipalIsAWSService = "true"`. On that reading a wildcard guarded by
`aws:SourceArn` grants nothing the generated statement could deny, exactly as
`Principal: {"Service": …}` grants nothing it could deny.

The argument fails on one documented sentence. `aws:PrincipalIsAWSService` is
false if the service uses the credentials of an IAM principal to make a request
on that principal's behalf — a forward access session — and a forward access
session does populate `aws:SourceArn`; a KMS key policy guarded by the calling
bucket's ARN for S3 server-side encryption is the canonical shape. "Carries
`aws:SourceArn`" and "is an AWS service principal" are therefore not the same
population, and the gap between them is precisely where an out-of-organization
caller would be denied. Un-blocking on the key risks an outage, so it is not a
confining key.

A condition or a resource scope can only ever narrow a grant, so neither can
hide a third party the scan should have found. No RCP generated under **this**
limitation breaks access a scan reading `aws:SourceArn` would have preserved,
because the limitation only ever over-blocks: the cost is coverage, not safety,
which is what makes the gap a roadmap item rather than a defect. The promise does
not generalize past it — reading a condition in order to un-block an account
inverts the direction, which is the asymmetry
[Condition-confined wildcards](#condition-confined-wildcards) states, and the
reason every shape that reader cannot prove resolves to a blocker. See
[`../../ROADMAP.md`](../../ROADMAP.md).

## References

- [IAM policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html)
- [Global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) - the `aws:`-prefixed keys, including `aws:PrincipalAccount` and the request-tag keys patterns 3 and 4 read
- [IAM condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IfExists) - the `...IfExists` forms are satisfied when the condition key is absent, a negated operator under `Effect: Deny` still denies when the key is absent, and the `ForAllValues` set operator "returns true if there are no context keys in the request or if the context key value resolves to a null dataset"
- [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) - per-service actions, and the condition keys each action supports. Evidence of what AWS has documented, not of what IAM does; see `deny_rds_unencrypted` for a key that works and is not listed
- [Cross-service confused deputy prevention](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html) - `aws:SourceArn` and `aws:SourceAccount` carry their information for requests made by AWS service principals, and `aws:PrincipalIsAWSService` is false when a service uses an IAM principal's credentials on that principal's behalf
- [KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html) - `kms:CallerAccount` is the account of the calling principal, and `kms:ViaService` the service the call came through
- [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [Organizations limits](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)
