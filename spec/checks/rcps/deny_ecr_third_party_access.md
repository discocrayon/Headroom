---
id: deny_ecr_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_ecr_third_party_access.py
  - headroom/aws/ecr.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_ecr_third_party_access.py
  - tests/test_aws_ecr.py
  - tests/test_aws_policy_documents.py
---

# deny_ecr_third_party_access

## Objective

Deny ECR access by any principal outside the organization except the third-party
accounts that repository policies already grant, so a container image cannot be
pulled — or pushed — by a new external account.

### Scope

Private ECR repository policies and the region's registry policy, in every
enabled region.

### Non-goals

- Does not read the registry's replication configuration
  (`ecr:DescribeRegistry`) or its pull-through cache rules
  (`ecr:DescribePullThroughCacheRules`). The registry policy that authorizes
  those is read; how they are configured is not.
- Does not read ECR Public.
- Evaluates `Condition` only for a bound on the statement's principals, under
  the rule
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
  owns. A condition that narrows the grant rather than the principal set is
  unread, and so are `Resource`/`NotResource` and `NotAction`.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenyECRThirdPartyAccess
Action: ecr:*
```

Pattern 5a, principal account allowlist
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).

Terraform variables: `deny_ecr_third_party_access` and
`ecr_third_party_access_account_ids_allowlist`.

## Evidence

Per enabled region: `ecr:DescribeRepositories` (paginated), then
`ecr:GetRepositoryPolicy` per repository.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Condition`,
`Action`. The statement is read by `read_statement_principals` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`, which reads the `Principal` element with
`_read_principal` and, where that element is a wildcard, asks the `Condition`
whether it bounds what the wildcard reaches
([`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)).

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | An unconfined wildcard principal — a literal `*` whose statement carries no bound the reader can prove, or an `Allow` with `NotPrincipal`, which is never confined | `VIOLATION` |
| Not recorded | A wildcard the statement's `Condition` bounds to principals an allowlist can carry, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards) owns | Nothing is recorded for the wildcard itself. Each account the bound enumerates is read exactly as a named principal's account is, so an out-of-organization one makes the policy `COMPLIANT` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Violation | An ARN naming no account, under the rule [`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run) owns | `VIOLATION` |
| Aborts | A principal key AWS does not document | The run aborts |

## Failure behavior

| Situation | Behavior |
|---|---|
| `RepositoryPolicyNotFoundException` | The repository is skipped; it grants nothing. A repository reaches this check's results list on a third-party account, a wildcard, or a principal carrying no account ID |
| Any other `ClientError` on one repository | Re-raised, aborting the run |
| `ClientError` in any region | Logged and re-raised, aborting the run |
| A response carrying no `policyText` | `KeyError`, aborting the run. Indexed rather than defaulted: botocore marks the field optional, but `GetRepositoryPolicy` and `GetRegistryPolicy` raise `RepositoryPolicyNotFoundException` or `RegistryPolicyNotFoundException` when there is no policy, so a response carrying neither the field nor the exception is an unread policy, not an empty one (INV-01) |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| `Principal` neither string, list, nor object | `MalformedPolicyError` |
| An `Allow` carrying neither `Principal` nor `NotPrincipal` | `MalformedPolicyError` — AWS stores no such statement, so it is a document misread rather than a grant to nobody |
| A `Federated` or `CanonicalUser` principal, or an ARN naming no account | Recorded as `has_non_account_principals`; the account is blocked |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

A `Federated` or `CanonicalUser` principal used to raise here and stop the whole
run. It is now recorded as a violation instead, under the rule
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#a-blocker-stops-the-account-a-document-headroom-cannot-read-stops-the-run)
owns.

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `policies_third_parties_can_access` | Violations plus compliant |
| `policies_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_policies_analyzed`,
`policies_third_parties_can_access`, `policies_with_wildcards`,
`violations`, `unique_third_party_accounts`, `third_party_account_count`,
`actions_by_account`. The keys are named for the policy rather than the
resource because a registry policy is one of the things counted, and it is
not a repository.

`total_policies_analyzed` counts the policies that produced an entry — violations,
exemptions, and compliant together — not every policy read. Neither a
repository with no policy nor a repository or registry policy naming only
in-organization principals is entered or counted.

Entry shape: `scope`, `repository_name`, `repository_arn`, `region`,
`third_party_account_ids`, `actions_by_account`, `has_wildcard_principal`,
`has_non_account_principals`, `confined_by`.

`repository_name` and `repository_arn` are null on a registry-scoped entry,
which governs no single repository.

`confined_by` holds the condition keys, lower-cased, that each bounded one of
this policy's statements on their own, unioned across the policy. A key is
recorded whether or not the policy still blocks — one bounded statement beside
one unbounded one reports both the key and the violation — but only for a statement whose `Principal` was a wildcard. The reader
consults a `Condition` for nothing else, so a bound beside a `Principal`
that already names its callers is neither read nor recorded.
[`../../contracts/policy-model.md`](../../contracts/policy-model.md#condition-confined-wildcards)
owns which keys can appear and what each proves. The field is additive: a
result file written before it existed lacks the key, and no reader requires
anything outside `summary`
([`../../contracts/results.md`](../../contracts/results.md#summary-keys-a-reader-requires));
the known conflict below names the five keys the one RCP reader takes.

`service_principal_sources` is **not** written. `analyze_ecr_policies` carries
it on the in-memory analysis only, and
[`deny_service_confused_deputy`](deny_service_confused_deputy.md) reads it by
re-running that analyzer rather than by reading these files. That second call is
served from the analyzer's per-session memo and issues no AWS request;
[`../index.md`](../index.md) owns the accounting.

`actions_by_account` is filtered to third-party accounts.

`policies_with_wildcards` counts every violation, not only entries with a
literal wildcard principal. A `Federated` or `CanonicalUser` principal is now
recorded as a violation rather than aborting, so it is folded into the same
field and the name understates what the field holds. The same is true of the
equivalent field on all five resource-policy checks.

## Known conflict: the committed result files carry the old key names

Status: unresolved. Conflict 7 in
[`../index.md`](../index.md).

All four files under
`test_environment/headroom_results/rcps/deny_ecr_third_party_access/` carry
`repositories_third_parties_can_access`, `repositories_with_wildcards`, and
`total_repositories_analyzed`. The check has written `policies_*` and
`total_policies_analyzed` since the registry policy was added, so the table
above describes the code and not those files.

Nothing fails today, because nothing reads either key. There is one reader of an
RCP result file, `parse_rcp_result_files` in
`headroom/terraform/generate_rcps.py`, which loads each file and reads its
allowlist through the helpers `headroom/parse_results.py` shares with SCP
parsing (`_load_result_file_json`, `_extract_account_id_from_result`,
`_read_declared_allowlist`). That reader takes five summary keys and nothing
outside `summary`: `account_id`, `account_name`, `check`, `violations`, and
`unique_third_party_accounts`. A missing `account_id` falls back to
`account_name`, and through it to the organization hierarchy.

It still matters, because that directory is the default `results_dir`
([`../../contracts/configuration.md`](../../contracts/configuration.md)) rather
than a sample, so it is the wire format a first-time reader sees.

Rewriting the JSON is the wrong fix: the files are evidence of a run that
really did write `repositories_*`, and renaming the keys would make them claim
to be the output of a code version that never produced them. Regenerating them
needs a live run of the test organization, which costs real money and is
deliberately outside `tox`.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. **What a registry policy authorizes is read; how it is used is not.** The
   registry policy is read once per region, before the repositories, and a
   finding from it carries a null `repository_name` and `repository_arn`. The
   replication rules and pull-through cache rules that policy exists to permit
   are configured through `ecr:DescribeRegistry` and
   `ecr:DescribePullThroughCacheRules`, neither of which this check calls, so a
   grant is reported without the destinations it feeds.
2. `Resource` and `NotAction` are not evaluated, and neither is a `Condition`
   that narrows the grant rather than the statement's principals — so a grant
   confined by `aws:SourceVpce` still contributes its account at full width
   ([`../../contracts/policy-model.md`](../../contracts/policy-model.md#what-is-deliberately-not-read)).
3. A statement carrying `NotAction` instead of `Action` reaches
   `normalize_actions` as an absent key, which reads as no actions. The account
   still enters the allowlist and `actions_by_account` records nothing against
   it, so the finding understates what the grant covers. An `Action` that is
   neither a string nor a list is a different case and raises — see Failure
   behavior.
4. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a repository policy may grant nothing at all. It is
   still counted as a blocker, because whether the grant is live is not readable
   from the document and INV-01 forbids assuming it is not.

## Acceptance scenarios

1. A repository policy granting `111111111111`, outside the organization →
   compliant, and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A repository policy with `Principal: "*"` → violation; the account is blocked
   for ECR only.
4. A repository with no policy → not recorded, and not counted in
   `total_policies_analyzed`.
5. A `Deny` statement naming a third party → not recorded; only `Allow` grants.
6. A repository policy with a `Federated` principal → violation, recorded rather
   than aborting.
7. A repository policy with a `CanonicalUser` principal → violation, on the same
   grounds.
8. A repository policy naming a principal key AWS does not document → the run
   aborts.
9. A repository policy with `Principal: "*"` under `StringEquals
   aws:PrincipalAccount` naming `333333333333`, outside the organization →
   compliant rather than a violation; that account enters the allowlist with
   the statement's actions, and `confined_by` records
   `aws:principalaccount`.
10. The same wildcard under `StringEquals aws:PrincipalOrgID` naming this
    organization → not recorded and not counted; the bound admits only callers
    the deployed statement already spares, so there is no account to allowlist.
11. The same wildcard under `StringEquals kms:CallerAccount` naming
    `333333333333` → still a violation. No Amazon ECR request carries that key,
    so the clause admits nobody and the statement grants nobody anything; it is
    a bound in a KMS key policy and nowhere else.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_ecr_third_party_access.py`
- `headroom/aws/ecr.py` — `analyze_ecr_policies`
- `headroom/aws/policy_documents.py` — `read_statement_principals`,
  `_read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_ecr_third_party_access.py`,
  `tests/test_aws_ecr.py`, `tests/test_aws_policy_documents.py`
