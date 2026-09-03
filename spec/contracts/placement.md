# Contract: placement

Owns the decision of **where** a policy attaches: organization root, an OU, or
individual accounts. Placement never decides whether a guardrail is worth having
— only where it is already satisfied.

Implementation: `headroom/placement/hierarchy.py` (traversal),
`headroom/parse_results.py` (SCP predicates and recommendations),
`headroom/terraform/generate_rcps.py` (RCP predicates and recommendations).
Tests: `tests/test_placement_hierarchy.py`, `tests/test_nested_ou_hierarchy.py`,
`tests/test_parse_results.py`, `tests/test_generate_rcps.py`.

## Levels

| Level | Target | Meaning |
|---|---|---|
| `root` | Organization root | Every account is safe |
| `ou` | One OU | Every account in that OU's **subtree** is safe |
| `account` | One account | That account is safe; some other account is not |
| `none` | — | No account is safe; nothing is deployed for this check |

## The traversal

One generic algorithm, in `HierarchyPlacementAnalyzer.determine_placement`,
parameterized by three caller-supplied functions: `is_safe_for_root`,
`is_safe_for_ou`, and `get_account_id`. The traversal knows nothing about
policies; the predicates know nothing about the tree.

1. If the root is safe, return a single root candidate and stop. Nothing below
   is examined.
2. Otherwise walk down from the OUs that hang directly off the root. An OU that
   is safe becomes a candidate and its **whole subtree** is marked covered; its
   descendants are not visited, so they never collect a redundant second
   attachment. An unsafe OU hands the question to its child OUs.
3. Every account no OU claimed is offered as one account-level candidate.
   Accounts parented directly to the organization root land here by
   construction: they belong to no OU, so no OU-level attachment can reach them,
   and the root ID is not a substitute.

Callers apply their own safety filter to the account-level candidate. The
traversal offers accounts; it does not clear them.

### Subtree grouping

A result is grouped under its account's parent OU **and every OU above it**,
because a policy attached anywhere on that chain reaches the account (INV-05).
Grouping by the immediate parent alone let an OU be declared safe on the strength
of the accounts it shares a level with, while accounts in its child OUs — which
the policy would equally reach — were never consulted.

A cycle in the OU parent chain raises. An account absent from the hierarchy
raises rather than being placed.

## SCP placement

Safety is per account and binary: **zero violations**. Exemptions do not count
against it — an exempt resource is one the statement's condition spares, so it
cannot break.

| Predicate | Definition |
|---|---|
| `is_safe_for_root` | Every account's result has `violations == 0` |
| `is_safe_for_ou` | Every result in the OU's subtree has `violations == 0` |

If no account has zero violations, the check yields exactly one `none`
recommendation and generates no Terraform for that check.

`compliance_percentage` on a recommendation is `100.0` at every level that
places a policy, because `affected_accounts` always holds the zero-violation
subset. The `none` level is the exception and carries `0.0`, with an empty
`affected_accounts` — there is no subset to be complete about, and nothing reads
the figure because nothing is generated. It is not a coverage
figure. It once held the organization-wide coverage fraction for account-level
recommendations, which generation read as a safety signal — and which account
placement can never drive to 100% by construction, since the tier only exists
when some other account violates the check. Every per-account file therefore
emitted every policy as disabled. Coverage now appears in `reasoning`, which
describes reach rather than gating deployment.

Reach and evidence differ. A root SCP applies to every account in the hierarchy,
and an OU SCP to every account in the OU's subtree, in both cases except the
management account; safety is judged over the accounts that produced results,
and `skip_account_ids` and non-ACTIVE accounts are in the hierarchy and never
produce one
([`../architecture/aws-execution.md`](../architecture/aws-execution.md#analyzable-accounts--_select_analyzable_accounts)).
Root and OU `reasoning` therefore states analyzed-of-reached, with the
management account left out of the reached count: `3 of 5 accounts reached by
root were analyzed, all with zero violations - safe to deploy at root level; 2
accounts were not analyzed and will inherit it`, collapsing to `All 5 accounts
reached by root were analyzed, all with zero violations - safe to deploy at
root level` when the two agree. The count needs `management_account_id`, so
`analyze_scp_compliance` raises without it before reading a file;
[`configuration.md`](configuration.md#management_account_id) owns the field.

A recommendation reaching Terraform generation **is** the signal to enable the
policy. Generation does not re-derive safety, and a `none` recommendation
reaching a module raises rather than being rendered.

An SCP check that feeds an allowlist carries its values on
`SCPCheckResult.allowlist_values`, and every recommendation for it carries the
sorted union over the accounts it covers — root, OU, or account — on
`SCPPlacementRecommendations.allowlist_values`. Placement reads nothing from
the registry to do this: a result carrying a list is a result whose check
declared an allowlist, and one carrying `None` is not. `[]` is a legitimate
union, meaning the covered accounts observed nothing; generation decides what
that renders as (INV-06).

## RCP placement

Safety is per account and binary too, but the blocking condition is different: an
account is blocked when a resource policy names a principal **no allowlist can
express** — a wildcard principal above all. Third-party access is not itself a
blocker; it is the thing the allowlist is built from.

| Predicate | Definition |
|---|---|
| `is_safe_for_root` | No account in the organization is blocked |
| `is_safe_for_ou` | No account in the OU's **subtree** is blocked |

An OU is judged by every account it governs: the subtree is enumerated from the
hierarchy, not from the set of accounts that produced results.

**The blocked set, though, can only hold accounts that produced results.** It is
built by reading the result files present under the check's directory, so an
account in the subtree with no file for that check contributes no blocker and
the OU is cleared as if that account had been read and found clean. Reach is
counted over the whole hierarchy while blocking is counted over the scanned
subset, and that asymmetry is INV-01's shape: absence of evidence read as
evidence of safety. Three things keep it bounded, and one case is left open
deliberately:

| Why an account has no file | What holds |
|---|---|
| The scan could not read it | Nothing. A failure aborts the whole run (INV-02), so a completed scan means every analyzable account was read |
| The check itself never ran | A registered check with no results directory at all aborts generation, naming the check: a check absent from the results is indistinguishable from one that found nothing, and this output gates deployment |
| A previous run wrote the file | Resume is per account and per check, so the missing ones are scanned and the rest are read back. [`results.md`](results.md#resume) owns the granularity |
| The account is excluded from analysis | **Open, and deliberate.** The management account, accounts in `skip_account_ids`, and accounts in any non-ACTIVE lifecycle state are in the hierarchy and never produce results, so they cannot block a placement that reaches them. Exclusion removes an account from the compliance picture rather than holding a policy back; [`../architecture/aws-execution.md`](../architecture/aws-execution.md#analyzable-accounts--_select_analyzable_accounts) states it from the discovery side. The SCP reasoning strings say how many such accounts a placement reaches; [SCP placement](#scp-placement) owns that |

The converse aborts too: a directory under `rcps/` naming no registered check
stops generation rather than being stepped over. Parsing visits registered names,
so a directory it never visits holds results nobody reads, and those are
indistinguishable from results that were read (INV-01). The SCP reader aborts on
the same directory; [`results.md`](results.md#summary-keys-a-reader-requires)
states what each reader's error names.

Each check is placed **independently**, against its own blocked set. A resource
policy that blocks the S3 RCP in one account says nothing about that account's
IAM trust policies and must not suppress the STS RCP.

A check with no cleared accounts at all produces no recommendations and no
Terraform — distinct from the SCP `none` recommendation, which is materialized.

### Allowlist union

The allowlist attached to a placement is the **union** of the third-party
accounts observed across the accounts that placement covers.

| Level | Union over | `affected_accounts` |
|---|---|---|
| `root` | Every cleared account | **Every account in the hierarchy** |
| `ou` | The cleared accounts in that OU's subtree | Those accounts |
| `account` | That account alone | That account |

The root case reports every account in the hierarchy, including accounts that
produced no results, because a root attachment does reach them.

Union is the only safe combination: attaching one policy to a target means every
account beneath it must keep reaching the third parties it already reaches, so
the allowlist has to be the union rather than the intersection. The cost is that
a root-level RCP allows every third party any covered account uses. An operator
who wants narrower allowlists gets them by placing lower.

## Ordering

Placement output feeds a reconciled directory (INV-11), so it must be stable
between runs against unchanged input. Allowlists are sorted. Recommendations are
grouped by check name for display and by target for rendering.
