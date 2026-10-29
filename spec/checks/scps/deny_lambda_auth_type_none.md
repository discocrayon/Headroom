---
id: deny_lambda_auth_type_none
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_lambda_auth_type_none.py
  - headroom/aws/lambda_functions.py
depends_on:
  - INV-01
  - INV-02
  - INV-06
  - INV-07
  - INV-13
  - INV-16
verification:
  - tests/test_terraform_module_plans.py
  - tests/test_checks_deny_lambda_auth_type_none.py
  - tests/test_aws_lambda.py
---

# deny_lambda_auth_type_none

## Objective

Deny making a Lambda function URL public everywhere except for the function
URLs that already are, so the organization stops accruing unauthenticated HTTPS
endpoints — each with the function's execution role behind it — without
breaking the ones it depends on today.

### Scope

The function URL's auth type, at configuration time, and the ARN of every URL
that carries `NONE`: the ARNs become the allowlist.

### Non-goals

- Does not judge whether an existing public URL *should* be public. Every
  public URL found is allowlisted, and recorded as an exemption so it stays
  visible.
- Does not read the function's resource policy, so a URL with
  `AuthType: AWS_IAM` whose policy grants `lambda:InvokeFunctionUrl` to `*` is
  reported compliant. The generated statement covers `lambda:AddPermission`,
  so the policy path is *enforced* — it is just not *scanned*.
- Does not read API Gateway or ALB integrations.
- Does not cover URLs made public between the scan and the apply.

## Enforced statement

```
Effect:      Deny
Action:      lambda:CreateFunctionUrlConfig,
             lambda:UpdateFunctionUrlConfig,
             lambda:AddPermission
NotResource: <lambda_allowed_public_function_urls>   (Resource: "*" when the list is empty)
Condition:   StringEquals
               lambda:FunctionUrlAuthType = "NONE"
```

Pattern 6, a composition of a resource ARN allowlist (5b) with a conditional
deny (2). The condition confines the deny to the one bad value — `StringEquals`
denying `NONE`, rather than `StringNotEquals` denying everything but `AWS_IAM` —
and `NotResource` lifts it from the URLs that already carry that value, so a
re-apply of an existing public URL succeeds and every other function is denied
the value.

Lambda authorizes the three actions against the function *or the alias*: it
compares the policy's resource with both `FunctionName` and `Qualifier` in the
request, and a policy naming the unqualified ARN does not match a request that
names a qualifier
([Lambda developer guide](https://docs.aws.amazon.com/lambda/latest/dg/lambda-api-permissions-ref.html)).
A URL on the `prod` alias is therefore spared only by
`arn:aws:lambda:us-east-1:111111111111:function:api:prod`. An entry holding
`arn:aws:lambda:us-east-1:111111111111:function:api` would spare a `$LATEST`
URL and let the alias's next `UpdateFunctionUrlConfig` be denied — the break
this tool exists to prevent. The allowlist value is each public URL config's
own `FunctionArn`, exactly as `ListFunctionUrlConfigs` returns it. Measured
against a live account: a URL on `$LATEST` reports the unqualified ARN, and a
URL on an alias reports the alias-qualified one. The entry recorded for the
common case is therefore the ARN a default re-apply, which passes no
`Qualifier`, is authorized against.

## Evidence

Per enabled region: `lambda:ListFunctions` (paginated), then
`lambda:ListFunctionUrlConfigs` per function, also paginated.

| Read | Used for |
|---|---|
| The function's `FunctionName`, `FunctionArn` | Identity |
| Every URL config's `AuthType` | The verdict: `NONE` if any config carries it |
| Every URL config's `FunctionArn`, where its `AuthType` is `NONE` | The allowlist value |

A function URL can sit on `$LATEST` and on every alias, and AWS documents no
order for the configs `ListFunctionUrlConfigs` returns. The check once read the
first config only, so an alias URL with `AuthType: NONE` behind a `$LATEST` URL
with `AWS_IAM` was reported compliant; the SCP then deployed, and the next
`UpdateFunctionUrlConfig` on that alias would have been denied. The page cap is
50 configs, so the listing is paginated for the same reason. A config's
`FunctionArn` is a required key; a config missing one raises `KeyError`.

## Decision table

| State | Condition | Category |
|---|---|---|
| Exemption | Any URL config's `AuthType` is exactly `"NONE"`; its ARN is allowlisted | `EXEMPTION` |
| Compliant | No URL config, or every config has another `AuthType` | `COMPLIANT` |
| Violation | — | **Never produced** |
| Skipped | A function deleted between listing and reading | Recorded as compliant with no URL |

A public URL is an exemption rather than a violation because the statement
spares it: its ARN is in `NotResource`, so the deny never matches it, and it
must not count against deployability
([`../../architecture/check-framework.md`](../../architecture/check-framework.md#the-three-categories)).
This is the direct form of the claim `EXEMPTION` is reserved for — the scan
reads the very ARN the statement names — where `deny_ec2_imds_v1` reads a
proxy.

This check can never report a violation, so every account is always "safe" for
it. The safety argument therefore rests on the allowlist being complete, which
is why INV-07 applies and why the round trip below is specified end to end.

## Failure behavior

| Situation | Behavior |
|---|---|
| `ResourceNotFoundException` on `ListFunctionUrlConfigs` | The function was deleted mid-scan; recorded as having no URL, hence compliant |
| Any other `ClientError` on `ListFunctionUrlConfigs` | Logged and re-raised, aborting the run |
| `ClientError` on `ListFunctions` | Not caught; propagates and aborts |

The narrow `ResourceNotFoundException` exception is deliberate and is the pattern
INV-01 permits: a resource that no longer exists cannot violate anything.
Everything else aborts, because recording "no function URL" for a read that never
succeeded would be a clean verdict from no evidence — and, now that the
allowlist is built from the same read, an allowlist missing the URL the read
would have found.

## Result contract

Base document shape. Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `total_functions` | Count of functions found, across all three lists |
| `violations` | Always zero. Written, not omitted. |
| `exemptions` | Count of functions with at least one public URL |
| `compliant` | Count of functions with no public URL |
| `public_function_urls` | A sorted list of ARN **strings** — every public URL's `FunctionArn`, across functions |

`violations` is structurally zero: `categorize_result` never returns
`VIOLATION`. It is written anyway, because a reader cannot tell an absent key
from a genuine zero and SCP parsing refuses to guess
([`../../contracts/results.md`](../../contracts/results.md)).

There is no `compliance_percentage` key. An exemption counts as compliant, as
it does for `deny_ec2_imds_v1`, so the figure would always read 100 and say
nothing.

Entry shape, in every list: `function_name`, `function_arn`, `region`,
`has_function_url`, `function_url_auth_type`, `public_function_url_arns`.

`function_url_auth_type` is one value for the function: `NONE` if any URL
config carries it, otherwise the first config's type, and null when the
function has no URL. `public_function_url_arns` lists the ARNs the statement
spares for this function, empty for a compliant one; a function with a public
URL on `$LATEST` and another on an alias lists both. `violations` is always
empty.

**Result files written before `public_function_urls` existed do not parse.**
SCP parsing aborts by name on a summary missing the declared key, because an
absent key cannot be told from an account that observed nothing (INV-01), and
its error says which file to delete and re-scan.

## Placement and generated policy

Every account is safe, so placement lands at root unless another check's
recommendation moves this one — placement is per check
([`../../contracts/placement.md`](../../contracts/placement.md)).

The allowlist round trip (INV-07):

1. `summary.public_function_urls` — ARNs, with the account ID replaced by
   `REDACTED` when `exclude_account_ids` is set. A Lambda ARN carries the
   account between the region and the resource, and the redaction reads that
   field whatever the service.
2. SCP parsing restores the account ID into each ARN once the account is
   identified, because this check's `Allowlist` sets `restores_account_ids`.
3. `SCPCheckResult.allowlist_values`.
4. The sorted union across the accounts a placement covers.
5. `SCPPlacementRecommendations.allowlist_values`.
6. The `lambda_allowed_public_function_urls` Terraform variable, with each
   ARN's account field rewritten to `${local.<account_name>_account_id}` where
   the account is in the hierarchy. An ARN naming an account the hierarchy
   does not have is emitted literally.

Terraform variables: `deny_lambda_auth_type_none` (boolean) and
`lambda_allowed_public_function_urls` (list, rendered whenever the boolean is
true). The module validates each entry as a function ARN of one of the two
shapes above, with or without the alias qualifier, so an entry of any other
form is refused at plan time rather than by Organizations at apply time.

**An empty allowlist leaves the policy on.** When the accounts a module covers
hold no public function URL at all, step 6 renders
`lambda_allowed_public_function_urls = []`, and the module renders
`Resource: "*"` in place of `NotResource`: a resource array must hold at least
one value, and an empty `NotResource` would be rejected as malformed (INV-06).
[`../../invariants.md`](../../invariants.md#inv-06--an-empty-allowlist-is-never-rendered-as-an-empty-list)
owns why an empty resource array is invalid. This is the third shape INV-06
names, not the second — the empty list does not turn the statement off,
because a statement with nothing to spare is the full deny of `AuthType NONE`,
the protection the statement carried before it took an allowlist, and an
organization with no public URL is the one it protects best. The declaration
therefore sets no `empty_allowlist_comment`. The module builds the resource
clause from two conditionals merged into the statement rather than one,
because Terraform requires both arms of a conditional to share a type and
objects keyed `NotResource` and `Resource` do not. The module's
`tests/plan.tftest.hcl` plans both cases and the validation, under `tox`
through `tests/test_terraform_module_plans.py`.

[`deny_iam_user_creation`](deny_iam_user_creation.md) leaves its policy off in
the same case; whether it should render `Resource: "*"` instead is conflict 12
in [`../index.md`](../index.md#unresolved-conflicts).

## Accepted limitations

1. A function deleted mid-scan is recorded as compliant, which is correct for
   that run and stale if it is recreated with a public URL before the policy is
   attached.
2. The resource-policy path is enforced but unscanned; see Non-goals.
3. A URL made public between the scan and the apply is absent from the
   allowlist, and its next re-apply is denied.
4. A URL deleted after the scan stays in the allowlist, which is harmless: the
   `NotResource` entry simply matches nothing.
5. The allowlist competes for the module's 5,120-character SCP budget, and a
   Lambda ARN is long. An organization with many public URLs can exceed it at
   the root; the module fails at plan time with the character count rather
   than attaching a truncated policy.
6. `CreateFunctionUrlConfig`, `UpdateFunctionUrlConfig`, and
   `GetFunctionUrlConfig` reject `$LATEST` as a `Qualifier` with a
   `ValidationException`, so no request can address a `$LATEST` URL by a
   qualified ARN through them, and the unqualified entry spares every re-apply
   of the URL itself. `AddPermission` does accept `$LATEST` as a `Qualifier`.
   A permission re-applied with that explicit qualifier is authorized against
   `...:function:NAME:$LATEST`, which the entry does not match, and is denied;
   the default form, with no qualifier, is spared.
7. An account excluded from analysis — one in `skip_account_ids`, in a
   non-ACTIVE lifecycle state, or created between the scan and the apply —
   contributes no public URL, and the root placement this check always
   produces reaches it anyway. The management account is not part of this
   gap, since no SCP reaches it.
   [`../../contracts/placement.md`](../../contracts/placement.md#scp-placement)
   records the general case as "excluded from analysis" and calls it open and
   deliberate. A URL already public in such an account is denied on its next
   re-apply, while the check itself reports every analyzed account compliant.

## Acceptance scenarios

1. A function with no URL config → compliant, with an empty ARN list.
2. A function with a URL config of `AuthType: AWS_IAM` → compliant.
3. A function with a URL config of `AuthType: NONE` → exemption, and
   `summary.public_function_urls` holds its ARN.
4. A function that returns `ResourceNotFoundException` → compliant, no URL.
5. A function that returns `AccessDeniedException` → the run aborts.
6. A function whose `$LATEST` URL is `AWS_IAM` and whose alias URL is `NONE` →
   exemption, whichever order the API returns them in, and the ARN recorded is
   the alias-qualified one rather than the function's.
7. A function whose URL configs span two pages, with the `NONE` config on the
   second → exemption; every page is read.
8. An account with no public URL → `violations: 0`, `exemptions: 0`, and
   `public_function_urls: []`, present rather than absent; a module covering
   only such accounts renders `deny_lambda_auth_type_none = true` with
   `lambda_allowed_public_function_urls = []`, and the statement carries
   `Resource: "*"` rather than an empty `NotResource`
   (`empty_public_url_list_renders_resource_star` in the module's
   `tests/plan.tftest.hcl`).
9. A result written with `exclude_account_ids` → the ARNs carry `REDACTED`,
   and parsing restores the account ID before the union is built.
10. A written result parses with zero violations, one exemption, and
    `allowlist_values` holding the qualified ARN under `public_function_urls`.
11. An allowlist entry that is not a function ARN of either shape, such as one
    missing the `function:` segment → the module's variable validation rejects
    the plan, naming the variable and both forms
    (`function_arn_without_the_function_segment_is_rejected` in
    `test_environment/modules/scps/tests/plan.tftest.hcl`).

## Referenced invariants

INV-01, INV-02, INV-06, INV-07, INV-13, INV-16.

## Implementation

- `headroom/checks/scps/deny_lambda_auth_type_none.py`
- `headroom/aws/lambda_functions.py` — `get_deny_lambda_auth_type_none_analysis`
- `headroom/parse_results.py` — `_read_declared_allowlist`, `union_allowlist_values`
- `headroom/terraform/parameters.py` — `render_check_parameters`,
  `_replace_account_id_in_arn`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_lambda_auth_type_none.py`,
  `tests/test_aws_lambda.py`
