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
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_lambda_auth_type_none.py
  - tests/test_aws_lambda.py
---

# deny_lambda_auth_type_none

## Objective

Deny a Lambda function URL configured for unauthenticated access, which puts an
unauthenticated HTTPS endpoint in front of a function with the function's
execution role behind it.

### Scope

The function URL's auth type, at configuration time.

### Non-goals

- Does not read the function's resource policy, so a URL with
  `AuthType: AWS_IAM` whose policy grants `lambda:InvokeFunctionUrl` to `*` is
  reported compliant. The generated statement covers `lambda:AddPermission`,
  so the policy path is *enforced* — it is just not *scanned*.
- Does not report which qualifier carries the `NONE` URL. Every URL config
  is read, but the verdict is one per function.
- Does not read API Gateway or ALB integrations.

## Enforced statement

```
Effect:    Deny
Action:    lambda:CreateFunctionUrlConfig,
           lambda:UpdateFunctionUrlConfig,
           lambda:AddPermission
Resource:  *
Condition: StringEquals
             lambda:FunctionUrlAuthType = "NONE"
```

Pattern 2, conditional deny. Note the polarity: `StringEquals`, denying the bad
value, rather than `StringNotEquals` denying everything but the good one.

## Evidence

Per enabled region: `lambda:ListFunctions` (paginated), then
`lambda:ListFunctionUrlConfigs` per function, also paginated.

| Read | Used for |
|---|---|
| `FunctionName`, `FunctionArn` | Identity |
| Every URL config's `AuthType` | The verdict: `NONE` if any config carries it |

A function URL can sit on `$LATEST` and on every alias, and AWS documents no
order for the configs `ListFunctionUrlConfigs` returns. The check once read the
first config only, so an alias URL with `AuthType: NONE` behind a `$LATEST` URL
with `AWS_IAM` was reported compliant; the SCP then deployed, and the next
`UpdateFunctionUrlConfig` on that alias would have been denied, which is the
break this tool exists to prevent. The page cap is 50 configs, so the listing
is paginated for the same reason.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | Any URL config's `AuthType` is exactly `"NONE"` | `VIOLATION` |
| Compliant | No URL config, or every config has another `AuthType` | `COMPLIANT` |
| Exemption | — | Never produced |
| Skipped | A function deleted between listing and reading | Recorded as compliant with no URL |

## Failure behavior

| Situation | Behavior |
|---|---|
| `ResourceNotFoundException` on `ListFunctionUrlConfigs` | The function was deleted mid-scan; recorded as having no URL, hence compliant |
| Any other `ClientError` on `ListFunctionUrlConfigs` | Logged and re-raised, aborting the run |
| `ClientError` on `ListFunctions` | Not caught; propagates and aborts |

The narrow `ResourceNotFoundException` exception is deliberate and is the pattern
INV-01 permits: a resource that no longer exists cannot violate anything.
Everything else aborts, because recording "no function URL" for a read that never
succeeded would be a clean verdict from no evidence.

## Result contract

Base document shape. Summary fields beyond the common three: `total_functions`,
`violations`, `compliant`, `compliance_percentage`.

Entry shape: `function_name`, `function_arn`, `region`, `has_function_url`,
`function_url_auth_type`.

`function_url_auth_type` is one value for the function: `NONE` if any URL
config carries it, otherwise the first config's type, and null when the
function has no URL. It is the only value the verdict reads, so collapsing the
configs to it loses nothing the check acts on and keeps the entry shape
unchanged (INV-14).

## Placement and generated policy

Standard SCP placement at zero violations. Terraform variable
`deny_lambda_auth_type_none`, a boolean. No allowlist.

## Accepted limitations

1. A function deleted mid-scan is recorded as compliant, which is correct for
   that run and stale if it is recreated with a public URL before the policy is
   attached.
2. The resource-policy path is enforced but unscanned; see Non-goals.

## Acceptance scenarios

1. A function with no URL config → compliant.
2. A function with a URL config of `AuthType: AWS_IAM` → compliant.
3. A function with a URL config of `AuthType: NONE` → violation.
4. A function that returns `ResourceNotFoundException` → compliant, no URL.
5. A function that returns `AccessDeniedException` → the run aborts.
6. A function whose `$LATEST` URL is `AWS_IAM` and whose alias URL is `NONE` →
   violation, whichever order the API returns them in.
7. A function whose URL configs span two pages, with the `NONE` config on the
   second → violation; every page is read.

## Referenced invariants

INV-01, INV-02, INV-13, INV-16.

## Implementation

- `headroom/checks/scps/deny_lambda_auth_type_none.py`
- `headroom/aws/lambda_functions.py` — `get_deny_lambda_auth_type_none_analysis`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_lambda_auth_type_none.py`,
  `tests/test_aws_lambda.py`
