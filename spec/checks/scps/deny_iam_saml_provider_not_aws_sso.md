---
id: deny_iam_saml_provider_not_aws_sso
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_iam_saml_provider_not_aws_sso.py
  - headroom/aws/iam/saml_providers.py
depends_on:
  - INV-02
  - INV-07
  - INV-13
verification:
  - tests/test_checks_deny_iam_saml_provider_not_aws_sso.py
  - tests/test_aws_iam.py
---

# deny_iam_saml_provider_not_aws_sso

## Objective

Deny creation of IAM SAML providers, so federation into the account happens only
through AWS IAM Identity Center and not through a second, hand-rolled identity
provider that no one is watching.

### Scope

`iam:CreateSAMLProvider`, unconditionally.

### Non-goals

- Does not cover `iam:UpdateSAMLProvider` or `iam:DeleteSAMLProvider`.
- Does not read OIDC identity providers.
- Does not validate the SAML metadata document of the provider it accepts.

## Enforced statement

```
Effect:   Deny
Action:   iam:CreateSAMLProvider
Resource: *
```

Pattern 1, absolute deny — no `Condition` at all.

The Identity Center provider is created by `AWSServiceRoleForSSO`, a
service-linked role that SCPs do not restrict, so denying the action outright
does not prevent Identity Center from managing its own provider.

## Evidence

`iam:ListSAMLProviders`, a single call. Global — no region iteration, and
**not paginated**.

| Read | Used for |
|---|---|
| `Arn` | Identity, and the provider name after the last `/` |
| `CreateDate`, `ValidUntil` | Recorded, ISO-formatted |

The allowed shape is exactly one provider whose name begins `AWSSSO_`, matched
case-sensitively. An account with zero providers produces no results at all and
so no findings.

## Decision table

| State | Condition | Category | `violation_reason` |
|---|---|---|---|
| Compliant | The name begins `AWSSSO_` **and** exactly one provider exists | `COMPLIANT` | — |
| Violation | The name does not begin `AWSSSO_` | `VIOLATION` | `provider_prefix_not_awssso` |
| Violation | More than one provider exists, whatever their names | `VIOLATION` | `multiple_saml_providers_present` |
| Exemption | — | Never produced | — |
| No findings | The account has no SAML providers | Nothing recorded | — |

## Failure behavior

`ClientError` from `ListSAMLProviders` is logged and re-raised, aborting the run
(INV-02).

## Result contract

Base document shape. Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `total_saml_providers` | Count |
| `awssso_provider_count` | How many begin `AWSSSO_` |
| `non_awssso_provider_count` | How many do not |
| `allowed_provider_arn` | The single compliant provider's ARN, or `null` |
| `violating_provider_arns` | The ARNs of the violating providers |
| `violations` | Count. **This is the field placement reads.** |
| `exemptions` | Count, always zero — this check produces none |
| `compliant` | Count |
| `compliance_percentage` | 100 for an account with no providers at all |

Entry shape: `arn`, `name`, `create_date`, `valid_until`, plus
`violation_reason` on violations only.

## Placement and generated policy

| | |
|---|---|
| Terraform variable | `deny_iam_saml_provider_not_aws_sso`, a bare boolean |
| Allowlist variable | None. The statement takes no allowlist. |
| Allowlist round trip | Not applicable, though `allowed_provider_arn` is written as if there were one — see limitation 4 |
| Placement input | `summary.violations` |

Standard SCP placement at zero violations, like every other SCP check.

The count was once omitted from the summary while the offending ARNs were
reported in `violating_provider_arns`, so parsing read zero for every account
and the deny was recommended at root over organizations this check had just
rejected. `test_a_wholly_non_compliant_account_does_not_parse_as_safe` pins the
round trip through parsing rather than the summary alone, because the summary
was never the part that was visibly wrong.

The default that let it happen is gone too: SCP parsing now raises on a summary
with no `violations` key rather than reading zero
([`../../contracts/results.md`](../../contracts/results.md)), so a check that
repeats the omission stops the run instead of silently clearing every account.

## Accepted limitations

1. **Not paginated.** `ListSAMLProviders` is called once. An account holding more
   providers than one response carries would be under-reported — though any count
   above one is already a violation.
2. The `AWSSSO_` prefix is matched case-sensitively and is written literally in
   the module, with no shared constant.
3. An account with zero providers records nothing, which is indistinguishable in
   the result file from a check that ran and found nothing to say.
4. **`allowed_provider_arn` is written and read by nothing.** No field on
   `SCPCheckResult` carries it and no Terraform variable consumes it, so the
   allowlist round trip INV-07 describes is incomplete. It is harmless here
   because the statement takes no allowlist — the key is a record of which
   provider was accepted, not an input to anything.

## Acceptance scenarios

1. Exactly one provider named `AWSSSO_prod` → compliant.
2. One provider named `Okta` → violation with
   `violation_reason: provider_prefix_not_awssso`.
3. Two providers, both named `AWSSSO_*` → two violations with
   `violation_reason: multiple_saml_providers_present`.
4. No providers → no entries; `total_saml_providers: 0`.
5. An account matching scenario 2 → `summary.violations` is 1, the account is
   not in the zero-violation subset, and placement does not clear it for root.

## Referenced invariants

INV-02, INV-07 (see limitation 4), INV-13.

## Implementation

- `headroom/checks/scps/deny_iam_saml_provider_not_aws_sso.py` — class
  `DenySamlProviderNotAwsSsoCheck`
- `headroom/aws/iam/saml_providers.py` — `get_saml_providers_analysis`
- `headroom/parse_results.py` — `_parse_single_scp_result_file`
- Tests: `tests/test_checks_deny_iam_saml_provider_not_aws_sso.py`,
  `tests/test_aws_iam.py`
