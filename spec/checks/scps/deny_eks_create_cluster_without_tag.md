---
id: deny_eks_create_cluster_without_tag
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_eks_create_cluster_without_tag.py
  - headroom/aws/eks.py
  - headroom/aws/helpers.py
depends_on:
  - INV-02
  - INV-09
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_eks_create_cluster_without_tag.py
  - tests/test_aws_eks.py
  - tests/test_aws_helpers.py
---

# deny_eks_create_cluster_without_tag

## Objective

Deny EKS cluster creation that does not carry the paved-road tag, so every
cluster in the organization comes from the blessed module rather than from a
console click.

### Scope

`eks:CreateCluster` only.

### Non-goals

- Does not cover `eks:TagResource` or `eks:UntagResource`, so the tag can be
  removed after creation.
- Does not inspect the cluster's configuration, version, or networking. The tag
  asserts provenance, not correctness.
- Does not cover node groups, Fargate profiles, or add-ons.

## Enforced statement

```
Effect:    Deny
Action:    eks:CreateCluster
Resource:  *
Condition: StringNotEquals
             aws:RequestTag/PavedRoad = "true"
```

Pattern 3, paved road ([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).
This is not an exemption tag: it marks the blessed path rather than excusing a
departure from it.

## Evidence

Per enabled region: `eks:ListClusters`, then `eks:DescribeCluster` for each.

| Read | Used for |
|---|---|
| `cluster["arn"]` | Identity |
| `cluster["tags"]` | The verdict |

Like every tag check here, the existing cluster's tag stands in for the creation
request's tag (INV-09). The substitution is weaker than
[`deny_ec2_imds_v1`](deny_ec2_imds_v1.md)'s: a cluster created by the module and
later untagged reads as a violation, and a cluster tagged by hand after a console
creation reads as compliant.

## Decision table

| State | Condition | Category |
|---|---|---|
| Compliant | The tag's value is exactly `true`, under a key matched without regard to case | `COMPLIANT` |
| Violation | Anything else, including a missing tag, `PavedRoad=false`, and `PavedRoad=True` | `VIOLATION` |
| Exemption | — | Never produced |
| Unknown | — | Not produced; every failure aborts |

The key is matched the way IAM matches it and the value the way
`StringNotEquals` compares it, which pull opposite ways. The two halves are
settled in one place, `find_tag_value_as_iam_matches` in
`headroom/aws/helpers.py`, shared with [`deny_ec2_imds_v1`](deny_ec2_imds_v1.md)
so the two tag checks cannot read the same kind of tag by two different rules
again.

## Failure behavior

`headroom/aws/eks.py` has **no exception handling at all.** Every failure —
`AccessDenied`, an unreachable regional endpoint, a cluster deleted between
`ListClusters` and `DescribeCluster` — propagates and aborts the run (INV-02).
No sentinel value is produced. The one error it originates rather than
propagates is the ambiguous-tag case below, raised by the shared tag reader.

| Situation | Behavior |
|---|---|
| Any `ClientError` in any region | Propagates, aborting the run |
| Cluster carries the tag key twice in cases that differ | `RuntimeError` — AWS matches one spelling or the other, not both, so which value the condition compares is not guessable |
| Tag absent | Violation, not an error |

## Result contract

Base document shape. Summary fields beyond the common three: `total_clusters`
(**not** `total_instances`), `violations`, `compliant`,
`compliance_percentage`.

Because the count key is `total_clusters`, `SCPCheckResult.total_instances`
parses as `None` for this check. Nothing downstream reads it.

Entry shape: `cluster_name`, `cluster_arn`, `region`, `tags`,
`has_paved_road_tag`.

## Placement and generated policy

Standard SCP placement at zero violations. Terraform variable
`deny_eks_create_cluster_without_tag`, a boolean. No allowlist.

## Accepted limitations

1. The Terraform module spells `PavedRoad` and `true` out again. The analyzer
   reads `EKS_PAVED_ROAD_TAG_KEY` and `EKS_PAVED_ROAD_TAG_VALUE` from
   `headroom/constants.py`, so the two halves of the Python agree, but changing
   the constant does not change the rendered policy.
2. A cluster deleted mid-scan aborts the run rather than being skipped, unlike
   the comparable cases in [`deny_lambda_auth_type_none`](deny_lambda_auth_type_none.md)
   and [`deny_sqs_third_party_access`](../rcps/deny_sqs_third_party_access.md).
3. The evidence that the key matches without regard to case is AWS's documented
   rule plus [`deny_ec2_imds_v1`](deny_ec2_imds_v1.md)'s live measurement, not a
   measurement against `eks:CreateCluster`, which has no dry run.

## Acceptance scenarios

1. A cluster tagged `PavedRoad=true` → compliant.
2. A cluster with no tags → violation.
3. A cluster tagged `PavedRoad=false` → violation.
4. A cluster tagged `pavedroad=true` → compliant. The key is part of the
   condition key name, which AWS matches without regard to case.
5. A cluster tagged `PavedRoad=True` → violation. `StringNotEquals` compares the
   value case-sensitively.
6. A cluster carrying both `PavedRoad` and `pavedroad` → the run aborts.
7. `AccessDenied` on `ListClusters` in one region → the run aborts.

## Referenced invariants

INV-02, INV-09, INV-13, INV-16.

## Implementation

- `headroom/checks/scps/deny_eks_create_cluster_without_tag.py`
- `headroom/aws/eks.py` — `get_eks_cluster_tag_analysis`
- `headroom/aws/helpers.py` — `find_tag_value_as_iam_matches`
- `headroom/constants.py` — `EKS_PAVED_ROAD_TAG_KEY`, `EKS_PAVED_ROAD_TAG_VALUE`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_eks_create_cluster_without_tag.py`,
  `tests/test_aws_eks.py`, `tests/test_aws_helpers.py`
