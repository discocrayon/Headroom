# Product

## Problem

An AWS Organization can express a guardrail as a Service Control Policy or a
Resource Control Policy, but it cannot tell you what attaching one would break.
The policy either denies nothing you care about or takes down a workload, and
the only way to find out is to attach it. Organizations that have grown past a
handful of accounts therefore accumulate guardrails they believe in and never
deploy.

## What Headroom does

Headroom scans an AWS Organization and emits Terraform for the SCPs and RCPs
that **will not break existing workloads** — attached at the highest level of
the organization where that is true, with allowlists derived from what the
workloads actually do.

"Headroom" is the distance between what the workloads do today and what a policy
would permit. A check measures that distance for one policy statement.

## The safety promise

This is the guarantee the whole system exists to make, and every invariant in
[`invariants.md`](invariants.md) exists to protect it:

> **Every policy statement Headroom generates is one that the accounts it is
> attached to would already satisfy.**

Three consequences follow, and they are requirements rather than observations:

1. A policy is attached only where **every** account it reaches has zero
   violations. One violating account anywhere in an OU's subtree disqualifies
   the whole subtree, not just that account's level.
2. Where a statement is scoped by an allowlist, the allowlist holds the union of
   what the covered accounts were **observed** to use. An allowlist that is
   empty because nothing was observed never becomes a statement that denies
   everything; INV-06 in [`invariants.md`](invariants.md) sets out what is
   rendered instead, which differs by the shape the allowlist takes.
3. Absence of evidence is never read as evidence of safety. A run that could not
   read an account, or read no results at all, aborts rather than producing a
   policy that looks clean because it saw nothing.

## Users

| User | Uses Headroom to |
|---|---|
| Cloud security engineer | Find which guardrails are already deployable, and what stands in the way of the rest |
| Platform engineer | See which workloads a proposed guardrail would break, before it is attached |
| Auditor | Read the per-account violation record behind a deployed policy |

## Output

One run produces three artifacts, in this order:

1. **Result JSON**, one file per check per account — the violation record.
   Contract: [`contracts/results.md`](contracts/results.md).
2. **Placement recommendations**, printed and passed onward — where each policy
   can safely attach. Contract: [`contracts/placement.md`](contracts/placement.md).
3. **Terraform**, reconciled to this run — the policies and their attachments.
   Contract: [`contracts/terraform.md`](contracts/terraform.md).

The result JSON is durable and re-read on the next run; the Terraform directory
is a reconciled projection of the current run and holds nothing else.

## Non-goals

Headroom deliberately does not do these things. Each is a design decision rather
than a gap awaiting implementation.

| Non-goal | Why |
|---|---|
| Apply Terraform, or attach any policy | Headroom writes files. A human reviews and applies them. |
| Remediate violations | It reports what a policy would break; fixing that is the workload owner's decision. |
| Evaluate a policy condition for anything but a bound on a wildcard principal | A `Condition` is read to decide whether a wildcard principal reaches a set an allowlist can carry, and for nothing else: a condition that narrows the *grant* rather than the principal set — `s3:prefix`, `aws:SourceVpce`, `kms:ViaService`, a date — leaves the account it names at full width. Reading a condition in order to un-block an account inverts the safety direction, so every shape the reader cannot prove stays a blocker. See [`contracts/policy-model.md`](contracts/policy-model.md) and [`../ROADMAP.md`](../ROADMAP.md). |
| Analyze historical activity | Deployability is decided from current resource state, not from CloudTrail. Listed under [`../ROADMAP.md`](../ROADMAP.md). |
| Analyze the management account | SCPs and RCPs do not restrict it. See [`architecture/aws-execution.md`](architecture/aws-execution.md). |
| Guarantee an *undeployable* policy stays undeployable | A check reports the state it observed. New violations after a scan are the next run's problem. |
| Judge whether a guardrail is worth having | Headroom decides deployability, never desirability. |

## Status

Proof of concept. Every generated policy is meant to be reviewed before it is
applied. The [`../README.md`](../README.md) carries the current capability
summary for readers who are not implementing against this corpus.
