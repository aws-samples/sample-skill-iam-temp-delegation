---
name: procedure-verifier
description: >-
  The 5-step falsification procedure for Stage 4 verification. Covers SAR
  cross-checking, common falsification targets, attack path reachability,
  and verification state assignment.
keywords:
  - verifier
  - falsification
  - SAR verification
  - unverified
  - proof-backed
  - attack path
load: step-5
---

# Verifier Procedure

Reference for Stage 4 (verification). Read this before verifying reviewer findings.

The verifier's goal is **FALSIFICATION** — actively try to disprove each reviewer finding against the SAR data. You are not confirming the reviewer's work; you are trying to catch mistakes, hallucinations, and plausible-but-wrong recommendations.

---

## 5-Step Verification Procedure

For EACH finding from the reviewer, execute these steps in order:

### Step 1: Classify the finding source

- If the finding has `verification: "proof-backed"` (from Stage 1-2 / Access Analyzer) → it is AUTHORITATIVE. Pass it through unchanged. Never re-litigate proof-backed findings.
- If the finding is from the reviewer → proceed to Step 2.

### Step 2: Extract the recommendation

Identify what is being recommended:
- A specific **condition key** (e.g., "add `iam:PermissionsBoundary` condition")
- A specific **resource scope** (e.g., "scope to `arn:aws:iam::*:role/Prefix*`")
- A **structural observation** (e.g., "these two statements create an escalation chain")

### Step 3: Verify against `sar_context.json`

For condition key or resource scope recommendations:

1. Look up the action in `sar_context.json`.
2. Check whether the recommended condition key appears in the action's `condition_keys[]` list.
3. Check whether the action supports resource-level permissions:
   - If `resource_types` is EMPTY → the action is **permission-only** — it cannot be resource-scoped. Any recommendation to scope it to a specific ARN (other than `*`) is INCORRECT.
   - If `resource_types` is non-empty → verify the recommended resource type is listed.

For structural observations (escalation chains, Allow-overlap):
- Verify the actions and resource patterns exist as described in the policy.
- Confirm the logical chain is sound (both statements are present, the overlap is real).

### Step 4: Assign verification state

| Situation | State | Action |
|-----------|-------|--------|
| Finding is from Access Analyzer (Stage 1-2) | `proof-backed` | Pass through unchanged |
| SAR confirms the recommended condition key is supported | `verified` | Keep the finding |
| SAR does NOT list the condition key for this action | `unverified` | Flag for human review, explain why |
| Action is permission-only but resource scope recommended | `unverified` | Note the action cannot be scoped |
| Structural analysis is logically sound (actions/patterns exist) | `verified` | Keep the finding |
| Structural analysis references wrong action or pattern | `unverified` | Explain the discrepancy |

### Step 5: Reject or correct SAR-contradicting recommendations

If a recommendation actively CONTRADICTS the SAR:
- Condition key is NOT in the action's `condition_keys[]` at all
- Action has empty `resource_types` but resource scope is recommended

In these cases:
1. Mark `unverified`
2. Explain the contradiction ("SAR shows `iam:TagRole` supports these condition keys: [...]; `iam:PermissionsBoundary` is not among them")
3. Suggest an alternative if one exists (e.g., "split `TagRole` into a separate statement without the boundary condition")

---

## Common Falsification Targets

These are frequent reviewer errors to watch for — specific cases where the reviewer's recommendation is plausible but wrong:

| Reviewer says | Why it's wrong | What to do |
|---------------|---------------|------------|
| "Add `iam:PermissionsBoundary` condition on `iam:TagRole`" | TagRole does not support this condition key (not in its `condition_keys`) | Reject; suggest splitting into separate statement |
| "Scope `logs:CreateLogDelivery` to a specific resource ARN" | Permission-only action (empty `resource_types`); cannot be resource-scoped | Reject; mark unverified; note limitation |
| "Add `aws:RequestTag` condition on a describe/modify action" | RequestTag only applies to actions that create/tag resources | Reject if action is read/modify-only |
| "Scope `ec2:DescribeInstances` to specific VPC resources" | DescribeInstances does not support resource-level permissions | Reject resource scope recommendation |
| "Add `organizations:TransferType` condition on `AcceptHandshake`" | The condition key exists but is NOT supported by `AcceptHandshake` (only by invite/responsibility-transfer actions) | Reject; note the action-specific limitation |
| "Use `ForAnyValue` for OR logic across PrincipalTag keys" | Does not provide OR logic for single-valued keys | This IS a valid finding — verify it, don't falsify it |
| "Use `@{PartnerAccountId}` or `@{OrgId}` in boundary Resource" | Boundaries are pre-registered static policies — they do NOT support `@{...}` parameterization. Only templates support placeholders. | Reject; note the boundary is static. If scoping is possible, suggest a static ARN or accept the wildcard as a known limitation |

---

## Rules

1. **Never re-litigate proof-backed findings.** Access Analyzer's PASS/FAIL is mathematically proven.
2. **The SAR (`sar_context.json`) is authoritative.** If it says an action does not support a condition key, that key WILL NOT WORK regardless of how plausible it sounds. IAM silently ignores unsupported condition keys — the condition parses but never enforces.
3. **Err on the side of `unverified`.** If you cannot confirm a recommendation from the SAR data, mark it `unverified`. A human seeing `unverified` will investigate. A wrong `verified` label damages trust.
4. **Structural findings need different verification.** Escalation chains and Allow-overlap are logical observations about policy structure, not condition-key recommendations. Verify these by confirming the actions and patterns exist as described.
5. **Every `verified` finding must be backed by SAR data.** If you mark something `verified`, you must be able to point to the entry in `sar_context.json` that confirms the recommendation.
6. **Verify attack path reachability, not just condition support.** SAR confirmation means the condition key *works* — it does not mean the finding is *meaningful*. For each finding, trace the complete attack path: what preconditions must hold, and can those preconditions be achieved using only the actions granted in this bundle? If the threat requires an action not present in the bundle (e.g., the scenario assumes a boundary is removed, but no boundary-removal action is granted), mark the finding as unreachable and reject it or downgrade to informational. A condition that guards against a scenario no one can trigger is not a security improvement — it is noise.
