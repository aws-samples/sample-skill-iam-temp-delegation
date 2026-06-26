---
name: procedure-reviewer
description: >-
  Detection patterns, pitfalls table, and constraints for Stage 3 reviewer
  analysis. Covers escalation chains, allow-overlap, multi-resource completeness,
  tag misuse, wildcard exposure, and over-broad permissions.
keywords:
  - reviewer
  - detection patterns
  - escalation
  - allow-overlap
  - wildcard
  - condition key
load: step-4
---

# Reviewer Detection Patterns

Reference for Stage 3 analysis. Read this before performing the reviewer analysis step.

---

## Pattern 1: Cross-Statement Escalation Chains

Detect privilege escalation that spans multiple statements or artifacts. These are the hardest findings because each statement looks benign in isolation.

### PB-less CreateRole + PassRole chain (CRITICAL)

If the template grants `iam:CreateRole` without an `iam:PermissionsBoundary` condition, AND grants `iam:PassRole`, the principal can:
1. Create a role without a boundary (uncapped permissions)
2. Attach `AdministratorAccess` to it
3. Pass it to a service (e.g. EC2 via `RunInstances`)
→ Full account compromise.

**Detection:** Look for `iam:CreateRole` in any statement. Check if that statement has `"StringEquals": {"iam:PermissionsBoundary": "..."}`. If not, check if `iam:PassRole` appears in the same or any other statement. If both conditions hold → CRITICAL.

### AttachRolePolicy without guard

`iam:AttachRolePolicy` without EITHER:
- `iam:PermissionsBoundary` condition (boundary caps effective permissions), OR
- `iam:PolicyArn` condition with `ArnLike` (restricts which policies can be attached)

...allows attaching `AdministratorAccess` to any role in scope.

**Detection:** Find `iam:AttachRolePolicy`. Check its conditions for either `iam:PermissionsBoundary` or `iam:PolicyArn`. If neither → HIGH.

### DetachRolePolicy / DeleteRolePolicy + re-attach

If the template grants both `DetachRolePolicy` (or `DeleteRolePolicy`) AND `AttachRolePolicy` on the same resource scope, the principal can remove a restricting policy and attach a permissive one.

### Cross-artifact PB-on-CreateRole check

If the delegation template grants `iam:CreateRole`:
1. Verify the statement has a `StringEquals` condition on `iam:PermissionsBoundary`.
2. Verify the condition value uses the **partner-managed boundary ARN namespace** — NOT the traditional IAM managed policy ARN format.
3. If the boundary is absent from the bundle but `CreateRole` is granted → CRITICAL (roles created without a boundary have uncapped permissions).

**Partner boundary ARN format:**
```
arn:aws:iam::partner:policy/permission_boundary/<domain>/<boundary_name>
```

- `partner` is a **literal fixed string** (not a placeholder for an account ID). It is the ARN namespace used by the AWS Partner temporary delegation system.
- `<domain>` is the partner's registered domain (e.g., `acme`, `example-corp`).
- `<boundary_name>` is the specific boundary policy name.

**Do NOT suggest** the traditional IAM managed policy ARN format (`arn:aws:iam::<account-id>:policy/<name>`) for permission boundary conditions in temporary delegation templates. That format is for customer-managed policies, not partner-managed boundaries.

In parameterized templates, this ARN should appear as a **static, fully-qualified string** — not as a parameter. Example:
```
"iam:PermissionsBoundary": "arn:aws:iam::partner:policy/permission_boundary/acme.com/AcmeBoundary_2025_01_15"
```

Do NOT recommend `@{permissionBoundaryArn}` as a parameter for boundary conditions. The boundary ARN is known at registration time and should be hardcoded in the template for auditability.

### Unnecessary iam:CreatePolicy for boundary (Design Error)

If the delegation template includes `iam:CreatePolicy` with a resource targeting a boundary-like policy (e.g., `arn:aws:iam::@{AccountId}:policy/<BoundaryName>`), this is a design error. The partner does NOT need to create the boundary policy — IAM provisions it automatically from the registered bundle into customer accounts.

**Detection:** Look for `iam:CreatePolicy` in the template. Check if any of its resource ARNs reference a policy name that matches or resembles the boundary in the bundle. If so, flag as a design issue — the action is unnecessary and the boundary should reference the partner-managed namespace (`arn:aws:iam::partner:policy/permission_boundary/...`) instead.

**Severity:** medium (unnecessary permission that could also confuse the boundary enforcement model).

---

## Pattern 2: Allow-Overlap

Detect when a broad, unconditioned Allow statement neutralizes a narrower, conditioned one. IAM unions all Allow statements — if ANY Allow grants access without a condition, the condition on a different Allow for the same action is irrelevant.

### What to look for

- Statement A: `Action: "ec2:*"` or `Action: "ec2:*Instance*"` with NO conditions and `Resource: "*"`
- Statement B: `Action: "ec2:RunInstances"` with `aws:RequestTag` or `aws:ResourceTag` conditions

Statement A already grants `RunInstances` unconditionally. Statement B's conditions are dead code — they never deny anything because Statement A already allowed it.

### General rule

For each conditioned Allow statement, scan all other Allow statements for broader action patterns (`*` wildcards, action-prefix wildcards) that cover the same action WITHOUT the condition. If found, the condition is ineffective.

### Common manifestation

Partners add tighter statements during iteration without removing the original broad one. The result is a policy that *looks* tightened but isn't.

---

## Pattern 3: Multi-Resource Completeness

EC2 create actions evaluate against MULTIPLE resource ARNs in a single call. The action only succeeds if the policy allows EVERY resource involved.

| Action | Resources evaluated |
|--------|--------------------|
| `ec2:CreateSecurityGroup` | `security-group/*` AND `vpc/*` |
| `ec2:CreateNetworkInterface` | `network-interface/*` AND `subnet/*` AND `security-group/*` |
| `ec2:RunInstances` | `instance/*`, `image/*`, `security-group/*`, `subnet/*`, `network-interface/*`, `volume/*`, `key-pair/*`, `launch-template/*` (subset depending on params) |
| `ec2:AuthorizeSecurityGroupIngress/Egress` | `security-group/*` (and `security-group-rule/*` when tagging) |

**Detection:** For each EC2 create action, check that ALL required resource types are covered by the statement (or other statements). Flag missing ones.

**Critical subtlety:** `aws:RequestTag` conditions on referenced/pre-existing resources (VPC, subnet) ALWAYS FAIL because the tag is applied to the *new* resource, not the referenced one. Split referenced resources into a separate statement without the tag condition.

---

## Pattern 4: RequestTag vs ResourceTag Rules

| Condition key | Meaning | Use on |
|---|---|---|
| `aws:RequestTag/<key>` | "The tag is being applied right now in this request" | Actions that CREATE new resources and apply tags via `--tag-specifications` |
| `aws:ResourceTag/<key>` | "The resource already carries this tag" | Actions that OPERATE ON existing resources (delete, modify, describe-filtered) |

**Common errors:**
- Using `aws:RequestTag` on an action that operates on an existing resource → ALWAYS FAILS (tag is not in the request)
- Using `aws:RequestTag` on a referenced/customer-owned resource in a multi-resource create → ALWAYS FAILS (tag lands on the new resource, not the VPC/subnet)

---

## Pattern 5: Wildcard and Dangerous-API Flagging

### Dangerous APIs hidden in read wildcards

| Wildcard | Dangerous API it includes | Risk |
|----------|--------------------------|------|
| `ec2:Get*` | `ec2:GetPasswordData` | Retrieves decrypted Windows admin password |
| `iam:Get*` | `iam:GetCredentialReport` | Lists all IAM credentials in the account |
| `iam:Get*` | `iam:GetAccountAuthorizationDetails` | Full dump of all policies, roles, users |
| `iam:List*` | `iam:ListAccessKeys` | Enumerate all access keys per user |
| `iam:List*` | `iam:ListMFADevices` | Enumerate MFA devices (security posture) |

**Detection:** If the policy uses `ec2:Get*`, `iam:Get*`, or `iam:List*` wildcards, flag them specifically by naming the dangerous APIs they include. Don't just say "wildcard is broad" — name the specific risk.

### CreateTags escalation

`ec2:CreateTags` with broad resource scope (e.g. `arn:aws:ec2:*:*:*`) WITHOUT an `ec2:CreateAction` condition allows:
1. Tag any existing EC2 resource with the "managed" tag
2. Use a tag-scoped delete/modify permission to affect that resource

**Detection:** Find `ec2:CreateTags`. Check if it has an `ec2:CreateAction` condition. If not, check the resource scope — if it covers resource types beyond what the workflow creates, flag as escalation.

### Missing aws:TagKeys constraint

Any `iam:TagRole`, `ec2:CreateTags`, or similar tagging action should have `ForAllValues:StringEquals` on `aws:TagKeys` to restrict which keys can be set. Without it, the principal can add arbitrary tags.

---

## Pattern 6: Over-Broad Permissions

- `Resource: "*"` on WRITE actions without conditions — flag and suggest specific resource scoping or condition keys.
- `Action: "s3:*"`, `"iam:*"` — flag and suggest enumerating specific actions.
- `s3:Get*`, `s3:List*` — suggest enumerating the specific 10-30 APIs actually needed.

---

## Common Pitfalls Quick-Reference Table

| Pitfall | Category | What to flag |
|---------|----------|--------------|
| `AttachRolePolicy` without policy ARN or boundary condition | Escalation | Pattern 1 |
| `TagRole` in same SID as `CreateRole` with boundary condition | Semantics | TagRole does not support `iam:PermissionsBoundary` — split into separate SID |
| `Resource: "*"` on Lambda write actions | Scoping | Use `@{lambda_name}` parameter or function ARN |
| `PassRole` without `iam:PassedToService` condition | Scoping | Always restrict which service can assume the passed role |
| `ForAllValues:StringEquals` on `aws:TagKeys` without `Null` check | Semantics | Empty tag set passes condition (vacuous truth) — add `Null: {"aws:TagKeys": "false"}` |
| `ForAnyValue:StringEquals` on single-valued `aws:PrincipalTag/X` | Semantics | Does not provide OR logic for single-valued keys — use separate statements |
| `${aws:PrincipalTag/Prefix}*` in Resource without empty-value guard | Escalation | Empty tag → matches all resources for SNS/SQS |
| `sts:TagSession` granted without `aws:TagKeys` constraint | Escalation | Session tags can override role tags used in boundary scoping |
| `lambda:UpdateFunctionConfiguration` without `lambda:Layer` condition | Scoping | Allows attaching arbitrary layers |
| No explicit Deny in permission boundary | Design | Boundary can be circumvented by future identity policy changes |
| `ec2:CreateTags` without `ec2:CreateAction` condition | Escalation | Standalone tag-then-operate attack |
| Handshake ARN using receiver's org instead of sender's | Semantics | Handshake ARN always belongs to the initiating organization |
| `ListHandshakesForAccount` scoped to a resource ARN | Semantics | This action does not support resource-level permissions — must use `*` |
| SNS topic ARN pointing to dev/wrong account | Correctness | Verify account ID matches intended environment |
| Suggesting `@{...}` parameters in a permission boundary | Semantics | Boundaries are static, pre-registered policies — they do NOT support parameterization |
| Template includes `iam:CreatePolicy` for a boundary-like resource | Design | Partner does NOT create boundary policies — IAM provisions them automatically. Flag `iam:CreatePolicy` on resources like `arn:aws:iam::*:policy/<BoundaryName>` as unnecessary/incorrect |

---

## Constraints

When performing reviewer analysis:

1. Do NOT recommend condition keys that the SAR (`sar_context.json`) does not list for the action.
2. Do NOT recommend resource-level scoping for permission-only actions (empty `resource_types` in SAR).
3. Do NOT reason about statements in isolation — always consider cross-statement effects.
4. Do NOT re-litigate findings that are already proof-backed by Access Analyzer (Stages 1-2).
5. Do NOT emit findings without a before/after fix example when a concrete fix exists.
6. Every finding MUST include: severity, artifact reference, message, and verification state.
7. Do NOT suggest `@{...}` parameterized values in permission boundary fixes. Boundaries are **pre-registered static policies** managed by IAM — they are deployed ahead of time and cannot be modified or parameterized at delegation time. Only delegation templates support `@{...}` placeholder substitution. If a boundary has overly broad resource scoping (e.g., `Resource: "*"` or wildcards), the fix must use static values, AWS-native policy variables like `${aws:PrincipalAccount}`, `${aws:PrincipalTag/...}`, or accept the breadth as a known limitation — never suggest `@{PartnerAccountId}` or similar parameters in a boundary.
8. **Pattern-matching is necessary but not sufficient.** For every finding, you MUST reason about the complete attack path — not just whether a condition is missing, but whether the threat it guards against is actually achievable. Ask: "What sequence of actions would an attacker need to exploit this? Are ALL prerequisite actions available in this bundle (template + boundary combined)?" If the attack path requires an action that is NOT granted anywhere in the bundle, the threat cannot be realized by the delegation session. Do not emit findings for unreachable threats — a missing condition that guards against an impossible scenario is not a vulnerability, it is unnecessary defense. At most, note it as informational (`low`) with explicit acknowledgment that the path is unreachable.
