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

**Operator check:** If `iam:PolicyARN` is present, verify the condition operator is `ArnLike` (not `ArnEquals`). `ArnEquals` does NOT support wildcards — it treats `*` as a literal character. If the condition value contains wildcard patterns (e.g., `arn:aws:iam::*:policy/Splunk*`) but uses `ArnEquals`, the condition will silently never match, making the guard dead code. Flag as a functional bug.

### DetachRolePolicy / DeleteRolePolicy + re-attach

If the template grants both `DetachRolePolicy` (or `DeleteRolePolicy`) AND `AttachRolePolicy` on the same resource scope, the principal can remove a restricting policy and attach a permissive one.

### Cross-artifact PB-on-CreateRole check

If the delegation template grants `iam:CreateRole`:
1. Verify the statement has a `StringEquals` condition on `iam:PermissionsBoundary`.
2. If no boundary condition exists but `CreateRole` is granted → CRITICAL (roles created without a boundary have uncapped permissions).

> **Note:** Boundary ARN format validation, namespace correctness, domain/name consistency with metadata, and cross-statement ARN consistency are all handled by the deterministic gate. You do NOT need to re-check those here. Focus only on whether the boundary condition *exists* on CreateRole statements.

**Partner boundary ARN format (reference for recommendations):**
```
arn:aws:iam::partner:policy/permissions-boundary/<domain>/<boundary_name>
```

- `partner` is a **literal fixed string** (not a placeholder for an account ID). It is the ARN namespace used by the AWS Partner temporary delegation system.
- `<domain>` is the partner's registered domain (e.g., `acme`, `example-corp`).
- `<boundary_name>` is the specific boundary policy name.

When recommending fixes that involve boundary ARNs, always use the partner-managed namespace format above — NOT the traditional IAM managed policy ARN format (`arn:aws:iam::<account-id>:policy/<name>`). Do NOT recommend `@{permissionBoundaryArn}` as a parameter — the boundary ARN is known at registration time and should be hardcoded.

### Boundary ARN consistency across statements

> **Handled by deterministic gate.** The gate now detects multiple inconsistent boundary ARNs across statements and flags domain/name mismatches against metadata. You do NOT need to re-check this. If the gate passed without flagging boundary consistency issues, the boundary references are consistent.
>
> Focus your review on whether the *correct actions* are guarded by a boundary condition — not whether the ARN values themselves are correct.

### Unnecessary iam:CreatePolicy for boundary (Design Error)

If the delegation template includes `iam:CreatePolicy` with a resource targeting a boundary-like policy (e.g., `arn:aws:iam::@{AccountId}:policy/<BoundaryName>`), this is a design error. The partner does NOT need to create the boundary policy — IAM provisions it automatically from the registered bundle into customer accounts.

**Detection:** Look for `iam:CreatePolicy` in the template. Check if any of its resource ARNs reference a policy name that matches or resembles the boundary in the bundle. If so, flag as a design issue — the action is unnecessary and the boundary should reference the partner-managed namespace (`arn:aws:iam::partner:policy/permissions-boundary/...`) instead.

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

### SAR condition key inheritance caveat

SAR reports supported condition keys at the resource-type level, not the API-parameter level. When a resource type supports tags, ALL actions operating on that resource type inherit `aws:RequestTag/${TagKey}` and `aws:TagKeys` in SAR — regardless of whether the specific API call accepts tag input.

Practical impact:
- Create/purchase/tag actions typically accept tag input → RequestTag evaluates correctly.
- Modify/cancel/describe actions on the same resource type typically do NOT accept tag input → RequestTag is always null → StringEquals silently denies.

When grouping actions into "taggable" vs "untaggable" statements, or when recommending a RequestTag condition:
1. SAR confirms the condition key is valid syntax (policy won't be rejected) — necessary but not sufficient.
2. Confirm the API accepts tag input by checking the service's API reference for a tag parameter in the request schema.
3. If no tag parameter exists, the action belongs in an unconditioned statement (or conditioned on `aws:ResourceTag` if operating on an already-tagged resource).

This applies to ALL services, not just EC2. Examples: RDS modify/delete actions on taggable resources, ElastiCache modify actions, etc.

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

## Pattern 7: Cross-Artifact Resource Name Alignment

Detect mismatches between the resource name patterns the boundary expects to access and the resources the template can actually create/provision.

### Concept

The boundary grants the created role access to specific named resources (policies, roles, workgroups, buckets, etc.). For each named resource pattern in the boundary, determine its **provenance**:

1. **Created by this template** — the template has a corresponding create action with a resource scope that covers the name pattern. Names MUST align.
2. **Pre-existing customer resource** — the resource already exists in the customer account (e.g., VPCs, route tables, S3 buckets the customer owns). No creation needed; the boundary just grants access.
3. **Created by another mechanism** — another delegation template, CloudFormation stack, or manual setup creates it. Acceptable if documented.
4. **Unclear provenance** — cannot determine who creates this resource. Flag for clarification.

### Detection

1. Extract all resource ARN patterns from the boundary that include specific name prefixes/patterns (not just `*`).
2. For each, find the corresponding create/write action in the template.
3. Check if the template's `Resource` scope for that create action covers the boundary's name pattern.

### Examples

| Boundary references | Template creates | Verdict |
|---|---|---|
| `iam:GetPolicy` on `policy/SplunkFederation*` | `iam:CreatePolicy` on `policy/SplunkLinus*` | ❌ Mismatch — `SplunkFederation*` not creatable |
| `athena:StartQueryExecution` on `workgroup/LinusCWL*` | `athena:CreateWorkGroup` on `workgroup/LinusCWL*` | ✅ Aligned |
| `ec2:CreateRoute` on `route-table/*` | No route table create action | ✅ Pre-existing customer resource |
| `s3:GetObject` on `${aws:PrincipalTag/TargetBucket}` | No S3 create in template | ✅ Pre-existing customer bucket |
| `iam:GetRole` on `role/LinusDiscovery*` | `iam:CreateRole` on `role/@{DiscoverRole}` | ✅ Partner controls the name via parameter |

### Severity

- **Clear mismatch** (template clearly intended to create it but scope doesn't cover it): `medium`
- **Unclear provenance** (can't determine who creates the resource): `info` — ask the author to clarify intent
- **Pre-existing resource** (no create action needed): not a finding

### What NOT to flag

- Boundary resources that are clearly pre-existing customer infrastructure (VPCs, subnets, route tables, S3 buckets scoped by PrincipalTag)
- Resources where the template uses a parameter that the partner controls (e.g., `@{roleName}` can be set to any value at request time)
- Read-only actions in the boundary on resources the role itself doesn't create (e.g., monitoring role reading its own config)

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
| `ArnEquals` used with wildcard values in `iam:PolicyARN` condition | Functional | Condition is dead code — `ArnEquals` treats `*` as literal. Use `ArnLike` for wildcard patterns |
| Boundary references resource names the template cannot create | Design | Cross-check boundary name patterns against template create scopes. If provenance is unclear, emit `info` asking the author to clarify intent |

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
