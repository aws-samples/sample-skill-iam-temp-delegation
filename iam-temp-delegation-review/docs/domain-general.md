---
name: domain-general
description: >-
  Review and harden IAM temporary delegation policy templates for AWS Partner
  integrations. Use when reviewing IAM policies for partner delegation,
  permissions boundaries, or policy templates that use temporary credentials
  in customer accounts.
keywords:
  - iam
  - temporary delegation
  - policy template
  - permissions boundary
  - partner integration
  - privilege escalation
load: always
---

# IAM Temporary Delegation Policy Review

## Overview

This skill provides guidance for reviewing and hardening IAM policy templates used with the AWS IAM Temporary Delegation feature for AWS Partners. These policies grant temporary permissions in customer AWS accounts and require careful scoping to prevent privilege escalation.

## Key Concepts

- **Policy Templates**: Define temporary permissions requested in customer accounts. Support parameterized values (e.g., `@{lambda_name}`, `@{account_id}`) that are resolved at request creation time — before the customer reviews and approves the rendered policy.
- **Permissions Boundaries**: Attached to IAM roles created by partners to cap effective permissions regardless of identity policies. Boundaries are **pre-registered static policies** — they are deployed and managed by IAM ahead of time and do NOT support `@{...}` parameterization. Any resource scoping in a boundary must use static ARNs, wildcards, or AWS policy variables (`${aws:...}`).
  - **The partner does NOT create the boundary policy.** IAM provisions the boundary automatically from the registered bundle into customer accounts using the `arn:aws:iam::partner:policy/permission_boundary/<domain>/<name>` namespace. If a template includes `iam:CreatePolicy` targeting a boundary-like resource (e.g., `arn:aws:iam::@{AccountId}:policy/<BoundaryName>`), this is a design error — the partner is trying to manually create what IAM already manages.
- **Temporary Delegation Flow**: See `domain-delegation-system.md` for the full end-to-end flow, execution model, and threat model.

### Artifact Relationship Model

**IMPORTANT**: The policy template and permissions boundary operate at **different IAM principal levels** and are NOT intersected:

1. The **policy template** defines what the partner's *temporary onboarding session* can do (e.g., create StackSets, create IAM roles, read Orgs).
2. The **permissions boundary** is attached to the *IAM role created by the onboarding session* (e.g., an integration role deployed into member accounts).

The template and boundary are **not applied to the same principal**. Actions in the template that don't appear in the boundary are NOT dead code — they are standalone permissions for the onboarding session. Only actions exercised by the *created role* are subject to the boundary intersection.

When reviewing, do NOT flag template actions as "dead code" simply because they are absent from the boundary. Only flag allow-overlap issues for actions that the *created role* would use (i.e., actions the boundary is meant to constrain).

## Review Checklist

### 1. Split IAM Actions by Condition Key Support

Not all IAM actions support the same condition keys. Split statements accordingly:

- **Write actions** that support `iam:PermissionsBoundary`: `CreateRole`, `PutRolePolicy`, `DeleteRolePolicy`, `AttachRolePolicy`, `DetachRolePolicy`
- **Actions where `iam:PermissionsBoundary` support should be SAR-verified**: `DeleteRole` (check `sar_context.json` before relying on it)
- **Read actions** that do NOT carry `iam:PermissionsBoundary` context: `GetRole`, `GetRolePolicy`, `ListAttachedRolePolicies`, `ListRolePolicies`
- **TagRole** does NOT support `iam:PermissionsBoundary` — isolate into its own statement with `aws:RequestTag` conditions

### 2. Enforce Permissions Boundary on Role Creation

When a policy template creates IAM roles in customer accounts, require the permissions boundary:

```json
"Condition": {
    "StringEquals": {
        "iam:PermissionsBoundary": "arn:aws:iam::partner:policy/permission_boundary/<domain>/<boundary_name>"
    }
}
```

**Important:** The `partner` in the ARN above is a **literal fixed string** — it is the ARN namespace used by the AWS Partner temporary delegation system. It is NOT a placeholder for an account ID. Do NOT substitute it with a 12-digit account number or use the traditional `arn:aws:iam::<account-id>:policy/<name>` format for partner-managed boundaries.

This applies to `CreateRole` and other write actions that support the condition key. The boundary is the safety net — even if arbitrary policies are attached, effective permissions are capped.

### 3. Scope AttachRolePolicy Appropriately

Two strategies (pick one or combine):

- **Policy ARN condition**: Use `iam:PolicyArn` with `ArnLike` to restrict which policies can be attached
- **Permissions boundary condition**: Use `iam:PermissionsBoundary` to only allow attach on roles that have a boundary set (boundary caps effective permissions regardless)

The permissions boundary approach is "I don't care what you attach, the boundary contains it." The policy ARN approach is more explicit.

### 4. Restrict TagRole with aws:RequestTag

Isolate `iam:TagRole` in its own SID and restrict to specific tag keys:

```json
{
    "Sid": "IAMRoleTagging",
    "Effect": "Allow",
    "Action": ["iam:TagRole"],
    "Resource": "arn:aws:iam::*:role/<Prefix>*",
    "Condition": {
        "StringEquals": {
            "aws:RequestTag/ManagedBy": "<PartnerName>"
        }
    }
}
```

### 5. Use Parameterized Values for Runtime Scoping

Policy templates support parameters rendered at request time:
- `@{lambda_name}` — scope to specific function approved by customer
- `@{account_id}` — reference the customer's account ID

Use these to narrow `Resource` fields instead of wildcards.

### 6. Lambda Layer Condition Key

`lambda:UpdateFunctionConfiguration` supports `lambda:Layer` condition key to restrict which layers can be attached:

```json
"Condition": {
    "ForAllValues:StringLike": {
        "lambda:Layer": [
            "arn:aws:lambda:*:<PARTNER_ACCOUNT>:layer:<prefix>-*:*",
            "arn:aws:lambda:*:@{account_id}:layer:*:*"
        ]
    }
}
```

This ensures only partner-published layers and customer-owned layers are allowed. Third-party layers are blocked.

**Note**: `ForAllValues:StringLike` evaluates to true on an empty set (no layers in request). This is acceptable for read actions or config-only updates.

### 7. SNS Topic Account Verification

Check that SNS resource ARNs reference the correct account (production vs development). Common mistake: using a dev account ID in a production policy template.

### 8. Resource Scoping Best Practices

- CloudFormation stacks: scope to specific stack name prefixes (e.g., `stack/PartnerIntegration*/*`)
- IAM roles/policies: scope to partner-prefixed names (e.g., `role/Partner*`, `policy/Partner*`)
- Lambda functions: use parameterized values over `function:*`
- EC2 describe actions: `Resource: "*"` is acceptable (read-only, no resource-level permissions)
- Lambda layers: `Resource: "*"` is acceptable (cross-account ARNs)

### 9. Permissions Boundary Design

A well-designed boundary should:
- Allow read-only actions for resource discovery (Describe*, Get*, List*)
- Include an explicit `Deny` statement for dangerous write operations (CreateRole, CreateUser, PutObject, UpdateFunctionCode, RunInstances, etc.)
- The Deny ensures protection even if the identity policy is modified after role creation

### 10. PassRole Conditions

Always scope `iam:PassRole` with:
- Resource restricted to partner-prefixed roles
- `iam:PassedToService` condition limiting which services can assume the role

```json
"Condition": {
    "StringEquals": {
        "iam:PassedToService": "cloudformation.amazonaws.com"
    }
}
```

## Common Pitfalls

| Issue | Risk | Fix |
|-------|------|-----|
| `AttachRolePolicy` without policy ARN or boundary condition | Privilege escalation — attach AdministratorAccess | Add `iam:PermissionsBoundary` or `iam:PolicyArn` condition |
| `TagRole` in same SID as `CreateRole` with boundary condition | TagRole fails (doesn't support boundary context) | Split into separate SID |
| `Resource: "*"` on Lambda functions | Modify any function in account | Use `@{lambda_name}` parameter |
| SNS topic pointing to dev account | Callbacks fail in production | Verify account ID matches environment |
| No explicit Deny in permissions boundary | Boundary can be circumvented by future policy changes | Add DenyWriteOperations statement |
| `lambda:UpdateFunctionConfiguration` without layer condition | Attach arbitrary layers | Add `lambda:Layer` with `ForAllValues:StringLike` |
