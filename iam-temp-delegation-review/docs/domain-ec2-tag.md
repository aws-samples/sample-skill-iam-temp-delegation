---
name: domain-ec2-tag
description: >-
  Analyze and troubleshoot EC2 IAM policies that use tag-based access control
  (aws:RequestTag / aws:ResourceTag). Use when a CreateSecurityGroup,
  CreateNetworkInterface, or similar EC2 call fails with UnauthorizedOperation,
  when reviewing tag-scoped EC2 policies for correctness, or when designing
  least-privilege policies for workflows that create tagged networking resources.
keywords:
  - ec2
  - tag-based access control
  - aws:RequestTag
  - aws:ResourceTag
  - CreateSecurityGroup
  - CreateNetworkInterface
  - multi-resource evaluation
load: when ec2 actions present
---

# EC2 IAM Tag-Based Policy Analysis

This skill captures lessons from troubleshooting EC2 IAM policies that gate access
with resource tags. It covers the most common failure mode (multi-resource permission
evaluation), how to separate request-tag vs resource-tag conditions, how to safely
scope tagging permissions, and how to reproduce and verify a fix end-to-end.

## Core Concept: EC2 Actions Evaluate Against Multiple Resources

Many EC2 create actions are authorized against MORE than one resource ARN in a single
call. The action only succeeds if the policy allows EVERY resource involved.

| Action | Resources evaluated |
|--------|--------------------|
| `CreateSecurityGroup` | the new `security-group/*` AND the `vpc/*` it lives in |
| `CreateNetworkInterface` | the new `network-interface/*` AND the `subnet/*` AND any referenced `security-group/*` |
| `AuthorizeSecurityGroupIngress/Egress` | the `security-group/*` (and `security-group-rule/*` when tagging rules) |

### The classic failure

A policy applies `aws:RequestTag/ManagedService: true` to ALL resources in a create
statement. The request tag (from `--tag-specifications`) only lands on the NEW resource
being created — never on the pre-existing VPC/subnet/SG being referenced. So the
condition fails when evaluated against those customer-owned resources, producing:

```
UnauthorizedOperation ... not authorized to perform: ec2:CreateSecurityGroup
on resource: arn:aws:ec2:...:vpc/vpc-xxxx because no identity-based policy allows ...
```

The fix is to split the referenced (customer-owned) resources into their own statement
WITHOUT the tag condition, and keep the tag condition only on the resource that actually
receives the tag.

## The Three-Category Pattern

Separate create-action permissions into three intent-based buckets:

1. **Using customer-owned / pre-existing resources** — VPCs, subnets, existing SGs that
   are only referenced, not tagged. No tag condition (or condition on the resource's own
   tag if you want to restrict which VPCs are usable).

2. **Creating new managed resources** — ENIs, SGs, SG rules that receive the tag via
   `--tag-specifications`. Gate with `aws:RequestTag/<key>: <value>`.

3. **Operating on existing managed resources** — delete, modify rules, grant ENI
   permission. The tag is already on the resource, so gate with
   `aws:ResourceTag/<key>: <value>` (NOT RequestTag).

> Rule of thumb: `aws:RequestTag` = "the tag is being applied right now in this request."
> `aws:ResourceTag` = "the resource already carries this tag."
> Using RequestTag on an action that operates on an existing resource will always fail.

## Securing `ec2:CreateTags`

`CreateTags` is a privilege-escalation hotspot when tags drive access control. Watch for:

- **Overly broad resource scope** like `arn:aws:ec2:*:*:*`. This lets the principal tag
  ANY EC2 resource type (instances, volumes, AMIs). Scope to only the resource types the
  workflow creates (e.g. `network-interface/*`, `security-group/*`, `security-group-rule/*`).

- **Missing `ec2:CreateAction` condition.** Without it, `CreateTags` can be called
  standalone on existing resources. Combined with a tag-gated delete/modify statement, a
  principal could tag an unrelated resource with the magic tag and then delete/modify it.
  Lock tagging to creation time:

  ```json
  "Condition": {
    "ForAllValues:StringEquals": { "aws:TagKeys": ["ManagedService", "Name", "WorkflowId"] },
    "StringEquals": { "ec2:CreateAction": ["CreateNetworkInterface", "CreateSecurityGroup"] }
  }
  ```

- If the workflow genuinely needs to re-tag AFTER creation, drop `ec2:CreateAction` but
  add `aws:ResourceTag/<key>: <value>` so only already-managed resources can be re-tagged.

- Always restrict `aws:TagKeys` with `ForAllValues:StringEquals` so the principal cannot
  add arbitrary tag keys.

## Review Checklist

When reviewing a tag-scoped EC2 policy, verify:

- [ ] Every multi-resource create action allows ALL referenced resources (esp. `vpc/*`, `subnet/*`).
- [ ] Referenced/customer-owned resources are NOT gated by `aws:RequestTag`.
- [ ] Create-of-new-resource statements use `aws:RequestTag`.
- [ ] Delete/modify/permission statements use `aws:ResourceTag`, not `aws:RequestTag`.
- [ ] `CreateTags` resource scope is limited to needed resource types (no `*:*:*`).
- [ ] `CreateTags` is locked with `ec2:CreateAction` OR `aws:ResourceTag` (not wide open).
- [ ] `aws:TagKeys` is constrained with `ForAllValues:StringEquals`.
- [ ] Unconditioned "use existing resource" statements (e.g. any VPC/subnet) are an
      intentional trade-off; consider scoping to specific ARNs or a VPC tag if the
      workflow should be confined to designated VPCs.

## Reproduce & Verify a Fix (end-to-end)

Use a least-privilege test role + assume-role rather than touching the real principal.
See `test_scenario.md` in this project for the full worked example. Summary:

1. `aws iam create-policy --policy-name <test> --policy-document file://<policy>.json`
2. `aws iam create-role` with a trust policy allowing your own account to assume it.
3. `aws iam attach-role-policy` then `sleep 10-15` for IAM propagation.
4. `aws sts assume-role` and export the temp creds.
5. Run the failing CLI command (e.g. `aws ec2 create-security-group --vpc-id ... --tag-specifications ...`) to confirm the repro.
6. Update the policy (`create-policy-version --set-as-default`), wait for propagation, re-assume, retry.
7. Test BOTH the positive case (tagged create succeeds) AND the negative case (untagged create is denied) to confirm the guardrail still holds. Also exercise delete on a tagged resource.
8. Clean up: delete SGs, detach policy, delete role, delete non-default policy versions, delete policy. Unset temp creds and remove any temp credential files.

### Decoding authorization failures

When you hit `UnauthorizedOperation` with an encoded message, decode it to see exactly
which resource and condition failed:

```bash
aws sts decode-authorization-message --encoded-message <blob> --query DecodedMessage --output text | jq .
```

Look at `context.action`, `context.resource`, and the `conditions` block. If the failing
`resource` is a VPC/subnet/SG you're only referencing (not creating), you've hit the
multi-resource evaluation problem described above.

## Safety Notes

- Prefer ReadOnly/least-privilege creds; only use Admin when role/policy creation requires it.
- Never disable safeguards or delete production resources without explicit confirmation.
- Test with disposable IAM roles, not the live workflow principal.
- Never echo or persist secret credential values; clean up temp credential files after testing.
