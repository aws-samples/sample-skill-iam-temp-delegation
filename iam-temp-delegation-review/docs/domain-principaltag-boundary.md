---
name: domain-principaltag-boundary
description: >-
  Lessons learned and review guidance for IAM policies using aws:PrincipalTag
  variable substitution in permission boundaries for dynamic resource scoping.
keywords:
  - iam
  - permission boundary
  - principal tag
  - abac
  - s3
  - policy review
load: when boundary present in bundle
---

# IAM PrincipalTag Permission Boundary Review

Use this skill when reviewing or designing IAM policies that use `${aws:PrincipalTag/...}` policy variables in the `Resource` element of permission boundaries for dynamic scoping (S3, SNS, SQS, or similar).

---

## When to Recommend PrincipalTag Scoping

When reviewing a boundary, look for **data-plane actions granted on broad resources** (`Resource: "*"` or `arn:aws:s3:::*`). These are opportunities where PrincipalTag scoping in the boundary's Resource element could limit which specific resources the role accesses.

**Recommend PrincipalTag scoping when the boundary grants:**

| Action pattern | Risk without scoping | PrincipalTag opportunity |
|----------------|---------------------|--------------------------|
| `s3:GetObject`, `s3:PutObject`, `s3:ListBucket` on `*` | Role can read/write ANY bucket in the account | Scope to `${aws:PrincipalTag/TargetBucket}` |
| `sns:Publish`, `sns:Subscribe` on `*` | Role can publish to ANY topic | Scope to `${aws:PrincipalTag/TargetTopic}*` |
| `sqs:SendMessage`, `sqs:ReceiveMessage` on `*` | Role can access ANY queue | Scope to `${aws:PrincipalTag/TargetQueue}*` |
| `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:Query` on `*` | Role can read/write ANY table | Scope to `${aws:PrincipalTag/TargetTable}` |
| `kinesis:GetRecords`, `kinesis:PutRecord` on `*` | Role can access ANY stream | Scope to `${aws:PrincipalTag/TargetStream}` |

**Do NOT recommend PrincipalTag scoping for control-plane-only boundaries** — actions like `iam:CreateRole`, `cloudformation:CreateStack`, `organizations:AcceptHandshake` don't access customer data and are better scoped by resource ARN prefix or conditions.

**Key question to ask:** "Can the boundary limit *which* customer data resources the role touches, using a tag set at role creation time?" If yes → PrincipalTag scoping is appropriate.

---

## Key Findings (Empirically Validated)

### 1. PrincipalTag in Resource Elements Works

`${aws:PrincipalTag/TagKey}` resolves correctly in the `Resource` element of permission boundaries. IAM evaluates the tag value at request time and matches against the resolved ARN.

### 2. Wildcard Injection is NOT Possible

IAM tag values must match the regex `[\p{L}\p{Z}\p{N}_.:/=+\-@]*`. Characters `*` and `?` are **rejected by the IAM API** at tag-set time. This eliminates wildcard injection as a risk for policies using PrincipalTag in Resource ARNs.

### 3. Empty Tag Values Are Fail-Closed for S3

- `arn:aws:s3:::` (empty bucket name) does not match any real bucket
- `arn:aws:s3:::/*` (empty bucket + object wildcard) does not match any real objects
- Empty tag values produce unmatchable ARNs — no access granted

### 4. Absent Tags Are Fail-Closed

When a tag key does not exist on the role, `${aws:PrincipalTag/TagKey}` has no value. IAM treats Resource ARNs containing unresolved variables as unmatchable. No access is granted.

### 5. Empty Tag Values ARE Dangerous for Prefix-Based Patterns

For patterns like `arn:aws:sns:*:*:${aws:PrincipalTag/Prefix}*` or `arn:aws:sqs:*:*:${aws:PrincipalTag/Prefix}*`, an empty tag value produces `arn:aws:sns:*:*:*` which matches ALL resources. This is a **critical privilege escalation** for SNS/SQS but NOT for S3 (because S3 bucket ARNs don't use trailing wildcards at the bucket level).

### 6. Session Tags Override Role Tags

`aws:PrincipalTag` merges role tags and session tags. Session tags take precedence. There is NO IAM condition key to detect whether a PrincipalTag value came from a role tag or session tag.

- `aws:PrincipalSessionTagKeys` is NOT a valid condition key (confirmed by testing)
- The permission boundary CANNOT block session tag overrides
- Enforcement must happen in the trust policy by not granting `sts:TagSession`

### 7. sts:TagSession Must Be Explicitly Granted

`sts:TagSession` is a separate permissions-only action. It is NOT included in `sts:AssumeRole`. If the trust policy only grants `sts:AssumeRole` and a caller passes `--tags`, the entire AssumeRole call is rejected.

### 8. ForAnyValue:StringEquals Does NOT Work with Single-Valued PrincipalTag Keys

`ForAnyValue` is designed for multivalued condition keys (like `aws:TagKeys`). When used with single-valued keys like `aws:PrincipalTag/X`, it does NOT provide OR logic across keys. If you need "deny if ANY of these tag values is empty," you must use **separate Deny statements per tag key**.

### 9. ForAllValues:StringEquals with Empty Set Returns True

`ForAllValues:StringEquals` evaluates to true when the request set is empty (vacuous truth). Always pair with `Null: {"aws:TagKeys": "false"}` to require at least one tag in the request.

### 10. Multi-Slot Model (Multiple Tag Keys) Works

Using `TargetBucket1` through `TargetBucketN` in a single boundary is valid. Each slot resolves independently. Unused slots (absent tags) are unmatchable and safe.

---

## Review Checklist

When reviewing a permission boundary that uses PrincipalTag in Resource:

### Resource Element
- [ ] Does the policy use `${aws:PrincipalTag/...}` in the Resource element? → Confirm the tag key names are consistent between boundary, identity policy, and role tagging
- [ ] Does the Resource ARN include a trailing wildcard AFTER the variable (e.g., `${tag}*`)? → **HIGH RISK** for empty tag values (produces `arn:...:*` matching everything). Add Deny-on-empty or ensure tag value constraints
- [ ] Is `s3:ResourceAccount` condition present? → Prevents cross-account bucket access
- [ ] Are there multiple slots? → Verify all slots use the same pattern; absent slots are safe

### Tag Value Controls
- [ ] Who can set the tag values? → Check the permission template's `iam:TagRole` statement
- [ ] Is `aws:TagKeys` restricted with `ForAllValues:StringEquals`? → Only allowed keys should be settable
- [ ] Is `Null: {"aws:TagKeys": "false"}` present? → Prevents ForAllValues vacuous truth bypass
- [ ] Is wildcard injection a concern? → NO — IAM API rejects `*` and `?` in tag values
- [ ] Is empty string a concern? → For S3 bucket-level scoping: NO (fail-closed). For prefix-based patterns with trailing `*`: YES

### Trust Policy / Session Tags
- [ ] Does the trust policy grant `sts:TagSession`? → If yes, session tags can override role tags
- [ ] If `sts:TagSession` is granted, are the scoping tag keys excluded? → Use `ForAllValues:StringNotEquals` on `aws:TagKeys` to block the TargetBucket keys
- [ ] Is `sts:AssumeRole` the only action? → Safest configuration; no session tag override possible

### Tag Tampering Prevention
- [ ] Does the boundary include Deny on `iam:TagRole`, `iam:UntagRole`, `iam:UpdateAssumeRolePolicy`? → Prevents the assumed role from modifying its own tags or trust policy
- [ ] Does the permission template restrict which tag keys can be set? → Only bucket/scoping keys should be allowed

### Edge Cases
- [ ] What happens if the tag is removed entirely? → Fail-closed (unmatchable ARN) — safe
- [ ] What happens if the tag is set to empty string? → Depends on ARN pattern (see #3 and #5 above)
- [ ] Is role chaining possible? → If the boundary allows `sts:AssumeRole`, the role could chain to another role. Consider adding Deny on `sts:AssumeRole` if chaining is not needed
- [ ] Policy size? → Each tag slot adds ~120 chars to Resource. 6,144 char limit for managed policies. 5 slots ≈ 600 chars for Resource block

---

## Common Patterns

### Single-Bucket Boundary (Simplest)
```json
{
  "Resource": [
    "arn:aws:s3:::${aws:PrincipalTag/TargetBucket}",
    "arn:aws:s3:::${aws:PrincipalTag/TargetBucket}/*"
  ],
  "Condition": {
    "StringEquals": { "s3:ResourceAccount": "${aws:PrincipalAccount}" }
  }
}
```

### Multi-Bucket Boundary (N Slots)
```json
{
  "Resource": [
    "arn:aws:s3:::${aws:PrincipalTag/TargetBucket1}",
    "arn:aws:s3:::${aws:PrincipalTag/TargetBucket1}/*",
    "arn:aws:s3:::${aws:PrincipalTag/TargetBucket2}",
    "arn:aws:s3:::${aws:PrincipalTag/TargetBucket2}/*"
  ],
  "Condition": {
    "StringEquals": { "s3:ResourceAccount": "${aws:PrincipalAccount}" }
  }
}
```

### Permission Template (Tag Key Restriction)
```json
{
  "Action": "iam:TagRole",
  "Condition": {
    "ForAllValues:StringEquals": {
      "aws:TagKeys": ["TargetBucket1", "TargetBucket2", ...]
    },
    "Null": { "aws:TagKeys": "false" }
  }
}
```

### Trust Policy (No Session Tag Override)
```json
{
  "Action": "sts:AssumeRole",
  "Principal": { "AWS": "arn:aws:iam::PARTNER:root" }
}
```
No `sts:TagSession` statement = no session tag override risk.

---

## Anti-Patterns to Flag

| Anti-Pattern | Risk | Fix |
|---|---|---|
| `${aws:PrincipalTag/Prefix}*` in Resource without empty-value protection | Empty tag → matches all resources | Add per-slot Deny on empty, or don't use trailing wildcard |
| `sts:TagSession` granted without `aws:TagKeys` constraint | Session tag override bypasses boundary scoping | Remove `sts:TagSession` or constrain with `ForAllValues:StringNotEquals` |
| `ForAllValues:StringEquals` on `aws:TagKeys` without `Null` check | Empty tag set passes condition (vacuous truth) | Add `Null: {"aws:TagKeys": "false"}` |
| `ForAnyValue:StringEquals` on `aws:PrincipalTag/X` for OR logic | Does not work with single-valued keys | Use separate statements per key |
| `aws:PrincipalSessionTagKeys` in condition | Not a valid IAM condition key — condition is a no-op | Remove; enforce via trust policy instead |
| Permission boundary uses default value syntax `${tag, 'default'}` | Missing tag resolves to default instead of fail-closed | Never use defaults in boundary Resource elements |
| No `s3:ResourceAccount` condition | Cross-account bucket access possible if bucket policy allows | Add `StringEquals: {"s3:ResourceAccount": "${aws:PrincipalAccount}"}` |
