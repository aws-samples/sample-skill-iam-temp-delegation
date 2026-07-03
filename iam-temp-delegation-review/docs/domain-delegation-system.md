---
name: domain-delegation-system
description: >-
  How the IAM temporary delegation platform works end-to-end: execution model,
  parameter resolution, permission boundaries, and threat model. Always load
  alongside domain-general.md before reviewer analysis.
keywords:
  - delegation system
  - execution model
  - freeform session
  - parameter resolution
  - threat model
  - credential lifecycle
load: always
---

# Delegation System Context

Reference for understanding how IAM temporary delegation works at the platform level. **Always load this document** alongside `domain-general.md` before performing reviewer analysis.

---

## How the Delegation System Works

### End-to-End Flow

1. **Partner registers** a policy template (and optionally a permission boundary) with AWS during onboarding. AWS assigns each a unique ARN.
2. **Partner creates a delegation request** (`CreateDelegationRequest` API) — specifying the template ARN and parameter values (bucket names, account IDs, role prefixes, etc.).
3. **AWS renders the final policy** by substituting parameters into the template. The rendered policy has a 2048-character limit.
4. **Customer reviews the rendered policy** in the AWS Console — they see exactly what permissions will be granted, with all parameters resolved.
5. **Customer approves** and releases an exchange token (sent to the partner via SNS).
6. **Partner exchanges the token** for temporary AWS credentials (`GetDelegatedAccessToken` API).
7. **Partner uses credentials** to call AWS APIs directly — any action allowed by the rendered policy, in any order, with any valid arguments.
8. **Credentials expire** after the approved duration (max 12 hours). Any IAM roles created persist.

### Key Facts

- **Maximum credential duration:** 12 hours (4 hours if approved by root user)
- **Rendered policy size limit:** 2048 characters
- **All activity is logged** via AWS CloudTrail in the customer's account

---

## Execution Model: Freeform Capability Grant

The temporary delegation session is **freeform, not orchestrated**. Once the partner receives credentials:

- They can call **any action** the rendered policy allows
- They can call actions **in any order**
- They can use **any valid arguments** the policy permits (not just the "intended" parameters)
- There is **no platform-level enforcement** of a specific workflow or action sequence
- The **IAM policy is the sole enforcement mechanism** — nothing above it restricts what the partner does

This means: if the rendered policy allows `iam:TagRole` on `Resource: "arn:aws:iam::*:role/PartnerPrefix*"` without a tag-value condition, the partner CAN set any tag value — not just the one they "intended" during template design. The policy is what constrains them, not a workflow script.

**Implication for reviews:** Analyze the policy as a capability grant. Ask "what CAN this principal do?" — not "what WILL they do in the happy path?"

---

## Parameter Resolution

Parameters (`@{bucketName}`, `@{accountId}`, etc.) are:

- **Partner-provided** — the partner chooses values when calling `CreateDelegationRequest`
- **Resolved before approval** — AWS substitutes them into the template to produce the rendered policy
- **Visible to the customer** — the customer approves the final rendered policy with all values filled in
- **Not runtime-variable** — once the policy is rendered and approved, it is fixed for the session duration

Parameters support two types:
- `String` — single value, direct substitution
- `StringList` — multiple values, expands to multiple Resource entries (cross-product with other parameters)

Templates also support `@Enabled` directives for conditional statement inclusion based on parameter values.

**What this means for reviews:** Parameters narrow the policy scope at request time. They do NOT constrain what the partner does within that scope after credentials are issued. Review the rendered policy (after substitution) as a standard IAM policy — the parameters are already resolved.

---

## Permission Boundaries in Delegation

- **Immutable** — once registered, a boundary cannot be modified. Updates require registering a new version with a new date suffix.
- **Global** — the same boundary is shared across all customers. It cannot be per-customer.
- **Not templated** — boundaries do NOT support `@{...}` parameter substitution.
- **Partner-managed namespace** — boundaries use `arn:aws:iam::partner:policy/permissions-boundary/<domain>/<name>` (where `partner` is a literal fixed string, not an account ID).
- **IAM-provisioned** — the partner does NOT create the boundary in customer accounts. IAM provisions it automatically.
- **Applied to created roles** — the boundary is attached to IAM roles the partner creates during the session. It caps the role's effective permissions regardless of identity policies.

**The boundary does NOT apply to the temporary session itself.** Only the rendered policy template constrains the onboarding session. The boundary constrains the long-lived role the session creates.

---

## Threat Model for Reviews

### Threat Actors (in priority order)

| Threat | Description | Likelihood | Detection |
|--------|-------------|------------|-----------|
| **Compromised partner credentials** | Attacker gains access to the partner's system and exercises all granted permissions | Medium | CloudTrail logs all actions; anomalous patterns may be detected |
| **Partner misconfiguration** | Honest mistake in template design grants broader access than intended | High (common) | Review catches these proactively |
| **Malicious partner** | Partner deliberately abuses granted access against customer interests | Low | CloudTrail audit, contractual liability, ISV Accelerate membership at risk |

### Severity Calibration

When rating findings, consider the exploitation scenario:

| Scenario | Severity adjustment |
|----------|-------------------|
| Exploitable through normal operation or any granted action (no multi-step abuse required) | Rate at face value |
| Requires combining multiple actions in a specific sequence that deviates from the stated use case | Rate at face value (session is freeform — any sequence is valid) |
| Requires the partner to operate outside their rendered policy scope | Not possible — the IAM policy prevents this. Not a valid finding. |
| Requires a precondition that no action in the bundle can achieve (e.g., boundary removal without `DeleteRolePermissionsBoundary`) | Unreachable threat — do not emit, or emit as informational only |
| Defense-in-depth against a scenario where another principal (not this session) misconfigures the account in the future | Rate as `low` — valid hardening suggestion, but the threat is external to this bundle |

### What the Review DOES and DOES NOT Cover

**The review covers:**
- What the temporary session can do (rendered policy analysis)
- Whether the created role's boundary effectively caps permissions
- Whether the template grants more capability than the stated use case requires
- Cross-statement escalation paths achievable within the bundle

**The review does NOT cover:**
- Whether the partner's backend systems are secure (credential storage, rotation)
- Whether the partner's workflow logic follows the intended sequence
- Customer-side misconfiguration after the delegation completes
- Actions by other principals in the account that could weaken the setup later

---

## Impact on Review Approach

1. **The freeform model means all findings about "what if the partner calls X with argument Y" are valid** — as long as the policy allows it. Do not dismiss findings because "the partner wouldn't normally do that."

2. **BUT: assess whether the finding represents actual damage or just theoretical capability.** A partner CAN tag a role with any value if the policy lacks a tag-value condition. Whether that actually leads to privilege escalation depends on whether other policies reference that tag for authorization decisions.

3. **Boundary findings should focus on whether the boundary effectively caps the created role** — not on whether the onboarding session can bypass it (the boundary doesn't apply to the session).

4. **Defense-in-depth findings are valid but lower severity** when the precondition requires actions outside this bundle or future account changes by other principals.
