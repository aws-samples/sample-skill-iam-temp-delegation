---
name: domain-billing-transfer
description: >-
  Design and review least-privilege IAM temporary delegation policies for AWS
  Billing Transfer (responsibility transfer) flows. Use when scoping
  organizations:* handshake and responsibility-transfer actions, when a
  distributor orchestrates billing transfers across multiple AWS organizations
  (e.g. distributor -> partner/reseller -> customer), or when parameterizing
  IAM policy templates for temp delegation.
keywords:
  - billing transfer
  - iam temp delegation
  - aws organizations
  - handshake
  - responsibility transfer
  - least privilege
  - bill-source
  - bill-transfer
  - distributor
  - reseller
load: when organizations actions present
---

# AWS Billing Transfer — IAM Temp Delegation

Guidance for building and reviewing least-privilege IAM policies that get
temporarily delegated to perform AWS Billing Transfer onboarding actions.

## When to use this skill

- Reviewing or authoring IAM policies that use `organizations:*` actions for
  billing transfer (handshakes, responsibility transfers).
- A distributor/orchestrator (e.g., a large distributor) hands temporary credentials to a
  partner/reseller or customer to complete a billing transfer.
- You need to decide whether an action can be scoped to a resource ARN, or must
  remain `Resource: "*"`.

## Domain model (3-party billing transfer)

Billing Transfer lets one management account manage/pay another management
account's consolidated bill. It runs on top of the AWS Organizations
**handshake** mechanism (handshake type `transfer_responsibility`).

Roles (names vary, the pattern is what matters):

- **Distributor / Orchestrator** — owns the program, creates and delegates the
  temp IAM credentials. May also seed new payer accounts by converting one of
  its own linked accounts into a standalone org.
- **Bill-Transfer Account (sender / inviter)** — sends the billing transfer
  invitation; ends up managing and paying the bill. In a reseller model this is
  the Partner/Reseller.
- **Bill-Source Account (receiver)** — accepts the invitation; its consolidated
  bill is transferred away. In a reseller model this is the Customer (payer).

Flows:

1. **Onboard** — Sender invites → Receiver accepts → Sender pays the bill.
2. **Seed conversion** — A linked account leaves the distributor org, creates
   its own org, then accepts a transfer to become a new payer.

## The single most important rule: handshake ARN ownership

Handshake ARN format:

```
arn:${Partition}:organizations::${Account}:handshake/o-${OrganizationId}/${HandshakeType}/h-${HandshakeId}
```

`${Account}` and `o-${OrganizationId}` ALWAYS belong to the organization that
**initiated (sent)** the handshake — NOT the account that runs the action.

Consequence for scoping:

- A policy delegated to the **receiver** (the one calling `AcceptHandshake` /
  `DescribeHandshake`) must reference the **sender's** org id + management
  account id in the resource ARN.
- This is only possible to pre-populate when the orchestrator knows the sender's
  identity at delegation time (which is typical for distributor-run programs).

Verify in the `DescribeHandshake` API sample response: the `Arn` and the
`Parties[].Id` of type `ORGANIZATION` are the sender's org.

## Action scoping cheat-sheet (Service Authorization Reference)

Source of truth: `list_awsorganizations.html` in the Service Authorization
Reference. The "Resource types" column tells you if ARN scoping is possible.

| Action | Resource type | Scopable to ARN? | Notes |
|---|---|---|---|
| `organizations:AcceptHandshake` | `handshake*` | Yes | Scope to sender org ARN. No condition keys. |
| `organizations:DescribeHandshake` | `handshake*` | Yes | Scope to sender org ARN. No condition keys. |
| `organizations:ListHandshakesForAccount` | (none) | No — must use `*` | No condition keys. `HandshakeType` filter is API-request-level only, not IAM. |
| `organizations:DescribeResponsibilityTransfer` | `responsibilitytransfer*` | Yes | Supports `organizations:TransferType` + `TransferDirection` condition keys. |
| `organizations:InviteOrganizationToTransferResponsibility` | `account` | partial | Supports `organizations:TransferType` condition (`BILLING`). |
| `organizations:ListInbound/OutboundResponsibilityTransfers` | (none) | No — use `*` | Supports `organizations:TransferType` condition key. |
| `organizations:LeaveOrganization` | (none) | No — use `*` | Destructive / irreversible. |
| `organizations:CreateOrganization` | (none) | No — use `*` | Does NOT use `iam:AWSServiceName`; dependent action `iam:CreateServiceLinkedRole`. |
| `iam:CreateServiceLinkedRole` | n/a | condition | Scope with `iam:AWSServiceName = organizations.amazonaws.com`. |

Key API limitations to remember:

- There is **no IAM condition key** to restrict handshake actions to
  billing-only. `organizations:TransferType` applies to responsibility-transfer
  and invite actions, NOT to `AcceptHandshake` / `DescribeHandshake` /
  `ListHandshakesForAccount`.
- `ListHandshakesForAccount` can never be scoped — accept `Resource: "*"`.

## Review checklist

1. Identify who runs each policy and who initiated each handshake. The ARN uses
   the **initiator's** org, not the runner's.
2. Scope `AcceptHandshake` and `DescribeHandshake` to the sender's handshake ARN
   (`.../transfer_responsibility/h-*`) whenever the sender is known.
3. Keep `ListHandshakesForAccount` in its own statement on `Resource: "*"`.
   Don't bundle it with scopable actions or you lose the ability to scope them.
4. Split `organizations:CreateOrganization` and `iam:CreateServiceLinkedRole`
   into separate statements; the `iam:AWSServiceName` condition only applies to
   the SLR action.
5. Flag `LeaveOrganization` as destructive/irreversible; consider out-of-band
   confirmation before issuing the credentials.
6. Prefer tightening wildcards in ARNs (e.g. `o-*` -> `o-@{OrgId}`) when the
   orchestrator knows the value at delegation time.
7. Apply `organizations:TransferType = BILLING` condition on responsibility
   transfer and invite actions.

## Parameterization convention

Parameterize any value injected at delegation time (account IDs, org IDs) using
the `@{parameter_name}` format. Example scoped resource:

```json
"Resource": "arn:aws:organizations::@{PartnerMgmtAccountId}:handshake/o-@{PartnerOrgId}/transfer_responsibility/h-*"
```

Use `*/h-*` for the handshake-type segment only when the statement is for
general diagnostics that may need to describe non-billing handshakes; otherwise
pin it to `transfer_responsibility`.

## Authoritative references

- Service Authorization Reference — Actions, resources, condition keys for AWS
  Organizations:
  https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html
- DescribeHandshake API (shows ARN + Parties in sample response):
  https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeHandshake.html
- Transfer billing management to external accounts (AWS Billing):
  https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/orgs_transfer_billing.html
- Responding to invitations (minimum permissions, CLI flow):
  https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/orgs_transfer_billing-respond-invitation.html
