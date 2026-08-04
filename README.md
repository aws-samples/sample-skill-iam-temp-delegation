# IAM Temporary Delegation Review Skill

A security review pipeline for AWS IAM temporary delegation policy bundles used in partner integrations.

## Overview

This skill provides automated and AI-assisted analysis of IAM policy templates and permission boundaries to identify privilege escalation risks, misconfigurations, and opportunities for least-privilege hardening — before partners gain access to customer AWS accounts.

It runs a gated, multi-stage pipeline combining deterministic proof-backed checks with SAR-grounded semantic analysis. The agent manages a local registry that tracks versions, findings, and submission state across iterative reviews.

## Capabilities

| Capability | What it does |
|------------|--------------|
| **Fresh review** | Run the full pipeline (validation → Access Analyzer proofs → semantic analysis → verification) on a new policy bundle |
| **Re-review** | Re-run checks after policy edits; auto-creates a new version preserving the audit trail |
| **Resume** | Detect incomplete state in the registry and pick up where the last session left off |
| **Fix findings** | Edit policies in-place to address findings, then re-run selectively |
| **Package for submission** | Set dispositions (fixed/accepted), verify integrity, and produce a submission-ready bundle |
| **Discuss** | Explain any finding, summarize review status, or answer questions about the bundle |

## Pipeline Stages

The review runs four stages in order. Each stage gates the next — critical findings stop the pipeline until resolved.

1. **Gate (Stage 1)** — Syntax validation, size limits, structural checks, and metadata schema conformance
2. **Provable (Stage 2)** — AWS IAM Access Analyzer integration (`ValidatePolicy`, `CheckAccessNotGranted`, `CheckNoPublicAccess`) for proof-backed findings
3. **Reviewer (Stage 3)** — Semantic analysis using detection patterns: escalation chains, allow-overlap, multi-resource completeness, tag condition misuse, wildcard exposure
4. **Verifier (Stage 4)** — Falsification against live Service Authorization Reference (SAR) data to ensure every recommendation is actionable

## How It Works

```
User provides policy files
        │
        ▼
┌─────────────────────┐
│  Stage 1-2: Checks  │──── Gate fails? → Stop, show what to fix
│  (deterministic)    │
└─────────┬───────────┘
          │ gate passes
          ▼
┌─────────────────────┐
│  SAR Prefetch       │  ← Live data for grounding
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  Stage 3: Reviewer  │  ← Pattern-based semantic analysis
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  Stage 4: Verifier  │  ← Cross-checks against SAR
└─────────┬───────────┘
          ▼
   Findings + Report
          │
          ▼
  Fix → Re-review → Package
```

## Prerequisites

- Python 3.9+
- AWS credentials with `access-analyzer:ValidatePolicy`, `access-analyzer:CheckAccessNotGranted`, and `access-analyzer:CheckNoPublicAccess` permissions
- Dependencies installed automatically via `requirements.txt` (`boto3`, `botocore`, `httpx`)

## Quick Start

### 1. Install the skill

**Option A: Using the Skills CLI (recommended)**

```bash
npx skills add aws-samples/sample-skill-iam-temp-delegation
```

The CLI auto-detects your installed agents (Kiro, Claude Code, Cursor, etc.) and installs the skill to the appropriate location.

**Option B: Manual installation**

Clone into your IDE's skill directory:

```bash
# Kiro
git clone https://github.com/aws-samples/sample-skill-iam-temp-delegation.git .kiro/skills/iam-delegation-review

# Claude Code
git clone https://github.com/aws-samples/sample-skill-iam-temp-delegation.git .claude/skills/iam-delegation-review
```

### 2. Prepare your policy bundle

Place your IAM policy template, optional permission boundary, and bundle metadata in a directory:

```
partner-policies/
├── delegation_template.json        # Required — IAM policy template with @{...} placeholders
├── permission_boundary.json        # Optional — static permission boundary
└── bundle_metadata.json            # Optional — artifact names and descriptions
```

**One template per review.** Each IAM submission is atomic: one permission template + one optional boundary. Multiple templates require separate reviews.

**Bundle metadata** (`bundle_metadata.json`) provides registration names and descriptions:

```json
{
  "partner_domain": "acme.com",
  "template_name": "AcmeMonitoringDelegation_2026_06_19",
  "template_description": "Temporary delegation for read-only monitoring",
  "boundary_name": "AcmeMonitoringBoundary_2026_06_19",
  "boundary_description": "Caps monitoring role to read-only S3 and CloudWatch"
}
```

Names must end with a date suffix (`_YYYY_MM_DD`, `_YYYYMMDD`, or `_YYYY-MM-DD`). If you don't provide a metadata file, the agent will create one during the review.

### 3. Start a review

Ask the agent:

> "Review the IAM delegation template at partner-policies/delegation_template.json with boundary partner-policies/permission_boundary.json for partner Acme, use case monitoring"

The agent handles the full pipeline automatically — from environment setup through report generation.

### 4. Iterate on findings

After the review, you can:

- **Fix findings**: "Fix finding #2 — split TagRole into its own statement"
- **Re-run after edits**: "Re-run the review" (creates a new version)
- **Discuss**: "Explain finding #3" or "What's the current status?"
- **Resume later**: "Continue the review" (the agent detects where it left off)

### 5. Package for submission

When findings are resolved:

> "Package this for IAM submission"

The agent sets dispositions, verifies integrity hashes, and produces a submission bundle containing the final artifacts, report, accepted findings with justifications, and integrity proofs.

## Registry Structure

The skill maintains a local registry for version tracking and audit:

```
registry/
├── entries/         # Version history and status per partner/use_case
├── artifacts/       # Canonical copies of reviewed files (per version)
├── findings/        # Structured findings from each stage (per version)
├── reports/         # Human-readable Markdown reports (per version)
├── integrity/       # SHA-256 hashes for tamper detection
└── submissions/     # Packaged submission bundles
```

Each re-run creates a new version (v1, v2, v3...) — previous versions are preserved for audit trail.

## Detection Patterns

The reviewer (Stage 3) checks for:

1. **Cross-statement escalation chains** — e.g., CreateRole without boundary enforcement + PassRole
2. **Allow-overlap** — Unconditioned Allow neutralizing conditioned statements
3. **Multi-resource completeness** — Missing resource types in EC2 multi-resource evaluations
4. **RequestTag vs ResourceTag misuse** — Tag conditions applied to wrong action types
5. **Wildcard / dangerous-API exposure** — Overly broad permissions or hidden dangerous APIs
6. **CreateTags escalation** — Standalone tagging used to bypass tag-based access controls

All recommendations are verified against live SAR data before being reported.

## Domain Coverage

- EC2 tag-based access control
- Organizations billing transfer workflows
- PrincipalTag-based permission boundaries
- IAM role creation and permission management
- General delegation system threat model

## Evaluations

The skill includes a test suite with 27 unit tests and 5 functional tests to validate detection accuracy. Tests are evaluated using DeepEval with LLM-judged metrics (detection, severity, precision, recall, message quality) and a CI gate for pass/fail decisions.

See [evals/README.md](evals/README.md) for setup, running tests, and adding new test cases.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

