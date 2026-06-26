---
name: iam-temp-delegation-review
description: Run the IAM temporary delegation review pipeline on a partner's policy bundle. Use when asked to review IAM delegation templates, permission boundaries, or partner onboarding policies. Runs deterministic checks and Access Analyzer proofs before any semantic analysis.
license: MIT-0
compatibility: Requires Python 3.9+, AWS credentials with access-analyzer:ValidatePolicy and access-analyzer:CheckAccessNotGranted permissions, and network access to AWS APIs.
metadata:
  author: amazon
  version: "1.0.0"
---

## Overview

This skill reviews IAM temporary delegation policy bundles (templates + boundaries) through a multi-stage pipeline. Stages are strictly gated — later stages do NOT run if earlier stages find critical issues.

## Gotchas

- Pattern-matching a missing condition key is not enough to emit a finding. You MUST reason about whether the attack path is actually achievable with the permissions granted in this bundle. If the threat requires an action not present in the bundle, the finding is noise — not a vulnerability.
- Do NOT infer bundle metadata (partner domain, template name) from policy file content. These are registration-specific values — always ask the user.
- `sar_context.json` is the single source of truth for condition key support. IAM silently ignores unsupported condition keys — they parse but never enforce. Never recommend a key not listed in SAR data.
- Permission boundaries are pre-registered static policies. They do NOT support `@{...}` parameterization. Only delegation templates support placeholders.
- `iam:TagRole` does NOT support the `iam:PermissionsBoundary` condition key, even though it seems logical. The reviewer will suggest it — the verifier must catch it.
- Permission-only actions (empty `resource_types` in SAR) cannot be resource-scoped. `Resource: "*"` is correct and cannot be narrowed.
- `aws:RequestTag` only applies during creation/tagging. Using it on describe/modify actions always fails silently.
- The `run_checks.py` script prints registry artifact paths. Steps 3.5+ must use those paths, not the original input paths.
- Partners do NOT need `iam:CreatePolicy` for boundaries — IAM provisions them automatically. Flag it as a design error.
- Allow-overlap (Pattern 2) requires service-awareness. A boundary with `*` in the account field only creates exploitable overlap for **cross-account-capable services** (S3, Lambda layers, KMS via grants, STS). For **account-local services** (CloudFormation, CloudWatch, EC2, DynamoDB, RDS, Secrets Manager, CodeBuild), the API physically cannot reach resources in another account — `*` account scope is cosmetic, not a vulnerability. Flag account-local overlaps as `low` hygiene findings, not `medium`/`high` security findings.

## Entry: Detect State and Route

Before starting any workflow, determine the user's intent and check for existing state.

### 1. Check existing state

Look for `registry/entries/*.json` in the workspace. If entries exist:
- Note the partner name(s), use case(s), latest version number, and status (`submitted`, `reviewed`, `packaged`)
- Check if a report exists at `registry/reports/<partner>__<use_case>__v<N>.md`
- Check if `sar_context.json` exists in the artifacts directory

Present what you find: "I found an existing review for **[partner]/[use_case]** at v[N] (status: **[status]**). Would you like to continue working on this, or start a fresh review?"

If no registry exists, proceed to Fresh Review.

### 2. Check the workspace for policy files

Scan the workspace for JSON files that look like IAM policies (contain `"Statement"`, `"Effect"`, `"Action"`). If found, present them as suggestions — but still require the user to confirm paths and provide registration-specific values (partner name, domain, template name).

### 3. Route to the appropriate workflow

Based on the user's request, route to one of:

| User intent | Signals | Route to |
|-------------|---------|----------|
| **Fresh Review** | "review this", "check this policy", new files with no registry | → Full Pipeline (Steps 0-6) |
| **Re-review** | "review again", "re-run", policies changed since last review | → Step 2 (uses existing registry entry, creates new version) |
| **Resume** | "continue", "pick up where I left off", or detected incomplete state | → Resume at the incomplete step (check registry + artifacts) |
| **Fix findings** | "fix finding #N", "apply the recommendation", "update the policy" | → Fix Workflow (load `references/procedure-fix.md`) |
| **Package / Submit** | "package", "submit", "finalize", "accept findings" | → Submission Workflow (load `references/procedure-submit.md`) |
| **Status / Discuss** | "what's the status", "explain finding #N", "tell me about..." | → Read registry entry + latest report, summarize or explain |

### Resume detection logic

If routing to **Resume**, determine where the previous run stopped:

| State found | Resume at |
|-------------|-----------|
| No registry entry | Fresh Review (Step 0) |
| Registry entry exists, no findings files | Step 2 (run checks) |
| `*__checks.json` exists with critical findings | Step 3 (gate failed — tell user what to fix) |
| `*__checks.json` exists, gate passed, no `sar_context.json` | Step 3.5 (SAR prefetch) |
| `sar_context.json` exists, no `*__review.json` | Step 4 (reviewer analysis) |
| `*__review.json` exists | Step 6 already done — offer to discuss, fix, or package |

---

## Progress Checklist

- [ ] Step 0: Environment bootstrapped (.venv exists, AWS credentials verified)
- [ ] Step 1: User provided all inputs (template, boundary, partner, use case, metadata)
- [ ] Step 2: Deterministic checks completed (run_checks.py)
- [ ] Step 3: Gate check passed (no critical findings)
- [ ] Step 3.5: SAR data pre-fetched and read into context
- [ ] Step 4: Reviewer analysis complete (all patterns checked)
- [ ] Step 5: Verifier falsification complete (all findings verified/unverified)
- [ ] Step 6: Findings saved and report rendered

## Full Pipeline (Fresh Review)

### Step 0: Bootstrap environment

First, determine this skill's installation directory — it is the directory containing this `SKILL.md` file. All script and doc paths below are relative to this directory. Assign it to `SKILL_DIR`.

Before running any scripts, check if a `.venv` directory exists at the workspace root. If it does not, create one and install dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r <SKILL_DIR>/requirements.txt
```

If `.venv` already exists, skip this step.

**Verify AWS credentials:** Run `aws sts get-caller-identity` to confirm valid AWS credentials are available. The pipeline requires credentials with `access-analyzer:ValidatePolicy` and `access-analyzer:CheckAccessNotGranted` permissions.

```bash
aws sts get-caller-identity
```

If this fails: stop and tell the user to configure AWS credentials before proceeding. The deterministic checks (Stage 2) require Access Analyzer API access.

### Step 1: Identify inputs

Ask the user for:
- Template file path(s)
- Boundary file path (or confirm none)
- Partner name
- Use case name
- Bundle metadata file path (`bundle_metadata.json`)

**STOP and wait for the user to respond before continuing.** Do NOT infer or guess these values from file contents.

If the user already has a `bundle_metadata.json`, use it as-is. Do NOT re-run `create_metadata.py` on an existing file — any validation errors will be caught and addressed in Step 2.

If the user does not have a `bundle_metadata.json`, you MUST ask them the following questions and wait for answers. Do NOT infer these values from policy file content — they are registration-specific fields that only the user knows:

1. What is the partner's registered domain? (e.g., "acme.com") — this is the domain registered in the IAM delegation system, not necessarily visible in the policy JSON
2. What is the name of the permission template? (e.g., "AcmeMonitoringDelegation") — this is a human-chosen registration name, not the filename
3. What does the template do? (brief description for the metadata record)
4. If a boundary is included: What is the boundary name? What does it do (description)?

**Do NOT proceed to run the metadata creation script until the user has provided answers to these questions.**

Then run the metadata creation script to generate a validated `bundle_metadata.json`:

```bash
.venv/bin/python <SKILL_DIR>/scripts/create_metadata.py "<TEMPLATE_DIR>" "<PARTNER_DOMAIN>" "<TEMPLATE_NAME>" "<TEMPLATE_DESCRIPTION>" "<BOUNDARY_NAME>" "<BOUNDARY_DESCRIPTION>"
```

If there is no boundary, omit the last two arguments. The script auto-appends today's date suffix (`_YYYY_MM_DD`) to the template and boundary names if not already present, validates against the schema, and writes the file.

### Step 2: Run deterministic checks (Stages 1-2)

Run this command from the workspace root (substitute the actual paths from Step 1):

```bash
.venv/bin/python <SKILL_DIR>/scripts/run_checks.py "<TEMPLATE_PATH>" "<BOUNDARY_PATH>" "<PARTNER>" "<USE_CASE>" "<METADATA_PATH>"
```

If there is no boundary, pass `none` as the boundary path:

```bash
.venv/bin/python <SKILL_DIR>/scripts/run_checks.py "partner_tests/example-partner/template.json" "none" "example-partner" "example_use_case"
```

The script:
- Copies input artifacts into `registry/artifacts/<partner>__<use_case>__v<N>/` (canonical versions)
- Runs gate validation and Access Analyzer provable checks
- Saves findings to `registry/findings/<partner>__<use_case>__v<N>__checks.json`
- Renders an initial report to `registry/reports/<partner>__<use_case>__v<N>.md`
- Prints a gate signal (`⛔ GATE` or `✅ GATE`)

#### Handling metadata validation errors

If `run_checks.py` fails due to metadata schema validation (e.g., template name or boundary name missing a date suffix), do NOT re-run `create_metadata.py` to regenerate the file. The user already provided a `bundle_metadata.json` — treat it as the source of truth.

Instead:
1. Read the specific validation error message from the script output.
2. Show the user the exact field(s) that failed and explain what the schema requires (e.g., names must end with `_YYYY_MM_DD`, `_YYYYMMDD`, or `_YYYY-MM-DD`).
3. Ask the user how they want to fix it — either:
   - You edit the specific field(s) in their existing `bundle_metadata.json`, or
   - They fix it themselves.
4. After the fix, re-run `run_checks.py` with the corrected metadata file.

**Never** overwrite a user-provided `bundle_metadata.json` by re-running `create_metadata.py` unless the user explicitly asks you to regenerate it from scratch.

### Step 3: Gate check — STOP if critical issues found

Read the script output. **Do NOT proceed to Step 4 if:**
- The pipeline hard-failed (invalid JSON, size limit, boundary placeholder misuse)
- Any `critical` finding exists from the `provable` stage

If stopped: tell the user what must be fixed. Do NOT perform semantic analysis on a policy that will change.

If no critical/hard-fail findings: proceed.

### Step 3.5: Pre-fetch SAR data (grounding for Stage 3-4)

Run the SAR pre-fetch script to get live, authoritative data from the AWS Service Authorization Reference for every action in the bundle. Use the **registry artifact paths** (printed by `run_checks.py` in Step 2):

```bash
.venv/bin/python <SKILL_DIR>/scripts/sar_prefetch.py "registry/artifacts/<partner>__<use_case>__v<N>/delegation_template.json" "registry/artifacts/<partner>__<use_case>__v<N>/permission_boundary.json"
```

If there is no boundary, omit the second argument:

```bash
.venv/bin/python <SKILL_DIR>/scripts/sar_prefetch.py "registry/artifacts/<partner>__<use_case>__v<N>/delegation_template.json"
```

This writes `sar_context.json` to the registry artifacts directory (same directory as the template). **Read this file before proceeding to Step 4.** It contains, for each action:
- `resource_types`: what resource ARNs the action can be scoped to (empty = permission-only, CANNOT be resource-scoped)
- `condition_keys`: which condition keys the action actually supports (DO NOT recommend keys not in this list)
- `properties`: flags like `is_write`, `is_permission_management`
- `not_found`: if true, the action cannot be scoped or conditioned beyond global keys

**CRITICAL RULE:** In Steps 4 and 5, when recommending a condition key or resource scope, you MUST cross-check against this SAR data. If the `sar_context.json` does not list a condition key for an action, DO NOT recommend it. Mark the finding `unverified` instead.

### Step 4: Reviewer analysis (Stage 3)

Read these reference documents before analyzing:
- `<SKILL_DIR>/docs/procedure-reviewer.md` — detection patterns, pitfalls table, and constraints
- The relevant domain docs in `<SKILL_DIR>/docs/`:
  - `domain-general.md` — always load
  - `domain-delegation-system.md` — always load (delegation platform execution model and threat model)
  - `domain-ec2-tag.md` — if `ec2:` actions present
  - `domain-billing-transfer.md` — if `organizations:` actions present
  - `domain-principaltag-boundary.md` — if bundle has a boundary
- The `sar_context.json` generated in Step 3.5

Analyze the full bundle for:
1. Cross-statement escalation chains (Pattern 1)
2. Allow-overlap (Pattern 2)
3. Multi-resource completeness (Pattern 3)
4. RequestTag vs ResourceTag misuse (Pattern 4)
5. Wildcard/dangerous-API exposure (Pattern 5)
6. Cross-artifact PB-on-CreateRole check (Pattern 1, cross-artifact section)

Before recommending any condition key or resource scope, **verify it exists in `sar_context.json`** for that action. If the action shows `not_found` or the key is not listed, do NOT recommend it.

**Self-check before proceeding to Step 5:** Review each finding you produced and discard any that fail these checks:
- Does the recommended condition key appear in `sar_context.json` for this action? If not → remove.
- If recommending resource scoping, does the action have non-empty `resource_types` in SAR? If empty → remove.
- Is the finding about a permission boundary and recommending `@{...}` parameters? If yes → remove (boundaries are static).
- Trace the attack path end-to-end: what preconditions must hold for the threat to materialize, and can those preconditions be achieved using only actions granted in this bundle? If the attack requires an action not present in the bundle → remove (unreachable threat).

Only pass findings that survive this self-check to the verifier.

### Step 5: Verifier (Stage 4)

Read `<SKILL_DIR>/docs/procedure-verifier.md` — the 5-step falsification procedure and common falsification targets.

For each Stage 3 finding, follow the verification procedure:
- If the recommended condition key IS listed in `sar_context.json` for the action → mark `verified`
- If the recommended condition key is NOT listed → mark `unverified` (needs human review)
- If the action has empty `resource_types` (permission-only) and a resource scope was recommended → mark `unverified` and note the action cannot be resource-scoped
- Structural findings (escalation chains, Allow-overlap): verify the actions and patterns exist as described → mark `verified` if sound

Never re-litigate proof-backed findings from Stage 2.

### Step 6: Save findings and render report

After completing Stage 3-4 analysis, write the findings as a structured JSON array to a temporary file, then run `save_findings.py` to persist them and regenerate the report.

**IMPORTANT:** Always run `save_findings.py` even if Stage 3-4 produced zero findings. Pass an empty array (`[]`) in the findings JSON file. This regenerates the report with a clean closing section confirming semantic analysis completed.

**Findings JSON format** — each finding is an object with these fields:
```json
[
  {
    "stage": "reviewer",
    "severity": "medium",
    "artifact_ref": "template.json (Statement 2)",
    "message": "Short description of the finding",
    "verification": "verified",
    "fix_before": "optional — JSON snippet showing current state",
    "fix_after": "optional — JSON snippet showing suggested fix"
  }
]
```

Field values:
- `stage`: `"reviewer"` or `"verifier"`
- `severity`: `"low"` | `"medium"` | `"high"` | `"critical"`
- `verification`: `"verified"` (SAR-confirmed) or `"unverified"` (needs human review)
- `fix_before` / `fix_after`: optional, include when a concrete fix can be shown

Write the file to the partner test directory (e.g. `partner_tests/example-partner/stage34_findings.json`), then run:

```bash
.venv/bin/python <SKILL_DIR>/scripts/save_findings.py "<PARTNER>" "<USE_CASE>" "<FINDINGS_JSON_PATH>"
```

Example:
```bash
.venv/bin/python <SKILL_DIR>/scripts/save_findings.py "example-partner" "example_use_case" "partner_tests/example-partner/stage34_findings.json"
```

If the script reports validation errors:
1. Read the error messages
2. Fix the findings JSON (correct missing fields, invalid severity values, malformed artifact_ref, etc.)
3. Re-run `save_findings.py`
4. Only proceed when the script completes without errors

This script:
1. Validates the findings JSON against the schema
2. Writes (overwrites) to `registry/findings/<partner>__<use_case>__v<N>__review.json`
3. Regenerates the full report from all findings in the store (always from scratch)
4. Updates the registry entry with recomputed counts

**Re-running is safe:** If you need to correct findings, update the JSON file and re-run `save_findings.py`. It overwrites the previous findings and regenerates a clean report — no duplicates, no accumulation.
**Cleanup:** After `save_findings.py` completes successfully, delete the temporary findings JSON file (e.g., `partner_tests/example-partner/stage34_findings.json`).

### Optional: Re-render report manually

If you need to regenerate the report without re-running analysis:

```bash
.venv/bin/python <SKILL_DIR>/scripts/render_report.py "<PARTNER>" "<USE_CASE>"
```

---

## End of Review

Your review is complete. **Do NOT proceed to submission packaging automatically.**

Present the user with their options:
1. **Discuss findings** — explain any finding in detail
2. **Fix findings** — edit the policy to address issues (load `references/procedure-fix.md`)
3. **Re-run** — if policies were changed, re-run from Step 2 (creates a new version)
4. **Package for submission** — when ready, run the submission workflow (load `references/procedure-submit.md`)

Wait for the user to choose. Route back to the Entry section's routing table based on their response.
