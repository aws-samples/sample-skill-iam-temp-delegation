# Fixing Policies After Review

## When to use this

When the user asks to fix, update, or address findings in the reviewed policy. Load this reference when the user says things like "fix finding #2", "address the CreateRole issue", "update the template", or "apply the suggested fix."

## Working directory

Always edit files in the **registry artifacts directory** — never in the original source folder:

```
registry/artifacts/<partner>__<use_case>__v<N>/delegation_template.json
registry/artifacts/<partner>__<use_case>__v<N>/permission_boundary.json
```

The registry copy is the canonical version. The original source directory is irrelevant after intake.

## How to find the current version

Check the registry entry to determine the latest version number:

```
registry/entries/<partner>__<use_case>.json → count versions[]
```

The artifacts are at: `registry/artifacts/<partner>__<use_case>__v<N>/`

## Applying fixes

When fixing a finding:

1. Read the finding's `fix_before` and `fix_after` snippets (if provided in the review report)
2. Open the artifact file in the registry artifacts directory
3. Make the change
4. Verify the fix addresses the finding without introducing new issues

## Constraints when fixing

- **Do NOT remove `@{...}` placeholders** — these are resolved at delegation time by IAM
- **Do NOT add `@{...}` placeholders to permission boundaries** — boundaries are static, pre-registered policies
- **Do NOT change the policy `Version` field** unless there's a specific finding about it
- **Preserve `Sid` values** when splitting statements — add suffixes like `"TagOnly"`, `"WriteOnly"`, `"PassRoleOnly"`
- **When splitting a statement**, ensure all resource ARNs are distributed correctly to the new statements
- **When adding conditions**, verify the condition key is supported by the action (check `sar_context.json` in the artifacts directory)
- **The boundary uses the partner namespace** `arn:aws:iam::partner:policy/permission_boundary/...` — never suggest a traditional `arn:aws:iam::<account-id>:policy/...` format for boundary references

## After making fixes

Once a fix is applied, ask the user:

> "Fix applied. Would you like to re-run the review checks now, or address another finding first?"

- If the user wants to fix more findings → apply the next fix, ask again after each one
- If the user is ready to re-run → execute the review from Step 2:

```bash
.venv/bin/python <SKILL_DIR>/scripts/run_checks.py \
  "registry/artifacts/<partner>__<use_case>__v<N>/delegation_template.json" \
  "registry/artifacts/<partner>__<use_case>__v<N>/permission_boundary.json" \
  "<PARTNER>" "<USE_CASE>"
```

This creates a **new version** (v<N+1>) with the fixed artifacts copied fresh. The previous version is preserved for audit trail.

After `run_checks.py` passes, re-run the SAR prefetch and Stage 3-4 analysis on the new version if needed.

## Example workflow

1. User: "Fix finding #2 — split TagRole into its own statement"
2. Agent reads `registry/artifacts/acme-corp__monitoring__v1/delegation_template.json`
3. Agent edits the file (splits the statement, adds correct conditions)
4. Agent asks: "Fix applied. Would you like to re-run the review checks, or address another finding first?"
5. User: "Also fix finding #3"
6. Agent applies the second fix
7. Agent asks again: "Both fixes applied. Ready to re-run the review?"
8. User: "Yes, re-run"
9. Agent runs: `run_checks.py "registry/artifacts/acme-corp__monitoring__v1/delegation_template.json" ...`
10. New version v2 is created with the fixes
11. Agent re-runs SAR prefetch and Stage 3-4 if needed on v2
