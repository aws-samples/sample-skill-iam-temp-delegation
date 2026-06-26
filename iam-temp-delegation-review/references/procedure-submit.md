# Submission Packaging Workflow

## When to use this

Only when the user explicitly asks to **package**, **submit**, or **finalize** a reviewed bundle for IAM registration. Do NOT run this as part of a review — reviews end at Step 6.

## Prerequisites

- A completed review exists in the registry (Steps 0-6 already ran via the main skill)
- The partner has addressed findings (fixed in policy or accepted with justification)
- The user is ready to produce the final submission bundle

---

## Step 1: Confirm version to submit

The submission packages artifacts from the registry. Confirm with the user:
- **Which version to submit?** (default: latest). Check `registry/entries/<partner>__<use_case>.json` for available versions.
- **Were fixes applied?** If the user fixed policies after the last review, those fixes should have been re-run through `run_checks.py` (which creates a new version). Confirm the latest version contains the corrected artifacts.

The artifacts being submitted are at:
```
registry/artifacts/<partner>__<use_case>__v<N>/delegation_template.json
registry/artifacts/<partner>__<use_case>__v<N>/permission_boundary.json
```

If the user says they made fixes but didn't re-run the review, read `references/procedure-fix.md` and guide them through re-running first.

## Step 2: Set dispositions on findings

For each finding in the latest review, determine its resolution:

### disposition: "fixed"

Use when the finding was addressed in the corrected policy. The issue no longer exists in the artifact being submitted.

```json
{
  "disposition": "fixed"
}
```

### disposition: "accepted"

Use when the finding represents an intentional design choice or known limitation. Requires a justification explaining why the risk is acceptable.

```json
{
  "disposition": "accepted",
  "justification": "AcceptHandshake cannot be resource-scoped beyond handshake type. The boundary intentionally allows all handshake operations as this role is specifically for billing transfer acceptance."
}
```

### Rules

- **All Stage 3-4 findings must have a disposition** — any finding without one blocks packaging
- Stage 1-2 findings (gate, provable) do NOT require disposition — they are informational
- `"justification"` is required when disposition is `"accepted"`
- If a finding was fixed by removing the problematic code, you can either set `"disposition": "fixed"` or remove the finding from the JSON entirely — both are valid

### Persist dispositions

Update the findings JSON with dispositions and run:

```bash
.venv/bin/python <SKILL_DIR>/scripts/save_findings.py "<PARTNER>" "<USE_CASE>" "<FINDINGS_JSON_PATH>"
```

This overwrites the review findings and regenerates the report showing dispositions.

## Step 3: Package the submission

Run `package_submission.py` — it reads artifacts directly from the registry:

```bash
.venv/bin/python <SKILL_DIR>/scripts/package_submission.py "<PARTNER>" "<USE_CASE>"
```

To package a specific version (not the latest):

```bash
.venv/bin/python <SKILL_DIR>/scripts/package_submission.py "<PARTNER>" "<USE_CASE>" <VERSION_NUMBER>
```

Example:
```bash
.venv/bin/python <SKILL_DIR>/scripts/package_submission.py "acme-corp" "monitoring"
```

### What the script does

1. **Verifies integrity** — SHA-256 hashes of findings files match what was recorded (files not hand-edited since the pipeline wrote them)
2. **Checks dispositions** — All Stage 3-4 findings must be resolved (accepted or fixed)
3. **Packages the bundle** to `registry/submissions/<partner>__<use_case>__v<N>/`

### If integrity check fails

This means a findings file was hand-edited outside of `save_findings.py`. To fix:
- Re-run `save_findings.py` with the corrected findings JSON (this records fresh hashes)
- Then re-run `package_submission.py`

### If disposition check fails

The script prints which findings are still open. Go back to Step 2 and add dispositions.

## Step 4: Confirm output

The submission bundle is written to `registry/submissions/<partner>__<use_case>__v<N>/` and contains:

| File | Purpose |
|------|---------|
| `manifest.json` | Metadata: partner, version, findings summary, artifact references |
| `delegation_template.json` | The final policy template as-is (with `@{...}` placeholders) |
| `permission_boundary.json` | The final boundary (if applicable) |
| `review_report.md` | Complete findings report showing all stages + dispositions |
| `accepted_findings.json` | Only the findings with `"disposition": "accepted"` + justifications |
| `integrity.json` | SHA-256 hashes of all artifacts for audit verification |

Show the user:
- The submission directory path
- Number of accepted findings (with brief summary)
- Confirmation that integrity checks passed

The bundle is ready for IAM registration.
