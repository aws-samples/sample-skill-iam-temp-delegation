#!/bin/bash
# Run the IAM delegation review skill on 5 test cases using claude -p.
# Produces review_findings.json for each test case in evals/results/<test-case>/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

TEST_CASES=(
  "arnequals-with-wildcard"
  "create-without-tags"
  "incompatible-resource-scope"
  "unscoped-dataplane-write"
  "unconditioned-role-creation"
)

cd "$REPO_ROOT"
mkdir -p "$RESULTS_DIR"

for tc in "${TEST_CASES[@]}"; do
  echo "=== Running: $tc ==="

  TC_DIR="evals/unit-tests/$tc"
  OUT_DIR="$RESULTS_DIR/$tc"
  mkdir -p "$OUT_DIR"

  # Determine boundary
  BOUNDARY="none"
  if [ -f "$TC_DIR/boundary.json" ]; then
    BOUNDARY="$TC_DIR/boundary.json"
  fi

  # Invoke the full skill via claude -p
  claude -p \
    --dangerously-skip-permissions \
    --model sonnet \
    --append-system-prompt "$(cat iam-temp-delegation-review/SKILL.md)" \
    "Review this IAM delegation template bundle:
- Template: $TC_DIR/permissions.json
- Boundary: $BOUNDARY
- Metadata: $TC_DIR/bundle_metadata.json
- Partner: unit-test
- Use case: $tc

Run the full pipeline (Steps 0-8). At the end, output the Stage 3-4 findings JSON array between markers:
---FINDINGS_JSON---
<json array here>
---END_FINDINGS---" \
    > "$OUT_DIR/raw_output.txt" 2>&1 || true

  # Extract findings JSON
  python3 -c "
import json, re, sys

with open('$OUT_DIR/raw_output.txt') as f:
    content = f.read()

# Try marker-delimited extraction
if '---FINDINGS_JSON---' in content:
    parts = content.split('---FINDINGS_JSON---')
    if len(parts) > 1:
        json_part = parts[1].split('---END_FINDINGS---')[0].strip()
        try:
            data = json.loads(json_part)
            json.dump(data, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
            sys.exit(0)
        except json.JSONDecodeError:
            pass

# Fallback: find any JSON array with finding-like objects
arrays = re.findall(r'\[[\s\S]*?\]', content)
for arr in arrays:
    try:
        data = json.loads(arr)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            if any(k in data[0] for k in ('severity', 'rule_code', 'stage', 'message')):
                json.dump(data, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
                sys.exit(0)
    except json.JSONDecodeError:
        continue

# Last fallback: check registry for review findings
import glob
review_files = glob.glob('evals/registry/findings/unit-test__${tc}__*__review.json')
if review_files:
    with open(sorted(review_files)[-1]) as f:
        data = json.load(f)
    json.dump(data, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
    sys.exit(0)

# Nothing found
json.dump([], open('$OUT_DIR/review_findings.json', 'w'))
"

  # Copy expected.json
  cp "$TC_DIR/expected.json" "$OUT_DIR/expected.json"

  echo "  Done: $OUT_DIR/review_findings.json"
  echo ""
done

echo "All test cases complete. Results in: $RESULTS_DIR/"
