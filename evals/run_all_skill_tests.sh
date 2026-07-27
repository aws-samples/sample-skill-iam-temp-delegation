#!/bin/bash
# Run the IAM delegation review skill on ALL unit test cases using claude -p.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

cd "$REPO_ROOT"

for TC_DIR in evals/unit-tests/*/; do
  tc=$(basename "$TC_DIR")
  OUT_DIR="$RESULTS_DIR/$tc"

  # Skip if already has review_findings.json
  if [ -f "$OUT_DIR/review_findings.json" ] && [ -s "$OUT_DIR/review_findings.json" ]; then
    echo "SKIP (already done): $tc"
    continue
  fi

  echo "=== Running: $tc ==="
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
    "Read iam-temp-delegation-review/SKILL.md. Review this IAM delegation template bundle:
- Template: ${TC_DIR}permissions.json
- Boundary: $BOUNDARY
- Metadata: ${TC_DIR}bundle_metadata.json
- Partner: unit-test
- Use case: $tc

Run the full pipeline (Steps 0-8). After completing analysis, output the final Stage 3-4 findings as a JSON array." \
    > "$OUT_DIR/raw_output.txt" 2>&1 || true

  # Extract findings JSON from output
  python3 -c "
import json, re, sys, glob

with open('$OUT_DIR/raw_output.txt') as f:
    content = f.read()

# Try markdown code block extraction
match = re.search(r'\`\`\`json\s*(\[[\s\S]*?\])\s*\`\`\`', content)
if match:
    try:
        data = json.loads(match.group(1))
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

# Fallback: check registry for review findings
review_files = glob.glob('evals/registry/findings/unit-test__${tc}__*__review.json')
if review_files:
    with open(sorted(review_files)[-1]) as f:
        data = json.load(f)
    json.dump(data, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
    sys.exit(0)

# Nothing found - empty array
json.dump([], open('$OUT_DIR/review_findings.json', 'w'))
"

  # Copy expected.json
  cp "${TC_DIR}expected.json" "$OUT_DIR/expected.json"
  echo "  Done: $OUT_DIR/"
done

echo ""
echo "All test cases complete. Results in: $RESULTS_DIR/"
