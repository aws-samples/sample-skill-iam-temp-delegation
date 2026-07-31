#!/bin/bash
# Run the IAM delegation review skill on ALL unit test cases.
# Default: sequential (1 worker) for deterministic eval results.
# Pass a higher number for faster but less deterministic runs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
MAX_PARALLEL="${1:-1}"  # Default 1 (sequential) for eval accuracy; override with first arg

cd "$PROJECT_ROOT"
mkdir -p "$RESULTS_DIR"

START_TIME=$(date +%s)
echo "Starting at: $(date)"
echo "Max parallel jobs: $MAX_PARALLEL"
echo ""

# Function to run a single test case
run_test_case() {
  local TC_DIR="$1"
  local tc=$(basename "$TC_DIR")
  local OUT_DIR="$RESULTS_DIR/$tc"

  mkdir -p "$OUT_DIR"

  # Determine boundary
  local BOUNDARY="none"
  if [ -f "$TC_DIR/boundary.json" ]; then
    BOUNDARY="$TC_DIR/boundary.json"
  fi

  local TC_START=$(date +%s)

  # Invoke the full skill via claude -p
  claude -p \
    --dangerously-skip-permissions \
    --model sonnet \
    "/iam-temp-delegation-review

Review this IAM delegation template bundle:
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
review_files = glob.glob('iam-temp-delegation-review/registry/findings/unit-test__${tc}__*__review.json')
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

  local TC_END=$(date +%s)
  local TC_ELAPSED=$((TC_END - TC_START))
  echo "  DONE: $tc (${TC_ELAPSED}s)"
}

export -f run_test_case
export RESULTS_DIR

# Collect test cases to run (skip already-done ones)
TESTS_TO_RUN=()
for TC_DIR in evals/unit-tests/*/; do
  tc=$(basename "$TC_DIR")
  OUT_DIR="$RESULTS_DIR/$tc"
  if [ -f "$OUT_DIR/review_findings.json" ] && [ -s "$OUT_DIR/review_findings.json" ]; then
    echo "SKIP (already done): $tc"
  else
    TESTS_TO_RUN+=("$TC_DIR")
  fi
done

echo ""
echo "Running ${#TESTS_TO_RUN[@]} test cases with $MAX_PARALLEL parallel workers..."
echo ""

# Run in parallel using xargs
printf '%s\n' "${TESTS_TO_RUN[@]}" | xargs -P "$MAX_PARALLEL" -I {} bash -c 'run_test_case "$@"' _ {}

END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "All test cases complete."
echo "Results in: $RESULTS_DIR/"
echo "Total time: ${TOTAL_ELAPSED}s ($(( TOTAL_ELAPSED / 60 ))m $(( TOTAL_ELAPSED % 60 ))s)"
echo ""

# Summary
TOTAL=0
WITH_FINDINGS=0
EMPTY=0
for dir in "$RESULTS_DIR"/*/; do
  if [ -f "$dir/review_findings.json" ]; then
    TOTAL=$((TOTAL + 1))
    count=$(python3 -c "import json; print(len(json.load(open('${dir}review_findings.json'))))" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
      WITH_FINDINGS=$((WITH_FINDINGS + 1))
    else
      EMPTY=$((EMPTY + 1))
    fi
  fi
done
echo "Results: $TOTAL total | $WITH_FINDINGS with findings | $EMPTY empty (no findings)"
