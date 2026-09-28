#!/bin/bash
# Run the IAM delegation review skill on ALL test cases (unit + functional).
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

  # Extract findings JSON from output (LLM review + gate findings)
  python3 -c "
import json, re, sys, glob

with open('$OUT_DIR/raw_output.txt') as f:
    content = f.read()

findings = []

# Try markdown code block extraction
match = re.search(r'\`\`\`json\s*(\[[\s\S]*?\])\s*\`\`\`', content)
if match:
    try:
        findings = json.loads(match.group(1))
    except json.JSONDecodeError:
        pass

# Fallback: find any JSON array with finding-like objects
if not findings:
    arrays = re.findall(r'\[[\s\S]*?\]', content)
    for arr in arrays:
        try:
            data = json.loads(arr)
            if isinstance(data, list) and data and isinstance(data[0], dict):
                if any(k in data[0] for k in ('severity', 'rule_code', 'stage', 'message')):
                    findings = data
                    break
        except json.JSONDecodeError:
            continue

# Fallback: check registry for review findings
if not findings:
    review_files = glob.glob('registry/findings/unit-test__${tc}__*__review.json')
    if review_files:
        with open(sorted(review_files)[-1]) as f:
            findings = json.load(f)

json.dump(findings, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
"

  # Merge deterministic gate findings (run gate directly, not via LLM)
  python3 "$SCRIPT_DIR/run_gate_standalone.py" "$TC_DIR" > "$OUT_DIR/gate_findings.json" 2>/dev/null || echo "[]" > "$OUT_DIR/gate_findings.json"
  python3 -c "
import json
with open('$OUT_DIR/review_findings.json') as f:
    findings = json.load(f)
with open('$OUT_DIR/gate_findings.json') as f:
    gate = json.load(f)
findings.extend(gate)
json.dump(findings, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
"

  # Copy expected.json
  cp "${TC_DIR}expected.json" "$OUT_DIR/expected.json"

  local TC_END=$(date +%s)
  local TC_ELAPSED=$((TC_END - TC_START))
  echo "  DONE: $tc (${TC_ELAPSED}s)"
}

export -f run_test_case
export RESULTS_DIR
export SCRIPT_DIR

# --- UNIT TESTS ---
echo "=== UNIT TESTS ==="
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
echo "Running ${#TESTS_TO_RUN[@]} unit test cases with $MAX_PARALLEL parallel workers..."
echo ""

if [ ${#TESTS_TO_RUN[@]} -gt 0 ]; then
  printf '%s\n' "${TESTS_TO_RUN[@]}" | xargs -P "$MAX_PARALLEL" -I {} bash -c 'run_test_case "$@"' _ {}
fi

# --- FUNCTIONAL TESTS ---
echo ""
echo "=== FUNCTIONAL TESTS ==="
FUNC_RESULTS_DIR="$RESULTS_DIR/functional"
mkdir -p "$FUNC_RESULTS_DIR"

FUNC_TESTS_TO_RUN=()
for TC_DIR in evals/functional-tests/*/; do
  tc=$(basename "$TC_DIR")
  OUT_DIR="$FUNC_RESULTS_DIR/$tc"
  if [ -f "$OUT_DIR/review_findings.json" ] && [ -s "$OUT_DIR/review_findings.json" ]; then
    echo "SKIP (already done): $tc"
  else
    FUNC_TESTS_TO_RUN+=("$TC_DIR")
  fi
done

echo ""
echo "Running ${#FUNC_TESTS_TO_RUN[@]} functional test cases with $MAX_PARALLEL parallel workers..."
echo ""

# Function to run a functional test case (uses "functional-test" partner name)
run_functional_test_case() {
  local TC_DIR="$1"
  local tc=$(basename "$TC_DIR")
  local OUT_DIR="$FUNC_RESULTS_DIR/$tc"

  mkdir -p "$OUT_DIR"

  local BOUNDARY="none"
  if [ -f "$TC_DIR/boundary.json" ]; then
    BOUNDARY="$TC_DIR/boundary.json"
  fi

  local TC_START=$(date +%s)

  claude -p \
    --dangerously-skip-permissions \
    --model sonnet \
    "/iam-temp-delegation-review

Review this IAM delegation template bundle:
- Template: ${TC_DIR}permissions.json
- Boundary: $BOUNDARY
- Metadata: ${TC_DIR}bundle_metadata.json
- Partner: functional-test
- Use case: $tc

Run the full pipeline (Steps 0-8). After completing analysis, output the final Stage 3-4 findings as a JSON array." \
    > "$OUT_DIR/raw_output.txt" 2>&1 || true

  # Extract findings JSON from output (LLM review + gate findings)
  python3 -c "
import json, re, sys, glob

with open('$OUT_DIR/raw_output.txt') as f:
    content = f.read()

findings = []

# Try markdown code block extraction
match = re.search(r'\`\`\`json\s*(\[[\s\S]*?\])\s*\`\`\`', content)
if match:
    try:
        findings = json.loads(match.group(1))
    except json.JSONDecodeError:
        pass

# Fallback: find any JSON array with finding-like objects
if not findings:
    arrays = re.findall(r'\[[\s\S]*?\]', content)
    for arr in arrays:
        try:
            data = json.loads(arr)
            if isinstance(data, list) and data and isinstance(data[0], dict):
                if any(k in data[0] for k in ('severity', 'rule_code', 'stage', 'message')):
                    findings = data
                    break
        except json.JSONDecodeError:
            continue

# Fallback: check registry for review findings
if not findings:
    review_files = glob.glob('registry/findings/functional-test__${tc}__*__review.json')
    if review_files:
        with open(sorted(review_files)[-1]) as f:
            findings = json.load(f)

json.dump(findings, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
"

  # Merge deterministic gate findings (run gate directly, not via LLM)
  python3 "$SCRIPT_DIR/run_gate_standalone.py" "$TC_DIR" > "$OUT_DIR/gate_findings.json" 2>/dev/null || echo "[]" > "$OUT_DIR/gate_findings.json"
  python3 -c "
import json
with open('$OUT_DIR/review_findings.json') as f:
    findings = json.load(f)
with open('$OUT_DIR/gate_findings.json') as f:
    gate = json.load(f)
findings.extend(gate)
json.dump(findings, open('$OUT_DIR/review_findings.json', 'w'), indent=2)
"

  cp "${TC_DIR}expected.json" "$OUT_DIR/expected.json"

  local TC_END=$(date +%s)
  local TC_ELAPSED=$((TC_END - TC_START))
  echo "  DONE: $tc (${TC_ELAPSED}s)"
}

export -f run_functional_test_case
export FUNC_RESULTS_DIR

if [ ${#FUNC_TESTS_TO_RUN[@]} -gt 0 ]; then
  printf '%s\n' "${FUNC_TESTS_TO_RUN[@]}" | xargs -P "$MAX_PARALLEL" -I {} bash -c 'run_functional_test_case "$@"' _ {}
fi

# --- SUMMARY ---
END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "All test cases complete."
echo "Results in: $RESULTS_DIR/"
echo "Total time: ${TOTAL_ELAPSED}s ($(( TOTAL_ELAPSED / 60 ))m $(( TOTAL_ELAPSED % 60 ))s)"
echo ""

# Unit test summary
UNIT_TOTAL=0
UNIT_WITH_FINDINGS=0
UNIT_EMPTY=0
for dir in "$RESULTS_DIR"/*/; do
  [ "$(basename "$dir")" = "functional" ] && continue
  if [ -f "$dir/review_findings.json" ]; then
    UNIT_TOTAL=$((UNIT_TOTAL + 1))
    count=$(python3 -c "import json; print(len(json.load(open('${dir}review_findings.json'))))" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
      UNIT_WITH_FINDINGS=$((UNIT_WITH_FINDINGS + 1))
    else
      UNIT_EMPTY=$((UNIT_EMPTY + 1))
    fi
  fi
done
echo "Unit tests:       $UNIT_TOTAL total | $UNIT_WITH_FINDINGS with findings | $UNIT_EMPTY empty"

# Functional test summary
FUNC_TOTAL=0
FUNC_WITH_FINDINGS=0
FUNC_EMPTY=0
for dir in "$FUNC_RESULTS_DIR"/*/; do
  if [ -f "$dir/review_findings.json" ]; then
    FUNC_TOTAL=$((FUNC_TOTAL + 1))
    count=$(python3 -c "import json; print(len(json.load(open('${dir}review_findings.json'))))" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
      FUNC_WITH_FINDINGS=$((FUNC_WITH_FINDINGS + 1))
    else
      FUNC_EMPTY=$((FUNC_EMPTY + 1))
    fi
  fi
done
echo "Functional tests: $FUNC_TOTAL total | $FUNC_WITH_FINDINGS with findings | $FUNC_EMPTY empty"

# --- DEEPEVAL + CI GATE ---
echo ""
echo "=========================================="
echo "Running DeepEval evaluation (unit tests)..."
echo ""

python3 "$SCRIPT_DIR/eval_deepeval.py" --results-dir "$RESULTS_DIR"

echo ""
echo "Running DeepEval evaluation (functional tests)..."
echo ""

python3 "$SCRIPT_DIR/eval_deepeval.py" --results-dir "$FUNC_RESULTS_DIR"
# Rename functional results for ci_gate to pick up
mv "$FUNC_RESULTS_DIR/deepeval_results.json" "$RESULTS_DIR/functional_deepeval_results.json" 2>/dev/null || true

echo ""
echo "=========================================="
echo "Running CI gate..."
echo ""

python3 "$SCRIPT_DIR/ci_gate.py" --results-dir "$RESULTS_DIR"
