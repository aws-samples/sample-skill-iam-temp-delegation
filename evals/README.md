# Baseline Tests — IAM Delegation Review Skill

Test suite for validating the IAM temporary delegation review skill. Contains unit tests (targeted pattern detection) and functional tests (real partner policy bundles).

## Structure

```
evals/
├── unit-tests/                        # 27 targeted test cases (pattern-specific)
├── functional-tests/                  # 5 real partner policy bundles
├── eval_deepeval.py                   # DeepEval evaluation script (LLM judge)
├── ci_gate.py                         # CI/CD gate — exits 0 (pass) or 1 (fail)
├── run_all_skill_tests.sh             # Run all tests + DeepEval + CI gate (configurable concurrency)
├── run_functional_tests.sh            # Run functional tests only (standalone)
├── results/                           # Generated results (not committed)
├── test_run_log.txt                   # Log of all test runs (appended by ci_gate.py)
└── README.md
```

## Prerequisites

```bash
pip install deepeval boto3
```

AWS credentials must be configured with Bedrock access (region: us-east-1). The IAM principal needs `bedrock:InvokeModel` permission for model ID `us.anthropic.claude-sonnet-4-20250514-v1:0`.

## Running Tests

### Quick Start (Full Pipeline)

```bash
# Run everything: unit tests → functional tests → DeepEval → CI gate
bash evals/run_all_skill_tests.sh
```

This single command runs all unit and functional tests, evaluates results with DeepEval (LLM judge), and executes the CI gate. Results are logged to `test_run_log.txt`.

### Concurrency

```bash
# Default: 1 worker (sequential) — most deterministic results
bash evals/run_all_skill_tests.sh

# Faster: specify number of concurrent workers
bash evals/run_all_skill_tests.sh 5
```

The script accepts an optional argument to control concurrency. Sequential (1 worker) produces the most consistent findings. Higher concurrency is faster but may produce extra secondary findings due to context pressure.

### Running Functional Tests Only

```bash
bash evals/run_functional_tests.sh
```

### Kiro IDE (Interactive)

Open this workspace in Kiro IDE. The `iam-temp-delegation-review` skill is installed in `.agents/skills/`. To run a test case, send this prompt in Kiro chat:

```
Review this IAM delegation template bundle:
- Template: evals/unit-tests/<test-case>/permissions.json
- Boundary: evals/unit-tests/<test-case>/boundary.json (or "none" if no boundary)
- Metadata: evals/unit-tests/<test-case>/bundle_metadata.json
- Partner: unit-test
- Use case: <test-case>

Run the full pipeline (Steps 0-8). After completing analysis, output the final Stage 3-4 findings as a JSON array.
```

## Evaluating Results

After running the skill, compare actual output against expected:

```bash
# Evaluate unit tests
python3 evals/eval_deepeval.py

# Evaluate functional tests
python3 evals/eval_deepeval.py evals/results/functional
```

Results are saved to `evals/results/deepeval_results.json`.

## CI/CD Gate

The `ci_gate.py` script reads `deepeval_results.json` and provides a pass/fail decision for your pipeline:

```bash
# Default: 90% pass rate threshold
python3 evals/ci_gate.py

# Custom threshold
python3 evals/ci_gate.py --min-pass-rate 0.95

# Custom results directory
python3 evals/ci_gate.py --results-dir evals/results/functional
```

**Exit codes:**
- `0` — Gate passed, pipeline may proceed
- `1` — Gate failed, pipeline should break

**Example output:**
```
Tests: 25/25 passed (100%)
Threshold: 90%

GATE: PASS
```

## How DeepEval Accesses the LLM

DeepEval uses a custom `BedrockClaude` wrapper (defined in `evals/eval_deepeval.py`) that calls Claude via AWS Bedrock. The wrapper:

1. Creates a `boto3` Bedrock Runtime client (`us-east-1`)
2. Calls `invoke_model()` with the Bedrock model ID: `us.anthropic.claude-sonnet-4-20250514-v1:0`
3. Returns the response text to DeepEval's GEval metrics for scoring

```
DeepEval GEval metric
  → calls BedrockClaude.generate(prompt)
    → boto3 bedrock-runtime invoke_model()
      → Claude Sonnet on Bedrock (us-east-1)
```

**Authentication:** Uses your standard AWS credential chain (env vars, `~/.aws/credentials`, IAM role, or `AWS_PROFILE`).

## Test Case Format

Each test case directory contains:

| File | Purpose |
|------|---------|
| `permissions.json` | The delegation template (input) |
| `boundary.json` | Permissions boundary (optional) |
| `bundle_metadata.json` | Partner/bundle metadata |
| `expected.json` | Expected findings (`[]` = no issues) |

## Evaluation Metrics

The DeepEval script uses 5 GEval metrics powered by Claude on Bedrock:

| Metric | Threshold | What it measures |
|--------|-----------|-----------------|
| Detection Accuracy | 0.7 | Same vulnerabilities found (semantic match) |
| Severity Accuracy | 0.3 | Severity levels correct (informational) |
| Precision | 0.7 | No false positives |
| Recall | 0.6 | No false negatives |
| Message Quality | 0.6 | Clear explanation of issue and impact |

Cases where both expected and actual are `[]` auto-pass without invoking the LLM judge.

## Current Baseline

- **Unit tests:** 23/27 passed (85%) — sequential run
- **Functional tests:** 5/5 passed (100%)

## Adding a New Test Case

1. Create a directory under `evals/unit-tests/` or `evals/functional-tests/` with the test case name:
   ```
   evals/unit-tests/my-new-pattern/
   ├── permissions.json        # The delegation template
   ├── boundary.json           # Permission boundary (optional)
   ├── bundle_metadata.json    # Partner/bundle metadata
   └── expected.json           # Expected findings ([] if no issues)
   ```

2. Add the test case name to the `ALL_TEST_CASES` list in `evals/eval_deepeval.py` (for unit tests only — functional tests are discovered dynamically from the results directory).

3. Run the skill on the new test case and evaluate:
   ```bash
   bash evals/run_all_skill_tests.sh
   python3 evals/eval_deepeval.py
   python3 evals/ci_gate.py
   ```
