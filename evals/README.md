# Evals — IAM Delegation Review Skill

Test suite for validating the IAM temporary delegation review skill. Contains unit tests (targeted pattern detection) and functional tests (real partner policy bundles).

## Structure

```
sample-skill-iam-temp-delegation/
├── iam-temp-delegation-review/      # The skill source
│   ├── SKILL.md
│   ├── config/
│   ├── docs/
│   ├── scripts/
│   └── src/
├── evals/                           # ← You are here
│   ├── unit-tests/                  # 25 targeted test cases (pattern-specific)
│   ├── functional-tests/            # 5 real partner policy bundles
│   ├── registry/                    # Versioned artifacts from prior runs
│   ├── eval_deepeval.py             # DeepEval evaluation script (LLM judge)
│   ├── run_all_skill_tests.sh       # Run skill on all unit tests (Claude CLI)
│   ├── run_functional_tests.sh      # Run skill on all functional tests (Claude CLI)
│   ├── run_skill_tests.sh           # Run skill on 5 quick unit tests (Claude CLI)
│   ├── results/                     # Generated results (not committed)
│   └── README.md
└── .agents/skills/                  # Skill installed for local testing
```

## Prerequisites

```bash
pip install deepeval boto3
```

AWS credentials must be configured with Bedrock access (region: us-east-1). The IAM principal needs `bedrock:InvokeModel` permission for model ID `us.anthropic.claude-sonnet-4-20250514-v1:0`.

## Running Tests

There are two ways to run the skill on test cases:

### Method 1: Kiro IDE (interactive)

The skill is already installed in this repo's `.agents/skills/` directory for local testing. Open this workspace in Kiro IDE and send this prompt in chat:

```
Review this IAM delegation template bundle:
- Template: evals/unit-tests/<test-case>/permissions.json
- Boundary: evals/unit-tests/<test-case>/boundary.json (or "none" if no boundary)
- Metadata: evals/unit-tests/<test-case>/bundle_metadata.json
- Partner: unit-test
- Use case: <test-case>

Run the full pipeline (Steps 0-8). After completing analysis, output the final Stage 3-4 findings as a JSON array.
```

Save the output JSON array as `evals/results/<test-case>/review_findings.json`.

To run all test cases, repeat for each directory in `evals/unit-tests/` and `evals/functional-tests/`.

### Method 2: Claude Code CLI (batch)

Requires [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) installed and authenticated.

```bash
cd evals

# Run skill on unit test cases
bash run_all_skill_tests.sh

# Run skill on functional test cases
bash run_functional_tests.sh
```

This invokes `claude -p /iam-temp-delegation-review` on each test case and saves results to `evals/results/`.

### Evaluate results with DeepEval

After running the skill (via either method), compare actual output against expected:

```bash
cd evals

# Evaluate unit tests
python eval_deepeval.py results

# Evaluate functional tests
python eval_deepeval.py results/functional
```

Results are saved to `evals/results/deepeval_results.json`.

## How DeepEval Accesses the LLM

DeepEval uses a custom `BedrockClaude` wrapper (defined in `eval_deepeval.py`) that calls Claude via AWS Bedrock. The wrapper:

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

- **Unit tests:** 25/25 passed (100%)
- **Functional tests:** 5/5 passed (100%)

## Adding a New Test Case

1. Create a directory under `unit-tests/` or `functional-tests/` with the test case name:
   ```
   unit-tests/my-new-pattern/
   ├── permissions.json        # The delegation template
   ├── boundary.json           # Permission boundary (optional)
   ├── bundle_metadata.json    # Partner/bundle metadata
   └── expected.json           # Expected findings ([] if no issues)
   ```

2. Add the test case name to the `ALL_TEST_CASES` list in `eval_deepeval.py` (for unit tests only — functional tests are discovered dynamically from the results directory).

3. Run the skill on the new test case (via Kiro or Claude CLI) and save the output to `results/<test-case-name>/review_findings.json`.

4. Copy the expected file: `cp unit-tests/<test-case-name>/expected.json results/<test-case-name>/expected.json`

5. Run the evaluation to verify:
   ```bash
   python eval_deepeval.py results
   ```
