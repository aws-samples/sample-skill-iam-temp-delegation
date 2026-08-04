"""
DeepEval evaluation for IAM Delegation Review skill using AWS Bedrock.

Compares the skill's actual findings (review_findings.json) against expected
findings (expected.json) using DeepEval metrics powered by Claude on Bedrock.

Usage:
    .venv/bin/python evals/eval_deepeval.py [--results-dir evals/results]

Prerequisites:
    pip install deepeval boto3
"""

import json
import sys
from pathlib import Path

from deepeval import evaluate
from deepeval.evaluate.configs import AsyncConfig, DisplayConfig
from deepeval.metrics import GEval
from deepeval.models.base_model import DeepEvalBaseLLM
from deepeval.test_case import LLMTestCase, LLMTestCaseParams

import boto3


RESULTS_DIR = Path(__file__).parent / "results"
MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"

ALL_TEST_CASES = [
    "arnequals-with-wildcard",
    "arnequals-with-wildcard-good",
    "boundary-self-escalation",
    "boundary-self-escalation-with-boundary",
    "create-without-tags",
    "create-without-tags-good",
    "incompatible-resource-scope",
    "incompatible-resource-scope-good",
    "invalid-boundary-reference",
    "invalid-boundary-reference-good",
    "unconditioned-delegation-request",
    "multiple-boundary-references",
    "multiple-boundary-references-good",
    "access-grants-permission-only-action",
    "access-grants-permission-only-action-good",
    "sts-assume-role-in-boundary",
    "sts-assume-role-in-boundary-with-boundary",
    "unconditioned-role-creation",
    "unconditioned-role-creation-with-boundary",
    "unscoped-dataplane-read",
    "unscoped-dataplane-read-with-boundary",
    "unscoped-dataplane-write",
    "unscoped-dataplane-write-with-boundary",
    "unsupported-condition-key",
    "unsupported-condition-key-good",
    "variable-in-arn-namespace",
    "variable-in-arn-namespace-good",
]


class BedrockClaude(DeepEvalBaseLLM):
    """DeepEval LLM wrapper for AWS Bedrock Claude."""

    def __init__(self, model_id: str = MODEL_ID):
        self.model_id = model_id
        self.client = boto3.client("bedrock-runtime", region_name="us-east-1")

    def load_model(self):
        return self.client

    def generate(self, prompt: str, schema=None) -> str:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        response = self.client.invoke_model(
            modelId=self.model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )
        result = json.loads(response["body"].read())
        return result["content"][0]["text"]

    async def a_generate(self, prompt: str, schema=None) -> str:
        return self.generate(prompt, schema)

    def get_model_name(self) -> str:
        return self.model_id


def load_json(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def get_available_test_cases(results_dir: Path) -> list[str]:
    """Return only test cases that have both review_findings.json and expected.json."""
    available = []
    # First try the hardcoded list
    for tc in ALL_TEST_CASES:
        tc_dir = results_dir / tc
        if (tc_dir / "review_findings.json").exists() and (tc_dir / "expected.json").exists():
            available.append(tc)
    # If none matched, discover dynamically from the results directory
    if not available:
        for tc_dir in sorted(results_dir.iterdir()):
            if tc_dir.is_dir() and (tc_dir / "review_findings.json").exists() and (tc_dir / "expected.json").exists():
                available.append(tc_dir.name)
    return available


def build_test_cases(results_dir: Path) -> tuple[list[LLMTestCase], list[str], set[str]]:
    """Build DeepEval test cases from skill results vs expected."""
    test_cases = []
    test_case_names = get_available_test_cases(results_dir)
    auto_pass_cases = set()

    for tc in test_case_names:
        tc_dir = results_dir / tc
        actual = load_json(tc_dir / "review_findings.json")
        expected = load_json(tc_dir / "expected.json")

        # When both expected and actual are empty, auto-pass (no need for LLM judge)
        if not actual and not expected:
            auto_pass_cases.add(tc)

        # Load the original policy as input context
        policy_path = Path(__file__).parent / "unit-tests" / tc / "permissions.json"
        if not policy_path.exists():
            policy_path = Path(__file__).parent / "functional-tests" / tc / "permissions.json"
        policy_text = policy_path.read_text() if policy_path.exists() else "{}"

        input_text = (
            f"Review this IAM delegation template for security issues. "
            f"Test case: {tc}\n\nPolicy:\n{policy_text}"
        )

        actual_output = json.dumps(actual, indent=2) if actual else "[]"
        expected_output = json.dumps(expected, indent=2)

        test_cases.append(LLMTestCase(
            input=input_text,
            actual_output=actual_output,
            expected_output=expected_output,
        ))

    return test_cases, test_case_names, auto_pass_cases


def run_evaluation(results_dir: Path):
    """Run DeepEval with Bedrock Claude."""
    print(f"Model: {MODEL_ID}")
    print(f"Results dir: {results_dir}")
    print()

    bedrock_model = BedrockClaude()
    test_cases, test_case_names, auto_pass_cases = build_test_cases(results_dir)
    print(f"Found {len(test_cases)} test cases with results (out of {len(ALL_TEST_CASES)} total)")
    if auto_pass_cases:
        print(f"  ({len(auto_pass_cases)} will auto-pass: both expected and actual are empty)")
    print()

    # Metric 1: Detection accuracy — did it find the right vulnerabilities?
    detection_metric = GEval(
        name="Detection Accuracy",
        criteria=(
            "Does the actual output identify the SAME security vulnerabilities as the "
            "expected output? Match findings by SEMANTIC CONTENT — the same vulnerability "
            "affecting the same resource/action. IGNORE differences in JSON field names "
            "(e.g. 'rule_code' vs 'stage', 'decision' vs 'verification'). The outputs may "
            "use completely different schemas but describe the same security issues. "
            "Score 1.0 if all expected findings are semantically present. Score 0.0 if "
            "completely different issues are described. Partial credit for partial detection."
        ),
        evaluation_params=[
            LLMTestCaseParams.ACTUAL_OUTPUT,
            LLMTestCaseParams.EXPECTED_OUTPUT,
        ],
        model=bedrock_model,
        threshold=0.7,
    )

    # Metric 2: Severity correctness (informational — low threshold, does not gate pass/fail)
    severity_metric = GEval(
        name="Severity Accuracy",
        criteria=(
            "Are the severity levels in the actual output correct compared to expected? "
            "Score 1.0 if all severities match exactly. Score 0.7 if severities are off by "
            "one level (e.g. medium vs high). Score 0.5 if findings were detected but with "
            "very different severity. Score 0.0 if no findings match. "
            "Note: severity is subjective and small differences (medium vs high) are acceptable."
        ),
        evaluation_params=[
            LLMTestCaseParams.ACTUAL_OUTPUT,
            LLMTestCaseParams.EXPECTED_OUTPUT,
        ],
        model=bedrock_model,
        threshold=0.3,
    )

    # Metric 3: Precision — no false positives
    precision_metric = GEval(
        name="Precision (No False Positives)",
        criteria=(
            "Evaluate precision: what fraction of findings in the actual output are "
            "legitimate (semantically matching something in expected)? Match findings by "
            "SEMANTIC CONTENT — the same security vulnerability affecting the same resource/action. "
            "IGNORE differences in JSON field names, schema structure, artifact_ref naming "
            "(e.g. 'permissions.json' vs 'delegation_template.json'), or field presence "
            "(e.g. 'rule_code'/'decision' vs 'stage'/'verification'/'fix_before'/'fix_after'). "
            "A finding is a true positive if it describes the same security issue as any expected finding. "
            "Extra findings that describe GENUINELY DIFFERENT security issues not covered by expected "
            "are false positives. Score 1.0 if all actual findings semantically match expected findings. "
            "Score 0.0 if all actual findings describe completely different issues."
        ),
        evaluation_params=[
            LLMTestCaseParams.ACTUAL_OUTPUT,
            LLMTestCaseParams.EXPECTED_OUTPUT,
        ],
        model=bedrock_model,
        threshold=0.7,
    )

    # Metric 4: Recall — no false negatives
    recall_metric = GEval(
        name="Recall (No False Negatives)",
        criteria=(
            "Evaluate recall: what fraction of expected findings appear in the actual output? "
            "Match findings by their SEMANTIC CONTENT (same vulnerability, same affected resource), "
            "NOT by field names or JSON structure. Different field names (e.g. 'stage' vs 'rule_code') "
            "do not count as a miss if the same security issue is described. "
            "Score 1.0 if all expected findings were detected. Score 0.0 if none were detected."
        ),
        evaluation_params=[
            LLMTestCaseParams.ACTUAL_OUTPUT,
            LLMTestCaseParams.EXPECTED_OUTPUT,
        ],
        model=bedrock_model,
        threshold=0.6,
    )

    # Metric 5: Message quality
    message_metric = GEval(
        name="Message Quality",
        criteria=(
            "Does the actual finding message clearly explain: (1) what the security issue is, "
            "(2) which actions/resources are affected, (3) what the impact is? "
            "Compare against expected messages. Score on clarity and completeness."
        ),
        evaluation_params=[
            LLMTestCaseParams.ACTUAL_OUTPUT,
            LLMTestCaseParams.EXPECTED_OUTPUT,
        ],
        model=bedrock_model,
        threshold=0.6,
    )

    metrics = [detection_metric, severity_metric, precision_metric, recall_metric, message_metric]

    # Only send non-auto-pass cases to LLM judge
    judge_test_cases = [tc for i, tc in enumerate(test_cases) if test_case_names[i] not in auto_pass_cases]
    judge_test_case_names = [n for n in test_case_names if n not in auto_pass_cases]

    print(f"Running {len(judge_test_cases)} test cases through LLM judge ({len(auto_pass_cases)} auto-passed)...")
    print()

    # Run evaluation
    eval_results = evaluate(
        test_cases=judge_test_cases,
        metrics=metrics,
        display_config=DisplayConfig(
            print_results=True,
            inspect_after_run=False,
        ),
        async_config=AsyncConfig(run_async=False),
    )

    # Save structured results from eval_results
    output = {
        "model": MODEL_ID,
        "framework": "deepeval",
        "test_cases": {},
        "summary": {},
    }

    # Add auto-pass results first
    for tc_name in test_case_names:
        if tc_name in auto_pass_cases:
            output["test_cases"][tc_name] = {
                "passed": True,
                "auto_pass": True,
                "metrics": {
                    "Detection Accuracy": {"score": 1.0, "threshold": 0.7, "passed": True, "reason": "Both expected and actual are empty — no findings to evaluate"},
                    "Severity Accuracy": {"score": 1.0, "threshold": 0.3, "passed": True, "reason": "Both empty"},
                    "Precision (No False Positives)": {"score": 1.0, "threshold": 0.7, "passed": True, "reason": "No false positives (nothing reported)"},
                    "Recall (No False Negatives)": {"score": 1.0, "threshold": 0.6, "passed": True, "reason": "No false negatives (nothing expected)"},
                    "Message Quality": {"score": 1.0, "threshold": 0.6, "passed": True, "reason": "No messages to evaluate"},
                },
            }

    # Extract LLM-judged results
    if hasattr(eval_results, 'test_results'):
        for i, test_result in enumerate(eval_results.test_results):
            tc_name = judge_test_case_names[i] if i < len(judge_test_case_names) else f"test_case_{i}"
            tc_data = {
                "passed": test_result.success if hasattr(test_result, 'success') else False,
                "metrics": {},
            }
            if hasattr(test_result, 'metrics_data'):
                for md in test_result.metrics_data:
                    tc_data["metrics"][md.name] = {
                        "score": md.score,
                        "threshold": md.threshold,
                        "passed": md.success if hasattr(md, 'success') else (md.score >= md.threshold if md.score is not None else False),
                        "reason": md.reason if hasattr(md, 'reason') else None,
                    }
            output["test_cases"][tc_name] = tc_data

    # Compute summary
    total = len(output["test_cases"])
    passed = sum(1 for tc in output["test_cases"].values() if tc.get("passed"))
    output["summary"] = {
        "total_tests": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": f"{passed/total*100:.0f}%" if total else "0%",
    }

    output_path = results_dir / "deepeval_results.json"
    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to: {output_path}")

    # Print summary table
    print(f"\n{'='*70}")
    print(f"{'Test Case':<35} {'Pass?':<8} {'Detection':<10} {'Severity':<10} {'Precision':<10} {'Recall':<10} {'Message':<10}")
    print(f"{'-'*35} {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    def get_metric_score(metrics, prefix):
        for key, val in metrics.items():
            if key.startswith(prefix):
                return val.get("score", "?")
        return "?"

    for tc_name, tc_data in output["test_cases"].items():
        m = tc_data.get("metrics", {})
        det = get_metric_score(m, "Detection Accuracy")
        sev = get_metric_score(m, "Severity Accuracy")
        prec = get_metric_score(m, "Precision (No False Positives)")
        rec = get_metric_score(m, "Recall (No False Negatives)")
        msg = get_metric_score(m, "Message Quality")
        passed_str = "PASS" if tc_data.get("passed") else "FAIL"
        print(f"{tc_name:<35} {passed_str:<8} {det:<10} {sev:<10} {prec:<10} {rec:<10} {msg:<10}")
    print(f"\nOverall: {output['summary']['passed']}/{output['summary']['total_tests']} passed ({output['summary']['pass_rate']})")


if __name__ == "__main__":
    args = sys.argv[1:]
    results_dir = RESULTS_DIR
    while args:
        if args[0] == "--results-dir" and len(args) > 1:
            results_dir = Path(args[1])
            args = args[2:]
        else:
            results_dir = Path(args[0])
            args = args[1:]
    run_evaluation(results_dir)
