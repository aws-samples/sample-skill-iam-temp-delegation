#!/usr/bin/env python3
"""
CI gate: reads deepeval_results.json, exits 0 (proceed) or 1 (break pipeline).

Usage:
    python3 evals/ci_gate.py [--min-pass-rate 0.90] [--results-dir evals/results]
"""

import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
MIN_PASS_RATE = 0.90

# Parse optional args
args = sys.argv[1:]
results_dir = RESULTS_DIR
min_pass_rate = MIN_PASS_RATE

while args:
    if args[0] == "--results-dir" and len(args) > 1:
        results_dir = Path(args[1])
        args = args[2:]
    elif args[0] == "--min-pass-rate" and len(args) > 1:
        min_pass_rate = float(args[1])
        args = args[2:]
    else:
        args = args[1:]

# Load results
results_path = results_dir / "deepeval_results.json"
if not results_path.exists():
    print(f"ERROR: {results_path} not found. Run eval_deepeval.py first.")
    sys.exit(1)

results = json.loads(results_path.read_text())
summary = results["summary"]
test_cases = results["test_cases"]

total = summary["total_tests"]
passed = summary["passed"]
failed = summary["failed"]
pass_rate = passed / total if total else 0

# Print summary
print(f"Tests: {passed}/{total} passed ({pass_rate:.0%})")
print(f"Threshold: {min_pass_rate:.0%}")

if failed:
    print(f"\nFailed:")
    for name, data in test_cases.items():
        if not data.get("passed"):
            print(f"  - {name}")

# Gate decision
gate_result = "PASS" if pass_rate >= min_pass_rate else "FAIL"
print(f"\nGATE: {gate_result}")

# === Append to test run log ===
from datetime import datetime

log_file = Path(__file__).parent / "test_run_log.txt"

failing_cases = [name for name, data in test_cases.items() if not data.get("passed")]

# Check for functional test results
func_results_path = results_dir / "functional_deepeval_results.json"
func_passed = func_total = 0
func_failing = []
if func_results_path.exists():
    func_results = json.loads(func_results_path.read_text())
    func_summary = func_results["summary"]
    func_total = func_summary["total_tests"]
    func_passed = func_summary["passed"]
    func_test_cases = func_results["test_cases"]
    func_failing = [name for name, data in func_test_cases.items() if not data.get("passed")]

log_entry = []
log_entry.append("=" * 64)
log_entry.append(f"Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log_entry.append(f"Unit tests: {passed}/{total} passed ({pass_rate:.0%})")
if func_total:
    func_rate = func_passed / func_total
    log_entry.append(f"Functional tests: {func_passed}/{func_total} passed ({func_rate:.0%})")
log_entry.append(f"Threshold: {min_pass_rate:.0%}")
log_entry.append(f"Gate: {gate_result}")
if failing_cases:
    log_entry.append("Failing unit cases:")
    for name in failing_cases:
        log_entry.append(f"    - {name}")
if func_failing:
    log_entry.append("Failing functional cases:")
    for name in func_failing:
        log_entry.append(f"    - {name}")
log_entry.append("")

with open(log_file, "a") as f:
    f.write("\n".join(log_entry) + "\n")

print(f"\nRun logged to: {log_file}")

sys.exit(0 if gate_result == "PASS" else 1)
