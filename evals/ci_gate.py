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
if pass_rate >= min_pass_rate:
    print(f"\nGATE: PASS")
    sys.exit(0)
else:
    print(f"\nGATE: FAIL")
    sys.exit(1)
