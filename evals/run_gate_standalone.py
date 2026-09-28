#!/usr/bin/env python3
"""Run the deterministic gate directly on a test case directory.

Outputs gate findings (non-info severity) as a JSON array to stdout.
This avoids relying on the LLM skill orchestrator to write checks.json.
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "iam-temp-delegation-review" / "src"
sys.path.insert(0, str(SRC_DIR))

from iam_delegation_review.shared.types import Bundle, PolicyDoc
from iam_delegation_review.shared.metadata import cross_check_boundary_name
from iam_delegation_review.checks_lib import gate


def load_test_case(tc_dir: Path) -> tuple[Bundle, dict]:
    perm_path = tc_dir / "permissions.json"
    perm_text = perm_path.read_text()
    templates = [PolicyDoc(id="permissions.json", raw=perm_text)]

    boundary = None
    bpath = tc_dir / "boundary.json"
    if bpath.exists():
        boundary = PolicyDoc(id=bpath.name, raw=bpath.read_text())

    meta_path = tc_dir / "bundle_metadata.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    bundle = Bundle(
        partner_name=meta.get("partner_domain", "test-partner"),
        use_case=meta.get("template_name", "test-use-case"),
        templates=templates,
        boundary=boundary,
    )
    return bundle, meta


def run_gate_on_test_case(tc_dir: Path) -> list[dict]:
    bundle, meta = load_test_case(tc_dir)

    try:
        result = gate(bundle, run_validate_policy=True)
    except Exception:
        try:
            result = gate(bundle, run_validate_policy=False)
        except Exception as e:
            print(f"Gate error: {e}", file=sys.stderr)
            return []

    findings = []
    for f in result.findings:
        d = {"stage": f.stage, "severity": f.severity, "artifact_ref": f.artifact_ref, "message": f.message}
        if f.verification:
            d["verification"] = f.verification
        findings.append(d)

    boundary_cross = cross_check_boundary_name(meta, bundle.templates[0].raw)
    findings.extend(boundary_cross)

    return [f for f in findings if f.get("severity", "").lower() != "info"]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: run_gate_standalone.py <test-case-dir>", file=sys.stderr)
        sys.exit(1)
    tc_dir = Path(sys.argv[1])
    findings = run_gate_on_test_case(tc_dir)
    json.dump(findings, sys.stdout, indent=2)
    print()
