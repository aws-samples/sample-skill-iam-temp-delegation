"""Validate and persist Stage 3-4 findings to the findings store.

Usage:
    python scripts/save_findings.py <partner> <use_case> <findings_json_path>

Validates the findings JSON against the schema, writes (overwrites) the
review findings file, and regenerates the full report. Always idempotent —
running multiple times with the same input produces identical output.
"""

import hashlib
import json
import sys
from pathlib import Path

from jsonschema import validate, ValidationError

# Add the skill-local source to the path
_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

# Load the findings schema once at module level.
_FINDINGS_SCHEMA_PATH = _SKILL_ROOT / "config" / "findings_schema.json"
_FINDINGS_SCHEMA = json.loads(_FINDINGS_SCHEMA_PATH.read_text())

from iam_delegation_review.shared import Finding, format_summary
from iam_delegation_review.registry import create_registry
from iam_delegation_review.registry._file_store import _validate_path_component


def _validate_findings_json(data: object) -> None:
    """Validate findings data against the JSON Schema.

    :raises SystemExit: on validation failure, with a clear error message.
    """
    try:
        validate(instance=data, schema=_FINDINGS_SCHEMA)
    except ValidationError as e:
        path_str = " > ".join(str(p) for p in e.absolute_path)
        location = f" at [{path_str}]" if path_str else ""
        print(f"Error: Invalid findings JSON{location}: {e.message}")
        sys.exit(1)


def main() -> None:
    if len(sys.argv) < 4:
        print(
            "Usage: python save_findings.py <partner> <use_case> <findings_json_path>"
        )
        sys.exit(1)

    partner = sys.argv[1]
    use_case = sys.argv[2]
    findings_path = sys.argv[3]

    # Validate partner/use_case to prevent path traversal.
    _validate_path_component(partner, "partner")
    _validate_path_component(use_case, "use_case")

    # Load findings JSON.
    findings_raw = Path(findings_path).read_text()
    findings_data = json.loads(findings_raw)

    # Validate against schema.
    _validate_findings_json(findings_data)

    # Load registry.
    registry = create_registry(Path("registry"))
    entry = registry.get(partner, use_case)

    if entry is None:
        print(f"Error: No registry entry found for ({partner}, {use_case})")
        sys.exit(1)

    if not entry.versions:
        print(f"Error: Registry entry for ({partner}, {use_case}) has no versions")
        sys.exit(1)

    version_number = len(entry.versions)

    # Write (overwrite) the review findings to the store.
    saved_path = registry.save_findings(
        partner, use_case, version_number, "review", findings_data
    )
    print(f"Findings saved: {saved_path}")

    # Record integrity hash.
    review_hash = hashlib.sha256(saved_path.read_bytes()).hexdigest()
    registry.record_hash(
        partner, use_case, version_number, "review",
        sha256_hash=review_hash, recorded_by="save_findings.py",
    )

    # Regenerate the full report from all findings in the store.
    from render_report import render_full_report, _parse_finding

    all_findings_data = registry.load_all_findings(partner, use_case, version_number)
    all_findings = [_parse_finding(item) for item in all_findings_data]
    report_content = render_full_report(all_findings)
    report_path = registry.save_report(partner, use_case, version_number, report_content)

    # Update registry entry with fresh computed counts.
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        findings_count[f.severity] = findings_count.get(f.severity, 0) + 1
    unverified_count = sum(1 for f in all_findings if f.verification == "unverified")
    findings_summary = format_summary(findings_count, unverified_count)
    stages_completed = sorted({f.stage for f in all_findings})

    registry.update_latest_version(
        partner_name=partner,
        use_case=use_case,
        findings_summary=findings_summary,
        findings_count=findings_count,
        stages_completed=stages_completed,
        status="reviewed",
    )

    print(f"Report rendered: {report_path}")
    print(f"  Total findings: {len(all_findings)}")
    print(f"  Summary: {findings_summary}")


if __name__ == "__main__":
    main()
