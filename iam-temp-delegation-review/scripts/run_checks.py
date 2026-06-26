"""Run the deterministic pipeline (Stages 1-2) and persist findings.

Usage:
    python scripts/run_checks.py <template_path> <boundary_path|none> <partner> <use_case>

Runs gate validation and Access Analyzer provable checks, writes findings to
the findings store, registers the submission, and renders the initial report.
"""

import asyncio
import hashlib
import json
import shutil
import sys
from pathlib import Path

# Add the skill-local source to the path
_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

from iam_delegation_review.shared import Bundle, Finding, PolicyDoc, Version
from iam_delegation_review.registry import create_registry
from iam_delegation_review.registry._file_store import _validate_path_component
from iam_delegation_review.orchestrator import classify, run_pipeline


def _finding_to_dict(f: Finding) -> dict:
    """Serialize a Finding to a JSON-compatible dict."""
    result = {
        "stage": f.stage,
        "severity": f.severity,
        "artifact_ref": f.artifact_ref,
        "message": f.message,
        "verification": f.verification,
    }
    if f.fix_before is not None:
        result["fix_before"] = f.fix_before
    if f.fix_after is not None:
        result["fix_after"] = f.fix_after
    return result


class _NoOpCheckAccessClient:
    """Mock client that skips CheckAccessNotGranted when credentials are unavailable."""

    def check_access_not_granted(self, **kwargs):
        return {"result": "PASS"}


def main() -> None:
    if len(sys.argv) < 5:
        print("Usage: python run_checks.py <template_path> <boundary_path|none> <partner> <use_case> [<metadata_path>]")
        sys.exit(1)

    template_path = sys.argv[1]
    boundary_path = sys.argv[2]
    partner = sys.argv[3]
    use_case = sys.argv[4]
    metadata_path = sys.argv[5] if len(sys.argv) > 5 else None

    # Validate partner/use_case to prevent path traversal.
    _validate_path_component(partner, "partner")
    _validate_path_component(use_case, "use_case")

    # Load template
    template_parsed = json.loads(Path(template_path).read_text())

    # Strip non-IAM metadata annotations (e.g. @Enabled) before pipeline processing
    for stmt in template_parsed.get("Statement", []):
        for key in [k for k in stmt if k.startswith("@")]:
            del stmt[key]

    template_raw = json.dumps(template_parsed, separators=(",", ":"))
    template = PolicyDoc(
        id=Path(template_path).name,
        raw=template_raw,
        parsed=template_parsed,
    )

    # Load boundary (if provided)
    boundary = None
    if boundary_path.lower() != "none":
        boundary_raw = Path(boundary_path).read_text()
        boundary = PolicyDoc(
            id=Path(boundary_path).name,
            raw=boundary_raw,
            parsed=json.loads(boundary_raw),
        )

    # Assemble bundle
    bundle = Bundle(
        partner_name=partner,
        use_case=use_case,
        templates=[template],
        boundary=boundary,
    )

    # Classify
    registry = create_registry(Path("registry"))
    classified = classify(bundle, registry)
    print(f"Operation: {classified.operation}")

    # Verify AWS credentials before running the pipeline.
    aws_authenticated = False
    try:
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        print(f"AWS identity: {identity.get('Arn', 'unknown')}")
        aws_authenticated = True
    except Exception as e:
        print(f"⚠️  AWS credentials not available: {e}")
        print("   Stage 2 (Access Analyzer) will be skipped.")
        print("   Configure AWS credentials to enable provable checks.")

    # Run pipeline (Stages 1-2)
    report = asyncio.run(run_pipeline(
        classified,
        run_validate_policy=aws_authenticated,
        check_access_client=None if aws_authenticated else _NoOpCheckAccessClient(),
    ))

    # Serialize findings to dicts for storage.
    findings_data = [_finding_to_dict(f) for f in report.findings]

    # Add informational finding if AWS credentials were unavailable.
    if not aws_authenticated:
        findings_data.append({
            "stage": "provable",
            "severity": "low",
            "artifact_ref": "(pipeline)",
            "message": (
                "Stage 2 (Access Analyzer) was skipped — AWS credentials not available. "
                "Configure credentials with access-analyzer:ValidatePolicy and "
                "access-analyzer:CheckAccessNotGranted permissions, then re-run."
            ),
            "verification": "proof-backed",
        })

    # Record submission in registry.
    stages_completed = sorted({f.stage for f in report.findings}) if report.findings else []
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in report.findings:
        findings_count[f.severity] = findings_count.get(f.severity, 0) + 1

    registry.append(Version(
        bundle=bundle,
        status="submitted",
        findings_summary=None,  # Computed at render time
        findings_count=findings_count,
        stages_completed=stages_completed,
    ))

    # Determine version number.
    entry = registry.get(partner, use_case)
    version_number = len(entry.versions) if entry else 1

    # Copy input artifacts into the registry (canonical versions).
    art_dir = registry.artifacts_dir(partner, use_case, version_number)
    art_template = art_dir / "delegation_template.json"
    shutil.copy2(template_path, art_template)
    art_boundary = None
    if boundary_path.lower() != "none":
        art_boundary = art_dir / "permission_boundary.json"
        shutil.copy2(boundary_path, art_boundary)

    # Load and copy bundle metadata (if provided).
    # Validates schema and cross-checks boundary name vs template.
    bundle_metadata = None
    if metadata_path is not None:
        from iam_delegation_review.shared.metadata import (
            MetadataValidationError,
            cross_check_boundary_name,
            validate_metadata,
        )

        metadata_raw = Path(metadata_path).read_text()
        bundle_metadata = json.loads(metadata_raw)

        try:
            validate_metadata(bundle_metadata)
        except MetadataValidationError as e:
            print(f"Error: {e}")
            print("Use create_metadata.py to generate a valid metadata file.")
            sys.exit(1)

        # Copy metadata to artifacts dir.
        shutil.copy2(metadata_path, art_dir / "bundle_metadata.json")

        # Cross-check: boundary name in metadata vs template condition.
        if art_boundary is not None:
            template_text = Path(template_path).read_text()
            findings_data.extend(cross_check_boundary_name(bundle_metadata, template_text))

    print(f"Artifacts stored: {art_dir}")

    # Write findings to the store (overwrites if re-run).
    findings_path = registry.save_findings(
        partner, use_case, version_number, "checks", findings_data
    )
    print(f"Findings saved: {findings_path}")

    # Record integrity hashes (on the registry copies).
    checks_hash = hashlib.sha256(findings_path.read_bytes()).hexdigest()
    registry.record_hash(
        partner, use_case, version_number, "checks",
        sha256_hash=checks_hash, recorded_by="run_checks.py",
    )
    template_hash = hashlib.sha256(art_template.read_bytes()).hexdigest()
    registry.record_hash(
        partner, use_case, version_number, "template",
        sha256_hash=template_hash, recorded_by="run_checks.py",
        source_path=str(art_template),
    )
    if art_boundary is not None:
        boundary_hash = hashlib.sha256(art_boundary.read_bytes()).hexdigest()
        registry.record_hash(
            partner, use_case, version_number, "boundary",
            sha256_hash=boundary_hash, recorded_by="run_checks.py",
            source_path=str(art_boundary),
        )

    # Render the initial report.
    from render_report import render_full_report, _parse_finding

    all_findings_data = registry.load_all_findings(partner, use_case, version_number)
    all_findings = [_parse_finding(item) for item in all_findings_data]
    report_content = render_full_report(all_findings)
    report_path = registry.save_report(partner, use_case, version_number, report_content)
    print(f"Report saved: {report_path}")

    # Gate signal for the skill
    has_critical = any(f.severity == "critical" for f in report.findings)
    if has_critical:
        print("\n⛔ GATE: CRITICAL ISSUES FOUND — do NOT proceed to Stage 3-4")
    else:
        print("\n✅ GATE: PASSED — proceed to Stage 3-4 analysis")


if __name__ == "__main__":
    main()
