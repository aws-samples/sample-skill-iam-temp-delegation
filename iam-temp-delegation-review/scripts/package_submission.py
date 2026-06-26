"""Package a reviewed policy bundle into a submission-ready directory.

Usage:
    python scripts/package_submission.py <partner> <use_case> <template_path> [<boundary_path>]

Verifies all findings are resolved (accepted or fixed), checks integrity
hashes, and produces a submission bundle ready for IAM registration.
"""

import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add the skill-local source to the path
_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

from iam_delegation_review.shared import format_summary
from iam_delegation_review.registry import create_registry
from iam_delegation_review.registry._file_store import _validate_path_component


def _sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_dispositions(findings_data: list[dict]) -> list[dict]:
    """Check that all reviewer/verifier findings have a resolved disposition.

    Stage 1-2 findings (gate, provable) are proof-backed and do not require
    disposition — they are informational outputs from the deterministic pipeline.
    Only Stage 3-4 findings (reviewer, verifier) require explicit resolution.

    Returns the list of open (unresolved) findings.
    """
    open_findings: list[dict] = []
    for f in findings_data:
        # Stage 1-2 findings don't require disposition.
        if f.get("stage") in ("gate", "provable"):
            continue
        disposition = f.get("disposition")
        if disposition not in ("accepted", "fixed"):
            open_findings.append(f)
    return open_findings


def _verify_integrity(
    registry, partner: str, use_case: str, version_number: int,
    template_path: Path, boundary_path: Path | None,
) -> list[str]:
    """Verify SHA-256 hashes against the integrity manifest.

    Returns a list of error messages for any mismatches. Empty list = all good.
    """
    errors: list[str] = []
    manifest = registry.load_integrity_manifest(partner, use_case, version_number)

    if manifest is None:
        errors.append("No integrity manifest found — run the pipeline first")
        return errors

    hashes = manifest.get("hashes", {})

    # Check template.
    if "template" in hashes:
        expected = hashes["template"]["sha256"]
        actual = _sha256(template_path)
        if actual != expected:
            errors.append(
                f"Template modified since review: {template_path}\n"
                f"  Expected: {expected}\n"
                f"  Actual:   {actual}"
            )

    # Check boundary.
    if boundary_path and "boundary" in hashes:
        expected = hashes["boundary"]["sha256"]
        actual = _sha256(boundary_path)
        if actual != expected:
            errors.append(
                f"Boundary modified since review: {boundary_path}\n"
                f"  Expected: {expected}\n"
                f"  Actual:   {actual}"
            )

    # Check findings files.
    for label in ("checks", "review"):
        if label in hashes:
            findings_path = registry._findings_path(
                partner, use_case, version_number, label
            )
            if findings_path.exists():
                expected = hashes[label]["sha256"]
                actual = _sha256(findings_path)
                if actual != expected:
                    errors.append(
                        f"Findings '{label}' modified since pipeline wrote them:\n"
                        f"  Expected: {expected}\n"
                        f"  Actual:   {actual}"
                    )

    return errors


def main() -> None:
    if len(sys.argv) < 3:
        print(
            "Usage: python package_submission.py <partner> <use_case> [<version_number>]"
        )
        sys.exit(1)

    partner = sys.argv[1]
    use_case = sys.argv[2]

    # Validate inputs.
    _validate_path_component(partner, "partner")
    _validate_path_component(use_case, "use_case")

    # Load registry.
    registry = create_registry(Path("registry"))
    entry = registry.get(partner, use_case)

    if entry is None:
        print(f"Error: No registry entry for ({partner}, {use_case})")
        sys.exit(1)
    if not entry.versions:
        print(f"Error: No versions for ({partner}, {use_case})")
        sys.exit(1)

    # Determine version number.
    if len(sys.argv) >= 4:
        version_number = int(sys.argv[3])
    else:
        version_number = len(entry.versions)

    # Resolve artifact paths from the registry.
    art_dir = registry.artifacts_dir(partner, use_case, version_number)
    template_path = art_dir / "delegation_template.json"
    boundary_path = art_dir / "permission_boundary.json"

    if not template_path.exists():
        print(f"Error: Template not found in registry: {template_path}")
        print("Run run_checks.py first to ingest artifacts.")
        sys.exit(1)

    has_boundary = boundary_path.exists()

    # --- Gate 1: Verify integrity ---
    print("Verifying integrity...")
    integrity_errors = _verify_integrity(
        registry, partner, use_case, version_number,
        template_path, boundary_path if has_boundary else None,
    )
    if integrity_errors:
        print("\n⛔ INTEGRITY CHECK FAILED:")
        for err in integrity_errors:
            print(f"  • {err}")
        print("\nArtifacts were modified after the review. Re-run the pipeline first.")
        sys.exit(1)
    print("  ✅ All hashes match")

    # --- Gate 2: Check all findings are resolved ---
    print("Checking finding dispositions...")
    all_findings_data = registry.load_all_findings(partner, use_case, version_number)

    open_findings = _check_dispositions(all_findings_data)
    if open_findings:
        print(f"\n⛔ {len(open_findings)} OPEN FINDING(S) — must be accepted or fixed:\n")
        for i, f in enumerate(open_findings, 1):
            print(f"  {i}. [{f['severity'].upper()}] {f['message']}")
            print(f"     Artifact: {f['artifact_ref']}")
            print()
        print("Add 'disposition' and 'justification' to each finding in the")
        print("review JSON, then re-run save_findings.py.")
        sys.exit(1)
    print(f"  ✅ All {len(all_findings_data)} findings resolved")

    # --- Package the submission bundle ---
    bundle_dir = registry._submissions_dir / f"{partner}__{use_case}__v{version_number}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # Copy template as-is from registry artifacts.
    shutil.copy2(template_path, bundle_dir / "delegation_template.json")

    # Copy boundary as-is (if present).
    if has_boundary:
        shutil.copy2(boundary_path, bundle_dir / "permission_boundary.json")

    # Copy review report.
    report_path = Path("registry") / "reports" / f"{partner}__{use_case}__v{version_number}.md"
    if report_path.exists():
        shutil.copy2(report_path, bundle_dir / "review_report.md")

    # Extract accepted findings.
    accepted = [f for f in all_findings_data if f.get("disposition") == "accepted"]
    (bundle_dir / "accepted_findings.json").write_text(
        json.dumps(accepted, indent=2) + "\n"
    )

    # Copy integrity manifest.
    manifest_data = registry.load_integrity_manifest(partner, use_case, version_number)
    if manifest_data:
        (bundle_dir / "integrity.json").write_text(
            json.dumps(manifest_data, indent=2) + "\n"
        )

    # Generate submission manifest.
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings_data:
        findings_count[f["severity"]] = findings_count.get(f["severity"], 0) + 1
    unverified_count = sum(1 for f in all_findings_data if f.get("verification") == "unverified")

    # Load bundle metadata from artifacts (if present).
    bundle_metadata = {}
    metadata_file = art_dir / "bundle_metadata.json"
    if metadata_file.exists():
        bundle_metadata = json.loads(metadata_file.read_text())

    submission_manifest = {
        "partner_name": partner,
        "use_case": use_case,
        "version": version_number,
        "packaged_at": datetime.now(timezone.utc).isoformat(),
        "template_name": bundle_metadata.get("template_name"),
        "template_description": bundle_metadata.get("template_description"),
        "boundary_name": bundle_metadata.get("boundary_name"),
        "boundary_description": bundle_metadata.get("boundary_description"),
        "artifacts": {
            "delegation_template": "delegation_template.json",
            "permission_boundary": "permission_boundary.json" if has_boundary else None,
        },
        "review": {
            "total_findings": len(all_findings_data),
            "open_findings": 0,
            "accepted_findings": len(accepted),
            "findings_summary": format_summary(findings_count, unverified_count),
            "stages_completed": sorted({f["stage"] for f in all_findings_data}),
            "report": "review_report.md",
        },
        "source": {
            "artifacts_dir": str(art_dir),
        },
    }
    (bundle_dir / "manifest.json").write_text(
        json.dumps(submission_manifest, indent=2) + "\n"
    )

    # Update registry entry status to "packaged".
    registry.update_latest_version(
        partner_name=partner,
        use_case=use_case,
        findings_summary=format_summary(findings_count, unverified_count),
        findings_count=findings_count,
        stages_completed=sorted({f["stage"] for f in all_findings_data}),
        status="packaged",
    )

    print(f"\n✅ Submission bundle packaged: {bundle_dir}/")
    print(f"   Version: v{version_number}")
    print(f"   Template: delegation_template.json")
    if has_boundary:
        print(f"   Boundary: permission_boundary.json")
    print(f"   Report: review_report.md")
    print(f"   Accepted findings: {len(accepted)}")
    print(f"   Integrity manifest: integrity.json")
    print(f"   Status: packaged")


if __name__ == "__main__":
    main()
