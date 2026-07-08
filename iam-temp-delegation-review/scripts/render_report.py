"""Render a full findings report from the findings store.

Usage:
    python scripts/render_report.py <partner> <use_case> [<version_number>]

Reads all findings files for the specified version (checks.json + review.json),
computes counts fresh, and generates a complete markdown report. Always
overwrites the report file — idempotent by design.

If version_number is omitted, uses the latest version from the registry entry.
"""

import json
import sys
from pathlib import Path

# Add the skill-local source to the path
_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

from iam_delegation_review.shared import Finding, format_summary
from iam_delegation_review.registry import create_registry
from iam_delegation_review.registry._file_store import _validate_path_component
from iam_delegation_review.orchestrator._report import (
    _format_section,
    _severity_counts,
    _sort_findings,
)


def _parse_finding(item: dict) -> Finding:
    """Parse a single finding dict into a Finding object."""
    return Finding(
        stage=item["stage"],
        severity=item["severity"],
        artifact_ref=item["artifact_ref"],
        message=item["message"],
        verification=item["verification"],
        fix_before=item.get("fix_before"),
        fix_after=item.get("fix_after"),
        disposition=item.get("disposition"),
        justification=item.get("justification"),
        sar_rows=None,
    )


def render_full_report(all_findings: list[Finding]) -> str:
    """Render a complete markdown report from all findings across all stages.

    Groups findings by stage and verification state, computes summary
    counts fresh from the findings list.
    """
    # Partition by stage source.
    checks_findings = [f for f in all_findings if f.stage in ("gate", "provable")]
    review_findings = [f for f in all_findings if f.stage in ("reviewer", "verifier")]

    # Compute overall summary.
    total = len(all_findings)
    sev_counts = _severity_counts(all_findings)
    unverified_count = sum(1 for f in all_findings if f.verification == "unverified")

    sections: list[str] = []

    # --- Header ---
    sections.append("# IAM Delegation Review — Findings Report")
    sections.append("")

    # --- Stage 1-2 Summary ---
    checks_total = len(checks_findings)
    checks_sev = _severity_counts(checks_findings)
    checks_sev_parts = [f"{c} {s}" for s, c in checks_sev.items() if c > 0]
    checks_sev_str = ", ".join(checks_sev_parts) if checks_sev_parts else "none"

    sections.append("## Stage 1-2 Summary (Deterministic Pipeline)")
    sections.append("")
    sections.append(f"**Total findings:** {checks_total}")
    sections.append(f"**By severity:** {checks_sev_str}")
    sections.append("")

    if checks_total == 0:
        sections.append("No findings from deterministic checks (gate validation, Access Analyzer).")
        sections.append("")
    else:
        # Render gate findings.
        gate_findings = [f for f in checks_findings if f.stage == "gate"]
        aa_findings = [f for f in checks_findings if f.stage == "provable"]
        idx = 1

        if gate_findings:
            section = _format_section(
                "Deterministic Gate Findings",
                gate_findings,
                start_index=idx,
                heading_level=3,
                preamble=(
                    "These findings are from deterministic, local checks (JSON validation, "
                    "size limits, placeholder discipline, ARN structure). They are "
                    "authoritative and do not require AWS API calls."
                ),
            )
            sections.append(section)
            idx += len(gate_findings)

        if aa_findings:
            section = _format_section(
                "Proof-Backed Findings (Access Analyzer)",
                aa_findings,
                start_index=idx,
                heading_level=3,
                preamble=(
                    "These findings are backed by mathematical proof from IAM Access Analyzer. "
                    "They are deterministic and authoritative."
                ),
            )
            sections.append(section)

    # --- Stage 3-4 Section ---
    if review_findings:
        reviewer_findings = [f for f in review_findings if f.stage == "reviewer"]
        verifier_findings = [f for f in review_findings if f.stage == "verifier"]

        verified = [f for f in reviewer_findings if f.verification == "verified"]
        unverified = [f for f in reviewer_findings if f.verification == "unverified"]

        idx = len(checks_findings) + 1

        if verified:
            section = _format_section(
                "Stage 3: Reviewer Findings (Verified)",
                verified,
                start_index=idx,
                preamble=(
                    "These findings from semantic analysis have been verified "
                    "against the AWS Service Authorization Reference (SAR)."
                ),
            )
            sections.append(section)
            idx += len(verified)

        if unverified:
            section = _format_section(
                "Stage 3: Reviewer Findings (Unverified — Human Review Required)",
                unverified,
                start_index=idx,
                preamble=(
                    "These findings from semantic analysis could not be fully "
                    "verified and require human review."
                ),
            )
            sections.append(section)
            idx += len(unverified)

        if verifier_findings:
            section = _format_section(
                "Stage 4: Verifier Findings",
                verifier_findings,
                start_index=idx,
                preamble="Cross-check findings from the verification stage.",
            )
            sections.append(section)
    else:
        sections.append("## Stage 3-4 Summary (Semantic Analysis)")
        sections.append("")
        sections.append("No additional findings from semantic review.")
        sections.append("")

    # --- Combined Summary (at the end) ---
    sections.append("---")
    sections.append("")
    sections.append("## Summary")
    sections.append("")
    sections.append(f"**Total findings:** {total}")
    combined_summary = format_summary(sev_counts, unverified_count)
    sections.append(f"**Combined:** {combined_summary}")
    sections.append("")

    if unverified_count:
        sections.append(
            f"> ⚠️ **{unverified_count} finding(s) are unverified and require human review.**"
        )
        sections.append("")

    return "\n".join(sections)


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python render_report.py <partner> <use_case> [<version_number>]")
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
        print(f"Error: No registry entry found for ({partner}, {use_case})")
        sys.exit(1)

    if not entry.versions:
        print(f"Error: Registry entry for ({partner}, {use_case}) has no versions")
        sys.exit(1)

    # Determine version number.
    if len(sys.argv) >= 4:
        version_number = int(sys.argv[3])
    else:
        version_number = len(entry.versions)

    # Load all findings for this version.
    all_findings_data = registry.load_all_findings(partner, use_case, version_number)
    all_findings = [_parse_finding(item) for item in all_findings_data]

    # Render the full report.
    report_content = render_full_report(all_findings)

    # Write (overwrite) the report file.
    report_path = registry.save_report(partner, use_case, version_number, report_content)

    # Update registry entry with fresh computed counts (exclude info).
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        if f.severity == "info":
            continue
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
    )

    print(f"Report rendered: {report_path}")
    print(f"  Total findings: {len(all_findings)}")
    print(f"  Summary: {findings_summary}")


if __name__ == "__main__":
    main()
