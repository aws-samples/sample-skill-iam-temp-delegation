"""Consolidated findings report assembly and formatting.

Produces a structured, human-readable markdown report from pipeline findings.
Groups findings by verification state, distinguishes proof-backed from
agent-reasoned findings, and flags unverified findings for human review.
"""

from __future__ import annotations

from ..shared import Finding, Severity

# Severity ordering for sorting (critical first).
_SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (critical first)."""
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Count findings by severity."""
    counts: dict[Severity, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _format_finding(finding: Finding, index: int) -> str:
    """Format a single finding as markdown."""
    lines: list[str] = []
    lines.append(f"### {index}. [{finding.severity.upper()}] {finding.message}")
    lines.append("")
    lines.append(f"- **Stage:** {finding.stage}")
    lines.append(f"- **Severity:** {finding.severity}")
    lines.append(f"- **Artifact:** {finding.artifact_ref}")
    lines.append(f"- **Verification:** {finding.verification}")

    if finding.disposition is not None:
        lines.append(f"- **Disposition:** {finding.disposition}")
        if finding.justification:
            lines.append(f"- **Justification:** {finding.justification}")

    if finding.fix_before is not None:
        lines.append("")
        lines.append("**Before:**")
        lines.append(f"```json\n{finding.fix_before}\n```")

    if finding.fix_after is not None:
        lines.append("")
        lines.append("**After (suggested fix):**")
        lines.append(f"```json\n{finding.fix_after}\n```")

    if finding.sar_rows:
        lines.append("")
        lines.append("**SAR evidence:**")
        for row in finding.sar_rows:
            resources = ", ".join(row.resource_types) if row.resource_types else "(none)"
            keys = ", ".join(row.condition_keys) if row.condition_keys else "(none)"
            lines.append(f"- `{row.action}` → resources: [{resources}], keys: [{keys}]")

    return "\n".join(lines)


def _format_section(
    title: str,
    findings: list[Finding],
    *,
    start_index: int = 1,
    preamble: str | None = None,
    heading_level: int = 2,
) -> str:
    """Format a section of findings with a title and optional preamble."""
    if not findings:
        return ""

    heading_prefix = "#" * heading_level
    lines: list[str] = []
    lines.append(f"{heading_prefix} {title}")
    lines.append("")
    if preamble:
        lines.append(preamble)
        lines.append("")

    sorted_findings = _sort_findings(findings)
    for i, finding in enumerate(sorted_findings, start=start_index):
        lines.append(_format_finding(finding, i))
        lines.append("")

    return "\n".join(lines)


def format_report(findings: list[Finding]) -> str:
    """Format pipeline findings into a consolidated markdown report.

    The report:
    - Groups findings by verification state (proof-backed, verified, unverified).
    - Distinguishes proof-backed findings (from Access Analyzer) from
      agent-reasoned ones.
    - Flags unverified findings with a clear marker for human review.
    - Includes all fields per finding: stage, severity, artifact ref,
      before/after fix, verification state.
    - Sorts by severity (critical first) within each section.

    Parameters
    ----------
    findings:
        The list of findings from the pipeline (all stages combined).

    Returns
    -------
    str
        A markdown-formatted report string.
    """
    # Partition findings by verification state.
    proof_backed: list[Finding] = []
    verified: list[Finding] = []
    unverified: list[Finding] = []

    for f in findings:
        if f.verification == "proof-backed":
            proof_backed.append(f)
        elif f.verification == "verified":
            verified.append(f)
        else:
            unverified.append(f)

    # Build summary counts.
    total = len(findings)
    sev_counts = _severity_counts(findings)
    sev_parts = [
        f"{count} {level}" for level, count in sev_counts.items() if count > 0
    ]
    sev_summary = ", ".join(sev_parts) if sev_parts else "none"

    verification_parts: list[str] = []
    if proof_backed:
        verification_parts.append(f"{len(proof_backed)} proof-backed")
    if verified:
        verification_parts.append(f"{len(verified)} verified")
    if unverified:
        verification_parts.append(f"{len(unverified)} unverified")
    verification_summary = ", ".join(verification_parts) if verification_parts else "none"

    # Assemble the report.
    sections: list[str] = []

    # Header
    sections.append("# IAM Delegation Review — Findings Report")
    sections.append("")
    sections.append("## Stage 1-2 Summary (Deterministic Pipeline)")
    sections.append("")
    sections.append(f"**Total findings:** {total}")
    sections.append(f"**By severity:** {sev_summary}")
    sections.append(f"**By verification:** {verification_summary}")
    sections.append("")

    if unverified:
        sections.append(
            f"> ⚠️ **{len(unverified)} finding(s) are unverified and require human review.**"
        )
        sections.append("")

    # Empty report shortcut.
    if total == 0:
        sections.append("No findings from deterministic checks (gate validation, Access Analyzer).")
        sections.append("")
        return "\n".join(sections)

    # Track running index across sections.
    idx = 1

    # Proof-backed findings are split by source: deterministic gate checks vs
    # Access Analyzer provable checks. Both are authoritative, but the source
    # differs and users should see which came from AA vs local lint.
    gate_proof = [f for f in proof_backed if f.stage == "gate"]
    aa_proof = [f for f in proof_backed if f.stage != "gate"]

    if gate_proof:
        section = _format_section(
            "Deterministic Gate Findings",
            gate_proof,
            start_index=idx,
            preamble=(
                "These findings are from deterministic, local checks (JSON validation, "
                "size limits, placeholder discipline, ARN structure). They are "
                "authoritative and do not require AWS API calls."
            ),
        )
        sections.append(section)
        idx += len(gate_proof)

    if aa_proof:
        section = _format_section(
            "Proof-Backed Findings (Access Analyzer)",
            aa_proof,
            start_index=idx,
            preamble=(
                "These findings are backed by mathematical proof from IAM Access Analyzer. "
                "They are deterministic and authoritative."
            ),
        )
        sections.append(section)
        idx += len(aa_proof)

    # Verified section.
    if verified:
        section = _format_section(
            "Verified Findings (SAR-Grounded)",
            verified,
            start_index=idx,
            preamble=(
                "These findings have been independently verified against the "
                "AWS Service Authorization Reference (SAR)."
            ),
        )
        sections.append(section)
        idx += len(verified)

    # Unverified section.
    if unverified:
        section = _format_section(
            "⚠️ Unverified Findings — Human Review Required",
            unverified,
            start_index=idx,
            preamble=(
                "These findings could not be independently verified against the SAR. "
                "They are agent-reasoned and require human review before action."
            ),
        )
        sections.append(section)

    return "\n".join(sections)
