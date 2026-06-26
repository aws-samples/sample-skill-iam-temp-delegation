"""Shared data-model types for the IAM Temporary Delegation Review Pipeline.

These types are the contract between every module in the core (checks_lib,
sar_lib, aa_client, registry, orchestrator).

This module MUST NOT import any other module in this project. It is pure
type/data definitions so it can be imported freely without creating cycles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# --- enumerations (string-literal unions, per the design) -------------------

VersionStatus = Literal["submitted", "reviewed", "packaged", "approved", "rejected"]
"""Lifecycle status of a recorded bundle version."""

FindingStage = Literal["gate", "provable", "reviewer", "verifier"]
"""Pipeline stage that produced a finding."""

Severity = Literal["low", "medium", "high", "critical"]
"""Severity of a finding."""

Verification = Literal["proof-backed", "verified", "unverified"]
"""Verification state of a finding:

- ``proof-backed``: deterministic PASS/FAIL from Access Analyzer.
- ``verified``: SAR-grounded (supporting SAR rows attached).
- ``unverified``: flagged for human review (no SAR row could be produced).
"""


# --- data models ------------------------------------------------------------


@dataclass
class PolicyDoc:
    """A parsed/raw IAM policy document.

    ``raw`` is the original text exactly as submitted (used for JSON
    well-formedness checks, size limits, and precise error locations).
    ``parsed`` is the JSON-parsed form when available; it is ``None`` when the
    document failed to parse.
    """

    #: Identifier for the document within a bundle (e.g. file name or label).
    id: str
    #: The original document text, exactly as submitted.
    raw: str
    #: The JSON-parsed document, when well-formed; otherwise None.
    parsed: Any | None = None


@dataclass
class Bundle:
    """The unit of review.

    Exactly one (optional) permission boundary plus one or more delegation
    templates for a single ``(partner_name, use_case)``.
    """

    partner_name: str
    use_case: str
    #: 1..n delegation templates, each <= 2048 chars.
    templates: list[PolicyDoc] = field(default_factory=list)
    #: 1:1 with use_case (enforced at intake). Optional in some submissions.
    boundary: PolicyDoc | None = None


@dataclass
class Version:
    """A single recorded version of a bundle.

    Versions are append-only; the baseline is the latest version whose status
    is ``approved``.
    """

    bundle: Bundle
    status: VersionStatus
    #: ISO-8601 timestamp when the version was submitted/recorded.
    submitted_at: str | None = None
    #: ISO-8601 timestamp; present once approved.
    approved_at: str | None = None
    approved_by: str | None = None
    #: Summary of findings from the pipeline run (e.g. "1 critical, 2 high").
    findings_summary: str | None = None
    #: Findings count by severity.
    findings_count: dict[str, int] | None = None
    #: Which pipeline stages completed successfully.
    stages_completed: list[str] | None = None


@dataclass
class RegistryEntry:
    """Append-only state for a single ``(partner_name, use_case)`` key.

    ``versions`` is ordered oldest-to-newest.
    """

    partner_name: str
    use_case: str
    versions: list[Version] = field(default_factory=list)


@dataclass
class SarRow:
    """A SAR (Service Authorization Reference) row.

    The authoritative mapping of an action to the resource types it supports
    and the condition keys it honors.
    """

    action: str
    resource_types: list[str] = field(default_factory=list)
    condition_keys: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single finding produced by any stage of the pipeline."""

    stage: FindingStage
    severity: Severity
    #: Which doc + statement the finding refers to.
    artifact_ref: str
    message: str
    verification: Verification
    #: Before/after fix example, where applicable.
    fix_before: str | None = None
    fix_after: str | None = None
    #: Supporting SAR row(s) for verified findings.
    sar_rows: list[SarRow] | None = None
    #: Resolution state: "accepted", "fixed", or None (open).
    disposition: str | None = None
    #: Justification for why an accepted finding's risk is acceptable.
    justification: str | None = None


# --- utility functions operating on the shared types ------------------------


def format_summary(counts: dict[str, int], unverified_count: int = 0) -> str:
    """Format a one-line findings summary from severity counts.

    This is the single canonical implementation of the summary format used by
    ``Report.summary``, ``run_review.py``, and ``update_review.py``.

    :param counts: mapping of severity level → count (e.g.
        ``{"critical": 1, "high": 2, "medium": 0, "low": 0}``).
    :param unverified_count: number of unverified findings requiring human
        review. Appended as a suffix when > 0.
    :returns: a formatted string like
        ``"1 critical, 2 high; 1 unverified require human review"`` or
        ``"No findings."`` when total is zero.
    """
    total = sum(counts.values())
    if total == 0:
        return "No findings."
    parts = [f"{c} {s}" for s, c in counts.items() if c > 0]
    sev_str = ", ".join(parts)
    if unverified_count:
        return f"{sev_str}; {unverified_count} unverified require human review"
    return sev_str
