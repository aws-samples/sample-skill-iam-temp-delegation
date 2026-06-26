"""Internal type definitions for the orchestrator module.

Separated from __init__.py to avoid circular imports between __init__.py
and _intake.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ..shared import Bundle, Finding, Severity, format_summary

Operation = Literal["onboard", "update"]
"""Operation classification, derived from registry state (not submitter input)."""


@dataclass
class ClassifiedBundle:
    """A bundle assembled and classified at intake (Stage 0)."""

    bundle: Bundle
    operation: Operation
    key: str


@dataclass
class Report:
    """The consolidated findings report.

    Provides computed properties for filtering by verification state and
    summarising severity counts. The ``format()`` method produces a
    human-readable markdown report.
    """

    findings: list[Finding] = field(default_factory=list)

    # --- computed properties ------------------------------------------------

    @property
    def proof_backed_findings(self) -> list[Finding]:
        """Findings backed by mathematical proof (Access Analyzer)."""
        return [f for f in self.findings if f.verification == "proof-backed"]

    @property
    def verified_findings(self) -> list[Finding]:
        """Findings independently verified against the SAR."""
        return [f for f in self.findings if f.verification == "verified"]

    @property
    def unverified_findings(self) -> list[Finding]:
        """Findings that require human review (not SAR-grounded)."""
        return [f for f in self.findings if f.verification == "unverified"]

    @property
    def has_critical(self) -> bool:
        """Whether any finding has critical severity."""
        return any(f.severity == "critical" for f in self.findings)

    @property
    def summary(self) -> str:
        """Brief one-line summary of the report contents."""
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return format_summary(counts, len(self.unverified_findings))

    def format(self) -> str:
        """Produce a human-readable markdown report.

        Groups findings by verification state, distinguishes proof-backed from
        agent-reasoned, and flags unverified for human review.
        """
        from ._report import format_report

        return format_report(self.findings)
