"""Pipeline execution — Stages 1-2.

Implements the deterministic stage sequencing with short-circuit semantics:
    gate → provable semantics → report

On a hard-fail from the gate (invalid JSON, size limit, boundary placeholder
misuse): short-circuits and returns gate findings immediately. No later stage
runs.

The provable stage always receives the worst-case rendered bundle (never raw
``@{...}`` documents).

Stages 3-4 (reviewer + verifier) are performed by Kiro itself using the
procedure-reviewer and procedure-verifier reference docs.
"""

from __future__ import annotations

from typing import Any

from ..aa_client import (
    DEFAULT_CRITICAL_DENYLIST,
    CriticalDenylist,
    check_access_not_granted,
)
from ..checks_lib import GateResult, RenderedBundle, gate
from ..shared import Bundle, Finding
from ._types import ClassifiedBundle, Report


async def run_pipeline(
    classified: ClassifiedBundle,
    *,
    run_validate_policy: bool = False,
    aa_client_obj: Any = None,
    check_access_client: Any = None,
    check_public_access_client: Any = None,
    denylist: CriticalDenylist | None = None,
) -> Report:
    """Run the deterministic review pipeline (Stages 1-2) over a classified bundle.

    :param classified: classified bundle from Stage 0 (intake & classify).
    :param run_validate_policy: whether to run ValidatePolicy in the gate.
    :param aa_client_obj: injectable client for ValidatePolicy.
    :param check_access_client: injectable client for CheckAccessNotGranted.
    :param check_public_access_client: injectable client for CheckNoPublicAccess.
    :param denylist: critical-permission denylist override.
    :returns: consolidated findings report.
    """
    bundle: Bundle = classified.bundle
    effective_denylist = denylist if denylist is not None else DEFAULT_CRITICAL_DENYLIST

    # ─── Stage 1: Deterministic Gate ────────────────────────────────────────
    gate_result: GateResult = gate(
        bundle,
        run_validate_policy=run_validate_policy,
        aa_client_obj=aa_client_obj,
    )

    # Short-circuit on hard failure.
    if gate_result.hard_fail:
        return Report(findings=gate_result.findings)

    # ─── Stage 2: Provable Semantics ───────────────────────────────────────
    provable_findings: list[Finding] = []

    # Use the worst-case rendered bundle for provable checks.
    worst_case_rendered: RenderedBundle = gate_result.rendered[1]

    # CheckAccessNotGranted against critical-permission denylist.
    provable_findings.extend(
        check_access_not_granted(
            worst_case_rendered,
            effective_denylist,
            client=check_access_client,
        )
    )

    # CheckNoPublicAccess — deferred until bundle typing supports resource-based policies.
    if worst_case_rendered.bundle.boundary is not None:
        pass  # Resource-policy check wired but not active for identity-policy bundles.

    # ─── Stages 3-4 handled by Kiro via SKILL.md ───────────────────────────

    # ─── Assemble Report ───────────────────────────────────────────────────
    all_findings: list[Finding] = gate_result.findings + provable_findings
    return Report(findings=all_findings)
