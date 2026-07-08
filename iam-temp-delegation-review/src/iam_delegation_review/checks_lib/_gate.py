"""Gate assembly with short-circuit.

Composes the individual validators and the render pass into one ``gate()`` entry
point that runs over a whole Bundle.

Order of operations:

1. Non-render-dependent validators run first over every artifact (JSON, size,
   Version, placeholder discipline). Hard-fail conditions are OR-ed together.
2. Short-circuit on any hard failure — return immediately with ``hard_fail=True``
   and an empty rendered list. No later stage runs.
3. Render both nominal and worst-case copies. Validate ARN structure on the
   nominal render only (see note below).
4. Optionally run ValidatePolicy on each rendered doc (opt-in, requires AWS creds).

ARN-render choice: validation runs on the nominal render because the worst-case
render collapses placeholders to ``*`` which would only produce a subset of
(or identical) structural findings. Validating both would risk double-reporting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..shared import Bundle, Finding, PolicyDoc
from ._render import render_bundle, validate_arns
from ._validators import (
    validate_json,
    validate_placeholder_discipline,
    validate_template_size,
    validate_version,
)
from ._size_risk import compute_size_risk

if TYPE_CHECKING:
    from . import GateResult


def _run_boundary_checks(boundary: PolicyDoc) -> tuple[list[Finding], bool]:
    """Run validators applicable to a boundary (no size limit check)."""
    findings: list[Finding] = []
    hard_fail = False
    for result in (
        validate_json(boundary),
        validate_version(boundary),
        validate_placeholder_discipline(boundary, is_boundary=True),
    ):
        findings.extend(result.findings)
        hard_fail = hard_fail or result.hard_fail
    return findings, hard_fail


def _run_template_checks(template: PolicyDoc) -> tuple[list[Finding], bool]:
    """Run validators applicable to a template (includes size limit)."""
    findings: list[Finding] = []
    hard_fail = False
    for result in (
        validate_json(template),
        validate_template_size(template),
        validate_version(template),
        validate_placeholder_discipline(template, is_boundary=False),
        compute_size_risk(template),
    ):
        findings.extend(result.findings)
        hard_fail = hard_fail or result.hard_fail
    return findings, hard_fail


def run_gate(
    bundle: Bundle,
    *,
    run_validate_policy: bool = False,
    aa_client_obj: Any = None,
) -> GateResult:
    """Compose the deterministic gate over a whole bundle.

    :param bundle: the bundle (templates + optional boundary) to gate.
    :param run_validate_policy: opt-in: run ValidatePolicy on rendered docs.
    :param aa_client_obj: injectable Access Analyzer client for tests.
    :returns: GateResult with findings, rendered bundles, and hard_fail flag.
    """
    from . import GateResult

    findings: list[Finding] = []
    hard_fail = False

    # 1. Non-render-dependent validators.
    if bundle.boundary is not None:
        boundary_findings, boundary_hard = _run_boundary_checks(bundle.boundary)
        findings.extend(boundary_findings)
        hard_fail = hard_fail or boundary_hard

    for template in bundle.templates:
        template_findings, template_hard = _run_template_checks(template)
        findings.extend(template_findings)
        hard_fail = hard_fail or template_hard

    # 2. Short-circuit on hard failure.
    if hard_fail:
        return GateResult(findings=findings, rendered=[], hard_fail=True)

    # 3. Render (both modes) and validate ARNs on nominal render only.
    nominal = render_bundle(bundle, "nominal")
    worst_case = render_bundle(bundle, "worst-case")

    nominal_docs: list[PolicyDoc] = list(nominal.bundle.templates)
    if nominal.bundle.boundary is not None:
        nominal_docs.append(nominal.bundle.boundary)
    for doc in nominal_docs:
        findings.extend(validate_arns(doc).findings)

    # 4. ValidatePolicy (opt-in, uses rendered copies).
    if run_validate_policy:
        from ..aa_client._validate_policy import validate_policy

        for doc in nominal_docs:
            findings.extend(validate_policy(doc, client=aa_client_obj))

    return GateResult(
        findings=findings,
        rendered=[nominal, worst_case],
        hard_fail=False,
    )


__all__ = ["run_gate"]
