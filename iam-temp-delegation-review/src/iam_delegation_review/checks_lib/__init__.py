"""checks_lib — deterministic lint + placeholder render pass.

Standalone library with no external dependencies beyond boto3 (for optional
ValidatePolicy). Implements the Stage 1 deterministic gate: JSON well-formedness,
2048-char session-policy limit, placeholder discipline, ARN structural format,
Version date check, and the nominal/worst-case render pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from ..shared import Bundle, Finding
from ._validators import (
    AWS_VARIABLE_PATTERN,
    CROSS_ACCOUNT_SERVICE_PREFIXES,
    PARTNER_PLACEHOLDER_PATTERN,
    RESOURCE_ACCOUNT_CONDITION_KEYS,
    TEMPLATE_SIZE_LIMIT,
    VALID_POLICY_VERSIONS,
    CheckResult,
    validate_boundary_resource_account,
    validate_json,
    validate_placeholder_discipline,
    validate_template_size,
    validate_version,
)
from ._size_risk import compute_size_risk

RenderMode = Literal["nominal", "worst-case"]
"""Which placeholder rendering a downstream check consumed."""


@dataclass
class RenderedBundle:
    """A bundle whose ``@{...}`` placeholders have been substituted."""

    bundle: Bundle
    mode: RenderMode


@dataclass
class GateResult:
    """Result of running the deterministic gate over a bundle."""

    findings: list[Finding] = field(default_factory=list)
    rendered: list[RenderedBundle] = field(default_factory=list)
    #: True when a hard failure should short-circuit later stages.
    hard_fail: bool = False


def gate(
    bundle: Bundle,
    *,
    run_validate_policy: bool = False,
    aa_client_obj: Any = None,
) -> GateResult:
    """Run the deterministic gate over a bundle.

    Composes validators over every artifact, then (if no hard failure) renders
    and validates ARN structure. On hard failure, short-circuits and returns
    immediately with an empty rendered list.

    When ``run_validate_policy=True``, Access Analyzer's ValidatePolicy is run
    on each rendered doc. This is opt-in so the gate can run without AWS creds.

    :param bundle: templates + optional boundary to gate.
    :param run_validate_policy: opt-in ValidatePolicy execution.
    :param aa_client_obj: injectable Access Analyzer client for tests.
    :returns: GateResult with findings, rendered bundles, and hard_fail flag.
    """
    from ._gate import run_gate

    return run_gate(
        bundle,
        run_validate_policy=run_validate_policy,
        aa_client_obj=aa_client_obj,
    )


from ._render import (  # noqa: E402
    ARN_PREFIX,
    ARN_SEGMENT_COUNT,
    NOMINAL_PLACEHOLDER_VALUE,
    WORST_CASE_PLACEHOLDER_VALUE,
    is_structurally_valid_arn,
    render_bundle,
    render_doc,
    render_text,
    validate_arns,
)

__all__ = [
    "RenderMode",
    "RenderedBundle",
    "GateResult",
    "gate",
    "CheckResult",
    "TEMPLATE_SIZE_LIMIT",
    "VALID_POLICY_VERSIONS",
    "validate_json",
    "validate_template_size",
    "validate_version",
    "PARTNER_PLACEHOLDER_PATTERN",
    "AWS_VARIABLE_PATTERN",
    "validate_placeholder_discipline",
    "validate_boundary_resource_account",
    "CROSS_ACCOUNT_SERVICE_PREFIXES",
    "RESOURCE_ACCOUNT_CONDITION_KEYS",
    "compute_size_risk",
    "NOMINAL_PLACEHOLDER_VALUE",
    "WORST_CASE_PLACEHOLDER_VALUE",
    "ARN_PREFIX",
    "ARN_SEGMENT_COUNT",
    "render_text",
    "render_doc",
    "render_bundle",
    "is_structurally_valid_arn",
    "validate_arns",
]
