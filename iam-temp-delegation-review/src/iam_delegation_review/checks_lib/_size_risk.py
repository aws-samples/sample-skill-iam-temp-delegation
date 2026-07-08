"""Template size risk analysis — deterministic context for LLM limit review.

Computes the minified template size, identifies all ``@{...}`` parameters with
their occurrence counts, and emits an informational finding that provides the
LLM reviewer with the data needed to assess whether parameter substitution
could push the rendered policy past the 2048-character session-policy limit.

This validator never hard-fails. It always emits a single finding (severity:
``medium``, stage: ``gate``) containing the size context, regardless of how
close the template is to the limit.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from ..shared import Finding, PolicyDoc
from ._validators import CheckResult, PARTNER_PLACEHOLDER_PATTERN, TEMPLATE_SIZE_LIMIT


def compute_size_risk(doc: PolicyDoc) -> CheckResult:
    """Compute template size context for LLM limit review.

    Always emits one finding with size analysis data:
    - Minified character count
    - Remaining budget (2048 − size)
    - All ``@{...}`` parameters found with occurrence counts
    - Total characters occupied by placeholder literal strings

    This finding is informational context for the LLM reviewer's limit
    analysis. It is not a pass/fail gate check.
    """
    # Compute minified size.
    try:
        parsed = doc.parsed if doc.parsed is not None else json.loads(doc.raw)
        minified = json.dumps(parsed, separators=(",", ":"))
        minified_size = len(minified)
    except (json.JSONDecodeError, TypeError):
        minified = doc.raw
        minified_size = len(doc.raw)

    remaining_budget = TEMPLATE_SIZE_LIMIT - minified_size

    # Find all @{...} placeholders and count occurrences.
    placeholders = PARTNER_PLACEHOLDER_PATTERN.findall(minified)
    placeholder_counts = Counter(placeholders)

    # Total characters consumed by placeholder literals (the @{name} strings).
    total_placeholder_chars = sum(len(p) * c for p, c in placeholder_counts.items())

    # Build parameter summary.
    if placeholder_counts:
        param_details = ", ".join(
            f"`{param}` (×{count})" if count > 1 else f"`{param}`"
            for param, count in placeholder_counts.most_common()
        )
        params_section = (
            f"Parameters found: {param_details}. "
            f"Total placeholder literal characters: {total_placeholder_chars}."
        )
    else:
        params_section = "No @{{...}} parameters found in template."

    message = (
        f"Template size context for limit review: "
        f"minified size is {minified_size} characters, "
        f"remaining budget is {remaining_budget} characters "
        f"(limit: {TEMPLATE_SIZE_LIMIT}). "
        f"{params_section}"
    )

    finding = Finding(
        stage="gate",
        severity="info",
        artifact_ref=doc.id,
        message=message,
        verification="proof-backed",
    )
    return CheckResult(findings=[finding], hard_fail=False)


__all__ = ["compute_size_risk"]
