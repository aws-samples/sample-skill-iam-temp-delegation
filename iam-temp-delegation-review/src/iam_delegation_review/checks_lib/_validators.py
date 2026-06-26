"""Deterministic gate validators.

Pure, LLM-free validators for the Stage 1 deterministic gate:

- :func:`validate_json` — JSON well-formedness with precise error location.
- :func:`validate_template_size` — 2048-char session-policy size limit on
  delegation templates.
- :func:`validate_version` — policy ``Version`` date field.
- :func:`validate_placeholder_discipline` — ``@{...}`` must not appear in
  permission boundaries.

Each validator returns a :class:`CheckResult` with findings and a ``hard_fail``
flag. Hard failures (invalid JSON, size overage, boundary placeholder misuse)
trigger a short-circuit in the gate — no later stages run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..shared import Finding, PolicyDoc

# --- constants --------------------------------------------------------------

#: IAM session-policy size limit (chars). Applied to delegation templates;
#: boundaries are exempt (they are not session policies).
TEMPLATE_SIZE_LIMIT = 2048

#: Valid values of the IAM policy ``Version`` field.
VALID_POLICY_VERSIONS = ("2012-10-17", "2008-10-17")

#: Matches a partner-template placeholder ``@{...}``. Allowed only in
#: delegation templates; a hard-fail misuse in permission boundaries.
PARTNER_PLACEHOLDER_PATTERN = re.compile(r"@\{[^}]*\}")

#: Matches an AWS-native policy variable ``${...}`` (e.g.
#: ``${aws:PrincipalAccount}``). Allowed anywhere — never a finding.
AWS_VARIABLE_PATTERN = re.compile(r"\$\{[^}]*\}")


# --- result type ------------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of a single deterministic validator.

    ``hard_fail`` is True when the finding is a short-circuit condition
    (invalid JSON, size overage, or boundary placeholder misuse).
    """

    findings: list[Finding] = field(default_factory=list)
    hard_fail: bool = False


# --- validators -------------------------------------------------------------


def validate_json(doc: PolicyDoc) -> CheckResult:
    """Validate that ``doc.raw`` is well-formed JSON.

    On success, stores the parsed object on ``doc.parsed``. On failure, produces
    a critical hard-fail finding with precise location (line, column, offset).
    """
    try:
        doc.parsed = json.loads(doc.raw)
    except json.JSONDecodeError as exc:
        doc.parsed = None
        message = (
            f"Invalid JSON at line {exc.lineno}, column {exc.colno} "
            f"(char {exc.pos}): {exc.msg}."
        )
        finding = Finding(
            stage="gate",
            severity="critical",
            artifact_ref=doc.id,
            message=message,
            verification="proof-backed",
        )
        return CheckResult(findings=[finding], hard_fail=True)
    return CheckResult()


def validate_template_size(doc: PolicyDoc) -> CheckResult:
    """Enforce the 2048-char session-policy size limit on a template.

    Measures on minified JSON (what STS actually receives on the wire).
    A template at exactly the limit passes; one character over is a hard failure.
    Boundaries are not session policies and should not be passed to this function.
    """
    try:
        parsed = doc.parsed if doc.parsed is not None else json.loads(doc.raw)
        minified = json.dumps(parsed, separators=(",", ":"))
        length = len(minified)
    except (json.JSONDecodeError, TypeError):
        length = len(doc.raw)

    if length <= TEMPLATE_SIZE_LIMIT:
        return CheckResult()

    overage = length - TEMPLATE_SIZE_LIMIT
    message = (
        f"Template exceeds the {TEMPLATE_SIZE_LIMIT}-character session-policy "
        f"size limit: {length} characters minified ({overage} over)."
    )
    finding = Finding(
        stage="gate",
        severity="high",
        artifact_ref=doc.id,
        message=message,
        verification="proof-backed",
    )
    return CheckResult(findings=[finding], hard_fail=True)


def validate_version(doc: PolicyDoc) -> CheckResult:
    """Validate the policy ``Version`` date field when present.

    Must be one of ``"2012-10-17"`` or ``"2008-10-17"``. An absent ``Version``
    is not an error. This is not a hard failure.
    """
    parsed = doc.parsed
    if parsed is None:
        try:
            parsed = json.loads(doc.raw)
        except json.JSONDecodeError:
            return CheckResult()

    if not isinstance(parsed, dict) or "Version" not in parsed:
        return CheckResult()

    version = parsed["Version"]
    if version in VALID_POLICY_VERSIONS:
        return CheckResult()

    valid = " or ".join(repr(v) for v in VALID_POLICY_VERSIONS)
    message = (
        f"Invalid policy Version {version!r}: expected an IAM policy version "
        f"date ({valid})."
    )
    finding = Finding(
        stage="gate",
        severity="medium",
        artifact_ref=doc.id,
        message=message,
        verification="proof-backed",
    )
    return CheckResult(findings=[finding])


def validate_placeholder_discipline(doc: PolicyDoc, *, is_boundary: bool) -> CheckResult:
    """Enforce placeholder discipline on a policy document.

    - ``${...}`` (AWS-native variables): allowed anywhere, never a finding.
    - ``@{...}`` (partner-template placeholders): allowed only in delegation
      templates. In a permission boundary they are a hard-fail misuse (a
      boundary is a real, deployed policy and must not carry template placeholders).

    Detection runs on raw text, so it works even on malformed JSON.
    """
    if not is_boundary:
        return CheckResult()

    offenders = PARTNER_PLACEHOLDER_PATTERN.findall(doc.raw)
    if not offenders:
        return CheckResult()

    count = len(offenders)
    unique_offenders = list(dict.fromkeys(offenders))
    named = ", ".join(repr(p) for p in unique_offenders)
    noun = "placeholder" if count == 1 else "placeholders"
    message = (
        f"Permission boundary contains {count} partner-template {noun} "
        f"(@{{...}}): {named}. Partner placeholders are allowed only in "
        f"delegation templates; a boundary must not contain @{{...}}."
    )
    finding = Finding(
        stage="gate",
        severity="critical",
        artifact_ref=doc.id,
        message=message,
        verification="proof-backed",
    )
    return CheckResult(findings=[finding], hard_fail=True)


__all__ = [
    "PARTNER_PLACEHOLDER_PATTERN",
    "AWS_VARIABLE_PATTERN",
    "TEMPLATE_SIZE_LIMIT",
    "VALID_POLICY_VERSIONS",
    "CheckResult",
    "validate_json",
    "validate_placeholder_discipline",
    "validate_template_size",
    "validate_version",
]
