"""Deterministic gate validators.

Pure, LLM-free validators for the Stage 1 deterministic gate:

- :func:`validate_json` — JSON well-formedness with precise error location.
- :func:`validate_template_size` — 2048-char session-policy size limit on
  delegation templates.
- :func:`validate_parameters` — delegation parameters (``@{...}`` placeholders
  and ``@Enabled`` directive values) must have names 5–256 chars, printable
  ASCII (``[ -~]+``), and number at most 50, matching the
  ``CreateDelegationRequest`` API constraints.
- :func:`validate_version` — policy ``Version`` date field.
- :func:`validate_placeholder_discipline` — ``@{...}`` must not appear in
  permission boundaries.

Each validator returns a :class:`CheckResult` with findings and a ``hard_fail``
flag. Hard failures (invalid JSON, size overage, parameter-name length,
boundary placeholder misuse) trigger a short-circuit in the gate — no later
stages run.
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

#: Captures the inner parameter name of a ``@{name}`` placeholder.
PARTNER_PLACEHOLDER_NAME_PATTERN = re.compile(r"@\{([^}]*)\}")

#: Delegation parameter-name length bounds enforced by the platform's
#: ``CreateDelegationRequest`` API (``policyParameterNameType``: min 5, max 256,
#: pattern ``[ -~]+``). Every ``@{name}`` placeholder and every ``@Enabled``
#: (or other ``@``-directive) value becomes an entry in
#: ``Permissions.Parameters[].Name`` and must satisfy these bounds, or the
#: request fails validation before the policy is ever rendered.
PARAMETER_NAME_MIN_LENGTH = 5
PARAMETER_NAME_MAX_LENGTH = 256

#: Allowed characters in a delegation parameter name — printable ASCII only
#: (code points 0x20 space through 0x7E tilde). From ``policyParameterNameType``
#: pattern ``[ -~]+``; anchored here so the *entire* name must match (rejecting
#: embedded control characters or non-ASCII, which the platform also rejects).
PARAMETER_NAME_PATTERN = re.compile(r"[ -~]+")

#: Maximum number of parameters the platform accepts in
#: ``Permissions.Parameters`` (``policyParameterListType`` max 50). Each distinct
#: ``@{name}`` placeholder and ``@Enabled``-style directive value contributes one
#: parameter entry.
PARAMETER_COUNT_LIMIT = 50

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

    Measures the *rendered* form: minified JSON with ``@``-prefixed statement
    directives (e.g. ``@Enabled``) stripped, which is what STS actually receives
    on the wire after the delegation platform renders the session policy. The
    authored artifact keeps the directives; only this measurement drops them, so
    the gate's number matches the rendered policy regardless of authored form.

    A template at exactly the limit passes; one character over is a hard failure.
    Boundaries are not session policies and should not be passed to this function.
    """
    from ._render import strip_directives

    try:
        parsed = doc.parsed if doc.parsed is not None else json.loads(doc.raw)
        rendered = strip_directives(parsed)
        minified = json.dumps(rendered, separators=(",", ":"))
        length = len(minified)
    except (json.JSONDecodeError, TypeError):
        length = len(doc.raw)

    if length <= TEMPLATE_SIZE_LIMIT:
        return CheckResult()

    overage = length - TEMPLATE_SIZE_LIMIT
    message = (
        f"Template exceeds the {TEMPLATE_SIZE_LIMIT}-character session-policy "
        f"size limit: {length} characters minified ({overage} over). "
        f"Measured on the rendered form (@Enabled and other @-directives are "
        f"stripped before rendering, matching the delegation platform)."
    )
    finding = Finding(
        stage="gate",
        severity="high",
        artifact_ref=doc.id,
        message=message,
        verification="proof-backed",
    )
    return CheckResult(findings=[finding], hard_fail=True)


def _collect_parameter_names(parsed: object, raw: str) -> list[tuple[str, str]]:
    """Collect every delegation parameter name declared in a template.

    Two authoring constructs become entries in the platform's
    ``Permissions.Parameters[].Name`` list:

    1. ``@{name}`` placeholders — the inner token is the parameter name.
    2. ``@Enabled`` (and any other ``@``-prefixed) statement directive — the
       directive *value* names the parameter that gates the statement's
       inclusion (e.g. ``"@Enabled": "KMS"`` declares a parameter named
       ``KMS``).

    Returns a list of ``(name, source)`` tuples where ``source`` is a short
    human-readable origin like ``"@{name} placeholder"`` or
    ``"@Enabled directive"``. Placeholder inner names are read from ``raw`` so
    detection still works on the authored (un-rendered) text; directive values
    are read from the parsed statements.
    """
    names: list[tuple[str, str]] = []

    # 1. @{name} placeholders (from raw text so it works pre-render).
    for inner in PARTNER_PLACEHOLDER_NAME_PATTERN.findall(raw):
        names.append((inner, f"@{{{inner}}} placeholder"))

    # 2. @-prefixed statement directive values (e.g. @Enabled: "KMS").
    if isinstance(parsed, dict):
        statements = parsed.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if isinstance(statements, list):
            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                for key, value in stmt.items():
                    if not (isinstance(key, str) and key.startswith("@")):
                        continue
                    # Directive value(s) are the parameter name(s).
                    directive_values = value if isinstance(value, list) else [value]
                    for dv in directive_values:
                        if isinstance(dv, str):
                            names.append((dv, f"{key} directive"))
    return names


def validate_parameters(doc: PolicyDoc) -> CheckResult:
    """Enforce the delegation parameter constraints on a template.

    The platform's ``CreateDelegationRequest`` API turns every ``@{name}``
    placeholder and every ``@Enabled`` (or other ``@``-directive) value into an
    entry in ``Permissions.Parameters``. Each entry's ``Name`` must satisfy
    ``policyParameterNameType`` and the list is capped by
    ``policyParameterListType``:

    - **Length** — 5 to 256 characters. A short name such as
      ``"@Enabled": "KMS"`` (3 chars) fails with ``ParamValidation``
      (``valid min length: 5``).
    - **Pattern** — printable ASCII only (``[ -~]+``); embedded control
      characters or non-ASCII are rejected.
    - **Count** — at most 50 distinct parameters.

    Any violation is a hard-fail so the reviewer catches it before submission,
    rather than the partner hitting a ``ParamValidation`` error at request time.
    Each offending name is reported once; length and pattern are reported
    independently for the same name when both fail.
    """
    parsed = doc.parsed
    if parsed is None:
        try:
            parsed = json.loads(doc.raw)
        except json.JSONDecodeError:
            # JSON validity is reported by validate_json; nothing to do here.
            return CheckResult()

    findings: list[Finding] = []
    collected = _collect_parameter_names(parsed, doc.raw)

    # --- Per-name checks: length and pattern (dedup per name+issue). --------
    seen_length: set[str] = set()
    seen_pattern: set[str] = set()

    for name, source in collected:
        length = len(name)
        if not (PARAMETER_NAME_MIN_LENGTH <= length <= PARAMETER_NAME_MAX_LENGTH):
            if name not in seen_length:
                seen_length.add(name)
                if length < PARAMETER_NAME_MIN_LENGTH:
                    bound = (
                        f"is {length} character{'s' if length != 1 else ''} long; "
                        f"the delegation platform requires parameter names to be at "
                        f"least {PARAMETER_NAME_MIN_LENGTH} characters"
                    )
                else:
                    bound = (
                        f"is {length} characters long; the delegation platform "
                        f"requires parameter names to be at most "
                        f"{PARAMETER_NAME_MAX_LENGTH} characters"
                    )
                findings.append(Finding(
                    stage="gate",
                    severity="high",
                    artifact_ref=doc.id,
                    message=(
                        f"Parameter name {name!r} ({source}) {bound}. "
                        f"CreateDelegationRequest validates "
                        f"Permissions.Parameters[].Name against a minimum length of "
                        f"{PARAMETER_NAME_MIN_LENGTH} and a maximum of "
                        f"{PARAMETER_NAME_MAX_LENGTH}; the request would fail with a "
                        f"ParamValidation error before the policy is rendered. "
                        f"Rename the parameter to satisfy the length bounds."
                    ),
                    verification="proof-backed",
                ))

        # Pattern: the whole name must be printable ASCII (anchored match).
        if not PARAMETER_NAME_PATTERN.fullmatch(name):
            if name not in seen_pattern:
                seen_pattern.add(name)
                findings.append(Finding(
                    stage="gate",
                    severity="high",
                    artifact_ref=doc.id,
                    message=(
                        f"Parameter name {name!r} ({source}) contains characters "
                        f"outside the allowed set. CreateDelegationRequest requires "
                        f"Permissions.Parameters[].Name to match the pattern "
                        f"'[ -~]+' (printable ASCII only: space through '~', no tabs, "
                        f"newlines, or non-ASCII characters); the request would fail "
                        f"with a ParamValidation error. Use only printable ASCII in "
                        f"the parameter name."
                    ),
                    verification="proof-backed",
                ))

    # --- List-level check: at most 50 distinct parameters. -----------------
    distinct_names = {name for name, _ in collected}
    if len(distinct_names) > PARAMETER_COUNT_LIMIT:
        findings.append(Finding(
            stage="gate",
            severity="high",
            artifact_ref=doc.id,
            message=(
                f"Template declares {len(distinct_names)} distinct parameters "
                f"(@{{...}} placeholders and @-directive values), exceeding the "
                f"delegation platform limit of {PARAMETER_COUNT_LIMIT}. "
                f"CreateDelegationRequest caps Permissions.Parameters at "
                f"{PARAMETER_COUNT_LIMIT} entries; the request would fail with a "
                f"ParamValidation error. Reduce the number of distinct parameters."
            ),
            verification="proof-backed",
        ))

    return CheckResult(findings=findings, hard_fail=bool(findings))


#: Backward-compatible alias. The validator's scope expanded from name length
#: only to name length + pattern + parameter count; the original name is kept so
#: existing imports keep working.
validate_parameter_name_length = validate_parameters


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


CROSS_ACCOUNT_SERVICE_PREFIXES = frozenset({
    "s3:",
    "s3tables:",
    "glue:",
    "lakeformation:",
    "sts:",
    "kms:",
    "lambda:",
    "sns:",
    "sqs:",
})

RESOURCE_ACCOUNT_CONDITION_KEYS = frozenset({
    "aws:ResourceAccount",
    "aws:resourceaccount",
    "s3:ResourceAccount",
    "s3:resourceaccount",
})


def _normalise_actions(action_field: str | list) -> list[str]:
    """Normalise the Action field to a list of lowercase strings."""
    if isinstance(action_field, str):
        return [action_field.lower()]
    return [a.lower() for a in action_field]


def _has_resource_account_condition(statement: dict) -> bool:
    """Check if a statement has aws:ResourceAccount or equivalent."""
    condition = statement.get("Condition", {})
    for operator_block in condition.values():
        if not isinstance(operator_block, dict):
            continue
        for key in operator_block:
            if key.lower() in {k.lower() for k in RESOURCE_ACCOUNT_CONDITION_KEYS}:
                return True
    return False


def _resource_has_account_variable(statement: dict) -> bool:
    """Check if the Resource field uses ${aws:PrincipalAccount} in the ARN.

    If the author already placed the variable in the resource ARN (even in the
    account segment where it may not resolve), they intended same-account
    scoping. That's a separate issue (ARN-segment limitation) — not a missing
    ResourceAccount condition.
    """
    resource = statement.get("Resource", [])
    if isinstance(resource, str):
        resource = [resource]
    for r in resource:
        if "${aws:PrincipalAccount}" in r or "${aws:principalaccount}" in r.lower():
            return True
    return False


def _any_action_is_cross_account(actions: list[str]) -> tuple[bool, list[str]]:
    """Check if any action belongs to a cross-account-capable service.

    Returns (is_cross_account, list_of_matching_actions).
    """
    matching = []
    for action in actions:
        for prefix in CROSS_ACCOUNT_SERVICE_PREFIXES:
            if action.startswith(prefix):
                matching.append(action)
                break
    return bool(matching), matching


def validate_boundary_resource_account(doc: PolicyDoc) -> CheckResult:
    """Flag boundary Allow statements for cross-account services missing aws:ResourceAccount.

    Only runs on permission boundaries. Skips Deny statements and statements
    for account-local services (IAM, CloudWatch Logs, Athena, EC2, etc.).
    """
    parsed = doc.parsed
    if parsed is None:
        try:
            parsed = json.loads(doc.raw)
        except json.JSONDecodeError:
            return CheckResult()

    statements = parsed.get("Statement", [])
    if not isinstance(statements, list):
        return CheckResult()

    findings: list[Finding] = []

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "").lower() != "allow":
            continue

        action_field = stmt.get("Action", [])
        actions = _normalise_actions(action_field)

        is_cross_account, matching_actions = _any_action_is_cross_account(actions)
        if not is_cross_account:
            continue

        if _has_resource_account_condition(stmt):
            continue

        if _resource_has_account_variable(stmt):
            continue

        sid = stmt.get("Sid", "unnamed")
        sample_actions = matching_actions[:3]
        actions_str = ", ".join(sample_actions)
        if len(matching_actions) > 3:
            actions_str += f" (+{len(matching_actions) - 3} more)"

        message = (
            f"Boundary Allow statement '{sid}' grants cross-account-capable "
            f"actions ({actions_str}) without aws:ResourceAccount condition. "
            f"The created role could access resources in other accounts if "
            f"cross-account resource policies permit it. Add "
            f"\"StringEquals\": {{\"aws:ResourceAccount\": "
            f"\"${{aws:PrincipalAccount}}\"}} to restrict to same-account."
        )
        findings.append(Finding(
            stage="gate",
            severity="medium",
            artifact_ref=f"{doc.id} ({sid} statement)",
            message=message,
            verification="proof-backed",
        ))

    return CheckResult(findings=findings)


__all__ = [
    "CROSS_ACCOUNT_SERVICE_PREFIXES",
    "RESOURCE_ACCOUNT_CONDITION_KEYS",
    "PARTNER_PLACEHOLDER_PATTERN",
    "PARTNER_PLACEHOLDER_NAME_PATTERN",
    "PARAMETER_NAME_MIN_LENGTH",
    "PARAMETER_NAME_MAX_LENGTH",
    "PARAMETER_NAME_PATTERN",
    "PARAMETER_COUNT_LIMIT",
    "AWS_VARIABLE_PATTERN",
    "TEMPLATE_SIZE_LIMIT",
    "VALID_POLICY_VERSIONS",
    "CheckResult",
    "validate_boundary_resource_account",
    "validate_json",
    "validate_parameters",
    "validate_parameter_name_length",
    "validate_placeholder_discipline",
    "validate_template_size",
    "validate_version",
]
