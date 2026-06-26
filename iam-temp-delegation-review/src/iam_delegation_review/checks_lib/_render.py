"""Placeholder render pass + ARN structural validation.

The gate cannot hand raw ``@{AccountId}`` to Access Analyzer — it's not
parseable as a concrete ARN. The render pass produces a parseable copy by
substituting every ``@{...}`` placeholder in one of two modes:

- **nominal** — context-aware dummy values (``@{AccountId}`` → ``123456789012``,
  ``@{Region}`` → ``us-east-1``). Proves the document a partner expects once
  their values are filled in.
- **worst-case** — all placeholders become ``*``. Proves the most permissive
  interpretation, used by the provable stage.

AWS-native ``${...}`` policy variables are valid IAM syntax and are left intact
in both modes — Access Analyzer understands them natively.

ARN structural validation runs *after* rendering and checks the canonical
six-segment shape on every ``arn:``-prefixed string in the parsed JSON.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ..shared import Bundle, Finding, PolicyDoc
from ._validators import PARTNER_PLACEHOLDER_PATTERN, CheckResult

if TYPE_CHECKING:
    from . import RenderedBundle, RenderMode

# --- render constants -------------------------------------------------------

#: Generic fallback dummy value for nominal mode.
NOMINAL_PLACEHOLDER_VALUE = "placeholder0"

#: Wildcard substitution for worst-case mode.
WORST_CASE_PLACEHOLDER_VALUE = "*"

_DUMMY_ACCOUNT_ID = "123456789012"
_DUMMY_REGION = "us-east-1"
_DUMMY_PARTITION = "aws"

_ACCOUNT_KEYWORDS = {"account", "accountid", "account_id", "acctid", "awsaccountid"}
_REGION_KEYWORDS = {"region", "aws_region", "awsregion"}
_PARTITION_KEYWORDS = {"partition", "aws_partition"}


def _nominal_value_for_placeholder(placeholder_name: str) -> str:
    """Choose an appropriate dummy value based on the placeholder name."""
    normalized = placeholder_name.lower().replace("-", "").replace("_", "")

    if normalized in {k.replace("_", "") for k in _ACCOUNT_KEYWORDS}:
        return _DUMMY_ACCOUNT_ID
    if normalized.endswith("accountid") or normalized.endswith("acctid"):
        return _DUMMY_ACCOUNT_ID
    if "account" in normalized and "id" in normalized:
        return _DUMMY_ACCOUNT_ID

    if normalized in {k.replace("_", "") for k in _REGION_KEYWORDS}:
        return _DUMMY_REGION
    if normalized.endswith("region"):
        return _DUMMY_REGION

    if normalized in {k.replace("_", "") for k in _PARTITION_KEYWORDS}:
        return _DUMMY_PARTITION

    return NOMINAL_PLACEHOLDER_VALUE


# --- ARN structural rules ---------------------------------------------------

#: Only strings starting with this prefix are treated as ARNs for validation.
ARN_PREFIX = "arn:"

#: Canonical ARN segment count: arn:partition:service:region:account-id:resource
ARN_SEGMENT_COUNT = 6


def render_text(raw: str, mode: RenderMode) -> str:
    """Substitute every ``@{...}`` in ``raw`` per ``mode``; leave ``${...}`` intact.

    In nominal mode, each placeholder gets a context-aware dummy. Unrecognized
    placeholders get unique sequential values (placeholder0, placeholder1, ...)
    so that distinct placeholders like @{FhRole} and @{CwlRole} produce distinct
    ARNs — avoiding false-positive "redundant resource" findings from Access Analyzer.

    In worst-case mode, all become ``*``.
    """
    if mode == "worst-case":
        return PARTNER_PLACEHOLDER_PATTERN.sub(WORST_CASE_PLACEHOLDER_VALUE, raw)

    import re

    def _replace_nominal(match: re.Match[str]) -> str:
        full = match.group(0)
        name = full[2:-1]
        # Context-aware values for known types (account, region, partition).
        value = _nominal_value_for_placeholder(name)
        if value != NOMINAL_PLACEHOLDER_VALUE:
            return value
        # For unrecognized names: use the parameter name as the dummy value
        # so distinct placeholders produce distinct ARNs and findings are readable.
        return f"placeholder_{name}"

    return PARTNER_PLACEHOLDER_PATTERN.sub(_replace_nominal, raw)


def render_doc(doc: PolicyDoc, mode: RenderMode) -> PolicyDoc:
    """Render a single document's ``@{...}`` placeholders.

    Returns a new PolicyDoc (input not mutated) with rendered raw text and
    re-parsed JSON. ``${...}`` variables are left intact.
    """
    rendered_raw = render_text(doc.raw, mode)
    try:
        parsed = json.loads(rendered_raw)
    except json.JSONDecodeError:
        parsed = None
    return PolicyDoc(id=doc.id, raw=rendered_raw, parsed=parsed)


def render_bundle(bundle: Bundle, mode: RenderMode) -> RenderedBundle:
    """Render every document in a bundle and record the mode used."""
    from . import RenderedBundle

    rendered_templates = [render_doc(t, mode) for t in bundle.templates]
    rendered_boundary = render_doc(bundle.boundary, mode) if bundle.boundary else None
    rendered_bundle = replace(
        bundle,
        templates=rendered_templates,
        boundary=rendered_boundary,
    )
    return RenderedBundle(bundle=rendered_bundle, mode=mode)


# --- ARN structural validation ----------------------------------------------


def is_structurally_valid_arn(value: str) -> bool:
    """Return whether ``value`` has the canonical ARN six-segment shape.

    Partition, service, and resource must be non-empty; region and account may
    be empty (e.g. ``arn:aws:s3:::bucket``).
    """
    if not value.startswith(ARN_PREFIX):
        return False
    segments = value.split(":", ARN_SEGMENT_COUNT - 1)
    if len(segments) != ARN_SEGMENT_COUNT:
        return False
    arn_literal, partition, service, _region, _account, resource = segments
    if arn_literal != "arn":
        return False
    return bool(partition) and bool(service) and bool(resource)


def _iter_strings(node: Any) -> list[str]:
    """Recursively collect every string value in a parsed-JSON structure."""
    found: list[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for value in node.values():
            found.extend(_iter_strings(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_iter_strings(item))
    return found


def validate_arns(doc: PolicyDoc) -> CheckResult:
    """Validate ARN structural format on a rendered document.

    Walks the parsed JSON and checks every ``arn:``-prefixed string for the
    canonical six-segment shape. A bare ``*`` Resource is valid and not treated
    as an ARN. Structural errors produce medium findings (not hard failures).

    Expects a rendered doc — raw ``@{...}`` would make ARNs unparseable.
    """
    if doc.parsed is None:
        return CheckResult()

    findings: list[Finding] = []
    for value in _iter_strings(doc.parsed):
        if not value.startswith(ARN_PREFIX):
            continue
        if is_structurally_valid_arn(value):
            continue
        message = (
            f"Structurally invalid ARN {value!r}: expected the form "
            f"'arn:partition:service:region:account-id:resource' with "
            f"{ARN_SEGMENT_COUNT} segments (partition, service, and resource "
            f"non-empty)."
        )
        findings.append(
            Finding(
                stage="gate",
                severity="medium",
                artifact_ref=doc.id,
                message=message,
                verification="proof-backed",
            )
        )
    return CheckResult(findings=findings, hard_fail=False)


__all__ = [
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
