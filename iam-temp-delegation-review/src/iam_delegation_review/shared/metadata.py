"""Bundle metadata validation and utilities.

Shared by create_metadata.py and run_checks.py to ensure consistent
schema validation and boundary name cross-checking.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import validate, ValidationError

_SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "bundle_metadata_schema.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text())

_DATE_SUFFIX_PATTERN = re.compile(
    r"_(\d{4}_\d{2}_\d{2}|\d{8}|\d{4}-\d{2}-\d{2})$"
)


class MetadataValidationError(Exception):
    """Raised when bundle metadata fails validation."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Invalid bundle_metadata.json: {detail}")


def validate_metadata(metadata: dict) -> None:
    """Validate bundle metadata against the schema.

    :raises MetadataValidationError: if validation fails.
    """
    try:
        validate(instance=metadata, schema=_SCHEMA)
    except ValidationError as e:
        raise MetadataValidationError(e.message) from e


def ensure_date_suffix(name: str) -> str:
    """Append today's date suffix (_YYYY_MM_DD) if not already present."""
    from datetime import date

    if _DATE_SUFFIX_PATTERN.search(name):
        return name
    today = date.today().strftime("%Y_%m_%d")
    return f"{name}_{today}"


def cross_check_boundary_name(
    metadata: dict, template_text: str
) -> list[dict]:
    """Cross-check boundary name from metadata against template content.

    The boundary ARN is pre-registered and fixed — the template should
    reference it literally (e.g., arn:aws:iam::partner:policy/permissions-boundary/domain/name),
    NOT via a parameter like @{permissionBoundaryArn}.

    When partner_domain is available, constructs and validates the full expected ARN.

    Returns a list of finding dicts (may be empty if all is consistent).
    """
    findings: list[dict] = []
    meta_boundary_name = metadata.get("boundary_name")
    partner_domain = metadata.get("partner_domain")

    if not meta_boundary_name:
        return findings

    # Construct the expected full boundary ARN if domain is available.
    if partner_domain:
        expected_arn = f"arn:aws:iam::partner:policy/permissions-boundary/{partner_domain}/{meta_boundary_name}"
    else:
        expected_arn = None

    # Check if template uses @{...} parameter for the boundary reference.
    # This is incorrect — boundary ARN is fixed and known at authoring time.
    _PARAM_PATTERN = re.compile(r"@\{[^}]*[Bb]oundary[^}]*\}")
    param_matches = _PARAM_PATTERN.findall(template_text)
    if param_matches:
        message = (
            f"Template references the boundary via parameter ({param_matches[0]}). "
            f"Permission boundaries are pre-registered with IAM and have a fixed ARN — "
        )
        if expected_arn:
            message += f"use the literal boundary ARN '{expected_arn}' instead of a parameter."
        else:
            message += (
                f"use the literal boundary ARN "
                f"'arn:aws:iam::partner:policy/permissions-boundary/<domain>/{meta_boundary_name}' "
                f"instead of a parameter."
            )
        findings.append({
            "stage": "gate",
            "severity": "medium",
            "artifact_ref": "delegation_template (iam:PermissionsBoundary condition)",
            "message": message,
            "verification": "proof-backed",
        })
    elif expected_arn and expected_arn in template_text:
        pass  # Full ARN found literally — perfect
    elif meta_boundary_name in template_text:
        pass  # Name found (may not be full ARN but acceptable)
    else:
        # Name not found in any form — warning
        message = (
            f"Boundary name '{meta_boundary_name}' from metadata does not appear "
            f"in the template's iam:PermissionsBoundary condition. "
        )
        if expected_arn:
            message += f"Expected the template to contain: '{expected_arn}'"
        else:
            message += "Verify the template enforces the correct boundary at role creation time."
        findings.append({
            "stage": "gate",
            "severity": "low",
            "artifact_ref": "bundle_metadata.json",
            "message": message,
            "verification": "proof-backed",
        })

    return findings
