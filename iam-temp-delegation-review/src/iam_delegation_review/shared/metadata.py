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
    """Cross-check boundary ARN references in template against bundle metadata.

    Performs deterministic structural validation:
    1. Extracts all iam:PermissionsBoundary condition values from the template.
    2. For each extracted boundary ARN:
       - Validates it uses the correct partner namespace format.
       - Cross-checks the domain component against metadata partner_domain.
       - Cross-checks the name component against metadata boundary_name.
    3. Checks for inconsistency (multiple different boundary ARNs).
    4. Detects parameterized boundary references (@{...}).

    Returns a list of finding dicts (may be empty if all is consistent).
    """
    findings: list[dict] = []
    meta_boundary_name = metadata.get("boundary_name")
    partner_domain = metadata.get("partner_domain")

    if not meta_boundary_name:
        return findings

    # Construct the expected full boundary ARN.
    if partner_domain:
        expected_arn = f"arn:aws:iam::partner:policy/permissions-boundary/{partner_domain}/{meta_boundary_name}"
    else:
        expected_arn = None

    # --- Check 1: Parameterized boundary reference ---
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
        # If parameterized, skip structural checks (nothing concrete to parse).
        return findings

    # --- Extract all iam:PermissionsBoundary condition values from parsed JSON ---
    try:
        parsed = json.loads(template_text)
    except (json.JSONDecodeError, TypeError):
        return findings

    boundary_arns = _extract_boundary_condition_values(parsed)

    if not boundary_arns:
        # No boundary condition found anywhere in the template.
        findings.append({
            "stage": "gate",
            "severity": "low",
            "artifact_ref": "delegation_template",
            "message": (
                f"Boundary name '{meta_boundary_name}' is declared in metadata but no "
                f"iam:PermissionsBoundary condition was found in the template. "
                f"Verify the template enforces the correct boundary at role creation time."
            ),
            "verification": "proof-backed",
        })
        return findings

    # --- Check 2: Validate each extracted boundary ARN ---
    _PARTNER_NS = "arn:aws:iam::partner:policy/permissions-boundary/"
    unique_arns = sorted(set(boundary_arns))

    for arn in unique_arns:
        # Check namespace format.
        if not arn.startswith(_PARTNER_NS):
            findings.append({
                "stage": "gate",
                "severity": "high",
                "artifact_ref": "delegation_template (iam:PermissionsBoundary condition)",
                "message": (
                    f"Boundary ARN uses wrong namespace format: '{arn}'. "
                    f"Expected the partner-managed namespace "
                    f"'arn:aws:iam::partner:policy/permissions-boundary/<domain>/<name>'. "
                    f"Using a traditional IAM policy ARN bypasses the delegation boundary system."
                ),
                "verification": "proof-backed",
            })
            continue

        # Parse domain and name from the ARN.
        suffix = arn[len(_PARTNER_NS):]
        parts = suffix.split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            findings.append({
                "stage": "gate",
                "severity": "high",
                "artifact_ref": "delegation_template (iam:PermissionsBoundary condition)",
                "message": (
                    f"Boundary ARN has malformed path after namespace: '{arn}'. "
                    f"Expected format: 'arn:aws:iam::partner:policy/permissions-boundary/<domain>/<name>'."
                ),
                "verification": "proof-backed",
            })
            continue

        arn_domain, arn_name = parts[0], parts[1]

        # Cross-check domain.
        if partner_domain and arn_domain != partner_domain:
            findings.append({
                "stage": "gate",
                "severity": "high",
                "artifact_ref": "delegation_template (iam:PermissionsBoundary condition)",
                "message": (
                    f"Boundary ARN domain mismatch: template references domain '{arn_domain}' "
                    f"but metadata declares partner_domain '{partner_domain}'. "
                    f"This may enforce another partner's boundary. "
                    f"Expected: '{expected_arn}'."
                ),
                "verification": "proof-backed",
            })

        # Cross-check boundary name.
        if arn_name != meta_boundary_name:
            findings.append({
                "stage": "gate",
                "severity": "medium",
                "artifact_ref": "delegation_template (iam:PermissionsBoundary condition)",
                "message": (
                    f"Boundary name mismatch: template references '{arn_name}' "
                    f"but metadata declares boundary_name '{meta_boundary_name}'. "
                    f"This may be an outdated boundary version or a typo. "
                    + (f"Expected: '{expected_arn}'." if expected_arn else
                       f"Expected boundary name: '{meta_boundary_name}'.")
                ),
                "verification": "proof-backed",
            })

    # --- Check 3: Inconsistent boundary references ---
    if len(unique_arns) > 1:
        arns_list = ", ".join(f"'{a}'" for a in unique_arns)
        findings.append({
            "stage": "gate",
            "severity": "medium",
            "artifact_ref": "delegation_template (iam:PermissionsBoundary conditions)",
            "message": (
                f"Template references {len(unique_arns)} different boundary ARNs "
                f"across statements: {arns_list}. "
                f"A bundle should reference exactly one boundary consistently."
            ),
            "verification": "proof-backed",
        })

    return findings


def _extract_boundary_condition_values(parsed: Any) -> list[str]:
    """Recursively extract all iam:PermissionsBoundary condition values from a parsed policy.

    Walks through all statements and condition blocks to find StringEquals
    or StringLike conditions on the iam:PermissionsBoundary key.
    """
    values: list[str] = []

    if not isinstance(parsed, dict):
        return values

    statements = parsed.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        condition = stmt.get("Condition", {})
        if not isinstance(condition, dict):
            continue
        # Check both StringEquals and StringLike operators.
        for operator in ("StringEquals", "StringLike", "ArnEquals", "ArnLike"):
            op_block = condition.get(operator, {})
            if not isinstance(op_block, dict):
                continue
            boundary_val = op_block.get("iam:PermissionsBoundary")
            if boundary_val is None:
                continue
            if isinstance(boundary_val, str):
                values.append(boundary_val)
            elif isinstance(boundary_val, list):
                values.extend(v for v in boundary_val if isinstance(v, str))

    return values
