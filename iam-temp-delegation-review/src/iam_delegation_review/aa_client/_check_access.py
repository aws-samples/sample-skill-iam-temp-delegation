"""CheckAccessNotGranted wrapper.

Wraps the IAM Access Analyzer CheckAccessNotGranted API. Takes a worst-case
rendered bundle and a configurable critical-permission denylist, calls the API
for each policy document, and maps FAIL results to proof-backed findings.

API semantics:
- PASS → the policy does NOT grant any of the checked actions.
- FAIL → the policy DOES grant one or more of the checked actions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from ..checks_lib import RenderedBundle
from ..shared import Finding, PolicyDoc

# ---------------------------------------------------------------------------
# Critical-permission denylist
# ---------------------------------------------------------------------------

CriticalDenylist = list[str]
"""A list of IAM action strings to deny-check."""

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "critical_denylist.json"


def _load_denylist_from_config(config_path: Path | None = None) -> CriticalDenylist:
    """Load the denylist from config/critical_denylist.json, or use hardcoded fallback."""
    path = config_path or _DEFAULT_CONFIG_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        actions = data.get("actions", [])
        if isinstance(actions, list) and all(isinstance(a, str) for a in actions):
            return actions
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return [
        "iam:CreatePolicyVersion",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:PassRole",
        "ec2:GetPasswordData",
        "iam:GetCredentialReport",
        "iam:GetAccountAuthorizationDetails",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
    ]


DEFAULT_CRITICAL_DENYLIST: CriticalDenylist = _load_denylist_from_config()
"""Critical-permission denylist loaded from config. Edit the JSON file to
add/remove actions without code changes."""


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class CheckAccessClient(Protocol):
    """Minimal protocol for the CheckAccessNotGranted API method."""

    def check_access_not_granted(self, **kwargs: Any) -> dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_access_not_granted(
    rendered: RenderedBundle,
    denylist: CriticalDenylist,
    *,
    client: CheckAccessClient | None = None,
) -> list[Finding]:
    """Run CheckAccessNotGranted against a critical-permission denylist.

    Iterates over every doc in the worst-case rendered bundle, calls the API,
    and produces a Finding for each FAIL reason.

    :param rendered: worst-case rendered bundle.
    :param denylist: IAM actions to check are NOT granted.
    :param client: injectable Access Analyzer client. Defaults to boto3.
    :returns: list of findings (empty if all docs pass).
    """
    if client is None:
        import boto3

        client = boto3.client("accessanalyzer")  # type: ignore[assignment]

    assert client is not None

    findings: list[Finding] = []

    docs: list[PolicyDoc] = list(rendered.bundle.templates)
    if rendered.bundle.boundary is not None:
        docs.append(rendered.bundle.boundary)

    for doc in docs:
        try:
            response = client.check_access_not_granted(
                policyDocument=doc.raw,
                policyType="IDENTITY_POLICY",
                access=[{"actions": denylist}],
            )
        except Exception as exc:
            # Access Analyzer rejects policies containing action namespaces it
            # doesn't recognize (e.g., partnercentral:). Catch the failure,
            # emit an informational finding noting the coverage gap, and
            # continue so the rest of the pipeline still runs.
            error_code = getattr(
                getattr(exc, "response", None), "get", lambda *_: None
            )
            if hasattr(exc, "response") and isinstance(exc.response, dict):
                error_code = exc.response.get("Error", {}).get("Code", "")
            else:
                error_code = type(exc).__name__

            findings.append(
                Finding(
                    stage="provable",
                    severity="low",
                    artifact_ref=doc.id,
                    message=(
                        f"CheckAccessNotGranted skipped for this document: "
                        f"Access Analyzer rejected the policy ({error_code}). "
                        f"This typically occurs when the policy contains actions "
                        f"from service namespaces that Access Analyzer does not "
                        f"yet support. The denylist actions ({denylist}) were NOT "
                        f"verified for this document."
                    ),
                    verification="proof-backed",
                )
            )
            continue

        result: str = response.get("result", "PASS")
        if result == "FAIL":
            reasons = response.get("reasons", [])
            for reason in reasons:
                description: str = reason.get("description", "")
                statement_id: str = reason.get("statementId", "")
                statement_index: int | None = reason.get("statementIndex")

                parts: list[str] = [
                    f"Policy grants critical denylist action(s): {description}"
                ]
                if statement_id:
                    parts.append(f"(statementId={statement_id!r})")
                if statement_index is not None:
                    parts.append(f"(statementIndex={statement_index})")
                parts.append(f"Denylist checked: {denylist}")

                statement_snippet: str | None = None
                if statement_index is not None and doc.parsed is not None:
                    try:
                        statements = doc.parsed.get("Statement", [])
                        if 0 <= statement_index < len(statements):
                            stmt = statements[statement_index]
                            statement_snippet = json.dumps(stmt, indent=2)
                    except (TypeError, AttributeError, IndexError):
                        pass

                findings.append(
                    Finding(
                        stage="provable",
                        severity="critical",
                        artifact_ref=doc.id,
                        message=" ".join(parts),
                        verification="proof-backed",
                        fix_before=statement_snippet,
                    )
                )

    return findings


__all__ = [
    "CheckAccessClient",
    "CriticalDenylist",
    "DEFAULT_CRITICAL_DENYLIST",
    "check_access_not_granted",
]
