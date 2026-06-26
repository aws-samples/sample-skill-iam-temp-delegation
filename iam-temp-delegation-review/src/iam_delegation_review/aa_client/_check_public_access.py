"""CheckNoPublicAccess wrapper.

Wraps the IAM Access Analyzer CheckNoPublicAccess API. Takes a rendered
resource-based policy document and checks whether it allows public access.

API semantics:
- PASS → the policy does NOT allow public access.
- FAIL → the policy DOES allow public access.

Currently wired but not active in the pipeline (identity-policy bundles don't
have resource-based policies). Ready to flip on when bundle typing supports it.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..shared import Finding, PolicyDoc


class CheckPublicAccessClient(Protocol):
    """Minimal protocol for the CheckNoPublicAccess API method."""

    def check_no_public_access(self, **kwargs: Any) -> dict[str, Any]:
        ...


DEFAULT_RESOURCE_TYPE: str = "AWS::IAM::AssumeRolePolicyDocument"
"""Default resource type for assume-role trust policy documents."""


def check_no_public_access(
    doc: PolicyDoc,
    *,
    resource_type: str = DEFAULT_RESOURCE_TYPE,
    client: CheckPublicAccessClient | None = None,
) -> list[Finding]:
    """Run CheckNoPublicAccess on a resource-based policy.

    :param doc: a rendered PolicyDoc (placeholders already substituted).
    :param resource_type: Access Analyzer resource type string.
    :param client: injectable client. Defaults to boto3.
    :returns: list of findings (empty if policy passes).
    """
    if client is None:
        import boto3

        client = boto3.client("accessanalyzer")  # type: ignore[assignment]

    assert client is not None

    response = client.check_no_public_access(
        policyDocument=doc.raw,
        resourceType=resource_type,
    )

    result: str = response.get("result", "PASS")
    if result == "PASS":
        return []

    findings: list[Finding] = []
    reasons = response.get("reasons", [])
    for reason in reasons:
        description: str = reason.get("description", "")
        statement_id: str = reason.get("statementId", "")
        statement_index: int | None = reason.get("statementIndex")

        parts: list[str] = [f"Policy allows public access: {description}"]
        if statement_id:
            parts.append(f"(statementId={statement_id!r})")
        if statement_index is not None:
            parts.append(f"(statementIndex={statement_index})")

        findings.append(
            Finding(
                stage="provable",
                severity="high",
                artifact_ref=doc.id,
                message=" ".join(parts),
                verification="proof-backed",
            )
        )

    return findings


__all__ = [
    "CheckPublicAccessClient",
    "DEFAULT_RESOURCE_TYPE",
    "check_no_public_access",
]
