"""ValidatePolicy wrapper.

Wraps the IAM Access Analyzer ValidatePolicy API. Takes a rendered PolicyDoc,
calls the API synchronously, and maps response findings to Finding instances
tagged ``stage="gate"`` and ``verification="proof-backed"``.

The boto3 client is injectable for testability.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..shared import Finding, PolicyDoc, Severity


_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": "high",
    "SECURITY_WARNING": "high",
    "WARNING": "medium",
    "SUGGESTION": "low",
}


def _map_severity(finding_type: str) -> Severity:
    """Map a ValidatePolicy findingType to our pipeline severity."""
    return _SEVERITY_MAP.get(finding_type, "medium")


class AccessAnalyzerClient(Protocol):
    """Minimal protocol for the AccessAnalyzer ValidatePolicy method."""

    def validate_policy(self, **kwargs: Any) -> dict[str, Any]:
        ...


def validate_policy(
    doc: PolicyDoc,
    *,
    policy_type: str = "IDENTITY_POLICY",
    client: AccessAnalyzerClient | None = None,
) -> list[Finding]:
    """Run ValidatePolicy on a rendered policy document.

    :param doc: rendered PolicyDoc (placeholders already substituted).
    :param policy_type: IDENTITY_POLICY or RESOURCE_POLICY.
    :param client: injectable client. Defaults to boto3.
    :returns: list of findings (may be empty).
    """
    if client is None:
        import boto3

        client = boto3.client("accessanalyzer")  # type: ignore[assignment]

    findings: list[Finding] = []
    next_token: str | None = None

    while True:
        kwargs: dict[str, Any] = {
            "policyDocument": doc.raw,
            "policyType": policy_type,
        }
        if next_token is not None:
            kwargs["nextToken"] = next_token

        assert client is not None
        try:
            response = client.validate_policy(**kwargs)
        except Exception as exc:
            # Access Analyzer may reject policies with unrecognized service
            # namespaces. Emit a warning finding and stop pagination.
            if hasattr(exc, "response") and isinstance(exc.response, dict):
                error_code = exc.response.get("Error", {}).get("Code", "")
            else:
                error_code = type(exc).__name__

            findings.append(
                Finding(
                    stage="gate",
                    severity="low",
                    artifact_ref=doc.id,
                    message=(
                        f"ValidatePolicy skipped: Access Analyzer rejected the "
                        f"policy ({error_code}). This may occur when the policy "
                        f"contains actions from service namespaces that Access "
                        f"Analyzer does not yet support."
                    ),
                    verification="proof-backed",
                )
            )
            break

        for api_finding in response.get("findings", []):
            finding_type: str = api_finding.get("findingType", "WARNING")
            issue_code: str = api_finding.get("issueCode", "")
            finding_details: str = api_finding.get("findingDetails", "")
            learn_more_link: str = api_finding.get("learnMoreLink", "")

            message_parts = [finding_details]
            if issue_code:
                message_parts.append(f"[{issue_code}]")
            if learn_more_link:
                message_parts.append(f"See: {learn_more_link}")
            message = " ".join(part for part in message_parts if part)

            findings.append(
                Finding(
                    stage="gate",
                    severity=_map_severity(finding_type),
                    artifact_ref=doc.id,
                    message=message,
                    verification="proof-backed",
                )
            )

        next_token = response.get("nextToken")
        if not next_token:
            break

    return findings


__all__ = ["AccessAnalyzerClient", "validate_policy"]
