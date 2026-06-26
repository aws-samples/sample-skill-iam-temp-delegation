"""aa_client — thin wrapper over AWS IAM Access Analyzer check APIs.

Wraps ValidatePolicy, CheckAccessNotGranted, CheckNoPublicAccess, and
(deferred) CheckNoNewAccess. Always consumes rendered copies of policy
documents and tags deterministic results as ``proof-backed``.
"""

from __future__ import annotations

from ..checks_lib import RenderedBundle
from ..shared import Finding
from ._check_access import (
    DEFAULT_CRITICAL_DENYLIST,
    CheckAccessClient,
    check_access_not_granted,
)
from ._check_access import CriticalDenylist as CriticalDenylist
from ._check_public_access import (
    DEFAULT_RESOURCE_TYPE,
    CheckPublicAccessClient,
    check_no_public_access,
)
from ._validate_policy import AccessAnalyzerClient, validate_policy


async def check_no_new_access(
    rendered: RenderedBundle,
    baseline: RenderedBundle,
) -> list[Finding]:
    """Deferred: CheckNoNewAccess against a stored baseline.

    The update/diff operation is out of v1 scope. Interface is wired so
    enabling it later is additive.
    """
    raise NotImplementedError(
        "check_no_new_access: deferred — update/diff operation is out of v1 scope"
    )


__all__ = [
    "AccessAnalyzerClient",
    "CheckAccessClient",
    "CheckPublicAccessClient",
    "CriticalDenylist",
    "DEFAULT_CRITICAL_DENYLIST",
    "DEFAULT_RESOURCE_TYPE",
    "validate_policy",
    "check_access_not_granted",
    "check_no_public_access",
    "check_no_new_access",
]
