"""Host-agnostic core for the IAM Temporary Delegation Review Pipeline.

Re-exports the shared data models and exposes each module's public surface.
No Kiro-specific dependency — this is a standalone library.
"""

from __future__ import annotations

from . import aa_client, checks_lib, orchestrator, registry, sar_lib
from .shared import (
    Bundle,
    Finding,
    FindingStage,
    PolicyDoc,
    RegistryEntry,
    SarRow,
    Severity,
    Verification,
    Version,
    VersionStatus,
)

__all__ = [
    # modules
    "checks_lib",
    "sar_lib",
    "aa_client",
    "registry",
    "orchestrator",
    # shared data models
    "Bundle",
    "Finding",
    "FindingStage",
    "PolicyDoc",
    "RegistryEntry",
    "SarRow",
    "Severity",
    "Verification",
    "Version",
    "VersionStatus",
]
