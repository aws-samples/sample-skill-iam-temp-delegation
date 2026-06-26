"""Stage 0 — Intake & Classify.

Assembles submissions into a classified bundle, derives the operation from
registry state, and enforces the boundary 1:1 invariant.
"""

from __future__ import annotations

from ..registry import Registry, registry_key
from ..shared import Bundle
from ._types import ClassifiedBundle, Operation


class BoundaryConflictError(Exception):
    """Raised when a submission's boundary is already owned by a different key.

    A permission boundary belongs to exactly one (partner_name, use_case).
    """

    def __init__(self, bundle: Bundle, owner_key: str) -> None:
        self.bundle = bundle
        self.owner_key = owner_key
        boundary_id = bundle.boundary.id if bundle.boundary else "<none>"
        bundle_key = registry_key(bundle.partner_name, bundle.use_case)
        super().__init__(
            f"Boundary '{boundary_id}' is already owned by key '{owner_key}'; "
            f"cannot associate with '{bundle_key}'."
        )


def classify(bundle: Bundle, registry: Registry) -> ClassifiedBundle:
    """Intake and classify a submission bundle.

    1. Enforces boundary uniqueness: raises BoundaryConflictError if the
       boundary is already owned by a different (partner, use_case).
    2. Derives the operation from registry state:
       - Baseline exists → "update".
       - No baseline → "onboard".
    3. Returns a ClassifiedBundle as a single review unit for the pipeline.
    """
    # Enforce boundary uniqueness.
    if registry.is_boundary_owned_elsewhere(bundle):
        owner_key = "<another (partner, use_case)>"
        raise BoundaryConflictError(bundle, owner_key)

    # Derive operation from registry state.
    baseline = registry.baseline(bundle.partner_name, bundle.use_case)
    operation: Operation = "update" if baseline is not None else "onboard"

    key = registry_key(bundle.partner_name, bundle.use_case)
    return ClassifiedBundle(bundle=bundle, operation=operation, key=key)
