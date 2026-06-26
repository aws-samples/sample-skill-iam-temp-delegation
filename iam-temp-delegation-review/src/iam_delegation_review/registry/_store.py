"""In-memory append-only registry store.

Implements the Registry protocol with a dict-backed store. History is strictly
append-only: prior versions are never mutated or deleted.
"""

from __future__ import annotations

from ..shared import Bundle, RegistryEntry, Version
from . import registry_key


class InMemoryRegistry:
    """Dict-backed append-only registry.

    Keys are ``registry_key(partner_name, use_case)`` strings. Values are
    ``RegistryEntry`` instances whose ``versions`` list is only ever appended to.
    """

    def __init__(self) -> None:
        self._entries: dict[str, RegistryEntry] = {}
        # Secondary index: boundary_id → registry_key that owns it.
        self._boundary_owners: dict[str, str] = {}

    # --- Registry protocol methods ------------------------------------------

    def get(self, partner_name: str, use_case: str) -> RegistryEntry | None:
        """Read the entry for a key, or ``None`` if absent."""
        key = registry_key(partner_name, use_case)
        return self._entries.get(key)

    def append(self, version: Version) -> None:
        """Append a new version to the entry, creating it if needed.

        Prior versions are never mutated or deleted (append-only invariant).
        The version is appended at the end of the list (oldest-to-newest order).
        When the version's bundle includes a boundary, the boundary ownership
        mapping is recorded.
        """
        partner_name = version.bundle.partner_name
        use_case = version.bundle.use_case
        key = registry_key(partner_name, use_case)

        entry = self._entries.get(key)
        if entry is None:
            entry = RegistryEntry(
                partner_name=partner_name,
                use_case=use_case,
                versions=[],
            )
            self._entries[key] = entry

        entry.versions.append(version)

        # Record boundary ownership if the bundle has a boundary.
        if version.bundle.boundary is not None:
            self._boundary_owners[version.bundle.boundary.id] = key

    def baseline(self, partner_name: str, use_case: str) -> Version | None:
        """The latest approved version for the key (the baseline), if any.

        Iterates in reverse (newest-to-oldest) and returns the first version
        with status ``"approved"``.
        """
        entry = self.get(partner_name, use_case)
        if entry is None:
            return None
        for version in reversed(entry.versions):
            if version.status == "approved":
                return version
        return None

    def is_boundary_owned_elsewhere(self, bundle: Bundle) -> bool:
        """Check if the bundle's boundary is already owned by a different key.

        Returns ``True`` if the boundary's ``id`` is already recorded as owned
        by a different ``(partner_name, use_case)`` key. Returns ``False`` when:
        - The bundle has no boundary (nothing to check).
        - The boundary is new (not yet recorded in the index).
        - The boundary is already owned by the *same* key (re-submission is OK).
        """
        if bundle.boundary is None:
            return False

        boundary_id = bundle.boundary.id
        owner_key = self._boundary_owners.get(boundary_id)

        if owner_key is None:
            # Boundary has not been seen before — not owned elsewhere.
            return False

        # Check if the owner is a *different* (partner, use_case).
        bundle_key = registry_key(bundle.partner_name, bundle.use_case)
        return owner_key != bundle_key
