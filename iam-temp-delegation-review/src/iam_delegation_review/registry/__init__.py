"""registry — append-only state per (partner_name, use_case).

History is append-only: prior versions are never mutated or deleted. The
baseline is the latest version whose status is ``approved``. Enforces the
boundary 1:1 invariant (a permission boundary belongs to exactly one
(partner_name, use_case)).
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..shared import Bundle, RegistryEntry, Version


def registry_key(partner_name: str, use_case: str) -> str:
    """Compose the registry key for a ``(partner_name, use_case)``."""
    return f"{partner_name}\x00{use_case}"


class Registry(Protocol):
    """Append-only store keyed by ``(partner_name, use_case)``."""

    def get(self, partner_name: str, use_case: str) -> RegistryEntry | None:
        """Read the entry for a key, or ``None`` if absent."""
        ...

    def append(self, version: Version) -> None:
        """Append a new version to the entry, creating the entry if needed."""
        ...

    def baseline(self, partner_name: str, use_case: str) -> Version | None:
        """The latest approved version for the key (the baseline), if any."""
        ...

    def is_boundary_owned_elsewhere(self, bundle: Bundle) -> bool:
        """Is this boundary already owned by a different ``(partner, use_case)``?"""
        ...


def create_registry(path: Path | None = None) -> Registry:
    """Construct a registry instance.

    Parameters
    ----------
    path:
        If ``None`` (default), returns an in-memory registry (useful for tests).
        If a ``Path`` is provided, returns a file-backed persistent registry
        that stores state as JSON files under the given directory.
    """
    if path is not None:
        from ._file_store import FileBackedRegistry

        return FileBackedRegistry(path)

    from ._store import InMemoryRegistry

    return InMemoryRegistry()


__all__ = ["registry_key", "Registry", "FileBackedRegistry", "create_registry"]
