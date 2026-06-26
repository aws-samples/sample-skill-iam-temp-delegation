"""File-backed append-only registry store.

Implements the ``Registry`` protocol with JSON files on disk. Each
``(partner_name, use_case)`` pair gets its own entry file under
``<base_dir>/entries/``. A global ``index.json`` tracks boundary ownership.

Storage layout::

    <base_dir>/
      index.json                        ← boundary ownership index
      entries/
        <partner>__<use_case>.json      ← one file per (partner, use_case)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import validate, ValidationError

from ..shared import Bundle, PolicyDoc, RegistryEntry, Version, VersionStatus
from . import registry_key

# --- schema validation ------------------------------------------------------

_SCHEMA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "config"
_REGISTRY_ENTRY_SCHEMA = json.loads(
    (_SCHEMA_DIR / "registry_entry_schema.json").read_text()
)


class RegistryEntryCorruptedError(Exception):
    """Raised when a registry entry file fails schema validation."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(
            f"Corrupted registry entry at {path}: {detail}"
        )


# --- path safety ------------------------------------------------------------

#: Characters allowed in partner_name and use_case path components.
#: Alphanumeric, hyphens, underscores, and dots (no slashes, no ..).
_SAFE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _validate_path_component(value: str, label: str) -> str:
    """Validate that a value is safe to use as a file path component.

    Rejects empty strings, path traversal sequences (``..``, ``/``, ``\\``),
    and characters outside the allowed set.

    :raises ValueError: if the value is unsafe for use in a file name.
    """
    if not value:
        raise ValueError(f"{label} must not be empty")
    if ".." in value or "/" in value or "\\" in value:
        raise ValueError(
            f"{label} contains path traversal characters: {value!r}"
        )
    if not _SAFE_NAME_PATTERN.match(value):
        raise ValueError(
            f"{label} contains invalid characters (allowed: alphanumeric, "
            f"hyphens, underscores, dots): {value!r}"
        )
    return value


# --- serialization helpers --------------------------------------------------


def _serialize_version(version: Version, version_number: int) -> dict[str, Any]:
    """Serialize a Version to a JSON-compatible dict.

    Only stores document IDs (not full raw content) to keep files small.
    """
    bundle = version.bundle
    result: dict[str, Any] = {
        "version_number": version_number,
        "status": version.status,
        "submitted_at": version.submitted_at,
        "template_ids": [t.id for t in bundle.templates],
        "boundary_id": bundle.boundary.id if bundle.boundary is not None else None,
        "approved_at": version.approved_at,
        "approved_by": version.approved_by,
    }
    if version.findings_summary is not None:
        result["findings_summary"] = version.findings_summary
    if version.findings_count is not None:
        result["findings_count"] = version.findings_count
    if version.stages_completed is not None:
        result["stages_completed"] = version.stages_completed
    return result


def _deserialize_version(
    data: dict[str, Any], partner_name: str, use_case: str
) -> Version:
    """Deserialize a Version from a JSON dict.

    Reconstructs PolicyDoc objects with just the ``id`` field populated
    (raw="" and parsed=None) since full content lives on disk elsewhere.
    """
    templates = [PolicyDoc(id=tid, raw="", parsed=None) for tid in data["template_ids"]]
    boundary: PolicyDoc | None = None
    if data["boundary_id"] is not None:
        boundary = PolicyDoc(id=data["boundary_id"], raw="", parsed=None)

    bundle = Bundle(
        partner_name=partner_name,
        use_case=use_case,
        templates=templates,
        boundary=boundary,
    )

    status: VersionStatus = data["status"]
    return Version(
        bundle=bundle,
        status=status,
        submitted_at=data.get("submitted_at"),
        approved_at=data.get("approved_at"),
        approved_by=data.get("approved_by"),
        findings_summary=data.get("findings_summary"),
        findings_count=data.get("findings_count"),
        stages_completed=data.get("stages_completed"),
    )


# --- FileBackedRegistry -----------------------------------------------------


class FileBackedRegistry:
    """JSON-file-backed append-only registry.

    Each ``(partner_name, use_case)`` is persisted as a separate JSON file.
    Boundary ownership is tracked in a global ``index.json``.
    """

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._entries_dir = base_dir / "entries"
        self._artifacts_dir = base_dir / "artifacts"
        self._findings_dir = base_dir / "findings"
        self._integrity_dir = base_dir / "integrity"
        self._reports_dir = base_dir / "reports"
        self._submissions_dir = base_dir / "submissions"

        # Create directories if they don't exist.
        self._entries_dir.mkdir(parents=True, exist_ok=True)
        self._artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._findings_dir.mkdir(parents=True, exist_ok=True)
        self._integrity_dir.mkdir(parents=True, exist_ok=True)
        self._reports_dir.mkdir(parents=True, exist_ok=True)

        # Load boundary ownership index.
        self._index_path = base_dir / "index.json"
        self._boundary_owners: dict[str, str] = {}
        if self._index_path.exists():
            data = json.loads(self._index_path.read_text())
            self._boundary_owners = data.get("boundary_owners", {})

    # --- private helpers ----------------------------------------------------

    def _entry_path(self, partner_name: str, use_case: str) -> Path:
        """Compute the path for an entry file (uses __ as separator).

        :raises ValueError: if partner_name or use_case contain unsafe characters.
        """
        _validate_path_component(partner_name, "partner_name")
        _validate_path_component(use_case, "use_case")
        return self._entries_dir / f"{partner_name}__{use_case}.json"

    def _read_entry(self, partner_name: str, use_case: str) -> RegistryEntry | None:
        """Read and deserialize an entry file, or return None if absent.

        Validates the file content against the registry entry schema.

        :raises RegistryEntryCorruptedError: if the file exists but fails
            schema validation.
        """
        path = self._entry_path(partner_name, use_case)
        if not path.exists():
            return None
        data = json.loads(path.read_text())

        # Validate against schema.
        try:
            validate(instance=data, schema=_REGISTRY_ENTRY_SCHEMA)
        except ValidationError as e:
            path_str = " > ".join(str(p) for p in e.absolute_path)
            location = f" at [{path_str}]" if path_str else ""
            raise RegistryEntryCorruptedError(path, f"{e.message}{location}") from e

        versions = [
            _deserialize_version(v, data["partner_name"], data["use_case"])
            for v in data["versions"]
        ]
        return RegistryEntry(
            partner_name=data["partner_name"],
            use_case=data["use_case"],
            versions=versions,
        )

    def _write_entry(self, entry: RegistryEntry) -> None:
        """Serialize and write an entry to its JSON file."""
        path = self._entry_path(entry.partner_name, entry.use_case)
        data = {
            "partner_name": entry.partner_name,
            "use_case": entry.use_case,
            "versions": [
                _serialize_version(v, i + 1) for i, v in enumerate(entry.versions)
            ],
        }
        path.write_text(json.dumps(data, indent=2) + "\n")

    def _write_index(self) -> None:
        """Persist the boundary ownership index to index.json."""
        data = {"boundary_owners": self._boundary_owners}
        self._index_path.write_text(json.dumps(data, indent=2) + "\n")

    # --- Registry protocol methods ------------------------------------------

    def get(self, partner_name: str, use_case: str) -> RegistryEntry | None:
        """Read the entry for a key, or ``None`` if absent."""
        return self._read_entry(partner_name, use_case)

    def append(self, version: Version) -> None:
        """Append a new version to the entry, creating it if needed.

        Writes the updated entry to disk and updates boundary ownership.
        Auto-populates ``submitted_at`` with the current UTC timestamp if not set.
        """
        from datetime import datetime, timezone

        partner_name = version.bundle.partner_name
        use_case = version.bundle.use_case

        # Auto-populate submitted_at if not provided.
        if version.submitted_at is None:
            version.submitted_at = datetime.now(timezone.utc).isoformat()

        entry = self._read_entry(partner_name, use_case)
        if entry is None:
            entry = RegistryEntry(
                partner_name=partner_name,
                use_case=use_case,
                versions=[],
            )

        entry.versions.append(version)
        self._write_entry(entry)

        # Record boundary ownership if the bundle has a boundary.
        if version.bundle.boundary is not None:
            key = registry_key(partner_name, use_case)
            self._boundary_owners[version.bundle.boundary.id] = key
            self._write_index()

    def update_latest_version(
        self,
        partner_name: str,
        use_case: str,
        findings_summary: str,
        findings_count: dict[str, int],
        stages_completed: list[str],
        status: str | None = None,
    ) -> None:
        """Update the latest version's findings metadata in place.

        Used after Stage 3-4 analysis enriches the report with additional
        findings beyond what the deterministic pipeline (Stages 1-2) produced.
        Optionally transitions the version status.
        """
        entry = self._read_entry(partner_name, use_case)
        if entry is None:
            raise ValueError(
                f"No registry entry found for ({partner_name}, {use_case})"
            )
        if not entry.versions:
            raise ValueError(
                f"Registry entry for ({partner_name}, {use_case}) has no versions"
            )

        latest = entry.versions[-1]
        latest.findings_summary = findings_summary
        latest.findings_count = findings_count
        latest.stages_completed = stages_completed
        if status is not None:
            latest.status = status
        self._write_entry(entry)

    def save_report(
        self, partner_name: str, use_case: str, version_number: int, report_content: str
    ) -> Path:
        """Save a detailed findings report to disk and return the file path.

        The report is written to ``reports/<partner>__<use_case>__v<N>.md``.

        :raises ValueError: if partner_name or use_case contain unsafe characters.
        """
        _validate_path_component(partner_name, "partner_name")
        _validate_path_component(use_case, "use_case")
        filename = f"{partner_name}__{use_case}__v{version_number}.md"
        report_path = self._reports_dir / filename
        report_path.write_text(report_content, encoding="utf-8")
        return report_path

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
        by a different ``(partner_name, use_case)`` key.
        """
        if bundle.boundary is None:
            return False

        boundary_id = bundle.boundary.id
        owner_key = self._boundary_owners.get(boundary_id)

        if owner_key is None:
            return False

        bundle_key = registry_key(bundle.partner_name, bundle.use_case)
        return owner_key != bundle_key

    # --- findings store methods ---------------------------------------------

    def _findings_path(
        self, partner_name: str, use_case: str, version_number: int, stage_label: str
    ) -> Path:
        """Compute the path for a findings file.

        :raises ValueError: if any component contains unsafe characters.
        """
        _validate_path_component(partner_name, "partner_name")
        _validate_path_component(use_case, "use_case")
        _validate_path_component(stage_label, "stage_label")
        filename = f"{partner_name}__{use_case}__v{version_number}__{stage_label}.json"
        return self._findings_dir / filename

    def save_findings(
        self,
        partner_name: str,
        use_case: str,
        version_number: int,
        stage_label: str,
        findings_data: list[dict],
    ) -> Path:
        """Write (overwrite) a findings JSON file for a specific stage.

        Always overwrites — idempotent by design.

        :param partner_name: partner identifier.
        :param use_case: use case identifier.
        :param version_number: version number (1-indexed).
        :param stage_label: label for this findings set (e.g., "checks", "review").
        :param findings_data: list of finding dicts to persist.
        :returns: path to the written file.
        """
        path = self._findings_path(partner_name, use_case, version_number, stage_label)
        path.write_text(json.dumps(findings_data, indent=2) + "\n")
        return path

    def load_findings(
        self,
        partner_name: str,
        use_case: str,
        version_number: int,
        stage_label: str,
    ) -> list[dict]:
        """Read a findings JSON file for a specific stage.

        Returns an empty list if the file does not exist.
        """
        path = self._findings_path(partner_name, use_case, version_number, stage_label)
        if not path.exists():
            return []
        return json.loads(path.read_text())

    def load_all_findings(
        self, partner_name: str, use_case: str, version_number: int
    ) -> list[dict]:
        """Read and merge all findings files for a version.

        Scans the findings directory for all files matching the
        ``<partner>__<use_case>__v<N>__*.json`` pattern and merges them
        into a single list. Order: checks first, then review, then any others
        alphabetically.
        """
        _validate_path_component(partner_name, "partner_name")
        _validate_path_component(use_case, "use_case")
        prefix = f"{partner_name}__{use_case}__v{version_number}__"
        all_findings: list[dict] = []

        # Sort to ensure deterministic order (checks before review).
        matching_files = sorted(
            f for f in self._findings_dir.iterdir()
            if f.name.startswith(prefix) and f.name.endswith(".json")
        )
        for findings_file in matching_files:
            data = json.loads(findings_file.read_text())
            if isinstance(data, list):
                all_findings.extend(data)
        return all_findings

    # --- integrity manifest methods -----------------------------------------

    def _integrity_path(
        self, partner_name: str, use_case: str, version_number: int
    ) -> Path:
        """Compute the path for an integrity manifest file."""
        _validate_path_component(partner_name, "partner_name")
        _validate_path_component(use_case, "use_case")
        filename = f"{partner_name}__{use_case}__v{version_number}.json"
        return self._integrity_dir / filename

    def record_hash(
        self,
        partner_name: str,
        use_case: str,
        version_number: int,
        label: str,
        sha256_hash: str,
        recorded_by: str,
        source_path: str | None = None,
    ) -> None:
        """Record a SHA-256 hash in the integrity manifest.

        Updates only the specified label entry (read-modify-write).
        Creates the manifest file if it doesn't exist.
        """
        from datetime import datetime, timezone

        path = self._integrity_path(partner_name, use_case, version_number)
        if path.exists():
            manifest = json.loads(path.read_text())
        else:
            manifest = {"version": version_number, "hashes": {}}

        manifest["hashes"][label] = {
            "sha256": sha256_hash,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "recorded_by": recorded_by,
        }
        if source_path is not None:
            manifest["hashes"][label]["source_path"] = source_path

        path.write_text(json.dumps(manifest, indent=2) + "\n")

    def load_integrity_manifest(
        self, partner_name: str, use_case: str, version_number: int
    ) -> dict | None:
        """Load the integrity manifest for a version, or None if absent."""
        path = self._integrity_path(partner_name, use_case, version_number)
        if not path.exists():
            return None
        return json.loads(path.read_text())

    # --- artifacts store methods --------------------------------------------

    def artifacts_dir(
        self, partner_name: str, use_case: str, version_number: int
    ) -> Path:
        """Return the artifacts directory for a version, creating it if needed.

        :raises ValueError: if partner_name or use_case contain unsafe characters.
        """
        _validate_path_component(partner_name, "partner_name")
        _validate_path_component(use_case, "use_case")
        path = self._artifacts_dir / f"{partner_name}__{use_case}__v{version_number}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_artifact_path(
        self, partner_name: str, use_case: str, version_number: int, filename: str
    ) -> Path:
        """Return the path to a specific artifact file (may or may not exist)."""
        return self.artifacts_dir(partner_name, use_case, version_number) / filename
