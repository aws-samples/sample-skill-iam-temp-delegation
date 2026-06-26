"""Parsed in-memory model for the AWS service reference feed.

These dataclasses represent a single service's reference document
(e.g. ``.../v1/<service>/<service>.json``). They are produced by
``_feed.parse_service_document`` and consumed by the lookup in ``__init__``.

Per-service JSON structure:
- ``Actions[]`` with ``Name``, ``ActionConditionKeys[]``, ``Resources[]`` refs,
  and ``Annotations.Properties`` flags.
- ``Resources[]`` with ``Name``, ``ARNFormats[]``, and ``ConditionKeys[]``.
- A permission-only action has no ``Resources`` entry → empty ``resource_refs``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ActionProperties:
    """Action-level property flags from ``Annotations.Properties`` in the feed."""

    is_write: bool = False
    is_list: bool = False
    is_permission_management: bool = False
    is_tagging_only: bool = False


@dataclass
class ParsedAction:
    """A single parsed ``Action`` from a service document.

    ``resource_refs`` holds the names of the resources this action supports
    (references into the document's ``Resources[]``). An **empty** list is the
    explicit representation of a ``[permission only]`` action — one the feed
    declares with no ``Resources`` entry. This is distinguishable from "the
    action was never parsed" because a missing action yields no ``ParsedAction``
    at all (the lookup returns a miss), whereas a permission-only action yields a
    ``ParsedAction`` whose ``resource_refs`` is the empty list.
    """

    name: str
    condition_keys: list[str] = field(default_factory=list)
    resource_refs: list[str] = field(default_factory=list)
    properties: ActionProperties = field(default_factory=ActionProperties)

    @property
    def is_permission_only(self) -> bool:
        """True when the action supports no resources (``[permission only]``)."""
        return len(self.resource_refs) == 0


@dataclass
class ParsedResource:
    """A single parsed ``Resource`` from a service document."""

    name: str
    arn_formats: list[str] = field(default_factory=list)
    condition_keys: list[str] = field(default_factory=list)


@dataclass
class ServiceDocument:
    """The parsed reference document for one service.

    ``actions`` and ``resources`` are keyed by lower-cased name for
    case-insensitive resolution (IAM action/resource names are case-insensitive).
    ``modified`` carries the index ``modified`` stamp the document was fetched
    against; it is the cache-invalidation signal (see ``_feed``).
    """

    service: str
    version: str | None = None
    modified: str | None = None
    actions: dict[str, ParsedAction] = field(default_factory=dict)
    condition_keys: list[str] = field(default_factory=list)
    resources: dict[str, ParsedResource] = field(default_factory=dict)

    def get_action(self, action: str) -> ParsedAction | None:
        """Case-insensitively resolve an action by name, or ``None``."""
        return self.actions.get(action.lower())

    def get_resource(self, resource: str) -> ParsedResource | None:
        """Case-insensitively resolve a resource by name, or ``None``."""
        return self.resources.get(resource.lower())


__all__ = [
    "ActionProperties",
    "ParsedAction",
    "ParsedResource",
    "ServiceDocument",
]
