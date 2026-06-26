"""sar_lib — SAR (Service Authorization Reference) lookup.

A thin local wrapper over AWS's public machine-readable service reference feed
(``https://servicereference.us-east-1.amazonaws.com/``). No server, no
transport — just fetch + parse + cache. Suitable for later wrapping as an MCP
server if external partners require it.

Layering:

- ``_model``  — parsed in-memory model (ServiceDocument, ParsedAction,
  ParsedResource, ActionProperties).
- ``_feed``   — ServiceReferenceClient: fetch the index, fetch per-service JSON
  on demand, parse, and cache with invalidation driven by the index ``modified``
  timestamp.
- this module — the public ``lookup(service, action)`` surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..shared import SarRow
from ._feed import (
    DEFAULT_INDEX_URL,
    HttpFetcher,
    HttpxFetcher,
    IndexEntry,
    ServiceReferenceClient,
    parse_index,
    parse_service_document,
)
from ._model import (
    ActionProperties,
    ParsedAction,
    ParsedResource,
    ServiceDocument,
)


@dataclass
class LookupHit:
    """Successful lookup result for a single (service, action)."""

    row: SarRow
    properties: ActionProperties
    found: Literal[True] = True


@dataclass
class LookupMiss:
    """Explicit not-found result (unknown service/action)."""

    found: Literal[False] = False


LookupResult = LookupHit | LookupMiss


# Process-local default client used by the module-level ``lookup`` convenience
# function. Tests and hosts that need isolation can construct their own
# ``ServiceReferenceClient`` (with an injected fetcher) instead.
_default_client: ServiceReferenceClient | None = None


def get_default_client() -> ServiceReferenceClient:
    """Return (constructing on first use) the process-local default client."""
    global _default_client
    if _default_client is None:
        _default_client = ServiceReferenceClient()
    return _default_client


def set_default_client(client: ServiceReferenceClient | None) -> None:
    """Override (or reset to ``None``) the process-local default client.

    Primarily a test seam so the public ``lookup`` can be exercised against an
    injected fetcher without touching the network.
    """
    global _default_client
    _default_client = client


def _merge_condition_keys(
    action: ParsedAction, document: ServiceDocument
) -> list[str]:
    """Return the condition keys an action honors, action-level first.

    The verifier needs the full "action -> supported resource types -> supported
    condition keys" picture (Requirements 4.4, 5.2). The feed splits condition
    keys across two places:

    - ``ActionConditionKeys`` on the action itself, and
    - ``ConditionKeys`` on each resource type the action references.

    We merge both: the action-level keys first (most directly applicable), then
    the resource-level keys contributed by the referenced resources, in resource
    reference order. The result is de-duplicated while preserving first-seen
    order so a key that appears at both levels is reported once.
    """
    merged: list[str] = []
    seen: set[str] = set()

    def _add(keys: list[str]) -> None:
        for key in keys:
            if key not in seen:
                seen.add(key)
                merged.append(key)

    _add(action.condition_keys)
    for ref in action.resource_refs:
        resource = document.get_resource(ref)
        if resource is not None:
            _add(resource.condition_keys)
    return merged


async def lookup(
    service: str, action: str, *, client: ServiceReferenceClient | None = None
) -> LookupResult:
    """Look up an action in the SAR.

    Resolves ``(service, action)`` against the AWS service reference feed and
    returns the supported resource types, condition keys, and property flags, or
    an explicit not-found.

    :param service: the service prefix (e.g. ``"organizations"``);
        case-insensitive.
    :param action: the action name (e.g. ``"AcceptHandshake"``);
        case-insensitive.
    :param client: optional client override. Defaults to the process-local
        :func:`get_default_client`. Tests can either pass a client built on a
        fake fetcher here, or install one via :func:`set_default_client`.
    :returns: a :class:`LookupHit` carrying a populated :class:`SarRow` plus the
        action's :class:`ActionProperties`, or a :class:`LookupMiss` when the
        service is unknown or the action is not present.

    Resolution semantics:

    - Unknown service (the client returns no document) -> :class:`LookupMiss`.
    - Action not present in the document -> :class:`LookupMiss` (explicit
      not-found).
    - On a hit, the :class:`SarRow` carries:

      - ``action``: a normalized ``"<service>:<ActionName>"`` string — the
        service lower-cased, the action using its parsed (correctly cased) name
        (e.g. ``"organizations:DescribeOrganization"``).
      - ``resource_types``: the action's ``resource_refs``. For a
        ``[permission only]`` action this is the empty list, which is a valid
        hit (an explicit "no scopable resources"), **not** a miss.
      - ``condition_keys``: the action-level condition keys merged with the
        condition keys of the resource types it references (see
        :func:`_merge_condition_keys`).
    """
    resolver = client if client is not None else get_default_client()
    document = await resolver.get_service_document(service)
    if document is None:
        return LookupMiss()

    parsed_action = document.get_action(action)
    if parsed_action is None:
        return LookupMiss()

    row = SarRow(
        action=f"{service.lower()}:{parsed_action.name}",
        resource_types=list(parsed_action.resource_refs),
        condition_keys=_merge_condition_keys(parsed_action, document),
    )
    return LookupHit(row=row, properties=parsed_action.properties)


__all__ = [
    # public lookup surface
    "ActionProperties",
    "LookupHit",
    "LookupMiss",
    "LookupResult",
    "lookup",
    "get_default_client",
    "set_default_client",
    # feed/cache layer
    "DEFAULT_INDEX_URL",
    "HttpFetcher",
    "HttpxFetcher",
    "IndexEntry",
    "ServiceReferenceClient",
    "parse_index",
    "parse_service_document",
    # parsed model
    "ParsedAction",
    "ParsedResource",
    "ServiceDocument",
]
