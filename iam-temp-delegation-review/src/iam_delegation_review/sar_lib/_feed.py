"""Feed client + cache layer for the AWS service reference feed.

Fetches the index at ``https://servicereference.us-east-1.amazonaws.com/`` (an
array of ``{service, url, modified}``), fetches per-service documents on demand,
parses them into the in-memory model, and caches per service with invalidation
driven by the index ``modified`` timestamp.

Network access is injected via the HttpFetcher protocol for testability.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from ._model import (
    ActionProperties,
    ParsedAction,
    ParsedResource,
    ServiceDocument,
)

DEFAULT_INDEX_URL = "https://servicereference.us-east-1.amazonaws.com/"

#: Allowed domain suffixes for SAR feed URLs. Only amazonaws.com endpoints
#: are trusted sources for the service reference data.
_ALLOWED_DOMAIN_SUFFIXES = (".amazonaws.com",)


def _validate_feed_url(url: str) -> None:
    """Validate that a feed URL points to an allowed AWS domain.

    Only HTTPS URLs on ``*.amazonaws.com`` are permitted. This prevents
    the client from being redirected to fetch and parse JSON from an
    untrusted source.

    :raises ValueError: if the URL scheme is not HTTPS or the domain is
        not an allowed AWS endpoint.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"SAR feed URL must use HTTPS: {url!r}"
        )
    hostname = (parsed.hostname or "").lower()
    if not any(hostname.endswith(suffix) for suffix in _ALLOWED_DOMAIN_SUFFIXES):
        raise ValueError(
            f"SAR feed URL must be on an amazonaws.com domain, "
            f"got: {hostname!r}"
        )


@runtime_checkable
class HttpFetcher(Protocol):
    """Minimal async HTTP surface needed by the feed client.

    Implementations return the parsed JSON body for a GET of ``url``. Keeping
    this narrow makes it trivial to inject a fake in tests (no network, no
    ``httpx`` dependency).
    """

    async def get_json(self, url: str) -> Any:
        """GET ``url`` and return its parsed JSON body."""
        ...


class HttpxFetcher:
    """Default :class:`HttpFetcher` backed by ``httpx``.

    ``httpx`` is imported lazily in ``__init__`` so merely importing this module
    does not require the dependency; only real network use does.
    """

    def __init__(self, *, timeout: float = 10.0) -> None:
        import httpx  # noqa: PLC0415  (lazy import keeps httpx optional at import time)

        self._httpx = httpx
        self._timeout = timeout

    async def get_json(self, url: str) -> Any:
        async with self._httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()


@dataclass(frozen=True)
class IndexEntry:
    """One entry from the feed index: ``{ service, url, modified }``."""

    service: str
    url: str
    modified: str | None = None


@dataclass
class _CacheEntry:
    """A cached service document plus the ``modified`` stamp it was fetched at."""

    document: ServiceDocument
    modified: str | None


def parse_index(payload: Any) -> dict[str, IndexEntry]:
    """Parse the feed index array into a mapping of service name -> entry.

    The index is an array of objects with ``service``, ``url`` and (usually)
    ``modified`` keys. Entries missing ``service`` or ``url`` are skipped. The
    service name is lower-cased for case-insensitive lookups.
    """
    entries: dict[str, IndexEntry] = {}
    if not isinstance(payload, list):
        return entries
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        service = raw.get("service")
        url = raw.get("url")
        if not isinstance(service, str) or not isinstance(url, str):
            continue
        modified = raw.get("modified")
        modified_str = str(modified) if modified is not None else None
        entries[service.lower()] = IndexEntry(
            service=service, url=url, modified=modified_str
        )
    return entries


def _parse_properties(annotations: Any) -> ActionProperties:
    """Map ``Annotations.Properties`` flags onto :class:`ActionProperties`."""
    props = ActionProperties()
    if not isinstance(annotations, dict):
        return props
    properties = annotations.get("Properties")
    if not isinstance(properties, dict):
        return props
    return ActionProperties(
        is_write=bool(properties.get("IsWrite", False)),
        is_list=bool(properties.get("IsList", False)),
        is_permission_management=bool(properties.get("IsPermissionManagement", False)),
        is_tagging_only=bool(properties.get("IsTaggingOnly", False)),
    )


def _as_str_list(value: Any) -> list[str]:
    """Coerce a JSON value into a list of strings, dropping non-strings."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _as_ref_list(value: Any) -> list[str]:
    """Coerce a list of resource references into a list of names.

    The feed expresses an action's ``Resources`` as a list of objects with a
    ``Name`` key (references into the document's ``Resources[]``). Bare strings
    are also accepted for resilience. Anything else is dropped.
    """
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for item in value:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("Name")
            if isinstance(name, str):
                names.append(name)
    return names


def _parse_action(raw: Any) -> ParsedAction | None:
    """Parse a single ``Actions[]`` entry, or ``None`` if it has no name."""
    if not isinstance(raw, dict):
        return None
    name = raw.get("Name")
    if not isinstance(name, str):
        return None
    return ParsedAction(
        name=name,
        condition_keys=_as_str_list(raw.get("ActionConditionKeys")),
        # A permission-only action has no Resources key -> empty list, which is
        # the explicit representation of [permission only].
        resource_refs=_as_ref_list(raw.get("Resources")),
        properties=_parse_properties(raw.get("Annotations")),
    )


def _parse_resource(raw: Any) -> ParsedResource | None:
    """Parse a single ``Resources[]`` entry, or ``None`` if it has no name."""
    if not isinstance(raw, dict):
        return None
    name = raw.get("Name")
    if not isinstance(name, str):
        return None
    return ParsedResource(
        name=name,
        arn_formats=_as_str_list(raw.get("ARNFormats")),
        condition_keys=_as_str_list(raw.get("ConditionKeys")),
    )


def parse_service_document(
    service: str, payload: Any, *, modified: str | None = None
) -> ServiceDocument:
    """Parse a per-service reference document into a :class:`ServiceDocument`.

    Tolerant of missing/extra keys: unknown shapes are skipped rather than
    raising, so a partial feed still yields a usable document.
    """
    doc = ServiceDocument(service=service, modified=modified)
    if not isinstance(payload, dict):
        return doc

    version = payload.get("Version")
    doc.version = str(version) if version is not None else None

    for raw_action in payload.get("Actions", []) or []:
        action = _parse_action(raw_action)
        if action is not None:
            doc.actions[action.name.lower()] = action

    doc.condition_keys = _as_str_list(payload.get("ConditionKeys"))

    for raw_resource in payload.get("Resources", []) or []:
        resource = _parse_resource(raw_resource)
        if resource is not None:
            doc.resources[resource.name.lower()] = resource

    return doc


class ServiceReferenceClient:
    """Fetches, parses and caches AWS service reference documents.

    The client lazily fetches the index (once, then memoized) and per-service
    documents on demand. Each service document is cached and only refetched when
    the index ``modified`` stamp for that service changes — the cache
    invalidation signal called for by the design.

    The cache is held on the instance (process-local) so it is easy to reason
    about and test. An :class:`asyncio.Lock` serializes index/document fetches
    so concurrent callers don't issue duplicate network requests.

    :param fetcher: HTTP access. Defaults to an :class:`HttpxFetcher`
        (constructed lazily so importing this module never requires ``httpx``).
    :param index_url: Override the feed index URL (useful for tests/mirrors).
    """

    def __init__(
        self,
        fetcher: HttpFetcher | None = None,
        *,
        index_url: str = DEFAULT_INDEX_URL,
    ) -> None:
        _validate_feed_url(index_url)
        self._fetcher = fetcher
        self._index_url = index_url
        self._index: dict[str, IndexEntry] | None = None
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()

    @property
    def _resolved_fetcher(self) -> HttpFetcher:
        """Return the injected fetcher, constructing the httpx default lazily."""
        if self._fetcher is None:
            self._fetcher = HttpxFetcher()
        return self._fetcher

    async def get_index(self, *, force_refresh: bool = False) -> dict[str, IndexEntry]:
        """Return the parsed feed index, fetching it once and memoizing it.

        :param force_refresh: refetch the index even if already cached. This is
            how callers pick up a newer ``modified`` stamp to trigger per-service
            cache invalidation.
        """
        async with self._lock:
            if self._index is None or force_refresh:
                payload = await self._resolved_fetcher.get_json(self._index_url)
                self._index = parse_index(payload)
            return self._index

    async def get_service_document(
        self, service: str, *, force_refresh: bool = False
    ) -> ServiceDocument | None:
        """Return the parsed document for ``service`` (cached), or ``None``.

        Resolution:

        1. Ensure the index is loaded (re-reading it when ``force_refresh`` is
           true so a newer ``modified`` stamp is observed); look up the
           service's index entry. If the service is not in the index, return
           ``None`` (explicit miss).
        2. If a cached document exists and the index ``modified`` stamp is
           unchanged, return the cached copy without refetching — even under
           ``force_refresh``. The stamp, not the flag, is the invalidation
           signal: ``force_refresh`` only forces a fresh *index* read.
        3. Otherwise fetch the per-service JSON from the entry's ``url``, parse
           it, cache it against the current ``modified`` stamp, and return it.
        """
        index = await self.get_index(force_refresh=force_refresh)
        key = service.lower()
        entry = index.get(key)
        if entry is None:
            return None

        async with self._lock:
            cached = self._cache.get(key)
            if cached is not None and cached.modified == entry.modified:
                return cached.document

            _validate_feed_url(entry.url)
            payload = await self._resolved_fetcher.get_json(entry.url)
            document = parse_service_document(
                entry.service, payload, modified=entry.modified
            )
            self._cache[key] = _CacheEntry(document=document, modified=entry.modified)
            return document

    def cached_services(self) -> list[str]:
        """Return the service keys currently held in the cache (for tests/introspection)."""
        return sorted(self._cache)

    def clear_cache(self) -> None:
        """Drop all cached service documents (the index memo is kept)."""
        self._cache.clear()


__all__ = [
    "DEFAULT_INDEX_URL",
    "HttpFetcher",
    "HttpxFetcher",
    "IndexEntry",
    "ServiceReferenceClient",
    "parse_index",
    "parse_service_document",
]
