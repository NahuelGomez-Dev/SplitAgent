"""A shared HTTP connection pool for the reconnaissance tools.

Every web tool used to build its own ``httpx.AsyncClient`` per call, which
means a fresh TCP handshake, a fresh TLS handshake and a fresh DNS lookup for
every single request. During a crawl or a path sweep that dominates the wall
clock. One client with keep-alive removes it entirely.

The pool is keyed by the flags that affect connection reuse (redirect and
verification policy), created lazily and closed by the engine at the end of a
run.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

_CLIENTS: dict[tuple[Any, ...], httpx.AsyncClient] = {}
_LOCK = asyncio.Lock()

DEFAULT_LIMITS = httpx.Limits(
    max_connections=64,
    max_keepalive_connections=32,
    keepalive_expiry=30.0,
)


def _http2_available() -> bool:
    """HTTP/2 needs the optional ``h2`` package; degrade silently without it."""
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True


HTTP2 = _http2_available()


def _key(
    follow: bool, verify: bool, timeout: float, headers: dict[str, str] | None
) -> tuple[Any, ...]:
    # Headers participate in the key so authenticated and anonymous traffic
    # never share a connection pool (and therefore never leak a cookie).
    header_key = tuple(sorted((headers or {}).items()))
    return (follow, verify, timeout, header_key)


async def get_client(
    *,
    follow: bool = True,
    verify: bool = False,
    timeout: float = 15.0,
    headers: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    """Return a pooled client for the given transport policy.

    The headers become the client's defaults. Callers must NOT pass the same
    headers per-request: httpx appends request headers to the client defaults,
    which would send each one twice and the server would reject the request as
    having conflicting headers. Use :func:`request_headers` to get the extras
    that still need to be added (a per-call override such as ``Origin``).
    """
    key = _key(follow, verify, timeout, headers)
    client = _CLIENTS.get(key)
    if client is not None and not client.is_closed:
        return client
    async with _LOCK:
        client = _CLIENTS.get(key)
        if client is not None and not client.is_closed:
            return client
        client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow,
            verify=verify,
            headers=dict(headers or {}),
            limits=DEFAULT_LIMITS,
            http2=HTTP2,
        )
        _CLIENTS[key] = client
        return client


def request_headers(
    client: httpx.AsyncClient, overrides: dict[str, str] | None = None
) -> dict[str, str]:
    """Return only the headers a caller must add on top of the client defaults.

    Anything already present as a client default is dropped, so a request never
    carries the same header twice.
    """
    if not overrides:
        return {}
    defaults = {name.lower() for name in client.headers}
    return {name: value for name, value in overrides.items() if name.lower() not in defaults}


async def aclose_all() -> None:
    """Close every pooled client (called when a run finishes)."""
    async with _LOCK:
        clients = list(_CLIENTS.values())
        _CLIENTS.clear()
    for client in clients:
        try:
            await client.aclose()
        except Exception:
            pass
