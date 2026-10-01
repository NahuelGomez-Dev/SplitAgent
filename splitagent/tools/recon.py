"""Reconnaissance tools (attack-surface mapping)."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from splitagent.tools.base import Tool, ToolContext

WELL_KNOWN = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9000: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

DEFAULT_PORTS = sorted(WELL_KNOWN)


async def _probe(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return None
    banner = ""
    try:
        if port in (80, 8080, 8000, 3000, 9000):
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        banner = data.decode("utf-8", "replace").strip().splitlines()[0] if data else ""
    except (asyncio.TimeoutError, OSError):
        banner = ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, RuntimeError):
            pass
    return {
        "port": port,
        "state": "open",
        "service": WELL_KNOWN.get(port, "unknown"),
        "banner": banner[:160],
    }


async def tcp_scan(
    ctx: ToolContext,
    host: str = "",
    ports: list[int] | None = None,
    timeout: float = 0.8,
    concurrency: int = 128,
) -> dict[str, Any]:
    host = host or (ctx.target.effective_hosts() or ["localhost"])[0]
    ctx.check_scope(host)
    port_list = ports or ctx.target.ports or DEFAULT_PORTS
    port_list = [int(p) for p in port_list][:2000]
    semaphore = asyncio.Semaphore(concurrency)

    async def worker(port: int) -> dict[str, Any] | None:
        async with semaphore:
            return await _probe(host, port, timeout)

    results = await asyncio.gather(*(worker(p) for p in port_list))
    open_ports = [r for r in results if r]
    open_ports.sort(key=lambda r: r["port"])
    return {
        "host": host,
        "scanned": len(port_list),
        "open": open_ports,
        "count": len(open_ports),
    }


def dns_lookup(host: str = "") -> dict[str, Any]:
    target = host or "localhost"
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror as exc:
        return {"host": target, "error": str(exc)}
    addresses = sorted({info[4][0] for info in infos})
    return {"host": target, "addresses": addresses}


def red_recon_tools(ctx: ToolContext) -> list[Tool]:
    async def _scan(host: str = "", ports: list[int] | None = None) -> dict[str, Any]:
        return await tcp_scan(ctx, host=host, ports=ports)

    return [
        Tool(
            name="dns_lookup",
            description=(
                "Resolve a hostname to IP addresses. Use it to confirm the target "
                "is reachable before scanning."
            ),
            parameters={
                "type": "object",
                "properties": {"host": {"type": "string"}},
            },
            func=dns_lookup,
            scope="red",
        ),
        Tool(
            name="port_scan",
            description=(
                "TCP connect scan against the authorised target. Returns open "
                "ports with service guesses and captured banners."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Explicit port list; defaults to common ports.",
                    },
                },
            },
            func=_scan,
            scope="red",
        ),
    ]
