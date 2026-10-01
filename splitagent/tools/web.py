"""Web/HTTP reconnaissance and configuration-audit tools."""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from splitagent.tools.base import Tool, ToolContext
from splitagent.tools.http_pool import get_client, request_headers

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set: TLS downgrade/stripping possible.",
    "content-security-policy": "No CSP: reflected content can execute scripts.",
    "x-content-type-options": "MIME sniffing not disabled.",
    "x-frame-options": "Clickjacking protection missing.",
    "referrer-policy": "Referrer leakage possible.",
    "permissions-policy": "Browser features not restricted.",
}

INFO_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")

TECH_SIGNATURES = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "django": "Django",
    "laravel": "Laravel",
    "php": "PHP",
    "express": "Express",
    "nginx": "Nginx",
    "apache": "Apache",
    "tomcat": "Tomcat",
    "spring": "Spring",
}

DEFAULT_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.env",
    "/.svn/entries",
    "/backup.zip",
    "/admin",
    "/admin/login",
    "/api",
    "/api/v1",
    "/swagger.json",
    "/openapi.json",
    "/actuator",
    "/actuator/health",
    "/debug",
    "/phpinfo.php",
    "/server-status",
    "/graphql",
]


async def _request(
    ctx: ToolContext,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    data: Any = None,
    follow: bool = True,
    max_body: int = 8000,
) -> dict[str, Any]:
    ctx.check_scope(url)
    started = time.perf_counter()
    merged_headers = ctx.auth_headers()
    merged_headers.update(headers or {})
    client = await get_client(follow=follow, verify=False, timeout=15.0, headers=merged_headers)
    # The client already carries merged_headers as defaults; sending them again
    # would duplicate every header.
    response = await client.request(
        method.upper(),
        url,
        headers=request_headers(client, headers),
        params=params,
        data=data,
    )
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    body = response.text[:max_body]
    return {
        "url": str(response.url),
        "status": response.status_code,
        "reason": response.reason_phrase,
        "headers": {k.lower(): v for k, v in response.headers.items()},
        "content_type": response.headers.get("content-type", ""),
        "elapsed_ms": elapsed,
        "body_length": len(response.content),
        "body": body,
        "truncated": len(response.content) > max_body,
    }


async def http_request(
    ctx: ToolContext,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    return await _request(ctx, url, method=method, headers=headers)


async def fetch(
    ctx: ToolContext,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    data: Any = None,
    follow: bool = True,
) -> dict[str, Any]:
    return await _request(
        ctx, url, method=method, headers=headers, params=params, data=data, follow=follow
    )


async def headers_audit(ctx: ToolContext, url: str) -> dict[str, Any]:
    response = await _request(ctx, url, method="GET")
    headers = response["headers"]
    missing = [
        {"header": name, "impact": impact}
        for name, impact in SECURITY_HEADERS.items()
        if name not in headers
    ]
    exposed = {name: headers[name] for name in INFO_HEADERS if name in headers}
    cookies = []
    for header_name, value in headers.items():
        if header_name == "set-cookie":
            cookies.append(value)
    cookie_flags = {
        "secure": any("secure" in c.lower() for c in cookies),
        "httponly": any("httponly" in c.lower() for c in cookies),
        "samesite": any("samesite" in c.lower() for c in cookies),
    }
    return {
        "url": response["url"],
        "status": response["status"],
        "missing_security_headers": missing,
        "information_disclosure": exposed,
        "cookie_count": len(cookies),
        "cookie_flags": cookie_flags if cookies else {},
    }


async def probe_paths(
    ctx: ToolContext,
    url: str,
    paths: list[str] | None = None,
    concurrency: int = 12,
) -> dict[str, Any]:
    ctx.check_scope(url)
    candidates = paths or DEFAULT_PATHS
    semaphore = asyncio.Semaphore(concurrency)
    found: list[dict[str, Any]] = []
    client = await get_client(follow=False, verify=False, timeout=10.0, headers=ctx.auth_headers())

    async def worker(path: str) -> None:
        target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
        async with semaphore:
            try:
                response = await client.get(target)
            except httpx.HTTPError:
                return
        interesting = response.status_code not in (404, 410) or (response.status_code == 403)
        if not interesting:
            return
        snippet = response.text[:300]
        found.append(
            {
                "path": path,
                "url": target,
                "status": response.status_code,
                "length": len(response.content),
                "snippet": snippet,
            }
        )

    await asyncio.gather(*(worker(p) for p in candidates))
    found.sort(key=lambda item: item["path"])
    return {"base": url, "found": found}


async def crawl(
    ctx: ToolContext, url: str, max_pages: int = 20, same_host: bool = True
) -> dict[str, Any]:
    ctx.check_scope(url)
    base_host = urlparse(url).hostname
    seen: set[str] = set()
    queue = [url]
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    link_re = re.compile(r"""href=["']([^"'#]+)["']""", re.IGNORECASE)
    form_re = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    action_re = re.compile(r"""action=["']([^"']*)["']""", re.IGNORECASE)
    input_re = re.compile(r"""name=["']([^"']+)["']""", re.IGNORECASE)

    client = await get_client(follow=True, verify=False, timeout=10.0, headers=ctx.auth_headers())
    while queue and len(pages) < max_pages:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            response = await client.get(current)
        except httpx.HTTPError:
            continue
        body = response.text[:60000]
        pages.append(
            {
                "url": str(response.url),
                "status": response.status_code,
                "title": _extract_title(body),
            }
        )
        for match in form_re.finditer(body):
            form_html = match.group(1)
            action = action_re.search(match.group(0))
            inputs = input_re.findall(form_html)
            forms.append(
                {
                    "page": str(response.url),
                    "action": action.group(1) if action else "",
                    "method": "post" if 'method="post"' in match.group(0).lower() else "get",
                    "inputs": inputs,
                }
            )
        for link in link_re.findall(body):
            absolute = urljoin(str(response.url), link)
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            if same_host and parsed.hostname != base_host:
                continue
            if absolute not in seen and absolute not in queue:
                queue.append(absolute)

    return {
        "base": url,
        "pages": pages,
        "forms": forms,
        "page_count": len(pages),
        "form_count": len(forms),
    }


def fingerprint(ctx: ToolContext, url: str = "") -> dict[str, Any]:
    return {"url": url or ctx.target.url, "note": "use headers_audit/fetch to fingerprint"}


def detect_technologies(body: str, headers: dict[str, str]) -> list[str]:
    haystack = body.lower()
    found = {name for signature, name in TECH_SIGNATURES.items() if signature in haystack}
    header_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for signature, name in TECH_SIGNATURES.items():
        if signature in header_blob:
            found.add(name)
    return sorted(found)


def _extract_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""


def red_web_tools(ctx: ToolContext) -> list[Tool]:
    async def _fetch(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
    ) -> dict[str, Any]:
        return await fetch(ctx, url, method=method, headers=headers, params=params, data=data)

    return [
        Tool(
            name="http_request",
            description=(
                "Send an arbitrary HTTP request to the target and inspect the "
                "status, response headers, timing and body slice."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object"},
                    "params": {"type": "object"},
                    "data": {"type": "object"},
                },
                "required": ["url"],
            },
            func=_fetch,
            scope="red",
        ),
        Tool(
            name="audit_security_headers",
            description=(
                "Audit HTTP security headers, information disclosure and cookie "
                "flags for a URL. Produces concrete, evidence-backed weaknesses."
            ),
            parameters={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
            func=lambda url: headers_audit(ctx, url),
            scope="red",
        ),
        Tool(
            name="probe_paths",
            description=(
                "Probe a curated list of sensitive paths (.git, .env, admin, "
                "swagger, actuator...) and report anything that is not a 404."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["url"],
            },
            func=lambda url, paths=None: probe_paths(ctx, url, paths),
            scope="red",
        ),
        Tool(
            name="crawl",
            description=(
                "Crawl the target up to max_pages, returning discovered URLs, "
                "titles and HTML forms (useful to find input points)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_pages": {"type": "integer", "default": 20},
                },
                "required": ["url"],
            },
            func=lambda url, max_pages=20: crawl(ctx, url, max_pages=max_pages),
            scope="red",
        ),
    ]
