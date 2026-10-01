"""Defensive tools used by the Blue Agent (log triage, hardening, patching)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from splitagent.tools.base import Tool, ToolContext
from splitagent.tools.http_pool import get_client
from splitagent.tools.web import SECURITY_HEADERS

FIREWALL_TEMPLATES = {
    "iptables": "iptables -A INPUT -p tcp --dport {port} -s {source} -j {action}",
    "nft": "nft add rule inet filter input tcp dport {port} ip saddr {source} {action}",
    "ufw": "ufw {action_map} from {source} to any port {port} proto tcp",
    "windows": (
        'New-NetFirewallRule -DisplayName "SplitAgent-{port}" -Direction Inbound '
        "-Protocol TCP -LocalPort {port} -RemoteAddress {source} -Action {action_map}"
    ),
}

HARDEN_SNIPPETS = {
    "nginx": """# /etc/nginx/conf.d/security-headers.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
server_tokens off;""",
    "apache": """# httpd.conf / .htaccess
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'none'"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
ServerTokens Prod
ServerSignature Off""",
    "express": """// app.js (Express)
import helmet from "helmet";
app.use(helmet());
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});""",
}

PATCH_TEMPLATES = {
    "sql_injection": {
        "language": "python",
        "title": "Use parameterised queries",
        "diff": (
            "- cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
            '+ cursor.execute("SELECT * FROM users WHERE name = %s", (name,))'
        ),
    },
    "reflected_xss": {
        "language": "javascript",
        "title": "Context-aware output encoding",
        "diff": (
            "- el.innerHTML = userInput;\n"
            "+ el.textContent = userInput;\n"
            "// or, server side: escape with your template engine's autoescaping"
        ),
    },
    "path_traversal": {
        "language": "python",
        "title": "Canonicalise and confine file paths",
        "diff": (
            "- path = os.path.join(BASE, request.args['file'])\n"
            "+ safe = os.path.basename(request.args['file'])\n"
            "+ path = os.path.realpath(os.path.join(BASE, safe))\n"
            "+ if not path.startswith(os.path.realpath(BASE) + os.sep):\n"
            "+     raise ValueError('path traversal attempt')"
        ),
    },
    "command_injection": {
        "language": "python",
        "title": "Avoid the shell; pass an argument vector",
        "diff": (
            "- os.system('ping -c 1 ' + host)\n"
            "+ subprocess.run(['ping', '-c', '1', host], shell=False, check=True)"
        ),
    },
    "cors_misconfiguration": {
        "language": "python",
        "title": "Restrict CORS to an allow-list",
        "diff": (
            "- values['Access-Control-Allow-Origin'] = '*'\n"
            "+ if origin in ALLOWED_ORIGINS:\n"
            "+     values['Access-Control-Allow-Origin'] = origin\n"
            "+     values['Vary'] = 'Origin'"
        ),
    },
    "open_redirect": {
        "language": "python",
        "title": "Validate redirect targets against an allow-list",
        "diff": (
            "- return redirect(request.args['next'])\n"
            "+ target = urlparse(request.args.get('next', '/'))\n"
            "+ if target.netloc and target.netloc not in ALLOWED_HOSTS:\n"
            "+     return redirect('/')\n"
            "+ return redirect(request.args['next'])"
        ),
    },
}

LOG_PATTERNS = {
    "sqli": r"(union\s+select|or\s+1=1|sleep\(|information_schema)",
    "xss": r"(<script|onerror=|onload=|javascript:)",
    "traversal": r"(\.\./|%2e%2e|/etc/passwd)",
    "scanner": r"(nikto|sqlmap|nmap|masscan|acunetix|nessus|dirbuster|gobuster)",
    "auth_fail": r"(failed password|authentication failure|invalid user|401)",
    "server_error": r"(500 internal server error|traceback|exception|stack trace)",
}


def _firewall_rule(platform: str, action: str, port: int, source: str = "any") -> dict[str, Any]:
    template = FIREWALL_TEMPLATES.get(platform)
    if not template:
        return {"error": f"unknown platform '{platform}'", "platforms": list(FIREWALL_TEMPLATES)}
    action_map = {
        "block": "DROP" if platform in ("iptables", "nft") else "block",
        "allow": "ACCEPT" if platform in ("iptables", "nft") else "allow",
    }.get(action, action.upper())
    if platform == "ufw":
        rule = template.format(
            port=port, source=source, action_map="deny" if action == "block" else "allow"
        )
    elif platform == "windows":
        rule = template.format(
            port=port, source=source, action_map="Block" if action == "block" else "Allow"
        )
    else:
        rule = template.format(port=port, source=source, action=action_map)
    return {
        "platform": platform,
        "action": action,
        "port": port,
        "source": source,
        "rule": rule,
    }


async def _analyze_logs(
    ctx: ToolContext, path: str = "", source: str = "auto", max_lines: int = 4000
) -> dict[str, Any]:
    text = ""
    origin = path
    if source in ("auto", "file") and path:
        candidate = Path(path)
        if candidate.exists() and candidate.is_file():
            text = candidate.read_text(encoding="utf-8", errors="replace")
        else:
            return {"error": f"log file not found: {path}"}
    if not text and source in ("auto", "sandbox"):
        sandbox = ctx.settings.get("sandbox")
        if sandbox is not None:
            text = await sandbox.logs(tail=1000)
            origin = f"sandbox:{sandbox.name}"
    if not text:
        return {
            "info": "no log source available",
            "hint": "pass a path to a log file or enable the Docker sandbox",
        }
    lines = text.splitlines()[-max_lines:]
    matches: dict[str, list[str]] = {}
    for name, pattern in LOG_PATTERNS.items():
        regex = re.compile(pattern, re.IGNORECASE)
        hits = [line.strip()[:300] for line in lines if regex.search(line)]
        if hits:
            matches[name] = hits[-10:]
    return {
        "source": origin,
        "lines_analyzed": len(lines),
        "categories": {k: len(v) for k, v in matches.items()},
        "samples": matches,
        "suspicious": bool(matches),
    }


# Which validator re-proves which finding category. This is what turns a
# mitigation from "proposed" into "verified": we attack the target again and
# see whether the hole is actually gone.
_REPROBE_BY_CATEGORY = {
    "sql_injection": ("test_sql_injection", "parameter"),
    "reflected_xss": ("test_xss", "parameter"),
    "xss": ("test_xss", "parameter"),
    "path_traversal": ("test_path_traversal", "parameter"),
    "command_injection": ("test_command_injection", "parameter"),
    "open_redirect": ("test_open_redirect", "parameter"),
}

# Categories whose proof is a service state, not an HTTP response.
_REPROBE_SERVICE = {
    "unauthenticated_shell": ("validate_root_shell", "port"),
    "backdoor": ("validate_vsftpd_backdoor", "port"),
    "database_exposure": ("validate_mysql_blank_password", "port"),
}


def _finding_port(finding: Any) -> int | None:
    """Pull a port out of an endpoint such as ``tcp/1524`` or ``host:3306``."""
    import re

    blob = f"{finding.endpoint or ''} {finding.target or ''}"
    match = re.search(r"(?:tcp|udp)/\s*(\d{2,5})", blob)
    if match:
        return int(match.group(1))
    match = re.search(r":(\d{2,5})\b", blob)
    return int(match.group(1)) if match else None


def _finding_host(finding: Any, ctx: ToolContext) -> str:
    import re
    from urllib.parse import urlparse

    blob = f"{finding.endpoint or ''} {finding.target or ''}"
    url_match = re.search(r"https?://([^/\s:]+)", blob)
    if url_match:
        return url_match.group(1)
    if finding.target and "://" not in finding.target:
        return finding.target.split()[0].split(":")[0]
    hosts = ctx.target.effective_hosts()
    return urlparse(hosts[0] if hosts else "localhost").hostname or "localhost"


async def _verify_control(ctx: ToolContext, finding_id: str) -> dict[str, Any]:
    """Re-attack the target to see whether a mitigation actually closed it.

    This is the difference between a report that says "apply this rule" and one
    that says "this rule is in place and the hole is gone". Only the second is
    worth anything to the operator, and only a confirmed re-test counts toward
    the resilience score.
    """
    finding = ctx.context.state.get_finding(finding_id)
    if finding is None:
        return {"error": f"finding '{finding_id}' not found"}

    category = (finding.category or "").lower()
    host = _finding_host(finding, ctx)
    result: dict[str, Any] = {"test": "re-probe", "category": category}

    # 1. Service-level findings: re-run the matching validator.
    if category in _REPROBE_SERVICE:
        from splitagent.tools import validate as validators

        name, _kind = _REPROBE_SERVICE[category]
        port = _finding_port(finding)
        validator = getattr(validators, name, None)
        if validator is not None:
            try:
                probe = await validator(ctx, host, *((port,) if port else ()))
            except Exception as exc:
                return {"error": f"{type(exc).__name__}: {exc}", "verified": False}
            # The exploit no longer works -> the control holds.
            closed = probe.get("validated") is False
            result.update(
                {
                    "verified": closed,
                    "still_exploitable": probe.get("validated") is True,
                    "evidence": (
                        f"Re-ran {name}: "
                        + (
                            "the exploit no longer succeeds, the control holds."
                            if closed
                            else "the target is STILL vulnerable: "
                            + str(probe.get("evidence"))[:160]
                        )
                    ),
                }
            )
            return _record_verification(ctx, finding_id, result)

    # 2. HTTP-level findings: re-run the injection probe.
    if category in _REPROBE_BY_CATEGORY:
        from splitagent.tools import exploit as probes

        name, _arg = _REPROBE_BY_CATEGORY[category]
        probe_fn = getattr(probes, name, None)
        parameter = _guessed_parameter(finding)
        url = finding.endpoint or ctx.target.url
        if probe_fn is not None and url and parameter:
            try:
                probe = await probe_fn(ctx, url, parameter)
            except Exception as exc:
                return {"error": f"{type(exc).__name__}: {exc}", "verified": False}
            closed = probe.get("vulnerable") is False
            result.update(
                {
                    "verified": closed,
                    "still_exploitable": probe.get("vulnerable") is True,
                    "evidence": (
                        f"Re-ran {name} on '{parameter}': "
                        + (
                            "no longer exploitable, the control holds."
                            if closed
                            else "STILL exploitable: " + str(probe.get("evidence"))[:160]
                        )
                    ),
                }
            )
            return _record_verification(ctx, finding_id, result)

    # 3. Header / configuration findings: compare the actual response.
    url = finding.endpoint or ctx.target.url
    if url:
        ctx.check_scope(url)
        client = await get_client(follow=False, verify=False, timeout=10.0)
        response = await client.get(url)
        headers = {k.lower(): v for k, v in response.headers.items()}
        if category in ("headers", "misconfiguration"):
            missing = [h for h in SECURITY_HEADERS if h not in headers]
            # Half or more of the headers present means the hardening landed.
            verified = len(missing) < len(SECURITY_HEADERS) // 2
            result.update(
                {
                    "verified": verified,
                    "status": response.status_code,
                    "remaining_missing": missing,
                    "evidence": (
                        f"{len(SECURITY_HEADERS) - len(missing)}/"
                        f"{len(SECURITY_HEADERS)} security headers present"
                    ),
                }
            )
            return _record_verification(ctx, finding_id, result)
        result.update(
            {
                "verified": None,
                "status": response.status_code,
                "evidence": (
                    "The endpoint answers. This category has no automatic re-test; "
                    "confirm by hand before marking it closed."
                ),
            }
        )
        return result

    return {
        "verified": None,
        "reason": "finding has no testable endpoint",
        "evidence": "Nothing to re-test: the finding is informational.",
    }


def _guessed_parameter(finding: Any) -> str:
    """Recover the parameter name a web finding was found on."""
    import re

    blob = f"{finding.endpoint or ''} {finding.evidence or ''}"
    match = re.search(r"[?&]([A-Za-z_][\w-]{0,30})=", blob)
    if match:
        return match.group(1)
    match = re.search(r"parameter[:\s]+'?([A-Za-z_][\w-]{0,30})", blob, re.IGNORECASE)
    return match.group(1) if match else ""


def _record_verification(
    ctx: ToolContext, finding_id: str, result: dict[str, Any]
) -> dict[str, Any]:
    """Persist the verdict so the resilience score can trust it."""
    verified = result.get("verified") is True
    state = ctx.context.state
    for mitigation in state.mitigations:
        if mitigation.finding_id != finding_id:
            continue
        mitigation.verified = verified
        mitigation.status = "verified" if verified else "proposed"
    finding = state.get_finding(finding_id)
    if finding is not None:
        finding.status = "mitigated" if verified else "open"
    ctx.context.save()
    return result


def blue_tools(ctx: ToolContext) -> list[Tool]:
    async def _logs(path: str = "", source: str = "auto") -> dict[str, Any]:
        return await _analyze_logs(ctx, path=path, source=source)

    return [
        Tool(
            name="analyze_logs",
            description=(
                "Triage logs (from a file or the running sandbox container) for "
                "injection attempts, scanners, auth failures and server errors."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "source": {"type": "string", "enum": ["auto", "file", "sandbox"]},
                },
            },
            func=_logs,
            scope="blue",
        ),
        Tool(
            name="generate_firewall_rule",
            description=(
                "Produce a ready-to-apply firewall rule (iptables, nft, ufw or "
                "Windows) to block or allow a port for a given source."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "enum": list(FIREWALL_TEMPLATES),
                    },
                    "action": {"type": "string", "enum": ["block", "allow"]},
                    "port": {"type": "integer"},
                    "source": {"type": "string"},
                },
                "required": ["platform", "action", "port"],
            },
            func=lambda platform, action, port, source="any": _firewall_rule(
                platform, action, port, source
            ),
            scope="blue",
        ),
        Tool(
            name="harden_headers",
            description=(
                "Return a server-specific hardening snippet adding the missing "
                "security headers (nginx, apache or express)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "server": {"type": "string", "enum": list(HARDEN_SNIPPETS)},
                },
                "required": ["server"],
            },
            func=lambda server: {
                "server": server,
                "snippet": HARDEN_SNIPPETS.get(server, "unknown server"),
            },
            scope="blue",
        ),
        Tool(
            name="suggest_patch",
            description=(
                "Return a code-level remediation diff for a vulnerability "
                "category (sql_injection, reflected_xss, path_traversal, "
                "command_injection, cors_misconfiguration, open_redirect)."
            ),
            parameters={
                "type": "object",
                "properties": {"category": {"type": "string"}},
                "required": ["category"],
            },
            func=lambda category: PATCH_TEMPLATES.get(
                category, {"error": f"no template for '{category}'"}
            ),
            scope="blue",
        ),
        Tool(
            name="verify_control",
            description=(
                "Re-test a finding's endpoint to confirm whether the applied "
                "mitigation actually closed the issue."
            ),
            parameters={
                "type": "object",
                "properties": {"finding_id": {"type": "string"}},
                "required": ["finding_id"],
            },
            func=lambda finding_id: _verify_control(ctx, finding_id),
            scope="blue",
        ),
    ]
