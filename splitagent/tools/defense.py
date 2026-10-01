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


async def _verify_control(ctx: ToolContext, finding_id: str) -> dict[str, Any]:
    finding = ctx.context.state.get_finding(finding_id)
    if finding is None:
        return {"error": f"finding '{finding_id}' not found"}
    url = finding.endpoint or ctx.target.url
    if not url:
        return {"verified": False, "reason": "finding has no testable endpoint"}
    ctx.check_scope(url)
    client = await get_client(follow=False, verify=False, timeout=10.0)
    response = await client.get(url)
    headers = {k.lower(): v for k, v in response.headers.items()}
    if finding.category in ("headers", "misconfiguration"):
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        verified = len(missing) < len(SECURITY_HEADERS)
        return {
            "verified": verified,
            "status": response.status_code,
            "remaining_missing": missing,
            "evidence": f"{len(SECURITY_HEADERS) - len(missing)}/{len(SECURITY_HEADERS)} security headers present",
        }
    return {
        "verified": None,
        "status": response.status_code,
        "evidence": "endpoint reachable; manual re-test recommended for this category",
    }


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
