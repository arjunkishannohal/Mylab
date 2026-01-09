#!/usr/bin/env python3
"""HAR Analyzer (Agent 2)

Reads a .har file and extracts high-value testing data:
- Auth/session headers, cookies, tokens
- Endpoints, parameters, JSON keys
- Status code / security header / CORS signals
- Scope drift (hosts not in outputs/activesubdomain.txt)

Outputs:
- outputs/agent2/important_data.txt
- outputs/agent2/agent2-har-report.md
- outputs/agent2/har_summary.json

Design goals:
- No external dependencies (stdlib only)
- Works on Windows
- Handles typical HARs from browser devtools (Chrome/Firefox)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs


TOKEN_HEADER_KEYS = {
    "authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "xsrf-token",
}

SECURITY_RESPONSE_HEADER_KEYS = {
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
}

CORS_HEADER_PREFIXES = (
    "access-control-",
)

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

SUSPECT_SECRET_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "api_key",
    "apikey",
    "secret",
    "password",
    "pass",
}


def _norm_host(host: str) -> str:
    host = (host or "").strip().lower()
    if host.endswith("."):
        host = host[:-1]
    return host


def read_text_file_lines(path: str) -> List[str]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def load_allowlist_hosts(workspace: str) -> Set[str]:
    allowlist_path = os.path.join(workspace, "outputs", "activesubdomain.txt")
    hosts = set()
    for line in read_text_file_lines(allowlist_path):
        hosts.add(_norm_host(line))
    return hosts


def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def try_parse_json(text: str) -> Optional[Any]:
    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    if not (text.startswith("{") or text.startswith("[")):
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def iter_json_keys(obj: Any, prefix: str = "", limit: int = 2000) -> Iterable[str]:
    # Yields dotted paths for keys; bounded to avoid runaway.
    stack: List[Tuple[str, Any]] = [(prefix, obj)]
    yielded = 0
    while stack and yielded < limit:
        p, cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                key = str(k)
                np = f"{p}.{key}" if p else key
                yielded += 1
                yield np
                stack.append((np, v))
        elif isinstance(cur, list):
            # Don’t include indexes (too noisy); just descend.
            for v in cur[:50]:
                stack.append((p, v))


def headers_to_dict(headers: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in headers or []:
        name = str(h.get("name", "")).strip()
        value = str(h.get("value", "")).strip()
        if name:
            out[name.lower()] = value
    return out


def parse_cookies_from_cookie_header(cookie_header_value: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    if not cookie_header_value:
        return cookies
    parts = cookie_header_value.split(";")
    for part in parts:
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        cookies[k.strip()] = v.strip()
    return cookies


def parse_set_cookie_headers(set_cookie_values: List[str]) -> List[Dict[str, Any]]:
    parsed: List[Dict[str, Any]] = []
    for sc in set_cookie_values:
        if not sc:
            continue
        parts = [p.strip() for p in sc.split(";") if p.strip()]
        name = ""
        value = ""
        flags = set()
        attrs: Dict[str, str] = {}
        if parts and "=" in parts[0]:
            name, value = parts[0].split("=", 1)
            name = name.strip()
            value = value.strip()
        for p in parts[1:]:
            if "=" in p:
                ak, av = p.split("=", 1)
                attrs[ak.strip().lower()] = av.strip()
            else:
                flags.add(p.strip().lower())
        parsed.append(
            {
                "name": name,
                "value_preview": value[:24] + ("…" if len(value) > 24 else ""),
                "secure": "secure" in flags,
                "httponly": "httponly" in flags,
                "samesite": attrs.get("samesite"),
                "domain": attrs.get("domain"),
                "path": attrs.get("path"),
            }
        )
    return parsed


def decode_har_text(text: str, encoding: Optional[str]) -> str:
    if not text:
        return ""
    if encoding and encoding.lower() == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def redact_value(value: str, keep: int = 10) -> str:
    if value is None:
        return ""
    value = str(value)
    if len(value) <= keep:
        return value
    return value[:keep] + "…"


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze HAR and extract testing-relevant data")
    ap.add_argument("--har", required=True, help="Path to .har file")
    ap.add_argument("--workspace", default=".", help="Workspace root (default: .)")
    ap.add_argument("--outdir", default=os.path.join("outputs", "agent2"), help="Output directory")
    args = ap.parse_args()

    workspace = os.path.abspath(args.workspace)
    har_path = os.path.abspath(args.har)
    outdir = os.path.abspath(os.path.join(workspace, args.outdir))
    safe_mkdir(outdir)

    allowlist_hosts = load_allowlist_hosts(workspace)
    has_allowlist = bool(allowlist_hosts)

    agent1_report_path = os.path.join(workspace, "outputs", "reports", "agent1-recon-report.md")
    agent1_report_text = ""
    if os.path.exists(agent1_report_path):
        with open(agent1_report_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            agent1_report_text = f.read()

    with open(har_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        har = json.load(f)

    entries = (((har.get("log") or {}).get("entries")) or [])
    total_entries = len(entries)

    host_counter = Counter()
    method_counter = Counter()
    status_counter = Counter()

    unique_endpoints: Set[str] = set()  # METHOD path
    unique_full_urls: Set[str] = set()

    out_of_scope_hosts: Set[str] = set()

    auth_headers_found: Dict[str, Set[str]] = defaultdict(set)
    cookies_seen: Set[str] = set()
    set_cookie_details: List[Dict[str, Any]] = []

    query_param_names: Set[str] = set()
    json_key_paths: Set[str] = set()

    jwt_samples: Set[str] = set()

    cors_headers_seen: Set[str] = set()
    security_headers_present: Set[str] = set()

    interesting_flows: Set[str] = set()

    for e in entries:
        request = e.get("request") or {}
        response = e.get("response") or {}

        method = str(request.get("method") or "").upper()
        url = str(request.get("url") or "")

        if not url:
            continue

        unique_full_urls.add(url)

        parsed = urlparse(url)
        host = _norm_host(parsed.hostname or "")
        path = parsed.path or "/"

        if host:
            host_counter[host] += 1
            if has_allowlist and host not in allowlist_hosts:
                out_of_scope_hosts.add(host)

        method_counter[method] += 1

        endpoint_key = f"{method} {path}"
        unique_endpoints.add(endpoint_key)

        # Status
        status = response.get("status")
        if isinstance(status, int):
            status_counter[str(status)] += 1

        # Request headers
        req_headers = headers_to_dict(request.get("headers") or [])

        # Capture auth/token headers
        for hk, hv in req_headers.items():
            if hk in TOKEN_HEADER_KEYS and hv:
                auth_headers_found[hk].add(redact_value(hv, keep=14))

        # Cookie header
        cookie_header = req_headers.get("cookie")
        if cookie_header:
            parsed_cookies = parse_cookies_from_cookie_header(cookie_header)
            for ck in parsed_cookies.keys():
                cookies_seen.add(ck)

        # Query params
        qs = parse_qs(parsed.query)
        for qk in qs.keys():
            if qk:
                query_param_names.add(qk)

        # Request postData
        post = request.get("postData") or {}
        mime = str(post.get("mimeType") or "").lower()
        text = str(post.get("text") or "")
        encoding = post.get("encoding")
        decoded_text = decode_har_text(text, encoding)

        # Flag interesting flows based on URL/path patterns
        low_path = path.lower()
        if any(x in low_path for x in ("login", "signin", "logout", "register", "signup", "reset", "forgot", "oauth", "sso")):
            interesting_flows.add(endpoint_key)
        if any(x in low_path for x in ("admin", "dashboard", "manage", "panel")):
            interesting_flows.add(endpoint_key)
        if "graphql" in low_path:
            interesting_flows.add(endpoint_key)
        if mime.startswith("multipart/"):
            interesting_flows.add(endpoint_key)

        # Extract JSON keys from request bodies when possible
        if "json" in mime and decoded_text:
            parsed_json = try_parse_json(decoded_text)
            if parsed_json is not None:
                for key_path in iter_json_keys(parsed_json):
                    json_key_paths.add(key_path)

        # Token discovery in bodies
        if decoded_text:
            for m in JWT_RE.findall(decoded_text):
                jwt_samples.add(redact_value(m, keep=18))
            # Also detect key=value like access_token=...
            for k in SUSPECT_SECRET_KEYS:
                if re.search(rf"\b{re.escape(k)}\b", decoded_text, flags=re.IGNORECASE):
                    # Only mark the endpoint as interesting, don’t dump raw secrets.
                    interesting_flows.add(endpoint_key)

        # Response headers
        resp_headers_list = response.get("headers") or []
        resp_headers = headers_to_dict(resp_headers_list)

        # Set-Cookie
        set_cookie_values = []
        for h in resp_headers_list:
            if str(h.get("name", "")).lower() == "set-cookie":
                set_cookie_values.append(str(h.get("value", "")))
        if set_cookie_values:
            set_cookie_details.extend(parse_set_cookie_headers(set_cookie_values))

        # CORS + security headers
        for hk in resp_headers.keys():
            if hk.startswith(CORS_HEADER_PREFIXES):
                cors_headers_seen.add(hk)
            if hk in SECURITY_RESPONSE_HEADER_KEYS:
                security_headers_present.add(hk)

    # Build outputs
    run_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    summary = {
        "har": os.path.relpath(har_path, workspace),
        "workspace": workspace,
        "generatedAtUtc": run_ts,
        "entriesProcessed": total_entries,
        "uniqueHosts": len(host_counter),
        "uniqueUrls": len(unique_full_urls),
        "uniqueEndpoints": len(unique_endpoints),
        "topHosts": host_counter.most_common(20),
        "methods": dict(method_counter),
        "statusCodes": dict(status_counter),
        "outOfScopeHosts": sorted(out_of_scope_hosts),
        "authHeaderTypesFound": sorted(auth_headers_found.keys()),
        "cookieNamesSeen": sorted(cookies_seen),
        "setCookieFlagsSummary": {
            "count": len(set_cookie_details),
            "missingSecure": sum(1 for c in set_cookie_details if not c.get("secure")),
            "missingHttpOnly": sum(1 for c in set_cookie_details if not c.get("httponly")),
            "samesiteMissing": sum(1 for c in set_cookie_details if not c.get("samesite")),
        },
        "queryParamNames": sorted(query_param_names),
        "jsonKeyPaths": sorted(list(json_key_paths))[:2000],
        "jwtSamplesRedacted": sorted(jwt_samples),
        "corsHeadersSeen": sorted(cors_headers_seen),
        "securityHeadersPresent": sorted(security_headers_present),
        "interestingEndpoints": sorted(list(interesting_flows))[:500],
    }

    # important_data.txt (human-focused)
    important_txt_path = os.path.join(outdir, "important_data.txt")
    with open(important_txt_path, "w", encoding="utf-8") as f:
        f.write("IMPORTANT DATA (Agent 2 HAR Extraction)\n")
        f.write(f"Generated (UTC): {run_ts}\n")
        f.write(f"HAR: {os.path.relpath(har_path, workspace)}\n")
        f.write(f"Entries processed: {total_entries}\n")
        f.write("\n=== Scope ===\n")
        f.write(f"Allowlist present: {'yes' if has_allowlist else 'no'}\n")
        f.write(f"Unique hosts in HAR: {len(host_counter)}\n")
        if has_allowlist:
            f.write("Out-of-scope hosts (DO NOT TEST unless explicitly allowed):\n")
            for h in sorted(out_of_scope_hosts):
                f.write(f"- {h}\n")
        else:
            f.write(
                "Allowlist file missing/empty (outputs/activesubdomain.txt). "
                "Scope drift detection is skipped; follow the program scope manually.\n"
            )

        f.write("\n=== Auth / Tokens (redacted previews) ===\n")
        if not auth_headers_found and not cookies_seen and not jwt_samples:
            f.write("No obvious auth headers/cookies/JWTs detected.\n")
        for hk in sorted(auth_headers_found.keys()):
            f.write(f"{hk}:\n")
            for hv in sorted(auth_headers_found[hk])[:30]:
                f.write(f"  - {hv}\n")
        if cookies_seen:
            f.write("\nCookie names seen in requests:\n")
            for ck in sorted(cookies_seen):
                f.write(f"- {ck}\n")
        if set_cookie_details:
            f.write("\nSet-Cookie findings (flags):\n")
            for c in set_cookie_details[:50]:
                f.write(
                    f"- {c.get('name')} secure={c.get('secure')} httponly={c.get('httponly')} samesite={c.get('samesite')} domain={c.get('domain')} path={c.get('path')}\n"
                )
        if jwt_samples:
            f.write("\nJWT-like strings found in bodies (redacted):\n")
            for j in sorted(jwt_samples)[:30]:
                f.write(f"- {j}\n")

        f.write("\n=== Endpoints & Inputs ===\n")
        f.write(f"Unique endpoints (method+path): {len(unique_endpoints)}\n")
        f.write("\nInteresting endpoints (auth/admin/graphql/upload/etc):\n")
        for ep in sorted(list(interesting_flows))[:200]:
            f.write(f"- {ep}\n")

        f.write("\nQuery parameter names:\n")
        for q in sorted(query_param_names):
            f.write(f"- {q}\n")

        f.write("\nJSON key paths (sample, up to 2000):\n")
        for k in sorted(list(json_key_paths))[:2000]:
            f.write(f"- {k}\n")

        f.write("\n=== Security Signals ===\n")
        f.write("Status codes:\n")
        for code, cnt in status_counter.most_common():
            f.write(f"- {code}: {cnt}\n")
        f.write("\nCORS headers observed:\n")
        for hk in sorted(cors_headers_seen):
            f.write(f"- {hk}\n")
        f.write("\nSecurity headers present:\n")
        for hk in sorted(security_headers_present):
            f.write(f"- {hk}\n")

    # agent2-har-report.md (narrative)
    report_md_path = os.path.join(outdir, "agent2-har-report.md")
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write("# Agent 2 HAR Report\n\n")
        f.write(f"- Generated (UTC): {run_ts}\n")
        f.write(f"- HAR: `{os.path.relpath(har_path, workspace)}`\n")
        f.write(f"- Entries processed: **{total_entries}**\n")
        f.write(f"- Unique hosts: **{len(host_counter)}**\n")
        f.write(f"- Unique endpoints (method+path): **{len(unique_endpoints)}**\n\n")

        if agent1_report_text.strip():
            f.write("## Context (Agent 1 report excerpt)\n")
            f.write("(Keep this short; full details live in Agent 1 report.)\n\n")
            excerpt = agent1_report_text.strip().splitlines()[:30]
            f.write("\n".join(excerpt) + "\n\n")

        f.write("## Scope drift\n")
        if not has_allowlist:
            f.write("Allowlist file missing/empty (outputs/activesubdomain.txt). Scope drift check skipped.\n")
        elif out_of_scope_hosts:
            f.write("Out-of-scope hosts seen in HAR (do not test unless explicitly allowed):\n")
            for h in sorted(out_of_scope_hosts):
                f.write(f"- {h}\n")
        else:
            f.write("No out-of-scope hosts detected (based on activesubdomain allowlist).\n")
        f.write("\n")

        f.write("## Auth & sessions\n")
        f.write("Auth header types found:\n")
        for hk in sorted(auth_headers_found.keys()):
            f.write(f"- {hk}\n")
        if cookies_seen:
            f.write("\nCookie names seen:\n")
            for ck in sorted(cookies_seen):
                f.write(f"- {ck}\n")
        f.write("\n")

        f.write("## Suggested first testing queue (from HAR signals)\n")
        f.write("Prioritize endpoints that look like auth/admin/graphql/upload, then endpoints with many parameters/JSON keys.\n\n")
        for ep in sorted(list(interesting_flows))[:50]:
            f.write(f"- {ep}\n")

    # har_summary.json
    summary_path = os.path.join(outdir, "har_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Wrote: {os.path.relpath(important_txt_path, workspace)}")
    print(f"Wrote: {os.path.relpath(report_md_path, workspace)}")
    print(f"Wrote: {os.path.relpath(summary_path, workspace)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
