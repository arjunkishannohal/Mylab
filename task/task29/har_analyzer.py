#!/usr/bin/env python3
"""HAR analyzer (stdlib-only).

Purpose
- Parse HAR captures (browser/mobile traffic) and extract high-value testing data.
- Enforce scope using outputs/activesubdomain.txt (hostname allowlist).
- Save account-specific data (tokens, IDs, auth) in SEPARATE per-account files.
- Save common data (endpoints, headers) in shared files.

Inputs
- --har <path>            : HAR file to analyze
- --workspace <path>      : repo/workspace root (default: '.')

Outputs (created/overwritten)
- outputs/har/common_data.txt              (shared: endpoints, headers, CORS)
- outputs/har/har-report.md                (summary report)
- outputs/har/har_summary.json             (machine-readable summary)
- outputs/har/accounts/<harname>_auth.txt  (per-account: tokens, cookies, IDs)
- outputs/har/accounts/<harname>_auth.json (per-account: machine-readable)

Safety
- No network calls.
- Designed for deterministic output.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit


# Patterns to identify ID-like parameters (account IDs, user IDs, etc.)
ID_PARAM_HINTS = (
    "id",
    "uid",
    "userid",
    "user_id",
    "accountid",
    "account_id",
    "orgid",
    "org_id",
    "teamid",
    "team_id",
    "projectid",
    "project_id",
    "customerid",
    "customer_id",
    "profileid",
    "profile_id",
    "memberid",
    "member_id",
)

# Patterns to identify auth-related parameters
AUTH_PARAM_HINTS = (
    "token",
    "auth",
    "session",
    "jwt",
    "key",
    "apikey",
    "api_key",
    "secret",
    "password",
    "pass",
    "sig",
    "signature",
    "code",
    "access_token",
    "refresh_token",
    "bearer",
    "csrf",
    "xsrf",
)

# Auth-related headers (we want to capture their VALUES for testing)
AUTH_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-access-token",
    "x-refresh-token",
    "x-session-id",
    "x-request-id",
}


def _safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("._-")
    return s or "har"


def _read_allowlist(path: Path) -> set[str]:
    if not path.exists():
        raise SystemExit(f"Missing allowlist file: {path}")
    hosts: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip().lower().rstrip(".")
        if s and not s.startswith("#"):
            hosts.add(s)
    if not hosts:
        raise SystemExit(f"Allowlist is empty: {path}")
    return hosts


def _safe_json_load(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        raise SystemExit(f"Failed to parse HAR JSON: {path} ({e})")


def _as_kv_list(obj: Any, name_key: str = "name", value_key: str = "value") -> List[Tuple[str, str]]:
    if not isinstance(obj, list):
        return []
    out: List[Tuple[str, str]] = []
    for item in obj:
        if not isinstance(item, dict):
            continue
        name = str(item.get(name_key, "")).strip()
        value = str(item.get(value_key, "")).strip()
        if name:
            out.append((name, value))
    return out


def _host_in_scope(host: Optional[str], allowlist: set[str]) -> bool:
    if not host:
        return False
    h = host.strip().lower().rstrip(".")
    return h in allowlist


def _is_id_param(key: str) -> bool:
    kl = (key or "").lower().replace("-", "_")
    return any(hint in kl for hint in ID_PARAM_HINTS)


def _is_auth_param(key: str) -> bool:
    kl = (key or "").lower().replace("-", "_")
    return any(hint in kl for hint in AUTH_PARAM_HINTS)


def _parse_cookies(cookie_header_value: str) -> List[Tuple[str, str]]:
    """Parse Cookie header into (name, value) pairs."""
    if not cookie_header_value:
        return []
    cookies: List[Tuple[str, str]] = []
    for part in cookie_header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, value = part.split("=", 1)
            cookies.append((name.strip(), value.strip()))
        else:
            cookies.append((part, ""))
    return cookies


def _extract_entries(har: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    log = har.get("log")
    if not isinstance(log, dict):
        return []
    entries = log.get("entries")
    if not isinstance(entries, list):
        return []
    for e in entries:
        if isinstance(e, dict):
            yield e


def analyze(har_path: Path, workspace: Path) -> None:
    allowlist = _read_allowlist(workspace / "outputs" / "activesubdomain.txt")
    har = _safe_json_load(har_path)

    # Common aggregates (shared across accounts)
    hosts_seen: Counter[str] = Counter()
    methods_seen: Counter[str] = Counter()
    status_seen: Counter[int] = Counter()
    endpoint_seen: Counter[str] = Counter()
    req_header_seen: Counter[str] = Counter()
    resp_header_seen: Counter[str] = Counter()
    cors_notes: List[str] = []

    # Account-specific data (unique per HAR/account)
    auth_headers_raw: Dict[str, Set[str]] = {}  # header_name -> set of values
    cookies_raw: Dict[str, Set[str]] = {}       # cookie_name -> set of values
    id_params_raw: Dict[str, Set[str]] = {}     # param_name -> set of values
    auth_params_raw: Dict[str, Set[str]] = {}   # param_name -> set of values

    for entry in _extract_entries(har):
        req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}

        url = str(req.get("url", "")).strip()
        method = str(req.get("method", "")).strip().upper() or "GET"
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")

        if not _host_in_scope(host, allowlist):
            continue

        path = parts.path or "/"
        query_pairs = parse_qsl(parts.query or "", keep_blank_values=True)

        req_headers = _as_kv_list(req.get("headers"))
        resp_headers = _as_kv_list(resp.get("headers"))

        # Aggregate common data
        hosts_seen[host] += 1
        methods_seen[method] += 1
        status_seen[int(resp.get("status") or 0)] += 1
        endpoint_seen[f"{method} {path}"] += 1

        for k, _ in req_headers:
            req_header_seen[k.strip().lower()] += 1
        for k, _ in resp_headers:
            resp_header_seen[k.strip().lower()] += 1

        # Extract account-specific: auth headers (with full values)
        for k, v in req_headers:
            kl = k.strip().lower()
            if kl in AUTH_HEADER_NAMES and v:
                if kl not in auth_headers_raw:
                    auth_headers_raw[kl] = set()
                auth_headers_raw[kl].add(v)
            # Parse cookies separately for better granularity
            if kl == "cookie" and v:
                for cookie_name, cookie_value in _parse_cookies(v):
                    if cookie_name not in cookies_raw:
                        cookies_raw[cookie_name] = set()
                    if cookie_value:
                        cookies_raw[cookie_name].add(cookie_value)

        # Extract account-specific: ID and auth params from query string
        for k, v in query_pairs:
            if _is_id_param(k) and v:
                if k not in id_params_raw:
                    id_params_raw[k] = set()
                id_params_raw[k].add(v)
            if _is_auth_param(k) and v:
                if k not in auth_params_raw:
                    auth_params_raw[k] = set()
                auth_params_raw[k].add(v)

        # Extract account-specific: ID and auth params from POST body
        post_data = req.get("postData")
        if isinstance(post_data, dict):
            params = _as_kv_list(post_data.get("params"))
            for k, v in params:
                if _is_id_param(k) and v:
                    if k not in id_params_raw:
                        id_params_raw[k] = set()
                    id_params_raw[k].add(v)
                if _is_auth_param(k) and v:
                    if k not in auth_params_raw:
                        auth_params_raw[k] = set()
                    auth_params_raw[k].add(v)
            # Also check text body for JSON
            text = post_data.get("text", "")
            if text and text.strip().startswith("{"):
                try:
                    body_json = json.loads(text)
                    if isinstance(body_json, dict):
                        for k, v in body_json.items():
                            if isinstance(v, str):
                                if _is_id_param(k) and v:
                                    if k not in id_params_raw:
                                        id_params_raw[k] = set()
                                    id_params_raw[k].add(v)
                                if _is_auth_param(k) and v:
                                    if k not in auth_params_raw:
                                        auth_params_raw[k] = set()
                                    auth_params_raw[k].add(v)
                except json.JSONDecodeError:
                    pass

        # CORS notes (common)
        cors_acao = None
        cors_acac = None
        for k, v in resp_headers:
            kl = k.strip().lower()
            if kl == "access-control-allow-origin":
                cors_acao = v.strip()
            if kl == "access-control-allow-credentials":
                cors_acac = v.strip()
        if cors_acao:
            note = f"{host}{path} :: ACAO={cors_acao}"
            if cors_acac:
                note += f"; ACAC={cors_acac}"
            cors_notes.append(note)

    # Create output directories
    out_dir = workspace / "outputs" / "har"
    out_dir.mkdir(parents=True, exist_ok=True)

    accounts_dir = out_dir / "accounts"
    accounts_dir.mkdir(parents=True, exist_ok=True)

    har_id = _safe_slug(har_path.stem)

    # ==========================================
    # ACCOUNT-SPECIFIC FILE (per HAR / per user)
    # ==========================================
    account_lines: List[str] = []
    account_lines.append(f"# Account Data: {har_path.name}")
    account_lines.append(f"# HAR ID: {har_id}")
    account_lines.append("")

    # Auth headers (Authorization, cookies, etc.)
    if auth_headers_raw:
        account_lines.append("[Auth Headers - FULL VALUES]")
        for header_name in sorted(auth_headers_raw.keys()):
            for val in sorted(auth_headers_raw[header_name]):
                account_lines.append(f"{header_name}: {val}")
        account_lines.append("")

    # Cookies with values
    if cookies_raw:
        account_lines.append("[Cookies - FULL VALUES]")
        for cookie_name in sorted(cookies_raw.keys()):
            for val in sorted(cookies_raw[cookie_name]):
                account_lines.append(f"{cookie_name}={val}")
        account_lines.append("")

    # ID parameters (userId, accountId, etc.)
    if id_params_raw:
        account_lines.append("[ID Parameters - FULL VALUES]")
        for param_name in sorted(id_params_raw.keys()):
            for val in sorted(id_params_raw[param_name]):
                account_lines.append(f"{param_name}={val}")
        account_lines.append("")

    # Auth parameters (tokens, keys, etc.)
    if auth_params_raw:
        account_lines.append("[Auth Parameters - FULL VALUES]")
        for param_name in sorted(auth_params_raw.keys()):
            for val in sorted(auth_params_raw[param_name]):
                account_lines.append(f"{param_name}={val}")
        account_lines.append("")

    account_text = "\n".join(account_lines) + "\n"
    (accounts_dir / f"{har_id}_auth.txt").write_text(account_text, encoding="utf-8")

    # Account JSON (machine readable)
    account_json = {
        "har_path": str(har_path),
        "har_id": har_id,
        "auth_headers": {k: sorted(v) for k, v in auth_headers_raw.items()},
        "cookies": {k: sorted(v) for k, v in cookies_raw.items()},
        "id_params": {k: sorted(v) for k, v in id_params_raw.items()},
        "auth_params": {k: sorted(v) for k, v in auth_params_raw.items()},
    }
    (accounts_dir / f"{har_id}_auth.json").write_text(
        json.dumps(account_json, indent=2), encoding="utf-8"
    )

    # ==========================================
    # COMMON DATA FILE (shared across accounts)
    # ==========================================
    common_lines: List[str] = []
    common_lines.append(f"# Common Data (shared across accounts)")
    common_lines.append(f"# Last updated from: {har_path.name}")
    common_lines.append(f"# In-scope hosts: {len(hosts_seen)}")
    common_lines.append("")

    common_lines.append("[Hosts]")
    for h, c in hosts_seen.most_common():
        common_lines.append(f"- {h} (entries={c})")
    common_lines.append("")

    common_lines.append("[Endpoints]")
    for ep, c in endpoint_seen.most_common(200):
        common_lines.append(f"- {ep} (hits={c})")
    common_lines.append("")

    common_lines.append("[Request Headers]")
    for k, c in req_header_seen.most_common(100):
        common_lines.append(f"- {k} (hits={c})")
    common_lines.append("")

    common_lines.append("[Response Headers]")
    for k, c in resp_header_seen.most_common(100):
        common_lines.append(f"- {k} (hits={c})")
    common_lines.append("")

    if cors_notes:
        common_lines.append("[CORS Notes]")
        for line in sorted(set(cors_notes))[:200]:
            common_lines.append(f"- {line}")
        common_lines.append("")

    common_text = "\n".join(common_lines) + "\n"
    (out_dir / "common_data.txt").write_text(common_text, encoding="utf-8")

    # ==========================================
    # SUMMARY JSON (machine readable)
    # ==========================================
    summary = {
        "har_path": str(har_path),
        "har_id": har_id,
        "scope_allowlist_path": str(workspace / "outputs" / "activesubdomain.txt"),
        "in_scope_hosts": sorted(hosts_seen.keys()),
        "counts": {
            "entries_in_scope": sum(hosts_seen.values()),
            "unique_hosts": len(hosts_seen),
            "unique_endpoints": len(endpoint_seen),
        },
        "top": {
            "hosts": hosts_seen.most_common(50),
            "endpoints": endpoint_seen.most_common(100),
            "methods": methods_seen.most_common(),
            "status": status_seen.most_common(),
        },
    }
    (out_dir / "har_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # ==========================================
    # REPORT MD
    # ==========================================
    md: List[str] = []
    md.append("# HAR analysis report")
    md.append("")
    md.append("## Scope")
    md.append(f"- HAR: `{har_path}`")
    md.append("- Allowlist: `outputs/activesubdomain.txt`")
    md.append("")

    md.append("## Summary")
    md.append(f"- In-scope hosts: **{len(hosts_seen)}**")
    md.append(f"- In-scope entries: **{sum(hosts_seen.values())}**")
    md.append(f"- Unique endpoints: **{len(endpoint_seen)}**")
    md.append("")

    md.append("## Account-specific data (saved separately)")
    md.append(f"- Auth file: `outputs/har/accounts/{har_id}_auth.txt`")
    md.append(f"- Auth JSON: `outputs/har/accounts/{har_id}_auth.json`")
    md.append("")

    if hosts_seen:
        md.append("## Hosts (top)")
        for h, c in hosts_seen.most_common(25):
            md.append(f"- `{h}` (entries={c})")
        md.append("")

    if endpoint_seen:
        md.append("## Endpoints to test (top)")
        for ep, c in endpoint_seen.most_common(30):
            md.append(f"- `{ep}` (hits={c})")
        md.append("")

    md.append("## Outputs")
    md.append("- `outputs/har/common_data.txt` (shared: endpoints, headers)")
    md.append(f"- `outputs/har/accounts/{har_id}_auth.txt` (account: tokens, IDs)")
    md.append(f"- `outputs/har/accounts/{har_id}_auth.json` (account: machine-readable)")
    md.append("- `outputs/har/har_summary.json`")
    md.append("- `outputs/har/har-report.md`")
    md.append("")

    report_text = "\n".join(md) + "\n"
    (out_dir / "har-report.md").write_text(report_text, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze a HAR capture (stdlib-only).")
    ap.add_argument("--har", required=True, help="Path to HAR file")
    ap.add_argument("--workspace", default=".", help="Workspace root (default: .)")
    args = ap.parse_args()

    workspace = Path(args.workspace).resolve()
    har_path = Path(args.har).resolve()

    if not har_path.exists():
        raise SystemExit(f"HAR file not found: {har_path}")

    analyze(har_path=har_path, workspace=workspace)

    har_id = _safe_slug(har_path.stem)
    print(f"wrote outputs/har/accounts/{har_id}_auth.txt (account-specific)")
    print(f"wrote outputs/har/accounts/{har_id}_auth.json (account-specific)")
    print("wrote outputs/har/common_data.txt (shared)")
    print("wrote outputs/har/har_summary.json")
    print("wrote outputs/har/har-report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
