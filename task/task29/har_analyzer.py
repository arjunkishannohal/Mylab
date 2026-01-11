#!/usr/bin/env python3
"""HAR analyzer (stdlib-only).

Purpose
- Parse a HAR capture (browser/mobile traffic) and extract high-value testing data.
- Enforce scope using outputs/activesubdomain.txt (hostname allowlist).
- Redact sensitive values (tokens/cookies/secrets) in written reports.

Inputs
- --har <path>            : HAR file to analyze
- --workspace <path>      : repo/workspace root (default: '.')

Outputs (created/overwritten)
- outputs/har/important_data.txt
- outputs/har/har-report.md
- outputs/har/har_summary.json
- outputs/har/per_har/<harname>_*

Safety
- No network calls.
- Designed for deterministic output.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}

SENSITIVE_PARAM_HINTS = (
    "token",
    "auth",
    "session",
    "jwt",
    "key",
    "secret",
    "password",
    "pass",
    "sig",
    "signature",
    "code",
)

BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")


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


def _redact_value(header_or_key: str, value: str) -> str:
    key = (header_or_key or "").strip().lower()
    if key in SENSITIVE_HEADER_NAMES:
        if key == "authorization":
            return BEARER_RE.sub("Bearer <REDACTED>", value) if value else "<REDACTED>"
        return "<REDACTED>"

    if value and len(value) >= 24 and re.search(r"[A-Za-z0-9_\-]{24,}", value):
        return "<REDACTED>"

    return value


def _redact_query_params(params: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    redacted: List[Tuple[str, str]] = []
    for k, v in params:
        kl = (k or "").lower()
        if any(h in kl for h in SENSITIVE_PARAM_HINTS):
            redacted.append((k, "<REDACTED>" if v else ""))
        else:
            redacted.append((k, v))
    return redacted


def _host_in_scope(host: Optional[str], allowlist: set[str]) -> bool:
    if not host:
        return False
    h = host.strip().lower().rstrip(".")
    return h in allowlist


@dataclass(frozen=True)
class HarRow:
    host: str
    method: str
    path: str
    query_keys: Tuple[str, ...]
    status: int
    has_auth: bool
    cookie_names: Tuple[str, ...]
    req_header_names: Tuple[str, ...]
    resp_header_names: Tuple[str, ...]


def _cookie_names(cookie_header_value: str) -> List[str]:
    if not cookie_header_value:
        return []
    names: List[str] = []
    for part in cookie_header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            names.append(part.split("=", 1)[0].strip())
        else:
            names.append(part)
    return [n for n in names if n]


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

    rows: List[HarRow] = []

    hosts_seen: Counter[str] = Counter()
    methods_seen: Counter[str] = Counter()
    status_seen: Counter[int] = Counter()
    endpoint_seen: Counter[str] = Counter()
    query_key_seen: Counter[str] = Counter()
    req_header_seen: Counter[str] = Counter()
    resp_header_seen: Counter[str] = Counter()
    cookie_name_seen: Counter[str] = Counter()
    auth_usage: Counter[str] = Counter()
    cors_notes: List[str] = []

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
        query_pairs = _redact_query_params([(k, v) for k, v in query_pairs])
        query_keys = tuple(sorted({k for k, _ in query_pairs if k}))

        req_headers = _as_kv_list(req.get("headers"))
        resp_headers = _as_kv_list(resp.get("headers"))

        req_header_names = tuple(sorted({k.strip().lower() for k, _ in req_headers if k.strip()}))
        resp_header_names = tuple(sorted({k.strip().lower() for k, _ in resp_headers if k.strip()}))

        auth_header_val = ""
        cookie_header_val = ""
        for k, v in req_headers:
            kl = k.strip().lower()
            if kl == "authorization":
                auth_header_val = v
            if kl == "cookie":
                cookie_header_val = v

        has_auth = bool(auth_header_val.strip())
        cookie_names = tuple(sorted(set(_cookie_names(cookie_header_val))))

        status = int(resp.get("status") or 0)

        rows.append(
            HarRow(
                host=host,
                method=method,
                path=path,
                query_keys=query_keys,
                status=status,
                has_auth=has_auth,
                cookie_names=cookie_names,
                req_header_names=req_header_names,
                resp_header_names=resp_header_names,
            )
        )

        hosts_seen[host] += 1
        methods_seen[method] += 1
        status_seen[status] += 1
        endpoint_seen[f"{method} {path}"] += 1
        for qk in query_keys:
            query_key_seen[qk] += 1
        for hn in req_header_names:
            req_header_seen[hn] += 1
        for hn in resp_header_names:
            resp_header_seen[hn] += 1
        for cn in cookie_names:
            cookie_name_seen[cn] += 1

        if has_auth:
            auth_usage["authorization_header_present"] += 1
            auth_usage["authorization_header_value_redacted"] += 1
        elif cookie_names:
            auth_usage["cookie_auth_likely"] += 1
        else:
            auth_usage["no_auth_observed"] += 1

        cors_acao = None
        cors_acac = None
        for k, v in resp_headers:
            kl = k.strip().lower()
            if kl == "access-control-allow-origin":
                cors_acao = v.strip()
            if kl == "access-control-allow-credentials":
                cors_acac = v.strip()
        if cors_acao:
            note = f"{host}{path} :: ACAO={_redact_value('access-control-allow-origin', cors_acao)}"
            if cors_acac:
                note += f"; ACAC={cors_acac}"
            cors_notes.append(note)

    rows.sort(key=lambda r: (r.host, r.path, r.method))

    out_dir = workspace / "outputs" / "har"
    out_dir.mkdir(parents=True, exist_ok=True)

    per_har_dir = out_dir / "per_har"
    per_har_dir.mkdir(parents=True, exist_ok=True)
    har_id = _safe_slug(har_path.stem)

    important_lines: List[str] = []
    important_lines.append(f"HAR: {har_path}")
    important_lines.append(f"In-scope hosts matched: {len(hosts_seen)}")
    important_lines.append("")

    important_lines.append("[Hosts]")
    for h, c in hosts_seen.most_common():
        important_lines.append(f"- {h} (entries={c})")
    important_lines.append("")

    important_lines.append("[Endpoints]")
    for ep, c in endpoint_seen.most_common(200):
        important_lines.append(f"- {ep} (hits={c})")
    important_lines.append("")

    if query_key_seen:
        important_lines.append("[Query Keys]")
        for k, c in query_key_seen.most_common(200):
            important_lines.append(f"- {k} (hits={c})")
        important_lines.append("")

    if cookie_name_seen:
        important_lines.append("[Cookie Names]")
        for k, c in cookie_name_seen.most_common(200):
            important_lines.append(f"- {k} (hits={c})")
        important_lines.append("")

    important_lines.append("[Request Headers Seen]")
    for k, c in req_header_seen.most_common(100):
        important_lines.append(f"- {k} (hits={c})")
    important_lines.append("")

    important_lines.append("[Response Headers Seen]")
    for k, c in resp_header_seen.most_common(100):
        important_lines.append(f"- {k} (hits={c})")
    important_lines.append("")

    if cors_notes:
        important_lines.append("[CORS Notes]")
        for line in sorted(set(cors_notes))[:200]:
            important_lines.append(f"- {line}")
        important_lines.append("")

    important_data_text = "\n".join(important_lines) + "\n"
    (out_dir / "important_data.txt").write_text(important_data_text, encoding="utf-8")
    (per_har_dir / f"{har_id}_important_data.txt").write_text(important_data_text, encoding="utf-8")

    summary = {
        "har_path": str(har_path),
        "scope_allowlist_path": str(workspace / "outputs" / "activesubdomain.txt"),
        "in_scope_hosts": sorted(hosts_seen.keys()),
        "counts": {
            "entries_in_scope": sum(hosts_seen.values()),
            "unique_hosts": len(hosts_seen),
            "unique_endpoints": len(endpoint_seen),
            "unique_query_keys": len(query_key_seen),
            "unique_cookie_names": len(cookie_name_seen),
        },
        "top": {
            "hosts": hosts_seen.most_common(50),
            "endpoints": endpoint_seen.most_common(100),
            "query_keys": query_key_seen.most_common(100),
            "cookie_names": cookie_name_seen.most_common(100),
            "methods": methods_seen.most_common(),
            "status": status_seen.most_common(),
        },
        "auth_signals": auth_usage,
    }

    summary_text = json.dumps(summary, indent=2)
    (out_dir / "har_summary.json").write_text(summary_text, encoding="utf-8")
    (per_har_dir / f"{har_id}_har_summary.json").write_text(summary_text, encoding="utf-8")

    md: List[str] = []
    md.append("# HAR analysis report")
    md.append("")
    md.append("## Scope")
    md.append(f"- HAR: `{har_path}`")
    md.append("- Allowlist: `outputs/activesubdomain.txt`")
    md.append("")

    md.append("## High-signal summary")
    md.append(f"- In-scope hosts: **{len(hosts_seen)}**")
    md.append(f"- In-scope entries: **{sum(hosts_seen.values())}**")
    md.append(f"- Unique endpoints: **{len(endpoint_seen)}**")
    md.append("")

    if hosts_seen:
        md.append("## Hosts (top)")
        for h, c in hosts_seen.most_common(25):
            md.append(f"- `{h}` (entries={c})")
        md.append("")

    if endpoint_seen:
        md.append("## Endpoints to test first (top)")
        for ep, c in endpoint_seen.most_common(30):
            md.append(f"- `{ep}` (hits={c})")
        md.append("")

    if query_key_seen:
        md.append("## Interesting query keys (top)")
        for k, c in query_key_seen.most_common(30):
            md.append(f"- `{k}` (hits={c})")
        md.append("")

    if cookie_name_seen:
        md.append("## Cookies observed (names only, redacted values)")
        for k, c in cookie_name_seen.most_common(30):
            md.append(f"- `{k}` (hits={c})")
        md.append("")

    md.append("## Auth signals (redacted)")
    for k, c in auth_usage.most_common():
        md.append(f"- {k}: {c}")
    md.append("")

    if cors_notes:
        md.append("## CORS notes (best-effort)")
        for line in sorted(set(cors_notes))[:50]:
            md.append(f"- {line}")
        md.append("")

    md.append("## Outputs")
    md.append("- `outputs/har/important_data.txt`")
    md.append("- `outputs/har/har-report.md`")
    md.append("- `outputs/har/har_summary.json`")
    md.append("- `outputs/har/per_har/*`")
    md.append("")

    report_text = "\n".join(md) + "\n"
    (out_dir / "har-report.md").write_text(report_text, encoding="utf-8")
    (per_har_dir / f"{har_id}_har-report.md").write_text(report_text, encoding="utf-8")


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
    print("wrote outputs/har/important_data.txt")
    print("wrote outputs/har/har-report.md")
    print("wrote outputs/har/har_summary.json")
    print("wrote outputs/har/per_har/<harname>_important_data.txt")
    print("wrote outputs/har/per_har/<harname>_har-report.md")
    print("wrote outputs/har/per_har/<harname>_har_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
