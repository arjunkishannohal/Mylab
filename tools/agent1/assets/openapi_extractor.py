#!/usr/bin/env python3
"""Extract endpoints from Swagger/OpenAPI JSON URLs.

Reads a list of Swagger/OpenAPI document URLs (one per line) and produces a
deduped list of candidate endpoint URLs.

Design goals:
- Stdlib-only
- Safe defaults: scope allowlist enforcement
- Best-effort parsing for Swagger 2.0 and OpenAPI 3.x

Usage (example):
  python tools/agent1/assets/openapi_extractor.py \
    --docs outputs/api_docs_urls.txt \
    --allowlist outputs/activesubdomain.txt \
    --out outputs/api_endpoints_from_openapi.txt \
    --raw-dir temp/agent1/api_docs_raw
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def _read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def _write_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def _safe_filename_from_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "unknown"
    path = (parsed.path or "").strip("/") or "root"
    path = re.sub(r"[^A-Za-z0-9._-]+", "_", path)[:120]
    return f"{host}__{path}.json"


def _fetch(url: str, timeout: float) -> bytes | None:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; MylabOpenAPIExtractor/1.0)",
            "Accept": "application/json, */*",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None


def _json_loads_best_effort(data: bytes) -> dict | None:
    try:
        return json.loads(data.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None


def _extract_servers_openapi3(doc: dict) -> list[str]:
    servers = doc.get("servers")
    if isinstance(servers, list):
        urls: list[str] = []
        for s in servers:
            if isinstance(s, dict) and isinstance(s.get("url"), str):
                urls.append(s["url"].strip())
        return urls
    return []


def _extract_base_swagger2(doc: dict) -> list[str]:
    host = doc.get("host")
    base_path = doc.get("basePath", "")
    schemes = doc.get("schemes")

    if not isinstance(host, str) or not host.strip():
        return []

    if not isinstance(base_path, str):
        base_path = ""

    if not isinstance(schemes, list) or not schemes:
        schemes = ["https", "http"]

    bases: list[str] = []
    for scheme in schemes:
        if isinstance(scheme, str) and scheme:
            bases.append(f"{scheme}://{host}{base_path}")
    return bases


def _extract_paths(doc: dict) -> list[str]:
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []

    out: list[str] = []
    for p in paths.keys():
        if isinstance(p, str) and p.startswith("/"):
            out.append(p)
    return out


def _normalize_server_url(server_url: str, doc_url: str) -> list[str]:
    server_url = server_url.strip()
    if not server_url:
        return []

    if "{" in server_url and "}" in server_url:
        doc_host = urllib.parse.urlsplit(doc_url).hostname
        if doc_host:
            server_url = re.sub(r"\{[^}]+\}", doc_host, server_url)
        else:
            return []

    if server_url.startswith("/"):
        base = urllib.parse.urlsplit(doc_url)
        return [f"{base.scheme}://{base.netloc}{server_url}"]

    if server_url.startswith("http://") or server_url.startswith("https://"):
        return [server_url]

    return []


def _is_in_allowlist(url: str, allow_hosts: set[str]) -> bool:
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    return host.lower() in allow_hosts


def extract_endpoints(doc_url: str, doc: dict, allow_hosts: set[str]) -> set[str]:
    paths = _extract_paths(doc)

    bases: list[str] = []

    for s in _extract_servers_openapi3(doc):
        bases.extend(_normalize_server_url(s, doc_url))

    if not bases:
        bases.extend(_extract_base_swagger2(doc))

    if not bases:
        split = urllib.parse.urlsplit(doc_url)
        if split.scheme and split.netloc:
            bases = [f"{split.scheme}://{split.netloc}"]

    endpoints: set[str] = set()
    for base in bases:
        base = base.rstrip("/")
        for p in paths:
            full = f"{base}{p}"
            if _is_in_allowlist(full, allow_hosts):
                endpoints.add(full)

    return endpoints


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract endpoints from Swagger/OpenAPI JSON URLs")
    ap.add_argument("--docs", required=True, help="Path to API doc URL list")
    ap.add_argument("--allowlist", required=True, help="Path to outputs/activesubdomain.txt")
    ap.add_argument("--out", required=True, help="Output file for extracted endpoints")
    ap.add_argument("--raw-dir", default="", help="Optional dir to save downloaded JSON docs")
    ap.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout (seconds)")
    args = ap.parse_args()

    allow_hosts = {h.lower() for h in _read_lines(args.allowlist)}
    if not allow_hosts:
        print("Allowlist is empty; refusing to proceed.", file=sys.stderr)
        return 2

    doc_urls = _read_lines(args.docs)
    if not doc_urls:
        print("No API doc URLs found; nothing to extract.", file=sys.stderr)
        _write_lines(args.out, [])
        return 0

    if args.raw_dir:
        os.makedirs(args.raw_dir, exist_ok=True)

    all_endpoints: set[str] = set()
    processed = 0
    for url in doc_urls:
        if not (url.startswith("http://") or url.startswith("https://")):
            continue
        if not _is_in_allowlist(url, allow_hosts):
            continue

        data = _fetch(url, timeout=args.timeout)
        if not data:
            continue

        doc = _json_loads_best_effort(data)
        if not isinstance(doc, dict):
            continue

        processed += 1

        if args.raw_dir:
            raw_name = _safe_filename_from_url(url)
            raw_path = os.path.join(args.raw_dir, raw_name)
            try:
                with open(raw_path, "wb") as f:
                    f.write(data)
            except OSError:
                pass

        all_endpoints |= extract_endpoints(url, doc, allow_hosts)

    out_lines = sorted(all_endpoints)
    _write_lines(args.out, out_lines)

    print(f"Processed docs: {processed}")
    print(f"Extracted endpoints: {len(out_lines)}")
    print(f"Wrote: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
