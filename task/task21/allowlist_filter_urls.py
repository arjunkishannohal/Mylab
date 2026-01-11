#!/usr/bin/env python3
"""Filter a URL list by an allowlist of hosts.

- Reads allowlist hosts (one per line) from outputs/activesubdomain.txt (or specified file)
- Reads URLs (one per line)
- Writes only URLs whose hostname is in allowlist

Design goals:
- Stdlib-only
- Safe defaults (drop anything without a parseable hostname)

Usage:
  python task\task21\allowlist_filter_urls.py \
    --allowlist outputs\activesubdomain.txt \
        --in temp\agent1\url_corpus_raw.txt \
        --out outputs\url_corpus_all_in_scope.txt

You can also use it for queue files:
  python task\task21\allowlist_filter_urls.py --allowlist outputs\activesubdomain.txt --in outputs\queue_dynamic_endpoints_urls.txt --out outputs\queue_dynamic_endpoints_urls.txt
"""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import urlsplit


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _norm_host(host: str) -> str:
    host = (host or "").strip().lower()
    if host.endswith("."):
        host = host[:-1]
    return host


def main() -> int:
    ap = argparse.ArgumentParser(description="Filter URL list by allowlist hosts")
    ap.add_argument("--allowlist", required=True, help="Path to allowlist hosts file")
    ap.add_argument("--in", dest="in_path", required=True, help="Input URL list")
    ap.add_argument("--out", required=True, help="Output URL list")
    args = ap.parse_args()

    allowlist_path = Path(args.allowlist)
    in_path = Path(args.in_path)
    out_path = Path(args.out)

    allow_hosts = {_norm_host(h) for h in _read_lines(allowlist_path)}
    if not allow_hosts:
        raise SystemExit("Allowlist is empty; refusing to filter.")

    urls_in = _read_lines(in_path)

    kept: list[str] = []
    dropped = 0
    for u in urls_in:
        try:
            host = urlsplit(u).hostname
        except Exception:
            host = None
        if not host:
            dropped += 1
            continue
        if _norm_host(host) not in allow_hosts:
            dropped += 1
            continue
        kept.append(u)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")

    print(f"allow_hosts={len(allow_hosts)}")
    print(f"in={len(urls_in)} kept={len(kept)} dropped={dropped}")
    print(f"wrote={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
