#!/usr/bin/env python3
"""Offline JS analyzer (stdlib-only).

Scans saved JS responses and extracts:
- URL-like strings (absolute)
- API-ish paths (focused list: /api, /v1, /graphql, etc.)
- A limited set of relative URLs (best-effort; intentionally constrained to reduce noise)

Design goals:
- Stdlib-only
- Safe: no network calls
- Deterministic output

Tuning (edit in this file):
- PATH_RE: add/remove keywords for your target (e.g., payments, billing, orders)
- _safe_read_text(max_bytes): increase if bundles are very large (default 5MB)
- REL_URL_RE handling: adjust max length cutoff (default 200) or add more skip rules

Usage:
  python task\task21\js_analyzer.py \
    --index temp\agent1\js_fetch_index.txt \
        --out outputs\js_endpoints_from_js.txt

If you don't have an index file:
    python task\task21\js_analyzer.py --dir temp\agent1\js_fetch_dir --out outputs\js_endpoints_from_js.txt
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import urlsplit


URL_RE = re.compile(r"(?i)\b((?:https?://|wss?://)[^\s'\"<>\\]+)")

# Roughly matches /api/foo, /v1/foo, /graphql, etc. (keeps it broad)
PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(/(?:api|graphql|graphiql|v\d+|oauth|auth|login|token|session|user|users|admin|internal|private|public|config|settings|status|health|metrics)(?:/[A-Za-z0-9_\-\.~%:@]+)*)"
)

REL_URL_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(/[^\s'\"<>\\]+)")


# Skip common low-signal relative paths (tune as needed)
REL_PATH_SKIP_PREFIXES = (
    "/static/",
    "/assets/",
    "/images/",
    "/img/",
    "/fonts/",
)


def _read_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return [
        line.strip()
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _iter_files(index: Path | None, directory: Path | None) -> list[Path]:
    files: list[Path] = []
    if index:
        files.extend([Path(x) for x in _read_lines(index)])
    if directory:
        files.extend([p for p in directory.rglob("*") if p.is_file()])

    # Dedup + keep existing only
    uniq: dict[str, Path] = {}
    for p in files:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        if rp.exists():
            uniq[str(rp)] = rp
    return list(uniq.values())


def _safe_read_text(path: Path, max_bytes: int = 5_000_000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="ignore")


def _normalize_url(u: str) -> str:
    u = (u or "").strip()
    # drop trailing punctuation that often surrounds URLs in JS
    u = u.rstrip(")];,\"'\n\r\t")
    return u


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline JS analyzer (extract URLs/paths)")
    ap.add_argument("--index", help="Path to js_fetch_index.txt")
    ap.add_argument("--dir", dest="dir_path", help="Directory containing saved JS responses")
    ap.add_argument("--out", required=True, help="Output file for extracted strings")
    args = ap.parse_args()

    index = Path(args.index) if args.index else None
    directory = Path(args.dir_path) if args.dir_path else None
    out_path = Path(args.out)

    if not index and not directory:
        raise SystemExit("Provide --index or --dir")

    files = _iter_files(index=index, directory=directory)
    if not files:
        raise SystemExit("No input files found.")

    found: set[str] = set()

    for f in files:
        text = _safe_read_text(f)
        if not text:
            continue

        for m in URL_RE.finditer(text):
            found.add(_normalize_url(m.group(1)))

        for m in PATH_RE.finditer(text):
            found.add(_normalize_url(m.group(1)))

        # Keep a smaller set of general relative URLs; avoid exploding output by filtering
        # out extremely long strings.
        for m in REL_URL_RE.finditer(text):
            s = _normalize_url(m.group(1))
            if 1 < len(s) <= 200 and ("/" in s):
                # Skip source map references
                if s.endswith(".map"):
                    continue
                if s.startswith(REL_PATH_SKIP_PREFIXES):
                    continue
                found.add(s)

    # Normalize obvious URL garbage
    cleaned: list[str] = []
    for s in found:
        if not s or s == "/":
            continue
        # Drop strings that aren't parseable URLs but look like schemes with no host
        if s.lower().startswith(("http://", "https://", "ws://", "wss://")):
            try:
                if not urlsplit(s).hostname:
                    continue
            except Exception:
                continue
        cleaned.append(s)

    cleaned.sort()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(cleaned) + ("\n" if cleaned else ""), encoding="utf-8")

    print(f"files={len(files)}")
    print(f"extracted={len(cleaned)}")
    print(f"wrote={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
