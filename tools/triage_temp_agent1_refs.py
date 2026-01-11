#!/usr/bin/env python3
"""Triage temp/agent1 references from outputs/temp_agent1_refs_report.json.

This is a helper to quickly spot references that look like canonical outputs
but still live under temp/agent1.

Usage:
  python tools/triage_temp_agent1_refs.py

It does not modify any files.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT = REPO_ROOT / "outputs" / "temp_agent1_refs_report.json"

# Heuristic patterns for obvious intermediates.
IGNORE_REF_RE = re.compile(
    r"(?i)(\\\\logs|/logs|_part\\.txt$|_part\\.json$|_raw\\.txt$|_raw\\.json$|chunks_|api_docs_raw|js_responses|/response/|/responses/|\\.log$)"
)

# Files that are more like tool configuration or scratch lists.
SKIP_BASENAMES = {
    "resolvers.txt",
    "resolvers_good.txt",
    "content_wordlist.txt",
    "subdomain_wordlist.txt",
    "routes-small.kite",
}


def norm(ref: str) -> str:
    return ref.replace("\\\\", "/").replace("\\", "/")


def main() -> int:
    if not REPORT.exists():
        raise SystemExit(
            f"Missing report: {REPORT}. Run tools/scan_temp_agent1_refs.py first."
        )

    data = json.loads(REPORT.read_text(encoding="utf-8"))
    groups = data.get("groups", [])

    candidates: list[tuple[int, str]] = []
    for g in groups:
        ref = g.get("ref", "")
        count = int(g.get("count", 0))
        r = norm(ref)
        base = r.split("/")[-1].lower()

        if not r.lower().startswith("temp/agent1/"):
            continue
        if IGNORE_REF_RE.search(r):
            continue
        if base in SKIP_BASENAMES:
            continue
        if base.startswith("_"):
            continue

        candidates.append((count, ref))

    candidates.sort(reverse=True)

    print(f"Report: {REPORT}")
    print(f"Total groups: {len(groups)}")
    print(f"Candidate final-ish refs: {len(candidates)}")
    print("\nTop candidates (count, ref):")
    for count, ref in candidates[:80]:
        print(f"{count:4d}  {ref}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
