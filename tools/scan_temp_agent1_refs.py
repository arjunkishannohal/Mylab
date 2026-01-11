#!/usr/bin/env python3
"""Scan repo for references to temp/agent1 (both slash styles).

Writes:
- outputs/temp_agent1_refs_report.md   (human summary)
- outputs/temp_agent1_refs_report.json (machine readable)

This is stdlib-only and safe to run on Windows.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUTS_DIR = REPO_ROOT / "outputs"

# Match temp/agent1/<token> where token stops at whitespace or typical delimiters.
PATTERN = re.compile(r"temp[\\/]+agent1[\\/]+[^\s\)\]\}\"']+", re.IGNORECASE)

# Skip obviously irrelevant or huge/binary-ish files.
SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "bower_components",
    "__pycache__",
    # Generated artifacts and raw intermediates are intentionally noisy.
    # This scanner is for run-cards/scripts/docs, not produced data.
    "outputs",
    "temp",
}

SKIP_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".7z",
    ".gz",
    ".tar",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".jar",
    ".class",
    ".pdb",
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".wav",
    ".mp3",
    ".flac",
}

MAX_BYTES = 2_000_000  # 2MB per file


@dataclass
class Occurrence:
    path: str  # repo-relative, posix style
    line: int
    match: str
    line_text: str


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # prune dirs
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in SKIP_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def scan_file(path: Path) -> List[Occurrence]:
    try:
        data = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    rel = path.relative_to(REPO_ROOT).as_posix()
    occurrences: List[Occurrence] = []
    for idx, line in enumerate(data.splitlines(), start=1):
        for m in PATTERN.finditer(line):
            raw_match = m.group(0)
            # Normalize common punctuation artifacts from shell snippets.
            # Keep it conservative to avoid mangling legitimate paths.
            cleaned_match = raw_match.rstrip(";,\"").rstrip("/\\")
            occurrences.append(
                Occurrence(
                    path=rel,
                    line=idx,
                    match=cleaned_match,
                    line_text=line.strip(),
                )
            )
    return occurrences


def main() -> int:
    hits: List[Occurrence] = []
    for p in iter_files(REPO_ROOT):
        hits.extend(scan_file(p))

    # Group by exact matched token
    grouped: Dict[str, List[Occurrence]] = {}
    for occ in hits:
        grouped.setdefault(occ.match, []).append(occ)

    # Sort groups by count desc
    groups_sorted: List[Tuple[str, List[Occurrence]]] = sorted(
        grouped.items(), key=lambda kv: len(kv[1]), reverse=True
    )

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUTS_DIR / "temp_agent1_refs_report.json"
    md_path = OUTPUTS_DIR / "temp_agent1_refs_report.md"

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repo_root": str(REPO_ROOT),
        "unique_refs": len(groups_sorted),
        "total_occurrences": len(hits),
        "groups": [
            {
                "ref": ref,
                "count": len(occs),
                "occurrences": [asdict(o) for o in occs],
            }
            for ref, occs in groups_sorted
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines: List[str] = []
    lines.append("# temp/agent1 reference inventory")
    lines.append("")
    lines.append(f"Generated: {payload['generated_at']}")
    lines.append(f"Unique refs: {payload['unique_refs']}")
    lines.append(f"Total occurrences: {payload['total_occurrences']}")
    lines.append("")

    for ref, occs in groups_sorted:
        lines.append(f"## {ref} (count={len(occs)})")
        for o in occs[:10]:
            lines.append(f"- {o.path}#L{o.line}: `{o.line_text}`")
        if len(occs) > 10:
            lines.append(f"- … {len(occs) - 10} more")
        lines.append("")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {md_path}")
    print(f"Wrote {json_path}")
    print(f"Unique refs: {payload['unique_refs']}")
    print(f"Total occurrences: {payload['total_occurrences']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
