#!/usr/bin/env python3
"""Extract per-run-card tool name + input/output contracts from task/.

Writes:
  outputs/workflow_extracted.json

This is used to generate/maintain README.md.
Stdlib-only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TASK_DIR = REPO_ROOT / "task"
OUT_JSON = REPO_ROOT / "outputs" / "workflow_extracted.json"


TOOL_LINE_RE = re.compile(r"^#\s*Tool\s*(\d+)\s*[—-]\s*(.+)$")


def _looks_like_path_contract(text: str) -> bool:
    t = text.replace("\\\\", "/")
    return ("outputs/" in t) or ("temp/agent1" in t)


def parse_run_card(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    title = None
    tool_num = None
    for line in lines[:25]:
        m = TOOL_LINE_RE.match(line.strip())
        if m:
            tool_num = m.group(1)
            title = m.group(0).lstrip("# ").strip()
            break

    inputs: list[str] = []
    outputs: list[str] = []

    mode: str | None = None
    for raw in lines:
        s = raw.strip()
        if re.match(r"^#\s*Inputs?\b", s, re.IGNORECASE):
            mode = "in"
            continue
        if re.match(r"^#\s*Outputs?\b", s, re.IGNORECASE):
            mode = "out"
            continue

        if mode is None:
            continue

        # End of contract block (common section separators)
        if re.match(r"^#\s*-{5,}\s*$", s):
            mode = None
            continue
        if re.match(r"^#\s*(Time rule|Install|Preflight|Notes)\b", s, re.IGNORECASE):
            # Often follows the contract section
            if (mode == "in" and inputs) or (mode == "out" and outputs):
                mode = None
                continue

        t = s
        if t.startswith("#"):
            t = t.lstrip("#").strip()
        if not t:
            # blank line ends block if we already captured something
            if (mode == "in" and inputs) or (mode == "out" and outputs):
                mode = None
            continue

        # Normalize bullet lines
        if t.startswith("-"):
            t = t[1:].strip()

        if _looks_like_path_contract(t):
            if mode == "in":
                inputs.append(t)
            else:
                outputs.append(t)

    return {
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "tool": tool_num,
        "title": title,
        "inputs": inputs,
        "outputs": outputs,
    }


def main() -> int:
    cards = sorted(TASK_DIR.glob("task*/**/*.txt"))
    items = [parse_run_card(p) for p in cards]
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(items, indent=2), encoding="utf-8")
    print(f"Wrote {OUT_JSON}")
    print(f"Run-cards: {len(items)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
