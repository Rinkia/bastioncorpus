#!/usr/bin/env python3
"""Regenerate the golden contract fixtures for the corpus adapters.

The goldens freeze the exact shape each consumer receives:
  - to_probe   -> bastionprobe payloads.jsonl rows
  - to_semantic-> agentbastion templates + corpus
  - to_trace   -> bastiontrace injection signatures

`tests/test_contract_golden.py` fails when live adapter output drifts from these
files. That is the point: a corpus change that alters a consumer format must be a
DELIBERATE regeneration. Run this, then READ THE DIFF before committing — never
regenerate just to make CI pass (PRP §1.3, Risks).

    python scripts/regen_golden.py
"""

from __future__ import annotations

import json
from pathlib import Path

from bastioncorpus import load_corpus, to_probe, to_semantic, to_trace

GOLDEN = Path(__file__).resolve().parent.parent / "tests" / "golden"


def _write(name: str, data) -> None:
    path = GOLDEN / name
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {path.relative_to(GOLDEN.parent.parent)}")


def main() -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    rows = load_corpus()
    _write("probe.json", to_probe(rows))
    _write("semantic.json", to_semantic(rows))
    _write("trace.json", to_trace(rows))


if __name__ == "__main__":
    main()
