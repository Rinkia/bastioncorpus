"""Fold the legacy inline corpora of the three tools into the canonical corpus.

One-time, reproducible merge (kept in-repo so the dataset's provenance is
auditable). Reads:

  - bastionprobe   payloads.jsonl        (already near-canonical)
  - agentbastion   benchmark/corpus.jsonl + honest_corpus.jsonl  ({text,label,category})

maps each row into the canonical Injection schema, dedupes by stripped text
against the existing seed, and rewrites bastioncorpus/corpus/injections.jsonl
(seed rows kept first, new rows appended in source order). Idempotent.

    python tools/import_legacy.py \
        --probe   ../agentprobe/bastionprobe/payloads.jsonl \
        --corpus  ../agentfirewall/benchmark/corpus.jsonl \
        --honest  ../agentfirewall/benchmark/honest_corpus.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

CANARY_SLOT = "{canary}"
_LANG = re.compile(r"^(de|fr|es|it)_(.+)$")
_CAT_ALIAS = {"jailbreak": "jailbreak_persona", "injection": "direct_injection"}
_BENIGN_INTENTS = {"support", "codegen", "creative", "roleplay"}

_HERE = Path(__file__).resolve().parents[1]
_CORPUS = _HERE / "bastioncorpus" / "corpus" / "injections.jsonl"


def _norm(text: str) -> str:
    """Dedup key: canary-stripped, whitespace-collapsed text."""
    return " ".join(text.replace(CANARY_SLOT, "").split())


def _split_lang(cat: str) -> tuple[str, str]:
    m = _LANG.match(cat)
    return (m.group(1), m.group(2)) if m else ("en", cat)


def _canon(cat: str, label: str) -> tuple[str, str]:
    lang, base = _split_lang(cat)
    if base.startswith("fp_trap_"):
        return lang, "benign_" + base[len("fp_trap_"):]
    if label == "benign" and base in _BENIGN_INTENTS:
        return lang, "benign_" + base
    return lang, _CAT_ALIAS.get(base, base)


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _from_probe(d: dict) -> dict:
    # payloads.jsonl is already canonical bar label/lang.
    lang, cat = _canon(d["category"], "malicious")
    row = {
        "id": d["id"], "category": cat, "label": "malicious",
        "tactic": d.get("tactic", ""), "channel": d.get("channel", "tool_output"),
        "check": d.get("check", "canary"), "severity": int(d.get("severity", 3)),
        "lang": lang, "intent": d.get("intent", ""), "text": d["text"],
    }
    if d.get("forbidden_tool"):
        row["forbidden_tool"] = d["forbidden_tool"]
    return row


def _from_bastion(d: dict, idx: int, prefix: str) -> dict:
    label = d.get("label", "malicious")
    lang, cat = _canon(d.get("category", "direct_injection"), label)
    return {
        "id": f"{prefix}-{idx:03d}", "category": cat, "label": label,
        "tactic": "", "channel": "user_input", "check": "none",
        "severity": 4 if label == "malicious" else 0,
        "lang": lang, "intent": "", "text": d["text"],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--probe", type=Path, default=_HERE.parent / "agentprobe/bastionprobe/payloads.jsonl")
    p.add_argument("--corpus", type=Path, default=_HERE.parent / "agentfirewall/benchmark/corpus.jsonl")
    p.add_argument("--honest", type=Path, default=_HERE.parent / "agentfirewall/benchmark/honest_corpus.jsonl")
    args = p.parse_args()

    existing = _read_jsonl(_CORPUS)
    seen = {_norm(r["text"]) for r in existing}
    seen_ids = {r["id"] for r in existing}
    merged = list(existing)
    added = 0

    incoming: list[dict] = []
    if args.probe.exists():
        incoming += [_from_probe(d) for d in _read_jsonl(args.probe)]
    if args.corpus.exists():
        incoming += [_from_bastion(d, i, "ab") for i, d in enumerate(_read_jsonl(args.corpus), 1)]
    if args.honest.exists():
        incoming += [_from_bastion(d, i, "hp") for i, d in enumerate(_read_jsonl(args.honest), 1)]

    for row in incoming:
        key = _norm(row["text"])
        if key in seen or row["id"] in seen_ids:
            continue  # dedupe by text (near-identical seed row wins) or id collision
        seen.add(key)
        seen_ids.add(row["id"])
        merged.append(row)
        added += 1

    with _CORPUS.open("w", encoding="utf-8") as f:
        for r in merged:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"{len(existing)} seed + {added} imported = {len(merged)} rows -> {_CORPUS.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
