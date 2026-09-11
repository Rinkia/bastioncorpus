"""Project the canonical corpus into each consumer's native shape.

Each adapter returns plain dicts/lists (JSON-serializable), so the CLI can dump
them straight to the file the target tool already loads. No tool needs to know
bastioncorpus's schema - it just reads its own format, now sourced from here.
"""

from __future__ import annotations

from .schema import CANARY_SLOT, Injection

# A stripped literal must be at least this long to be a useful trace signature -
# shorter fragments (e.g. a lone "doc_id:") match too much benign text.
_MIN_SIGNATURE_LEN = 12


def to_probe(rows: list[Injection]) -> list[dict]:
    """bastionprobe payloads.jsonl rows: fireable malicious payloads only.

    A payload is fireable when it is planted in tool output (channel) and scored
    (check=canary|tool). Direct/user_input rows are defense/forensics only, so
    they are dropped here.
    """
    out = []
    for r in rows:
        if not r.is_malicious or r.check == "none" or r.channel != "tool_output":
            continue
        row = {
            "id": r.id,
            "category": r.category,
            "tactic": r.tactic,
            "channel": r.channel,
            "check": r.check,
            "severity": r.severity,
            "text": r.text,  # keep {canary} slot - the runner fills it
        }
        if r.forbidden_tool:
            row["forbidden_tool"] = r.forbidden_tool
        out.append(row)
    return out


def to_semantic(rows: list[Injection]) -> dict:
    """agentbastion inputs.

    - `templates`: distinct plain-language intents for SemanticDetector (embedded
      and compared by cosine similarity, so a handful of intents generalize).
    - `corpus`: benchmark rows `{text, label, category}` (malicious + benign),
      canary-stripped, in agentbastion's corpus.jsonl shape.
    """
    templates: list[str] = []
    seen: set[str] = set()
    for r in rows:
        if r.is_malicious and r.intent and r.intent not in seen:
            seen.add(r.intent)
            templates.append(r.intent)
    corpus = [
        {"text": r.stripped(), "label": r.label, "category": r.category}
        for r in rows
    ]
    return {"templates": templates, "corpus": corpus}


def _signature(text: str) -> str:
    """Longest literal fragment around the canary slot - what bastiontrace can
    substring-match in a tool_result without the per-run token throwing it off."""
    fragments = text.split(CANARY_SLOT)
    return max((f.strip() for f in fragments), key=len, default="").strip()


def to_trace(rows: list[Injection]) -> list[dict]:
    """bastiontrace injection signatures: `{category, severity, match, pattern}`.

    The analyzer flags the first tool_result whose content contains `pattern`.
    Only malicious rows that can appear in tool output are worth matching.
    """
    out = []
    for r in rows:
        if not r.is_malicious or r.channel != "tool_output":
            continue
        pattern = _signature(r.text)
        if len(pattern) < _MIN_SIGNATURE_LEN:
            continue
        out.append({
            "id": r.id,
            "category": r.category,
            "severity": r.severity,
            "match": "substring",
            "pattern": pattern,
        })
    return out
