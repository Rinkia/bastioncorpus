"""Canonical injection schema for the bastion trilogy.

One row = one attack (or one benign false-positive trap). The schema is the
*superset* of what the three consumers need, so a single corpus feeds all of
them without any tool re-rolling its own strings:

  - bastionprobe fires malicious rows as payloads     -> `id, text, category,
    tactic, channel, check, forbidden_tool, severity` (see adapters.to_probe)
  - agentbastion blocks them (SemanticDetector + benchmark corpus) -> `text,
    label, category` + plain-language `intent` templates (adapters.to_semantic)
  - bastiontrace matches them in tool_result content  -> canary-stripped
    signatures (adapters.to_trace)

`text` may carry a single `{canary}` placeholder; the probe runner fills it with
a unique token per run, and the other adapters strip it. `label` is
malicious|benign - benign rows are false-positive traps (they *look* like
injections but are legitimate user text), used to measure over-blocking.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Iterator, Optional

CANARY_SLOT = "{canary}"

VALID_LABELS = frozenset({"malicious", "benign"})
VALID_CHECKS = frozenset({"canary", "tool", "none"})

# Canonical taxonomy. Language is a separate `lang` field, never a category
# prefix, so `direct_injection` covers every language. `benign_*` categories
# name the false-positive trap family (label=benign).
MALICIOUS_CATEGORIES = frozenset({
    "direct_injection",
    "indirect_injection",
    "instruction_override",
    "jailbreak_persona",
    "exfiltration",
    "delimiter_injection",
    "obfuscation",
})


@dataclass(frozen=True)
class Injection:
    """One corpus row. Immutable."""

    id: str
    text: str
    category: str
    label: str = "malicious"
    tactic: str = ""
    channel: str = "tool_output"
    check: str = "none"  # "canary" | "tool" | "none"
    forbidden_tool: Optional[str] = None
    severity: int = 3
    lang: str = "en"
    intent: str = ""  # plain-language restatement, for semantic templates

    @property
    def is_malicious(self) -> bool:
        return self.label == "malicious"

    @property
    def has_canary(self) -> bool:
        return CANARY_SLOT in self.text

    def stripped(self) -> str:
        """`text` with the canary placeholder removed (for signatures/templates)."""
        return self.text.replace(CANARY_SLOT, "").strip()

    def render(self, canary: str) -> str:
        """Fill the canary slot. No-op if the row has no placeholder."""
        return self.text.replace(CANARY_SLOT, canary)


def _validate(d: dict) -> None:
    rid = d.get("id")
    if not rid or not d.get("text"):
        raise ValueError(f"row {rid!r}: 'id' and 'text' are required")
    label = d.get("label", "malicious")
    if label not in VALID_LABELS:
        raise ValueError(f"row {rid!r}: label {label!r} not in {sorted(VALID_LABELS)}")
    check = d.get("check", "none")
    if check not in VALID_CHECKS:
        raise ValueError(f"row {rid!r}: check {check!r} not in {sorted(VALID_CHECKS)}")
    if check == "tool" and not d.get("forbidden_tool"):
        raise ValueError(f"row {rid!r}: check=tool needs a forbidden_tool")
    if label == "malicious" and not d.get("category", "").startswith("benign") \
            and d.get("category") not in MALICIOUS_CATEGORIES:
        raise ValueError(f"row {rid!r}: unknown malicious category {d.get('category')!r}")


def _from_dict(d: dict) -> Injection:
    _validate(d)
    return Injection(
        id=d["id"],
        text=d["text"],
        category=d.get("category", "indirect_injection"),
        label=d.get("label", "malicious"),
        tactic=d.get("tactic", ""),
        channel=d.get("channel", "tool_output"),
        check=d.get("check", "none"),
        forbidden_tool=d.get("forbidden_tool"),
        severity=int(d.get("severity", 3)),
        lang=d.get("lang", "en"),
        intent=d.get("intent", ""),
    )


def _iter_lines(text: str) -> Iterator[dict]:
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield json.loads(line)


def load_corpus() -> list[Injection]:
    """Load the packaged canonical corpus, validated. Also enforces unique ids."""
    data = resources.files("bastioncorpus").joinpath("corpus/injections.jsonl").read_text(encoding="utf-8")
    rows = [_from_dict(d) for d in _iter_lines(data)]
    seen: set[str] = set()
    for r in rows:
        if r.id in seen:
            raise ValueError(f"duplicate id {r.id!r}")
        seen.add(r.id)
    return rows
