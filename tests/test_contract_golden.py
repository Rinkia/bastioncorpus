"""Contract test: the corpus adapters still emit the golden shapes (PRP §1.3).

bastioncorpus is the shared backbone. Its three adapters project the canonical
corpus into each consumer's native format. If that projection changes shape, the
change silently reaches bastionprobe / agentbastion / bastiontrace. These goldens
turn a silent break into a loud CI failure at the source.

A failure here is not "update the golden to pass". It means: a corpus edit changed
what a consumer receives. Decide whether that is intended, run
`python scripts/regen_golden.py`, READ THE DIFF, and bump/propagate accordingly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bastioncorpus import load_corpus, to_probe, to_semantic, to_trace

GOLDEN = Path(__file__).resolve().parent / "golden"


def _golden(name: str):
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rows():
    return load_corpus()


def test_probe_contract(rows):
    assert to_probe(rows) == _golden("probe.json"), (
        "to_probe output drifted from golden — regenerate deliberately and read the diff"
    )


def test_semantic_contract(rows):
    assert to_semantic(rows) == _golden("semantic.json"), (
        "to_semantic output drifted from golden — regenerate deliberately and read the diff"
    )


def test_trace_contract(rows):
    assert to_trace(rows) == _golden("trace.json"), (
        "to_trace output drifted from golden — regenerate deliberately and read the diff"
    )


def test_golden_keys_are_the_documented_contract(rows):
    """Guard the field *names* consumers depend on, independent of row values.
    If an adapter drops or renames a key, this fails even when a row happens to
    match — a second lock on the format itself."""
    probe = to_probe(rows)
    if probe:
        assert {"id", "category", "tactic", "channel", "check", "severity", "text"} <= probe[0].keys()
    semantic = to_semantic(rows)
    assert {"templates", "corpus"} == semantic.keys()
    if semantic["corpus"]:
        assert {"text", "label", "category"} == semantic["corpus"][0].keys()
    trace = to_trace(rows)
    if trace:
        assert {"id", "category", "severity", "match", "pattern"} == trace[0].keys()
