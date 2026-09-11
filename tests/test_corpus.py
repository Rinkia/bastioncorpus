"""Self-check: corpus loads clean and each adapter emits what its consumer loads."""

from bastioncorpus import load_corpus, to_probe, to_semantic, to_trace
from bastioncorpus.schema import CANARY_SLOT, MALICIOUS_CATEGORIES, VALID_CHECKS, VALID_LABELS

ROWS = load_corpus()


def test_corpus_loads_and_is_wellformed():
    assert len(ROWS) >= 20
    ids = [r.id for r in ROWS]
    assert len(ids) == len(set(ids)), "ids must be unique"
    for r in ROWS:
        assert r.label in VALID_LABELS
        assert r.check in VALID_CHECKS
        if r.check == "tool":
            assert r.forbidden_tool, f"{r.id}: tool check needs forbidden_tool"
        if r.is_malicious and not r.category.startswith("benign"):
            assert r.category in MALICIOUS_CATEGORIES


def test_has_both_malicious_and_benign_traps():
    assert any(r.is_malicious for r in ROWS)
    assert any(not r.is_malicious for r in ROWS), "need benign FP traps to measure over-blocking"


def test_probe_export_only_fireable_and_matches_schema():
    payloads = to_probe(ROWS)
    assert payloads, "expected some fireable payloads"
    for p in payloads:
        # bastionprobe's loader contract: tool checks must name a forbidden_tool
        assert p["check"] in ("canary", "tool")
        assert p["channel"] == "tool_output"
        if p["check"] == "tool":
            assert p.get("forbidden_tool")
    # direct/user_input rows are NOT fired
    fired_ids = {p["id"] for p in payloads}
    assert "di-001" not in fired_ids


def test_semantic_export_shape():
    bundle = to_semantic(ROWS)
    assert bundle["templates"], "SemanticDetector needs intent templates"
    assert all(CANARY_SLOT not in t for t in bundle["templates"])
    # benchmark corpus rows carry the fields agentbastion reads
    for row in bundle["corpus"]:
        assert set(row) == {"text", "label", "category"}
        assert CANARY_SLOT not in row["text"], "canary slot must be stripped for defense"


def test_trace_signatures_are_canary_free_and_substantial():
    sigs = to_trace(ROWS)
    assert sigs
    for s in sigs:
        assert CANARY_SLOT not in s["pattern"]
        assert len(s["pattern"]) >= 12
        assert s["match"] == "substring"


def test_render_fills_canary():
    canary_row = next(r for r in ROWS if r.has_canary)
    rendered = canary_row.render("AGP-DEAD")
    assert "AGP-DEAD" in rendered
    assert CANARY_SLOT not in rendered
