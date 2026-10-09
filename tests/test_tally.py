"""The shared promotion-bar tally.

Every shadow-mode detector in the suite is gated on a written bar ("20+ sessions
with 0 false blocks, then the default flips"). Three of the four bars had no
instrumentation at all, so they could never be met. See suite-tally-DESIGN.md.
"""

from __future__ import annotations

import json

import pytest

from bastioncorpus.tally import TallySpec, append, read_log, summarize

GATE = TallySpec(
    tool="bastiongate", unit="session",
    counted_as="one proxy process (hashed session id)",
    select=lambda r: r.get("event") == "tainted_egress",
    rule_key="event",
)

FUSE = TallySpec(
    tool="bastionfuse", unit="session",
    counted_as="one Claude Code session id",
    select=lambda r: r.get("tripped") and not r.get("allowed"),
    fired_key="fresh", flag_key="tripped",
)


def _write(tmp_path, rows, name="log.jsonl"):
    p = tmp_path / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return p


# --- the shape -------------------------------------------------------------

def test_summary_has_the_documented_shape(tmp_path):
    rows = [{"ts": 1.0, "event": "tainted_egress", "action": "block", "session": "aaa"},
            {"ts": 2.0, "event": "tool_call", "session": "aaa"},
            {"ts": 3.0, "event": "tainted_egress", "action": "warn", "session": "bbb"}]
    out = summarize(read_log(_write(tmp_path, rows)), GATE)
    assert out == {
        "tool": "bastiongate",
        "unit": "session",
        "counted_as": "one proxy process (hashed session id)",
        "records": 3,
        "sessions": 2,
        "fired_by_rule": {"tainted_egress": 2},
        # None, not {}: gate events carry no fired/repeat distinction, and
        # "zero repeats" would be a claim this spec hasn't earned.
        "repeat_by_rule": None,
        "shadow_notes": {},
        "window": {"first_ts": 1.0, "last_ts": 3.0},
    }


def test_unit_card_is_reported_for_a_scanner(tmp_path):
    """bastionsupply's bar counts cards, not sessions. A bar that can't say what
    it counted is how the 4-vs-2 session discrepancy happened."""
    spec = TallySpec(tool="bastionsupply", unit="card", counted_as="one scanned agent card",
                     session_key="card", select=lambda r: bool(r.get("findings")))
    rows = [{"card": "https://a.example/.well-known/agent.json", "findings": ["tool-poisoning"],
             "rule": "tool-poisoning", "ts": 1.0},
            {"card": "https://b.example/.well-known/agent.json", "findings": [], "ts": 2.0}]
    out = summarize(read_log(_write(tmp_path, rows)), spec)
    assert out["unit"] == "card" and out["counted_as"] == "one scanned agent card"
    assert out["sessions"] == 2, "two distinct cards"
    assert out["fired_by_rule"] == {"tool-poisoning": 1}


# --- D4: fired vs repeat, the issue #6 regression --------------------------

def test_one_firing_plus_three_repeats_is_not_four(tmp_path):
    """bastionfuse issue #6: post-trip refusals were counted as trips, so one
    trip plus N refusals read as N+1 and inflated the bar. The distinction
    belongs here so no tool has to rediscover it."""
    rows = [{"session": "s", "rule": "canary", "tripped": True, "allowed": False, "fresh": True},
            *({"session": "s", "rule": "canary", "tripped": True, "allowed": False,
               "fresh": False} for _ in range(3))]
    out = summarize(read_log(_write(tmp_path, rows)), FUSE)
    assert out["fired_by_rule"] == {"canary": 1}
    assert out["repeat_by_rule"] == {"canary": 3}


def test_rows_without_the_fired_key_fall_back_to_the_flag(tmp_path):
    """Records written before a tool learned the distinction must keep tallying
    the way they always did, rather than silently changing meaning."""
    rows = [{"session": "s", "rule": "canary", "tripped": True, "allowed": False}]
    out = summarize(read_log(_write(tmp_path, rows)), FUSE)
    assert out["fired_by_rule"] == {"canary": 1} and out["repeat_by_rule"] == {}


def test_a_spec_that_cannot_distinguish_says_so(tmp_path):
    """Silently reporting everything as 'fired' is what inflated the fuse bar.
    A spec with no fired_key must declare the ambiguity, not hide it."""
    spec = TallySpec(tool="t", select=lambda r: r.get("event") == "x", rule_key="event")
    out = summarize(read_log(_write(tmp_path, [{"event": "x", "session": "s"}])), spec)
    assert out["fired_by_rule"] == {"x": 1}
    assert out["repeat_by_rule"] is None, "None = not measured, which is not the same as zero"


# --- reading logs ----------------------------------------------------------

def test_damaged_and_hostile_lines_never_break_the_tally(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text("\n".join([
        json.dumps({"event": "tainted_egress", "session": "a", "ts": 1.0}),
        "{not json",
        "[1, 2, 3]",            # valid JSON, not a row
        "null",
        "",
        json.dumps({"event": "tainted_egress", "session": "b", "ts": 2.0,
                    "unknown_future_field": {"x": 1}}),
    ]) + "\n", encoding="utf-8")
    out = summarize(read_log(p), GATE)
    assert out["records"] == 2 and out["sessions"] == 2
    assert out["fired_by_rule"] == {"tainted_egress": 2}


def test_missing_log_is_distinguishable_from_an_empty_one(tmp_path):
    """"No log yet" must never look like "measured, and clean" — that is the
    whole failure this work exists to fix."""
    assert read_log(tmp_path / "nope.jsonl") is None
    assert read_log(_write(tmp_path, [])) == []

    out = summarize(None, GATE)
    assert out["records"] is None and out["sessions"] is None
    assert "no log" in out["note"].lower()

    empty = summarize([], GATE)
    assert empty["records"] == 0 and empty["sessions"] == 0 and "note" not in empty


def test_window_is_absent_without_timestamps(tmp_path):
    out = summarize(read_log(_write(tmp_path, [{"event": "tainted_egress", "session": "a"}])), GATE)
    assert out["window"] is None


def test_append_round_trips_and_is_append_only(tmp_path):
    p = tmp_path / "log.jsonl"
    append(p, {"event": "tainted_egress", "session": "a"})
    append(p, {"event": "tool_call", "session": "a"})
    rows = read_log(p)
    assert [r["event"] for r in rows] == ["tainted_egress", "tool_call"]
    assert all("ts" in r for r in rows), "append stamps a ts so windows work"


def test_append_creates_parent_directories(tmp_path):
    append(tmp_path / "deep" / "state" / "log.jsonl", {"event": "x"})
    assert (tmp_path / "deep" / "state" / "log.jsonl").is_file()


# --- shadow notes ----------------------------------------------------------

def test_shadow_notes_are_grouped_by_their_leading_phrase(tmp_path):
    """Shadow detectors log would-fire notes; the parenthetical detail varies per
    occurrence, so group on the phrase to keep the tally legible."""
    rows = [{"session": "s", "shadow": ["repeat (3 in 60s)", "repeat (9 in 60s)"]},
            {"session": "s", "shadow": ["encoded_result (base64)"]}]
    out = summarize(read_log(_write(tmp_path, rows)), FUSE)
    assert out["shadow_notes"] == {"repeat": 2, "encoded_result": 1}


# --- D2: the fuse must never disagree with the shared module ---------------

FUSE_FIXTURE = [
    {"ts": 1.0, "session": "s1", "tool": "Bash", "allowed": False, "rule": "self-protect",
     "tripped": False, "reason": "blocked", "shadow": []},
    {"ts": 2.0, "session": "s1", "tool": "curl", "allowed": False, "rule": "taint-egress",
     "tripped": True, "fresh": True, "reason": "tripped", "shadow": []},
    {"ts": 3.0, "session": "s1", "tool": "git", "allowed": False, "rule": "taint-egress",
     "tripped": True, "fresh": False, "reason": "already tripped", "shadow": []},
    {"ts": 4.0, "session": "s2", "tool": "Read", "allowed": True, "rule": "", "tripped": False,
     "reason": "ok", "shadow": ["repeat (4 in 60s)"]},
]


def test_shared_summary_agrees_with_the_fuse_numbers(tmp_path):
    """D2: the fuse keeps its own implementation and its own key names
    (`trips_by_rule`, `refused_after_trip`), because those are public output and
    domain words. What must hold is that the two never report different numbers.
    This mirrors `bastionfuse/cli.py::_log` exactly."""
    rows = read_log(_write(tmp_path, FUSE_FIXTURE))

    refused = [r for r in rows if r.get("tripped") and not r.get("allowed")]
    fuse_trips, fuse_after = {}, {}
    for r in refused:
        bucket = fuse_trips if r.get("fresh", r.get("tripped")) else fuse_after
        bucket[str(r.get("rule"))] = bucket.get(str(r.get("rule")), 0) + 1
    fuse_sessions = len({str(r.get("session")) for r in rows})

    out = summarize(rows, FUSE)
    assert out["records"] == len(rows)
    assert out["sessions"] == fuse_sessions
    assert out["fired_by_rule"] == fuse_trips == {"taint-egress": 1}
    assert out["repeat_by_rule"] == fuse_after == {"taint-egress": 1}


def test_summarize_does_not_mutate_its_input(tmp_path):
    rows = read_log(_write(tmp_path, FUSE_FIXTURE))
    before = json.dumps(rows, sort_keys=True)
    summarize(rows, FUSE)
    assert json.dumps(rows, sort_keys=True) == before


def test_spec_rejects_an_unknown_unit():
    with pytest.raises(ValueError, match="unit"):
        TallySpec(tool="t", unit="fortnight")
