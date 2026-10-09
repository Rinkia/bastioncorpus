"""The shared promotion-bar tally.

Every shadow-mode detector in the suite ships in warn/log mode behind a written
bar: "20+ real sessions with 0 false blocks, then the default flips". Three of
the four bars had no instrumentation, so they could never be met and all read 0
for weeks. This module is the measurement half, and nothing else: it reads an
append-only JSONL log a tool already writes and reports what is in it.

Two lessons from bastionfuse are built in rather than left to each caller:

* **Fired is not the same as still firing.** The fuse counted every call refused
  *after* a trip as another trip, so one trip plus N refusals read as N+1 and
  inflated the bar (issue #6). `fired_by_rule` and `repeat_by_rule` are always
  separate here, and a spec that cannot tell them apart reports `None` for
  repeats rather than folding them into the fired count.
* **"No log" must never look like "clean".** A missing log yields `None` counts
  and a note, never zeros. An unmeasured run that reads as a clean run is the
  exact failure this module exists to prevent.

What it deliberately does NOT do is judge. A "false positive" is a human
judgement about whether a flagged flow was benign, which no tool can make about
itself, so the summary reports the observable split and the dogfood guide stays
the place a person records how many were false.

    from bastioncorpus.tally import TallySpec, append, read_log, summarize

    spec = TallySpec(tool="bastiongate", counted_as="one proxy process",
                     select=lambda r: r.get("event") == "tainted_egress",
                     rule_key="event")
    print(json.dumps(summarize(read_log(path), spec), indent=2))
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

__all__ = ["TallySpec", "append", "read_log", "summarize"]

MAX_BYTES = 64 * 1024 * 1024  # refuse to slurp an implausible log into memory
_UNITS = ("session", "card", "run")


@dataclass(frozen=True)
class TallySpec:
    """How to read one tool's log. Field names, not behaviour.

    `select` picks the rows that count as the detector firing; everything else
    is a record. `fired_key` is the field meaning *this* row is what fired, and
    `flag_key` the field meaning "firing, now or earlier" — the pair that keeps
    repeats out of the headline number. Omit `fired_key` and repeats are
    reported as unmeasured instead of as zero.
    """

    tool: str
    unit: str = "session"
    counted_as: str = ""
    session_key: str = "session"
    rule_key: str = "rule"
    fired_key: str = ""
    flag_key: str = ""
    shadow_key: str = "shadow"
    ts_key: str = "ts"
    select: Optional[Callable[[dict], Any]] = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if self.unit not in _UNITS:
            raise ValueError(f"TallySpec `unit` must be one of {_UNITS}, got {self.unit!r}")
        if not self.tool:
            raise ValueError("TallySpec `tool` is required")


def read_log(path) -> Optional[list[dict]]:
    """Rows from an append-only JSONL log.

    Returns `None` when there is no log — distinct from `[]`, which means a log
    exists and is empty. Damaged lines and non-object rows are skipped: a
    half-written final line is normal for a log a live process appends to, and
    must never cost the reader the rest of the tally.
    """
    p = Path(path)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise ValueError(f"log is larger than {MAX_BYTES} bytes: {p}")
        text = p.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as e:
        raise ValueError(f"cannot read {p}: {e}") from None
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def append(path, row: dict) -> None:
    """Append one row, stamping `ts` if the caller left it out.

    Opened per call in append mode: concurrent writers interleave whole lines
    rather than corrupting each other, and nothing is held open across a crash.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(row)
    payload.setdefault("ts", round(time.time(), 3))
    line = json.dumps(payload, ensure_ascii=False, default=str) + "\n"
    with p.open("a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())


def summarize(rows: Optional[list[dict]], spec: TallySpec) -> dict:
    """One summary object, the same shape for every tool in the suite."""
    base = {"tool": spec.tool, "unit": spec.unit, "counted_as": spec.counted_as}
    if rows is None:
        return {**base, "records": None, "sessions": None, "fired_by_rule": None,
                "repeat_by_rule": None, "shadow_notes": None, "window": None,
                "note": "no log yet: nothing has been recorded, which is not the same as "
                        "nothing having happened. Run the tool with its log flag."}

    fired: Counter = Counter()
    repeats: Counter = Counter()
    shadow: Counter = Counter()
    units: set[str] = set()
    stamps: list[float] = []

    for row in rows:
        unit = row.get(spec.session_key)
        if unit is not None:
            units.add(str(unit))
        ts = row.get(spec.ts_key)
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            stamps.append(float(ts))
        for note in row.get(spec.shadow_key) or ():
            shadow[str(note).split("(")[0].strip()] += 1
        if spec.select is not None and not spec.select(row):
            continue
        rule = str(row.get(spec.rule_key, ""))
        if not spec.fired_key:
            fired[rule] += 1          # cannot distinguish; see repeat_by_rule below
            continue
        # A row written before the tool learned the distinction has no fired_key:
        # fall back to the flag so an old log keeps tallying the way it always did.
        fallback = row.get(spec.flag_key) if spec.flag_key else True
        (fired if row.get(spec.fired_key, fallback) else repeats)[rule] += 1

    return {
        **base,
        "records": len(rows),
        "sessions": len(units),
        "fired_by_rule": dict(fired),
        # None, not {}: this spec cannot tell a repeat from a first firing, and
        # saying "zero repeats" would be a claim it hasn't earned.
        "repeat_by_rule": dict(repeats) if spec.fired_key else None,
        "shadow_notes": dict(shadow),
        "window": {"first_ts": min(stamps), "last_ts": max(stamps)} if stamps else None,
    }


# --- self-check -------------------------------------------------------------

def _demo() -> None:
    import tempfile

    d = Path(tempfile.mkdtemp())
    log = d / "state" / "log.jsonl"
    assert read_log(log) is None, "a missing log is None, never empty"
    assert summarize(None, TallySpec(tool="t"))["records"] is None

    gate = TallySpec(tool="bastiongate", counted_as="one proxy process",
                     select=lambda r: r.get("event") == "tainted_egress", rule_key="event")
    append(log, {"event": "tool_call", "session": "a"})
    append(log, {"event": "tainted_egress", "action": "warn", "session": "a"})
    append(log, {"event": "tainted_egress", "action": "block", "session": "b"})
    out = summarize(read_log(log), gate)
    assert out["records"] == 3 and out["sessions"] == 2, out
    assert out["fired_by_rule"] == {"tainted_egress": 2}, out
    assert out["repeat_by_rule"] is None, "gate rows carry no fired/repeat distinction"

    # the issue #6 shape: one firing plus three refusals is one firing
    fuse = TallySpec(tool="bastionfuse", select=lambda r: r.get("tripped") and not r.get("allowed"),
                     fired_key="fresh", flag_key="tripped")
    rows = [{"session": "s", "rule": "canary", "tripped": True, "allowed": False, "fresh": True}]
    rows += [{"session": "s", "rule": "canary", "tripped": True, "allowed": False, "fresh": False}] * 3
    out = summarize(rows, fuse)
    assert out["fired_by_rule"] == {"canary": 1}, out
    assert out["repeat_by_rule"] == {"canary": 3}, out

    print("bastioncorpus tally self-check OK")


if __name__ == "__main__":
    _demo()
