# Shared-format contracts (PRP §1.3)

The suite's value is that formats flow between tools. A format change must fail CI
on **both** the producer and the consumer, never break one silently. Three formats
cross tool boundaries:

| Format | Producer | Consumer(s) | Contract status |
|---|---|---|---|
| `injections.jsonl` + adapters (`to_probe` / `to_semantic` / `to_trace`) | **bastioncorpus** | bastionprobe, agentbastion, bastiontrace | ✅ **locked** |
| `policy.yaml` | every `harden` (bastionsupply, bastionprobe, bastiontrace, bastionskill) | agentbastion, bastiongate | 📝 documented, golden suite pending |
| trace schema (tool-call JSONL) | bastionprobe run output | bastiontrace analyze input | 📝 documented, golden suite pending |

## injections.jsonl adapters — locked

- **Producer lock:** `tests/test_contract_golden.py` here pins each adapter's full
  output against `tests/golden/*.json`. Any shape drift fails CI at the source.
- **Consumer locks:** each consumer repo has `tests/test_corpus_contract.py` that
  runs the adapter and asserts the enrichment path actually engaged (not the silent
  `except Exception: fall back to built-ins` path every consumer has). So a format
  break fails there too, instead of quietly degrading recall.
- **Regeneration is deliberate.** A failing golden test means a corpus edit changed
  what a consumer receives. Run `python scripts/regen_golden.py`, **read the diff**,
  and if it is intended, follow §1.2 propagation. Never edit goldens to make CI pass.

## policy.yaml — the discipline to apply next

Add the same producer+consumer pair:
1. Freeze a golden `policy.yaml` from a fixed input (`bastionsupply harden fixture.json`).
2. Producer test in each `harden` tool: "my emitted policy still equals the golden."
3. Consumer test in agentbastion + bastiongate: "I still load and apply the golden
   policy" — assert the loader accepts every key the golden uses.

A key rename in `harden` then fails the producer; a loader that drops a key fails
the consumer.

## trace schema — the discipline to apply next

1. Freeze a golden trace JSONL emitted by `bastionprobe run`.
2. Producer test in bastionprobe: "my run output still matches the golden schema
   (required keys per event)."
3. Consumer test in bastiontrace: "`analyze` still parses the golden trace and
   returns a verdict."

## Rule

Golden fixtures are only as good as the care taken regenerating them. Regenerate
deliberately, read the diff, never "update golden to make CI pass" (PRP Risks).
