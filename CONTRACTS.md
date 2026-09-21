# Shared-format contracts (PRP §1.3)

The suite's value is that formats flow between tools. A format change must fail CI
on **both** the producer and the consumer, never break one silently. Three formats
cross tool boundaries:

| Format | Producer | Consumer(s) | Contract status |
|---|---|---|---|
| `injections.jsonl` + adapters (`to_probe` / `to_semantic` / `to_trace`) | **bastioncorpus** | bastionprobe, agentbastion, bastiontrace | ✅ **locked** |
| `policy.yaml` | every `harden` (bastionsupply, bastionprobe, bastiontrace, bastionskill) | agentbastion, bastiongate | ✅ **locked** (bastionsupply↔agentbastion; extend to the rest) |
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

## policy.yaml — locked (bastionsupply ↔ agentbastion)

- **Producer lock:** `bastionsupply/tests/test_policy_contract.py` freezes
  `bastionsupply harden`'s output of a fixed server fixture against
  `bastionsupply/tests/fixtures/policy_golden.yaml`.
- **Consumer lock:** `agentbastion/tests/test_policy_contract.py` loads the
  byte-identical golden (`agentbastion/tests/fixtures/policy_golden.yaml`) and
  asserts every key it relies on (default/allow/deny/rate_limits) parses and
  enforces (deny blocks, allow passes, rate limit caps).
- **Regeneration is deliberate.** Regenerate the golden from the fixture, read the
  diff, and keep the two copies byte-identical. Never edit a golden to pass CI.

**Still to extend** (same pattern, not yet locked): the other `harden` producers
(bastionprobe, bastiontrace, bastionskill) and the bastiongate consumer
(`tools:`/`scrub_results` keys the golden already carries).

## trace schema — the discipline to apply next

1. Freeze a golden trace JSONL emitted by `bastionprobe run`.
2. Producer test in bastionprobe: "my run output still matches the golden schema
   (required keys per event)."
3. Consumer test in bastiontrace: "`analyze` still parses the golden trace and
   returns a verdict."

## Rule

Golden fixtures are only as good as the care taken regenerating them. Regenerate
deliberately, read the diff, never "update golden to make CI pass" (PRP Risks).
