# Shared-format contracts (PRP §1.3)

The suite's value is that formats flow between tools. A format change must fail CI
on **both** the producer and the consumer, never break one silently. Four formats
cross tool boundaries:

| Format | Producer | Consumer(s) | Contract status |
|---|---|---|---|
| `injections.jsonl` + adapters (`to_probe` / `to_semantic` / `to_trace`) | **bastioncorpus** | bastionprobe, agentbastion, bastiontrace | ✅ **locked** |
| `policy.yaml` v1 (tool policy) | `harden` in bastionsupply ≤ 0.7, bastionprobe ≤ 0.17, bastiontrace ≤ 0.3 | agentbastion, bastiongate | ✅ **consumer-locked** (v1 still loads) |
| trace schema (tool-call JSONL) | bastionprobe run output | bastiontrace analyze input | ✅ **locked** |
| `policy.yaml` **v2** (`policy_version: 2`: tool policy + detector modes) | `harden` in bastionsupply ≥ 0.8, bastionprobe ≥ 0.18, bastiontrace ≥ 0.4 | agentbastion ≥ 0.12, bastiongate ≥ 0.8 | ✅ **locked** (all producers + both consumers) |

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

## policy.yaml v1 (tool policy) — consumer-locked

The `harden` producers emitted v1 up to the versions in the table; they now emit v2
(below). v1 files still load unchanged, so the consumers keep the v1 golden
(`policy_golden.yaml`, bastionsupply 0.7's output) as a regression lock.

- **Former producer locks (now v2, below):**
  - `bastionsupply/tests/test_policy_contract.py` freezes `bastionsupply harden`'s
    output of a fixed server fixture against `tests/fixtures/policy_golden.yaml`
    (the canonical byte-golden — carries default/allow/deny/rate_limits + per-tool
    `tools:`/`scrub_results`).
  - `bastionprobe/tests/test_policy_contract.py` and
    `bastiontrace/tests/test_policy_contract.py` shape-lock their `harden._policy_yaml`
    (the default-allow + deny-list subset of the same vocabulary).
- **Consumer locks (both load the byte-identical golden):**
  - `agentbastion/tests/test_policy_contract.py` — default/allow/deny/rate_limits
    parse + enforce (deny blocks, allow passes, rate limit caps at 10).
  - `bastiongate/tests/test_policy_contract.py` — default/allow/deny + the per-tool
    `tools:`/`scrub_results` overrides agentbastion ignores but gate honors.
- **Frozen.** No producer emits v1 any more, so nothing regenerates this golden; the
  agentbastion + bastiongate copies stay byte-identical.

### skill verdict — v2 `skill:` block, producer-locked

`bastionskill harden` (≥ 0.4) emits a `policy_version: 2` file whose only block is
the reserved `skill:` block (`skills:` → per-skill `verdict` / `reasons` /
`block_capabilities`). It has **no top-level `default:`**, so agentbastion and
bastiongate load it as valid v2 with no tool policy and ignore `skill:` (up to 0.3 it
carried `default: allow`, which loaded as an allow-every-tool policy). No suite tool
reads the verdict yet; it is for skill loaders and CI. **Producer-only lock:**
`bastionskill/tests/test_policy_contract.py` freezes its output of a fixed report
against `tests/fixtures/skill_policy_golden.yaml` and asserts no tool-policy keys
appear (only `malice`/`shadow` findings trip the verdict). Add a consumer lock the
day a tool reads it.

### memory harden — agentbastion corpus rows

`bastionmemory harden` (≥ 0.2) emits `injections.jsonl` rows `{text, label,
category}` (category `memory_<check>`) for its high-risk (`malice`) entries only: the
same row shape bastionprobe/bastiontrace `harden` emit, which agentbastion loads as
`SemanticDetector` templates. Plain directives are left out (legitimate user rules
would become false positives). Locked by `bastionmemory/tests/test_harden.py`.

## policy.yaml v2 — locked (all producers + both consumers)

`policy_version: 2` adds per-detector modes (`off | shadow | enforce`, the kill
switch) to the tool policy and is validated **strictly**: anything a consumer does
not understand fails at load/startup, never silently.

- **Shape.** A frozen shared core (`policy_version`, `default`, `allow`, `deny`,
  `rate_limits`, `detectors`) plus one block per tool (`gate:`, `bastion:`,
  `supply:`, `skill:`). Each tool validates the core and **its own** block, and never
  looks inside another tool's block, so one tool can add a knob without breaking the
  others. Changing the core is a suite-wide BREAKING change.
- **Tool policy.** `default` is required only alongside `allow` / `deny` /
  `rate_limits`; `default: allow` with a non-empty allow list is rejected (unlisted
  tools are denied whenever an allow list exists).
- **Detector IDs are namespaced.** `bastion.*` (agentbastion's detectors) and
  `custom.*` (a user's own signatures) are run by agentbastion. In bastiongate they
  reach agentbastion deep-inspect and require `gate: {result_inspector: agentbastion}`.
  bastiongate has **no** `gate.*` IDs (its `gate:` knobs are the modes:
  `scan_*: false` = off, `on_*: warn` = shadow) and rejects `gate.*` lines.
  `supply.*` / `skill.*` are reserved for those tools and ignored by the others.
- **Per-consumer differences (by design).** bastiongate accepts and ignores
  `rate_limits` (no rate limiter). A detectors-only file installs no tool policy in
  agentbastion and allows every tool in bastiongate: the same outcome.
- **Version floors.** Older consumers load a v2 file without error but drop what they
  don't know (agentbastion < 0.12 ignores `detectors:`; bastiongate < 0.8 also ignores
  the whole `gate:` block). `bastionsupply doctor --policy FILE` (≥ 0.7) warns about
  installed consumers below the floor.
- **Consumer locks (both load the byte-identical golden `tests/fixtures/policy_v2_golden.yaml`):**
  - `agentbastion/tests/test_policy_v2_contract.py`: exact parse (foreign namespaces
    dropped) + tool decisions + kill switch / shadow / still-enforced detectors.
  - `bastiongate/tests/test_policy_v2_contract.py`: exact parse (`gate:` knobs and
    defaults, `bastion.*` modes forwarded) + tool decisions + the same detector
    decisions through deep-inspect.
- **Producer locks (`harden` emits v2):**
  - `bastionsupply/tests/test_policy_contract.py` freezes `bastionsupply harden`'s
    output of a fixed server fixture against `tests/fixtures/policy_v2_harden_golden.yaml`
    (core `default`/`allow`/`deny`/`rate_limits` + `gate: {tools: {…: {scrub_results: true}}}`).
    agentbastion and bastiongate keep byte-identical copies, and their
    `tests/test_policy_contract.py` run the same decisions on it and on the v1 golden.
  - `bastionprobe/tests/test_policy_contract.py` and
    `bastiontrace/tests/test_policy_contract.py` shape-lock `policy_version: 2` +
    default-allow + deny list (`deny: []` when empty). Core only, so every consumer
    version reads them.
  - bastionsupply's output needs bastiongate ≥ 0.8 for the `gate:` overrides; older
    gates keep allow/deny and drop the scrub overrides (`doctor --policy` warns).
- **Regeneration is deliberate.** Change a golden in every repo that holds it in the
  same change (`policy_v2_golden.yaml`: agentbastion + bastiongate;
  `policy_v2_harden_golden.yaml`: bastionsupply + agentbastion + bastiongate), keep the
  copies byte-identical (compare sha256), read the diff.
- **v1 caveat.** In v1 a file **without** `default:` is `deny` in agentbastion but
  `allow` in bastiongate. v2 sidesteps this by requiring `default:` whenever tool
  lists are present; v1 behavior is unchanged.

## trace schema — locked (bastionprobe → bastiontrace)

- **Producer lock:** `bastionprobe/tests/test_trace_contract.py` asserts
  `AttackResult` still exposes every attribute bastiontrace's `from_bastionprobe`
  adapter duck-types (payload_id, canary, forbidden_tool, category, tactic,
  payload_text, landed, tool_calls, reply_excerpt).
- **Consumer lock:** `bastiontrace/tests/test_trace_schema_contract.py` freezes the
  produced trace JSONL against `tests/fixtures/probe_trace_golden.jsonl` and asserts
  `analyze` of that golden is stable (LANDED, inject seq 1 → action landing seq 2).
- **Regeneration is deliberate.** Regenerate the golden from the canonical probe
  result, read the diff. A schema-version bump (the header `v`) is a deliberate
  golden change, not a silent one.

## Rule

Golden fixtures are only as good as the care taken regenerating them. Regenerate
deliberately, read the diff, never "update golden to make CI pass" (PRP Risks).
