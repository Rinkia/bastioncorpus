# bastioncorpus

**The shared prompt-injection corpus for the bastion trilogy.** One canonical,
versioned dataset — attack strings, false-positive traps, taxonomy — that all
three tools pull from instead of each rolling its own.

| tool | role | depends on bastioncorpus since | reads bastioncorpus as |
|------|------|-------------------------------|------------------------|
| [agentbastion](https://github.com/Rinkia/agentbastion) | **prevent** | **v0.9.0** | SemanticDetector intent templates |
| [bastionprobe](https://github.com/Rinkia/bastionprobe) | **attack** | **v0.17.0** | fireable payloads (`load_payloads`) |
| [bastiontrace](https://github.com/Rinkia/bastiontrace) | **investigate** | **v0.2.0** | injection signatures (`analyzer._PATTERNS`) |

All three take `bastioncorpus>=0.2.0` as a dependency and keep a built-in
fallback, so one source of truth feeds prevent, attack, and investigate.

Same taxonomy, three directions. **128 rows** (81 malicious payloads / 47
benign false-positive traps; `en`/`it`/`de`/`fr`/`es`). No LLM, no cloud, no
dependencies — pure data plus a loader and three format adapters.

## Install

```bash
pip install bastioncorpus
```

## Use

Inspect:

```bash
bastioncorpus stats
bastioncorpus list --category indirect_injection
bastioncorpus validate
```

Export into each tool's native file:

```bash
bastioncorpus export --format probe    --out payloads.jsonl     # bastionprobe loads this
bastioncorpus export --format trace    --out signatures.jsonl   # bastiontrace matches these
bastioncorpus export --format semantic --out corpus.jsonl --templates templates.jsonl  # agentbastion
```

From Python:

```python
from bastioncorpus import load_corpus, to_probe, to_semantic, to_trace

rows = load_corpus()
payloads   = to_probe(rows)       # fireable attack payloads
semantic   = to_semantic(rows)    # {"templates": [...], "corpus": [...]}
signatures = to_trace(rows)       # canary-stripped substring signatures
```

## Schema

One row per attack (or benign trap). `text` may carry a single `{canary}`
placeholder the attack runner fills per run; defense and forensics adapters
strip it.

| field | meaning |
|-------|---------|
| `id` | stable unique id |
| `text` | the string (optional `{canary}` slot) |
| `category` | canonical class: `direct_injection`, `indirect_injection`, `instruction_override`, `jailbreak_persona`, `exfiltration`, `delimiter_injection`, `obfuscation`, or `benign_*` |
| `label` | `malicious` \| `benign` (benign = false-positive trap, to measure over-blocking) |
| `lang` | language code (`en`, `it`, `de`, …) — never baked into `category` |
| `tactic` | framing tactic (`authority`, `data-field`, `egress-legit`, …) |
| `channel` | where planted (`tool_output`, `user_input`) |
| `check` | how a hit is scored (`canary`, `tool`, `none`) |
| `forbidden_tool` | tool a `check=tool` payload tries to trigger |
| `severity` | 0–5 |
| `intent` | plain-language restatement, for semantic templates |

Direct/`user_input` rows are defense and forensics material; only
`tool_output` payloads with a scoring `check` are fired as attacks.

## Why

Before this, each tool hand-maintained overlapping payload lists that drifted
apart. bastioncorpus makes one of them authoritative: fix a payload here, every
tool in the trilogy gets it on the next export.

## License

MIT
