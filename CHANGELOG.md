# Changelog

## 0.3.0 - 2026-09-21

Added 2026 attack families (BASTION_INTEL.md §C). **128 -> 145 rows** (95
malicious / 50 benign traps; en/it/de/fr/es).

- **CoT-forgery / role-confusion** (`cot-*`, `jailbreak_persona`): text posing as
  the assistant's own reasoning to conclude the rules do not apply. Defense rows
  (feed agentbastion's SemanticDetector — closes the named recall gap). Multi-lingual.
- **Compaction-summary injection** (`cmp-*`, `instruction_override`): standing
  orders planted in the session summary layer. New `channel: "memory"` — inert for
  probe/trace (they only fire `tool_output`), feeds agentbastion; sets up
  bastiontrace's future memory inject-point.
- **Repo-doc / legal-filing / dependency-metadata** (`ind-doc-*`, `ind-legal-*`,
  `ind-depmeta-*`, `indirect_injection`): indirect injection via files the agent
  reads (CONTRIBUTING.md, legal PDFs, package metadata). Fireable (flow to probe/trace).
- Benign traps (`benign_reasoning`, `benign_docnote`, `benign_summary`) so the new
  families don't inflate false positives.

Golden contract fixtures regenerated deliberately (additive only). Minor bump; run
`scripts/propagate.py` to bump dependents.

## 0.2.1 - 2026-09-11

- Align two indirect exfil payloads' `tactic` to bastionprobe's established
  taxonomy (`egress-overt`), restoring tactic-grid parity for downstream tools.

## 0.2.0 - 2026-09-11

Folded the three tools' legacy inline corpora into the canonical dataset via
`tools/import_legacy.py` (reproducible, in-repo). **24 -> 128 rows** (81
malicious / 47 benign traps; en/it/de/fr/es), a superset of every tool's prior
data, so the tools can now depend on bastioncorpus with no coverage regression.

- bastionprobe's 16 payloads, agentbastion's 80-row benchmark corpus + 24-row
  honest set, all mapped to the canonical schema.
- Lang prefixes (`de_`, `fr_`, …) normalized into the `lang` field; `fp_trap_*`
  / `support` / `roleplay` / `codegen` / `creative` mapped to `benign_*`;
  `jailbreak` -> `jailbreak_persona`, `injection` -> `direct_injection`.
- Deduped by canary-stripped text. No API change.

## 0.1.0 - 2026-09-11

Initial release. The shared prompt-injection corpus for the bastion trilogy.

- Canonical `injections.jsonl` corpus: malicious payloads across the injection
  taxonomy (direct/indirect/override/jailbreak/exfiltration/delimiter/obfuscation)
  plus benign false-positive traps, with multilingual rows.
- `Injection` schema + validating `load_corpus()` loader (unique-id enforced).
- Three format adapters: `to_probe` (bastionprobe payloads), `to_semantic`
  (agentbastion SemanticDetector templates + benchmark corpus), `to_trace`
  (bastiontrace canary-stripped signatures).
- CLI: `list`, `stats`, `validate`, `export --format probe|semantic|trace`.
- No runtime dependencies. OIDC PyPI publishing on GitHub Release.
