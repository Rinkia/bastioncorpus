# Changelog

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
