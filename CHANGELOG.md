# Changelog

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
