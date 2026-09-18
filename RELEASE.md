# Release checklist — bastioncorpus (bastioncorpus)

Codifies the by-hand release we did for bastionskill so every tool ships the same way.
Publishing is automatic: pushing a **GitHub Release** tag triggers the OIDC publish workflow.

> **This is the root package.** After releasing, run the propagation script
> (`python scripts/propagate.py`) to open version-bump PRs in every dependent,
> and refresh `suite.json` in bastion-site. See PRP §1.2.

## Pre-flight

- [ ] Working tree clean, on the default branch, up to date with origin.
- [ ] CI green on the matrix (Python 3.10–3.13).
- [ ] `pytest tests/test_contract_golden.py` green — adapter output still matches the golden fixtures. **If it changed, that change propagates to every consumer — regenerate deliberately** (`python scripts/regen_golden.py`) and read the diff, never edit goldens to make CI pass.

## Bump

- [ ] Bump `__version__` in the package `__init__.py` **and** `version` in `pyproject.toml` (keep them equal).
- [ ] Update `CHANGELOG.md` (or the README changelog section) with the new version + date.

## Build & verify locally

```bash
python -m build
twine check dist/*
```

- [ ] `twine check` passes (README renders, metadata valid).

## Publish

- [ ] Tag + create a GitHub Release `v<version>` — the `publish.yml` OIDC workflow builds and uploads to PyPI.
- [ ] Confirm on PyPI: `pip install -U bastioncorpus` pulls the new version.

## Propagate version truth (PRP G5)

- [ ] Update `suite.json` in the **bastion-site** repo (or let the build-time `scripts/fetch-github-stats.mjs` re-fetch), so bastiondefense.dev never shows a stale version.
- [ ] `bastionsupply doctor` reports the new version as latest.
