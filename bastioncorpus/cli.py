"""bastioncorpus CLI: inspect the corpus and export it into each tool's format.

    bastioncorpus list [--category C] [--lang L] [--label malicious|benign]
    bastioncorpus stats
    bastioncorpus validate
    bastioncorpus export --format probe|semantic|trace [--out FILE]

`export` writes the exact file the target tool loads:
    bastioncorpus export --format probe    --out payloads.jsonl     # bastionprobe
    bastioncorpus export --format trace    --out signatures.jsonl   # bastiontrace
    bastioncorpus export --format semantic --out corpus.jsonl       # agentbastion
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from typing import Optional

from . import __version__
from .adapters import to_probe, to_semantic, to_trace
from .schema import Injection, load_corpus


def _filter(rows: list[Injection], category: Optional[str], lang: Optional[str],
            label: Optional[str]) -> list[Injection]:
    return [
        r for r in rows
        if (category is None or r.category == category)
        and (lang is None or r.lang == lang)
        and (label is None or r.label == label)
    ]


def _cmd_list(args, rows: list[Injection]) -> int:
    rows = _filter(rows, args.category, args.lang, args.label)
    for r in rows:
        tool = f" -> {r.forbidden_tool}" if r.forbidden_tool else ""
        print(f"{r.id:20} {r.label:9} {r.category:22} {r.lang} [{r.check}{tool}]  {r.stripped()[:60]}")
    print(f"\n{len(rows)} rows", file=sys.stderr)
    return 0


def _cmd_stats(args, rows: list[Injection]) -> int:
    by_cat = collections.Counter(r.category for r in rows)
    by_lang = collections.Counter(r.lang for r in rows)
    by_label = collections.Counter(r.label for r in rows)
    print(f"corpus v{__version__}: {len(rows)} rows")
    print(f"  label:    {dict(by_label)}")
    print(f"  lang:     {dict(by_lang)}")
    print(f"  category: {dict(by_cat)}")
    print(f"  fireable (probe): {len(to_probe(rows))}   signatures (trace): {len(to_trace(rows))}")
    return 0


def _cmd_validate(args, rows: list[Injection]) -> int:
    # load_corpus already validated + checked unique ids; reaching here = pass.
    print(f"ok: {len(rows)} rows valid, ids unique")
    return 0


def _write(obj, out: Optional[str], jsonl: bool) -> None:
    lines = (json.dumps(o, ensure_ascii=False) for o in obj) if jsonl else [json.dumps(obj, ensure_ascii=False, indent=2)]
    text = "\n".join(lines) + "\n"
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _cmd_export(args, rows: list[Injection]) -> int:
    if args.format == "probe":
        _write(to_probe(rows), args.out, jsonl=True)
    elif args.format == "trace":
        _write(to_trace(rows), args.out, jsonl=True)
    elif args.format == "semantic":
        # agentbastion loads corpus.jsonl (rows); templates go to stderr-note or --templates
        bundle = to_semantic(rows)
        if args.templates:
            _write(bundle["templates"], args.templates, jsonl=True)
        _write(bundle["corpus"], args.out, jsonl=True)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="bastioncorpus", description=__doc__)
    p.add_argument("--version", action="version", version=f"bastioncorpus {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ls = sub.add_parser("list", help="list rows")
    ls.add_argument("--category")
    ls.add_argument("--lang")
    ls.add_argument("--label", choices=["malicious", "benign"])

    sub.add_parser("stats", help="counts by category/lang/label")
    sub.add_parser("validate", help="validate schema + unique ids")

    ex = sub.add_parser("export", help="export into a consumer's format")
    ex.add_argument("--format", required=True, choices=["probe", "semantic", "trace"])
    ex.add_argument("--out", help="output file (default: stdout)")
    ex.add_argument("--templates", help="semantic only: also write intent templates here")

    args = p.parse_args(argv)
    try:
        rows = load_corpus()
    except Exception as e:  # noqa: BLE001 - surface a clean message, not a traceback
        print(f"corpus error: {e}", file=sys.stderr)
        return 2

    return {
        "list": _cmd_list, "stats": _cmd_stats,
        "validate": _cmd_validate, "export": _cmd_export,
    }[args.cmd](args, rows)


if __name__ == "__main__":
    raise SystemExit(main())
