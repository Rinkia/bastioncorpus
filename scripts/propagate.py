#!/usr/bin/env python3
"""Propagate a bastioncorpus release to its dependents (PRP §1.2).

bastioncorpus is the root dependency. When it releases, each dependent needs its
`bastioncorpus>=` floor bumped, its tests re-run, and — only on green — a PR opened.

Release order (documented so a human can veto any step):

    bastioncorpus
      -> bastionsupply, bastionprobe, bastiontrace, agentbastion   (direct floor bump)
      -> bastiongate      (via bastionsupply — bump its bastionsupply floor separately)
      -> bastionskill     (ONLY via the optional [prompt] extra — usually skipped)

SAFETY (PRP Risks): this is supply-chain sensitive. It is **dry-run by default**,
it **opens PRs for human merge**, and it **never tags a release**. `--execute` only
creates branches + PRs; a human reviews and merges, then tags the Release by hand
(the OIDC workflow publishes). Never wire auto-tagging into this script.

Assumes dependents are checked out as sibling directories (override with --root).
Requires `gh` on PATH for --execute.

    python scripts/propagate.py                 # dry run: show the plan
    python scripts/propagate.py --execute        # open floor-bump PRs (needs gh)
    python scripts/propagate.py --only bastionprobe bastiontrace
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from bastioncorpus import __version__ as CORPUS_VERSION

# dependent dir (as checked out) -> (default branch, dependency package name to bump)
# The dependency name is what appears in the dependent's pyproject, not its own name.
DEPENDENTS: dict[str, tuple[str, str]] = {
    "bastionsupply": ("master", "bastioncorpus"),
    "agentprobe": ("master", "bastioncorpus"),   # dir agentprobe / pkg bastionprobe
    "bastiontrace": ("master", "bastioncorpus"),
    "agentfirewall": ("main", "bastioncorpus"),   # dir agentfirewall / pkg agentbastion
    # bastiongate bumps its bastionsupply floor, not bastioncorpus directly:
    "bastiongate": ("master", "bastionsupply"),
    # bastionskill only depends on the corpus via the optional [prompt] extra — skip by default.
}


def bump_floor(pyproject_text: str, dep: str, new_version: str) -> str:
    """Raise `dep>=X` to `dep>=new_version` in a pyproject's dependency lines.

    Only bumps when the existing floor is lower; leaves an already-current or
    higher floor untouched. Pure string transform — the unit-testable core.
    """
    pattern = re.compile(rf'("{re.escape(dep)})>=([0-9][0-9A-Za-z.\-]*)"')

    def repl(m: re.Match) -> str:
        current = m.group(2)
        if _version_key(current) >= _version_key(new_version):
            return m.group(0)
        return f'{m.group(1)}>={new_version}"'

    return pattern.sub(repl, pyproject_text)


def _version_key(v: str) -> tuple:
    """Coarse PEP440-ish key: numeric release segments only, good enough to compare
    `0.2.0` vs `0.2.1`. Pre/post/dev suffixes are ignored for the >= comparison."""
    nums = re.findall(r"\d+", v.split("+")[0])
    return tuple(int(n) for n in nums) if nums else (0,)


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def propagate_one(root: Path, dirname: str, branch: str, dep: str,
                  new_version: str, execute: bool) -> str:
    repo = root / dirname
    pyproject = repo / "pyproject.toml"
    if not pyproject.exists():
        return f"SKIP {dirname}: no pyproject at {pyproject}"

    original = pyproject.read_text(encoding="utf-8")
    bumped = bump_floor(original, dep, new_version)
    if bumped == original:
        return f"OK   {dirname}: {dep} floor already >= {new_version}, nothing to do"

    if not execute:
        return f"PLAN {dirname}: bump {dep}>= to {new_version}, run tests, open PR"

    work_branch = f"chore/bump-{dep}-{new_version}"
    for cmd in (["git", "checkout", branch], ["git", "pull", "--ff-only"],
                ["git", "checkout", "-B", work_branch]):
        r = _run(cmd, repo)
        if r.returncode != 0:
            return f"FAIL {dirname}: `{' '.join(cmd)}` -> {r.stderr.strip()}"

    pyproject.write_text(bumped, encoding="utf-8")

    tests = _run(["python", "-m", "pytest", "-q"], repo)
    if tests.returncode != 0:
        return (f"FAIL {dirname}: tests red after bump — NOT opening PR.\n"
                f"{tests.stdout[-800:]}")

    _run(["git", "add", "pyproject.toml"], repo)
    _run(["git", "commit", "-m",
          f"chore: bump {dep} floor to {new_version}"], repo)
    push = _run(["git", "push", "-u", "origin", work_branch], repo)
    if push.returncode != 0:
        return f"FAIL {dirname}: push -> {push.stderr.strip()}"
    pr = _run(["gh", "pr", "create", "--fill",
               "--title", f"chore: bump {dep} floor to {new_version}",
               "--body", f"Automated floor bump after {dep} {new_version}. "
                         f"Tests green locally. Human review + merge, then tag a "
                         f"patch Release to publish. (PRP §1.2)"], repo)
    if pr.returncode != 0:
        return f"FAIL {dirname}: gh pr create -> {pr.stderr.strip()}"
    return f"PR   {dirname}: {pr.stdout.strip()}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2],
                    help="directory holding the dependent repos (default: parent of bastioncorpus)")
    ap.add_argument("--only", nargs="*", help="limit to these dependent dirs")
    ap.add_argument("--execute", action="store_true",
                    help="actually create branches + open PRs (default: dry run)")
    args = ap.parse_args(argv)

    targets = args.only or list(DEPENDENTS)
    print(f"bastioncorpus {CORPUS_VERSION} -> propagate to: {', '.join(targets)}")
    print(f"root: {args.root}  mode: {'EXECUTE' if args.execute else 'DRY RUN'}\n")

    for dirname in targets:
        if dirname not in DEPENDENTS:
            print(f"SKIP {dirname}: not a known dependent")
            continue
        branch, dep = DEPENDENTS[dirname]
        new_ver = CORPUS_VERSION if dep == "bastioncorpus" else _latest_floor(dep, args.root)
        print(propagate_one(args.root, dirname, branch, dep, new_ver, args.execute))

    if not args.execute:
        print("\n(dry run -- re-run with --execute to open PRs; never auto-tags)")
    return 0


def _latest_floor(dep: str, root: Path) -> str:
    """For indirect deps (e.g. bastiongate -> bastionsupply), read the dep's own
    installed version so we bump gate's floor to whatever supply just shipped."""
    try:
        from importlib.metadata import version
        return version(dep)
    except Exception:  # noqa: BLE001
        return CORPUS_VERSION


if __name__ == "__main__":
    raise SystemExit(main())
