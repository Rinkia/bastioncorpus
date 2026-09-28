"""Unit test for the propagation floor-bump logic (PRP §1.2).

Only the pure `bump_floor` transform is tested — no git, no gh, no network.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "propagate", Path(__file__).resolve().parent.parent / "scripts" / "propagate.py"
)
propagate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(propagate)
bump_floor = propagate.bump_floor


def test_bumps_lower_floor():
    text = 'dependencies = ["bastioncorpus>=0.2.0"]'
    assert bump_floor(text, "bastioncorpus", "0.3.0") == \
        'dependencies = ["bastioncorpus>=0.3.0"]'


def test_leaves_equal_or_higher_floor_untouched():
    text = 'dependencies = ["bastioncorpus>=0.3.0"]'
    assert bump_floor(text, "bastioncorpus", "0.3.0") == text
    assert bump_floor(text, "bastioncorpus", "0.2.5") == text


def test_only_touches_the_named_dep():
    text = '["bastioncorpus>=0.2.0", "pyyaml>=6.0", "bastionsupply>=0.3.1"]'
    out = bump_floor(text, "bastionsupply", "0.4.0")
    assert "bastioncorpus>=0.2.0" in out       # untouched
    assert "pyyaml>=6.0" in out                # untouched
    assert "bastionsupply>=0.4.0" in out       # bumped


def test_multiline_pyproject():
    text = (
        "dependencies = [\n"
        '    "bastioncorpus>=0.2.0",\n'
        '    "httpx>=0.27",\n'
        "]\n"
    )
    out = bump_floor(text, "bastioncorpus", "0.2.1")
    assert '"bastioncorpus>=0.2.1"' in out
    assert '"httpx>=0.27"' in out


def test_version_key_orders_patch():
    assert propagate._version_key("0.2.10") > propagate._version_key("0.2.9")


# --- compatible-release pins (`dep==X.Y.*`), e.g. bastionsandbox -------------

def test_moves_a_stale_compatible_pin():
    text = 'dependencies = ["bastioncorpus==0.3.*"]'
    assert bump_floor(text, "bastioncorpus", "0.4.0") == 'dependencies = ["bastioncorpus==0.4.*"]'


def test_leaves_a_current_compatible_pin_untouched():
    text = 'dependencies = ["bastioncorpus==0.4.*"]'
    assert bump_floor(text, "bastioncorpus", "0.4.0") == text
    assert bump_floor(text, "bastioncorpus", "0.4.3") == text   # patch release: same X.Y


def test_never_lowers_a_compatible_pin():
    text = 'dependencies = ["bastioncorpus==0.5.*"]'
    assert bump_floor(text, "bastioncorpus", "0.4.0") == text


def test_exact_pins_are_left_alone():
    # An exact `==0.3.2` pin is a deliberate choice; moving it is a human decision.
    text = 'dependencies = ["bastioncorpus==0.3.2"]'
    assert bump_floor(text, "bastioncorpus", "0.4.0") == text


def test_compatible_pin_only_touches_the_named_dep():
    text = '["bastionprobe==0.17.*", "bastiontrace==0.3.*", "bastioncorpus==0.3.*"]'
    out = bump_floor(text, "bastioncorpus", "0.4.0")
    assert out == '["bastionprobe==0.17.*", "bastiontrace==0.3.*", "bastioncorpus==0.4.*"]'


def test_sandbox_is_a_dependent():
    assert propagate.DEPENDENTS["bastionsandbox"] == ("main", "bastioncorpus")


# --- safety: never operate on a working tree with uncommitted changes -------

def test_execute_refuses_a_dirty_working_tree(tmp_path):
    import subprocess

    repo = tmp_path / "dep"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('dependencies = ["bastioncorpus==0.3.*"]\n', encoding="utf-8")
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "."],
                ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "init"]):
        subprocess.run(cmd, cwd=repo, check=True)
    (repo / "wip.py").write_text("# someone's uncommitted work\n", encoding="utf-8")

    result = propagate.propagate_one(tmp_path, "dep", "main", "bastioncorpus", "0.4.0", execute=True)

    assert result.startswith("FAIL") and "uncommitted" in result
    assert "0.3.*" in (repo / "pyproject.toml").read_text(encoding="utf-8")  # untouched


def test_dry_run_still_reports_the_plan_on_a_dirty_tree(tmp_path):
    repo = tmp_path / "dep"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('dependencies = ["bastioncorpus==0.3.*"]\n', encoding="utf-8")
    result = propagate.propagate_one(tmp_path, "dep", "main", "bastioncorpus", "0.4.0", execute=False)
    assert result.startswith("PLAN")
