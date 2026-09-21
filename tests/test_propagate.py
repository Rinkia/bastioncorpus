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
