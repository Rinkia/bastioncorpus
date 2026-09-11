"""bastioncorpus - the shared prompt-injection corpus for the bastion trilogy.

One canonical, versioned dataset that all three tools pull from:
agentbastion (prevent), bastionprobe (attack), bastiontrace (investigate).

    from bastioncorpus import load_corpus, to_probe, to_semantic, to_trace
    rows = load_corpus()
    payloads = to_probe(rows)
"""

from __future__ import annotations

from .adapters import to_probe, to_semantic, to_trace
from .schema import Injection, load_corpus

__version__ = "0.1.0"
__all__ = ["load_corpus", "Injection", "to_probe", "to_semantic", "to_trace", "__version__"]
