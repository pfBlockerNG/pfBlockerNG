"""Benchmark harness bootstrap.

The suite is fully self-contained: it compares two frozen reference matchers —
the flat dicts (`_baseline.py`) and the rejected domain trie (`_trie.py`) — and
no longer imports the production `pfb_unbound` module. This keeps the benchmark
of record stable across the ADR-01 roll-back. Only job here: make the sibling
helper modules importable regardless of the invocation directory.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
