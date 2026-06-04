"""Web-UI test tier for the ADR-04 live-VM smoke harness (ADR-14).

This subpackage adds authenticated webConfigurator coverage ON TOP of the
ADR-04 smoke VM (``tests.smoke.conftest.smoke_vm``). Like the rest of
``tests/smoke``, it is DESELECTED from the default ``python -m pytest`` run
(``pyproject.toml`` ``addopts = "... --ignore=tests/smoke"``) and is collected
only by the smoke/ui workflow, e.g.::

    python -m pip install -r tests/smoke/requirements.txt
    python -m pytest tests/smoke -m ui_render --override-ini="addopts="

Phase 1 (this commit) ships only the reusable authenticated session helper
(:mod:`tests.smoke.ui.webui`) and a ``ui_render``-marked test that pins the
login contract on the live box. Later phases build the render sweep
(``ui_render``), functional flows (``ui_e2e``), and the browser tier
(``ui_browser``) on top of it.
"""

from __future__ import annotations
