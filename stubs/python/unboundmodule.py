# Development/type-checking stand-in for Unbound's embedded ``unboundmodule``.
#
# Unbound's pythonmod injects these symbols directly into a script's module
# globals at runtime; the script never imports this module in production
# (release archives ship only ``src/``). This stub exists so that static type
# checkers (Pylance, mypy) can resolve the
# ``if TYPE_CHECKING: from unboundmodule import ...`` block in
# dns_proxy/pfb_upstream_observer.py, the one script Unbound still loads. It
# carries only the names that block imports.
from __future__ import annotations

from typing import Any

__all__ = [
    "MODULE_ERROR",
    "MODULE_EVENT_MODDONE",
    "MODULE_EVENT_NEW",
    "MODULE_EVENT_PASS",
    "MODULE_FINISHED",
    "MODULE_WAIT_MODULE",
    "log_warn",
    "register_inplace_cb_query_response",
]

# Module events: values of the C enum ``module_ev`` in util/module.h.
MODULE_EVENT_NEW = 0  # New query arrived; first module to handle it
MODULE_EVENT_PASS = 1  # Query passed from a previous module for further processing
MODULE_EVENT_MODDONE = 5  # Downstream module finished; resume this module

# Module external states, set on qstate.ext_state[id] inside operate(): the C enum
# positions of ``module_ext_state`` in util/module.h (initial 0, wait_reply 1,
# wait_module 2, restart_next 3, wait_subquery 4, error 5, finished 6).
MODULE_WAIT_MODULE = 2  # Module is waiting for another module to finish
MODULE_ERROR = 5  # Module encountered an error; abort query processing
MODULE_FINISHED = 6  # Module completed successfully; pass to next module


def log_warn(msg: object) -> None:
    """Log a warning message to Unbound's log at level WARN."""
    ...


def register_inplace_cb_query_response(*_: Any) -> bool:
    """Register a callback invoked after a query RESPONSE arrives from an upstream
    server, BEFORE Unbound finalises the client reply. Returns True on success."""
    ...
