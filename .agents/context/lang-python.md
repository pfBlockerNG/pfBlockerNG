# Python — language context

Scope: writing or changing Python. Load when: any touched `*.py` file.

- Indent **4 spaces**; target Python 3.11+; `from __future__ import annotations`. Type-hint
  new functions; no bare `except:` (`except Exception` minimum).
- `pfb_unbound.py` runs in Unbound's Python loader — **stdlib only, no external deps**.
- **No direct Python interpreter invocation ON the appliance.** There is no
  `python`/`python3` symlink. Appliance consumers invoke
  `/usr/local/pkg/pfblockerng/pfb_python.sh`, the only resolver allowed to construct the exact
  versioned path from the installed package dependency. `pfb_python_interpreter()` delegates
  to it for compatibility and test probes. Otherwise drive the box via PHP
  (`php`/`pfSsh.php`/`h.php_eval`) or POSIX sh.
  Enforced by `scripts/check_appliance_python.py` (pre-commit + CI). Bare `python3` in
  dev/CI tooling under `scripts/` is fine — it names the developer's interpreter.
- **Content hashing:** the Python side uses `hashlib.md5` for its own self-comparisons only,
  never a cross-language digest (PHP/shell use `xxh128`) — ADR-42 policy; see
  architecture-notes "Change detection / content hashing".
- **No fixed-time waits to coordinate concurrency (issue #456).** Use a synchronisation
  primitive (`threading.Event`/`Condition`/`Semaphore`, `queue.Queue`); a timeout is a
  deadlock guard only and must **raise loudly**, never return silently (exemplar
  `_Harness.wait_builds`, `tests/test_adr10_watcher.py`). A poll is a last resort against
  unsignalable production code.
- Unbound injects API symbols (`log_info`, `RR_TYPE_*`, …) as runtime globals; declared once
  in `stubs/python/unboundmodule.py` (the suite copies them onto `builtins`,
  `tests/conftest.py`). Add a new injected symbol there.
