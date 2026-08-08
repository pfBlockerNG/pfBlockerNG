# Python — language context

Scope: writing or changing Python. Load when: any touched `*.py` file.

- Indent **4 spaces**; target Python 3.11+; `from __future__ import annotations`. Type-hint
  new functions; no bare `except:` (`except Exception` minimum).
- `pfb_unbound.py` runs in Unbound's Python loader — **stdlib only, no external deps**.
- **No direct Python interpreter invocation ON the appliance.** No `python`/`python3` symlink
  exist. Appliance consumers call `/usr/local/pkg/pfblockerng/pfb_python.sh` — only resolver
  allowed to build exact versioned path from installed package dependency.
  `pfb_python_interpreter()` delegates to it for compatibility + test probes. Else drive box
  via PHP (`php`/`pfSsh.php`/`h.php_eval`) or POSIX sh.
  Enforced by `scripts/check_appliance_python.py` (pre-commit + CI). Bare `python3` in
  dev/CI tooling under `scripts/` fine — names developer's interpreter.
- **Content hashing:** Python side use `hashlib.md5` for own self-comparisons only,
  never cross-language digest (PHP/shell use `xxh128`) — ADR-42 policy; see
  architecture-notes "Change detection / content hashing".
- **No fixed-time waits to coordinate concurrency (issue #456).** Use synchronisation
  primitive (`threading.Event`/`Condition`/`Semaphore`, `queue.Queue`); timeout is
  deadlock guard only, must **raise loudly**, never return silently (exemplar
  `_Harness.wait_builds`, `tests/test_adr10_watcher.py`). Poll = last resort against
  unsignalable production code.
- Unbound inject API symbols (`log_info`, `RR_TYPE_*`, …) as runtime globals; declared once
  in `stubs/python/unboundmodule.py` (suite copy them onto `builtins`,
  `tests/conftest.py`). Add new injected symbol there.
