---
type: "query"
date: "2026-09-13T18:42:12.660265+00:00"
question: "ShellSpec locale skip allowlist developer setup module_durations_spec pfblockerng_adr26_locale_spec shard_modules_spec check_skip_allowlist"
contributor: "graphify"
outcome: "useful"
source_nodes: ["module_durations_spec.sh", "pfblockerng_adr26_locale_spec.sh", "shard_modules_spec.sh", "check_skip_allowlist.py"]
---

# Q: ShellSpec locale skip allowlist developer setup module_durations_spec pfblockerng_adr26_locale_spec shard_modules_spec check_skip_allowlist

## Answer

Narrowed to tests/test_check_skip_allowlist.py and tests/skip-allowlist.txt; the three locale-dependent ShellSpec skips (module_durations_spec.sh:192, pfblockerng_adr26_locale_spec.sh:163, shard_modules_spec.sh:657) self-skip on a minimal C/C.utf8/POSIX-only host and are legitimate per the existing local-skip-superset allowlist pattern (testing.md:68-70, skip-allowlist.txt:10-15); fixed by adding three reason-carrying allowlist entries plus two regression tests in tests/test_check_skip_allowlist.py (issue #3282).

## Outcome

- Signal: useful

## Source Nodes

- module_durations_spec.sh
- pfblockerng_adr26_locale_spec.sh
- shard_modules_spec.sh
- check_skip_allowlist.py