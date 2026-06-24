<?php
/**
 * pfSense supplemental stubs — IDE/PHPStan static analysis only.
 *
 * Hand-maintained. Holds pfSense functions that pfBlockerNG calls on its
 * supported target (CE 2.8) but which are ABSENT from the pinned stub-source
 * version used by scripts/update-pfsense-stubs.py (currently 2.7.2 — the newest
 * public pfSense source; Netgate's GitHub mirror has no RELENG_2_8_0 ref).
 *
 * The generator never overwrites this file (it is not a STUB_MODULES output),
 * and its symbols seed the generator's cross-file dedup set. Drop an entry once
 * the stub-source version catches up and the generator provides the function.
 *
 * Not shipped in release archives (stubs/ is dev-only).
 */

// @codingStandardsIgnoreFile

/** Read and parse the pfSense configuration (config.lib.inc; pfSense CE 2.8+). */
function config_read_file(bool $use_backup = false, bool $use_cache = true): array {}

/** Return true if the current logged-in user may access $page, per their privilege match list (priv.inc). */
function isAllowedPage($page) {}
