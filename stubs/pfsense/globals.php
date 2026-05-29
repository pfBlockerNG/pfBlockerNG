<?php
/**
 * pfSense global variable stubs — IDE static analysis only (Intelephense).
 *
 * Manually maintained. Run scripts/update-pfsense-stubs.py to regenerate
 * the function stubs; this file requires manual curation because the global
 * array shapes are not derivable by automated parsing.
 *
 * Reference: https://github.com/pfsense/pfsense/blob/RELENG_2_8_0/src/etc/inc/globals.inc
 */

// @codingStandardsIgnoreFile

/**
 * pfSense system globals: filesystem paths, product name, platform info, etc.
 * Populated at boot time from /etc/inc/globals.inc.
 *
 * Commonly used keys:
 *   vardb_path  — /var/db
 *   varlog_path — /var/log
 *   etc_path    — /etc
 *   tmp_path    — /tmp
 *   varetc_path — /var/etc
 *   conf_path   — /cf/conf
 *   product_name  — pfSense
 *   product_label — pfSense
 *   platform    — pfSense (or nanobsd, etc.)
 *   debug       — bool
 *
 * @var array<string, mixed> $g
 */
global $g;
$g = [];

/**
 * Live pfSense configuration mirroring /cf/conf/config.xml parsed into PHP.
 * Read with config_get_path(); write back with write_config().
 *
 * @var array<string, mixed> $config
 */
global $config;
$config = [];

/**
 * Registered privilege definitions, keyed by privilege identifier string.
 * Populated by privilege .inc files such as etc/inc/priv/pfblockerng.priv.inc.
 *
 * @var array<string, array{name: string, descr: string, match: list<string>}> $priv_list
 */
global $priv_list;
$priv_list = [];
