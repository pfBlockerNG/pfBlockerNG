<?php
/*
 * pfblockerng_extra.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file is used to 'include functions' not yet merged into pfSense

// logger() and localize_text() are pfSense-core helpers (src/etc/inc/util.inc)
// on pfSense Plus / master, but absent from released pfSense CE <= 2.8.1. Define
// fallbacks ONLY when core does not provide them, so this package runs on both:
// where core has them (Plus/master) these definitions are skipped and core wins
// unchanged; on CE 2.8.1 they fill the gap. Behaviour mirrors the core versions.
if (!function_exists('localize_text')) {
	function localize_text(...$args) {
		$arg0_len = strlen($args[0]);
		if (($arg0_len > 0) && ($arg0_len < 4096)) {
			$args[0] = gettext($args[0]);
		}
		return (count($args) == 1) ? $args[0] : sprintf(...$args);
	}
}

if (!function_exists('logger')) {
	function logger(int $priority, mixed $message, ?string $prefix = null, ?int $facilities = null): void {
		$log_prefix = match ($priority) {
			LOG_EMERG	=> 'EMERGENCY',
			LOG_ALERT	=> 'ALERT',
			LOG_CRIT	=> 'CRITICAL',
			LOG_ERR		=> 'ERROR',
			LOG_WARNING	=> 'WARNING',
			LOG_NOTICE	=> 'NOTICE',
			LOG_INFO	=> 'INFO',
			LOG_DEBUG	=> 'DEBUG',
			default		=> 'DEBUG'
		};
		if (isset($prefix)) {
			$log_prefix .= ' [' . gettext($prefix) . ']';
		}
		$pri = isset($facilities) ? ($priority | $facilities) : $priority;
		if (is_string($message)) {
			$message = str_replace(PHP_EOL, '', $message);
			$log_string = (strlen($message) > 0) ? "{$log_prefix} {$message}" : $log_prefix;
		} else {
			$log_string = $log_prefix . ' ' . str_replace(PHP_EOL, '', var_export($message, TRUE));
		}
		syslog($pri, $log_string);
	}
}
?>
