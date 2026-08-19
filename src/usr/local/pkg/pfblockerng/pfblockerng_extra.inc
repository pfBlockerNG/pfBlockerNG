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

const PFB_SETTINGS_FAMILY_RANK = ['3.3' => 0, '4.0' => 1, '4.1' => 2];

final class PfbConfig
{
	public static function read(string $key): mixed
	{
		self::assertRegistered($key);
		return config_get_path(self::path($key), NULL);
	}

	public static function write(string $key, mixed $value): void
	{
		self::assertRegistered($key);
		if ($key !== 'gen/pfb_pkg_ca_consent' || !function_exists('isAllowedPage') || !isAllowedPage('pkg_mgr_installed.php')) {
			throw new RuntimeException("PfbConfig: write of key '{$key}' denied");
		}
		self::writeValue($key, $value);
	}

	public static function writeSystem(string $key, mixed $value): void
	{
		self::assertRegistered($key);
		self::writeValue($key, $value);
	}

	private static function assertRegistered(string $key): void
	{
		if (!in_array($key, ['gen/settings_family', 'gen/pfb_pkg_ca_consent'], TRUE)) {
			throw new InvalidArgumentException("PfbConfig: key '{$key}' is not registered");
		}
	}

	private static function path(string $key): string
	{
		return match ($key) {
			'gen/settings_family' => 'installedpackages/pfblockerng/config/0/settings_family',
			'gen/pfb_pkg_ca_consent' => 'installedpackages/pfblockerng/config/0/pfb_pkg_ca_consent',
		};
	}

	private static function writeValue(string $key, mixed $value): void
	{
		if ($key === 'gen/settings_family') {
			if (!is_string($value) || !isset(PFB_SETTINGS_FAMILY_RANK[$value])) {
				throw new InvalidArgumentException('PfbConfig: invalid settings family');
			}
		} elseif (!is_string($value) || !in_array($value, ['on', ''], TRUE)) {
			throw new InvalidArgumentException('PfbConfig: invalid CA consent');
		}
		config_set_path(self::path($key), $value);
	}
}

function pfb_settings_family_current(): string
{
	$value = PfbConfig::read('gen/settings_family');
	if ($value === NULL || $value === '') {
		return '3.3';
	}
	if (!is_string($value) || !isset(PFB_SETTINGS_FAMILY_RANK[$value])) {
		throw new RuntimeException('pfBlockerNG: invalid settings family marker');
	}
	return $value;
}

function pfb_settings_family_path_is_safe(string $path, bool $directory, int $expected_owner): bool
{
	clearstatcache(TRUE, $path);
	$stat = @lstat($path);
	if ($stat === FALSE || is_link($path) || ($stat['uid'] ?? -1) !== $expected_owner) {
		return FALSE;
	}
	$type = $stat['mode'] & 0170000;
	if ($directory) {
		return $type === 0040000 && (($stat['mode'] & 0022) === 0);
	}
	return $type === 0100000 && (($stat['mode'] & 07777) === 0600);
}

function pfb_settings_family_root(): string
{
	global $pfb;
	return (string) ($pfb['dbdir'] ?? '/var/db/pfblockerng');
}

function pfb_settings_family_expected_owner(string $root): int
{
	global $pfb;
	if (isset($pfb['settings_family_expected_owner'])) {
		return (int) $pfb['settings_family_expected_owner'];
	}
	return $root === '/var/db/pfblockerng' ? 0 : (function_exists('posix_geteuid') ? posix_geteuid() : 0);
}

function pfb_settings_family_payload_is_valid(mixed $value, array &$active_references): bool
{
	if (!is_array($value)) {
		return is_scalar($value) || $value === NULL;
	}
	foreach ($value as $key => $nested) {
		$reference = ReflectionReference::fromArrayElement($value, $key);
		if ($reference !== NULL) {
			$reference_id = $reference->getId();
			if (isset($active_references[$reference_id])) {
				return FALSE;
			}
			$active_references[$reference_id] = TRUE;
			$valid = pfb_settings_family_payload_is_valid($nested, $active_references);
			unset($active_references[$reference_id]);
			if (!$valid) {
				return FALSE;
			}
		} elseif (!pfb_settings_family_payload_is_valid($nested, $active_references)) {
			return FALSE;
		}
	}
	return TRUE;
}

function pfb_settings_family_save(string $family): bool
{
	if (!isset(PFB_SETTINGS_FAMILY_RANK[$family])) {
		return FALSE;
	}
	$installed = config_get_path('installedpackages', []);
	if (!is_array($installed)) {
		return TRUE;
	}
	$owned = [];
	foreach ($installed as $section => $value) {
		if (str_starts_with((string) $section, 'pfblockerng')) {
			$owned[(string) $section] = $value;
		}
	}
	if ($owned === []) {
		return TRUE;
	}
	$active_references = [];
	if (!pfb_settings_family_payload_is_valid($owned, $active_references)) {
		return FALSE;
	}

	$root = pfb_settings_family_root();
	$expected_owner = pfb_settings_family_expected_owner($root);
	if (file_exists($root) || is_link($root)) {
		if (!pfb_settings_family_path_is_safe($root, TRUE, $expected_owner)) {
			return FALSE;
		}
	} elseif (!@mkdir($root, 0755, TRUE) || !pfb_settings_family_path_is_safe($root, TRUE, $expected_owner)) {
		return FALSE;
	}
	$slot = $root . '/settings-' . $family . '.xml';
	if (file_exists($slot) || is_link($slot)) {
		if (!pfb_settings_family_path_is_safe($slot, FALSE, $expected_owner)) {
			return FALSE;
		}
	}
	$encoded = base64_encode(serialize($owned));
	if (function_exists('dump_xml_config')) {
		$xml = @dump_xml_config(['family' => $family, 'payload' => $encoded], 'pfblockerng-settings');
	} else {
		$document = new SimpleXMLElement('<pfblockerng-settings/>');
		$document->addChild('family', $family);
		$document->addChild('payload', $encoded);
		$xml = $document->asXML();
	}
	if (!is_string($xml) || $xml === '') {
		return FALSE;
	}
	$tmp = @tempnam($root, '.settings-');
	if (!is_string($tmp)) {
		return FALSE;
	}
	$written = @file_put_contents($tmp, $xml, LOCK_EX);
	$exact = $written === strlen($xml) && @file_get_contents($tmp) === $xml;
	if (!$exact || !@chmod($tmp, 0600) || !pfb_settings_family_path_is_safe($tmp, FALSE, $expected_owner)) {
		@unlink($tmp);
		return FALSE;
	}
	if (!@rename($tmp, $slot)) {
		@unlink($tmp);
		return FALSE;
	}
	clearstatcache(TRUE, $slot);
	return pfb_settings_family_path_is_safe($slot, FALSE, $expected_owner)
		&& @file_get_contents($slot) === $xml;
}

function pfb_settings_family_replace(string $family): bool
{
	if (!isset(PFB_SETTINGS_FAMILY_RANK[$family])) {
		return FALSE;
	}
	$root = pfb_settings_family_root();
	$expected_owner = pfb_settings_family_expected_owner($root);
	$slot = $root . '/settings-' . $family . '.xml';
	if (!file_exists($slot) && !is_link($slot)) {
		return TRUE;
	}
	if (!pfb_settings_family_path_is_safe($root, TRUE, $expected_owner)
		|| !pfb_settings_family_path_is_safe($slot, FALSE, $expected_owner)) {
		return FALSE;
	}
	$parsed = NULL;
	if (function_exists('parse_xml_config')) {
		try {
			$parsed = parse_xml_config($slot, 'pfblockerng-settings');
		} catch (Throwable) {
			return FALSE;
		}
	} else {
		$document = @simplexml_load_file($slot, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOBLANKS);
		if ($document !== FALSE && $document->getName() === 'pfblockerng-settings') {
			$parsed = ['family' => (string) ($document->family ?? ''), 'payload' => (string) ($document->payload ?? '')];
		}
	}
	if (!is_array($parsed)
		|| !isset($parsed['family'], $parsed['payload'])
		|| !is_string($parsed['family'])
		|| $parsed['family'] !== $family
		|| !is_string($parsed['payload'])) {
		return FALSE;
	}
	$decoded = base64_decode($parsed['payload'], TRUE);
	if ($decoded === FALSE) {
		return FALSE;
	}
	try {
		$owned = @unserialize($decoded, ['allowed_classes' => FALSE]);
	} catch (Throwable) {
		return FALSE;
	}
	if (!is_array($owned) || $owned === []) {
		return FALSE;
	}
	foreach ($owned as $section => $_value) {
		if (!is_string($section) || !str_starts_with($section, 'pfblockerng')) {
			return FALSE;
		}
	}
	$active_references = [];
	if (!pfb_settings_family_payload_is_valid($owned, $active_references)) {
		return FALSE;
	}
	$installed = config_get_path('installedpackages', []);
	if (!is_array($installed)) {
		$installed = [];
	}
	$rebuilt = [];
	$owned_sections = array_keys($owned);
	$owned_index = 0;
	foreach ($installed as $section => $value) {
		if (str_starts_with((string) $section, 'pfblockerng')) {
			if (array_key_exists($owned_index, $owned_sections)) {
				$owned_section = $owned_sections[$owned_index++];
				$rebuilt[$owned_section] = $owned[$owned_section];
				unset($owned[$owned_section]);
			}
			continue;
		}
		$rebuilt[$section] = $value;
	}
	foreach ($owned as $section => $value) {
		$rebuilt[$section] = $value;
	}
	config_set_path('installedpackages', $rebuilt);
	write_config('pfBlockerNG: restore settings family');
	return TRUE;
}

function pfb_settings_family_record(string $family): bool
{
	if (!isset(PFB_SETTINGS_FAMILY_RANK[$family])) {
		return FALSE;
	}
	try {
		PfbConfig::writeSystem('gen/settings_family', $family);
		return TRUE;
	} catch (Throwable) {
		return FALSE;
	}
}

function pfb_install_settings_family_capture_restore(
	?callable $current = NULL,
	?callable $save = NULL,
	?callable $replace = NULL
): string {
	$current ??= 'pfb_settings_family_current';
	$save ??= 'pfb_settings_family_save';
	$replace ??= 'pfb_settings_family_replace';
	$source = $current();
	if (!is_string($source) || !isset(PFB_SETTINGS_FAMILY_RANK[$source]) || !$save($source)) {
		throw new RuntimeException('pfBlockerNG: unable to save source settings family');
	}
	if (!$replace('3.3')) {
		throw new RuntimeException('pfBlockerNG: unable to restore 3.3 settings family');
	}
	return $source;
}

function pfb_install_settings_family_finalize(?callable $record = NULL): void
{
	$record ??= 'pfb_settings_family_record';
	if (!$record('3.3')) {
		throw new RuntimeException('pfBlockerNG: unable to record 3.3 settings family');
	}
}

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
