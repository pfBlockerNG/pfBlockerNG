<?php
/*
 * pfblockerng_software.inc
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

/*
 * issue #2360 — ADR-19 channel-provenance + software-update-check backport, step 1.
 *
 * Self-contained ADR-19 backport: every function this file needs lives in this file (or
 * PHP/pfSense core) — nothing here requires pfblockerng_extra.inc. Deliberately NOT wired
 * into PfbConfig/PfbToggle on this branch (owner directive: zero touch to shared,
 * already-functional 3.3 code — pfblockerng_extra.inc stays byte-identical to its
 * pristine 3.3 state on this step). devel remains the canonical shape (PfbConfig registry
 * + PfbToggle enum); pfb_software_check_config_read()/_write() below are a narrow,
 * file-local stand-in for that one config field, matching devel's enabled/disabled
 * semantics exactly (see their docblock).
 *
 * Ported wholesale from devel's pfblockerng.inc (ADR-19 section). No tests ship on this
 * branch (owner ruling, issue #2360); a standalone off-repo assertion harness exercised
 * this file in isolation (never extra.inc) to prove the self-containment.
 */

/*
 * Channel a build is on, from its installed package NAME:
 *   pfSense-pkg-pfBlockerNG         -> 'stable'
 *   pfSense-pkg-pfBlockerNG-testing -> 'testing'
 *   pfSense-pkg-pfBlockerNG-edge    -> 'edge'
 *   pfSense-pkg-pfBlockerNG-devel   -> 'devel'   (retired port; installed boxes remain)
 *   pfSense-pkg-pfBlockerNG-NIGHTLY -> 'nightly' (ADR-18)
 * Anything unrecognised/empty -> NULL. Suffix match is case-insensitive so the
 * NIGHTLY/devel spellings are tolerant.
 *
 * Every channel catalogue publishes the canonical 'pfSense-pkg-pfBlockerNG' — channel
 * is catalogue placement — so pfb_channel_from_repo_name() is the authoritative channel
 * signal and this is the FALLBACK: the discriminator inside the legacy shared
 * 'pfblockerng' repo, which carries both the canonical and the -devel identity. It also
 * remains the prefix/identity filter inside pfb_pkg_installed_name().
 */
function pfb_channel_from_pkgname(?string $name): ?string {
	if (!is_string($name) || $name === '') {
		return null;
	}
	$lname = strtolower($name);
	if (!str_starts_with($lname, 'pfsense-pkg-pfblockerng')) {
		return null;
	}
	$suffix = substr($lname, strlen('pfsense-pkg-pfblockerng'));
	switch ($suffix) {
		case '':
			return 'stable';
		case '-testing':
			return 'testing';
		case '-edge':
			return 'edge';
		case '-devel':
			return 'devel';
		case '-nightly':
			return 'nightly';
		default:
			return null;
	}
}

/*
 * Channel a build is on, from the pkg REPOSITORY it was installed from (`pkg query '%R'`):
 *   pfblockerng-stable  -> 'stable'
 *   pfblockerng-testing -> 'testing'
 *   pfblockerng-edge    -> 'edge'
 *   pfblockerng-nightly -> 'nightly'
 * Anything else -> NULL.
 *
 * Every channel catalogue publishes the ONE canonical package identity
 * 'pfSense-pkg-pfBlockerNG' — channel is catalogue placement, never a package-name
 * suffix — so the installed NAME can no longer say which channel a box is on. A box
 * subscribes to exactly one project repository at a time, so the recorded repo is both
 * the only repo the package can upgrade within and the authoritative channel signal.
 *
 * The LEGACY shared repo 'pfblockerng' returns NULL deliberately: it carries BOTH
 * pfSense-pkg-pfBlockerNG and pfSense-pkg-pfBlockerNG-devel, so there the NAME still
 * discriminates and callers fall back to pfb_channel_from_pkgname(). Matching is EXACT
 * (unlike the name mapper's case-insensitive suffixes): we author every one of these conf
 * names ourselves, so a case variant is a repo we never created, not a spelling of ours.
 */
function pfb_channel_from_repo_name(?string $repo): ?string {
	if (!is_string($repo) || $repo === '') {
		return null;
	}
	switch ($repo) {
		case 'pfblockerng-stable':
			return 'stable';
		case 'pfblockerng-testing':
			return 'testing';
		case 'pfblockerng-edge':
			return 'edge';
		case 'pfblockerng-nightly':
			return 'nightly';
		default:
			return null;
	}
}

/*
 * The channel an install is on: the REPO decides, the NAME is the fallback.
 *
 * The two mappers above answer half the question each, and every caller needs both halves in
 * the same order — the Software page label, the cron notice text, and the cached channel. It
 * lives here as ONE function rather than as a repeated expression so the page and the notice
 * cannot drift into disagreeing about what channel a box is on.
 *
 * NULL when neither half recognises the install (a Netgate or hand-built package); callers
 * render that as 'unknown'.
 */
function pfb_channel_for_install(?string $repo, ?string $pkgname): ?string {
	return pfb_channel_from_repo_name($repo) ?? pfb_channel_from_pkgname($pkgname);
}

/*
 * Does a software-update cache describe the install currently on this box?
 *
 * An install is identified by BOTH halves, because either can change alone:
 *   - the REPO, since all four catalogues publish the one canonical identity, so the name
 *     cannot tell two catalogues apart — a channel switch changes only this;
 *   - the NAME, since the legacy shared 'pfblockerng' catalogue carries both
 *     pfSense-pkg-pfBlockerNG and ...-devel — an in-repo identity swap changes only this.
 *
 * Both consumers of the cache ask this one question, and must ask the WHOLE of it: the
 * cron orchestrator, deciding whether cached latest/last_notified may be reused, and the
 * Software page, deciding whether cached latest/last-checked/status may be DISPLAYED. The
 * orchestrator's reset lands only on the next tick, so a page asking a looser question
 * shows the new install's label beside the previous one's version and verdict until then.
 *
 * A cache with NO 'repo' key predates the repo scope. That is not a catalogue change — it
 * is every existing box, once — so that half is adopted rather than discarded; discarding
 * it would re-announce an already-notified version and blank the last-known latest.
 */
function pfb_software_cache_matches_install(array $cache, string $pkgname, string $repo): bool {
	if ((string) ($cache['pkgname'] ?? '') !== $pkgname) {
		return FALSE;
	}
	return !array_key_exists('repo', $cache) || (string) $cache['repo'] === $repo;
}

/*
 * Provenance gate: TRUE only when the build was installed FROM one of OUR repos — the
 * legacy shared 'pfblockerng' (stable + the retired -devel identity) or one of the four
 * per-channel catalogues 'pfblockerng-stable' / '-testing' / '-edge' / '-nightly'. The
 * repo is read from `pkg query '%R' <pkgname>`. A Netgate-installed add-on (repo
 * 'pfSense'), an empty/'unknown' origin, or anything else -> FALSE: the Software tab,
 * the page's own top-of-file guard, and the cron notice all gate on this so a stock
 * build shows none of them (the static priv match[] line cannot gate; the page guard
 * covers direct requests).
 */
function pfb_software_is_our_build(?string $installed_repo): bool {
	return in_array(
		$installed_repo,
		array('pfblockerng', 'pfblockerng-stable', 'pfblockerng-testing', 'pfblockerng-edge', 'pfblockerng-nightly'),
		TRUE
	);
}

/*
 * TRUE when $latest is strictly newer than $installed, via pfSense pkg_version_compare()
 * (never a string compare — it returns '<' | '=' | '>'). Empty/invalid inputs -> FALSE
 * (no update): a missing installed or latest version is never "an update is available".
 * Nightly's dated versions are only ever compared nightly-to-nightly (ADR-18 §1.5).
 */
function pfb_update_available(?string $installed, ?string $latest): bool {
	if (!is_string($installed) || $installed === '' || !is_string($latest) || $latest === '') {
		return FALSE;
	}
	return pkg_version_compare($installed, $latest) === '<';
}

/*
 * pfb_software_check_config_read()/_write() — the ONE config field this backport reads
 * (installedpackages/pfblockerng/config/0/pfb_software_check), owned locally rather than
 * through PfbConfig (owner directive: zero touch to the shared 3.3-line gateway on this
 * branch). Semantics match devel's registered field (devel compares the raw value; this
 * reader also trims surrounding whitespace before comparing):
 *   - absent (NULL)   -> ENABLED (issue #1887's registry default 'on');
 *   - present 'on' (case-insensitive, trimmed) -> ENABLED;
 *   - present '' or any other token             -> DISABLED (explicit Off / legacy junk).
 * Write persists devel's canonical stored form: 'on' when enabled, '' when disabled (empty
 * Off). Does NOT call write_config(); callers persist.
 */
const PFB_SOFTWARE_CHECK_PATH = 'installedpackages/pfblockerng/config/0/pfb_software_check';

function pfb_software_check_config_read(): bool {
	$raw = config_get_path(PFB_SOFTWARE_CHECK_PATH, NULL);
	if ($raw === NULL) {
		return TRUE;
	}
	return strtolower(trim((string) $raw)) === 'on';
}

function pfb_software_check_config_write(bool $enabled): void {
	config_set_path(PFB_SOFTWARE_CHECK_PATH, $enabled ? 'on' : '');
}

/*
 * Whether the "Check for new versions" setting (pfb_software_check) is enabled. Default
 * ENABLED: an our-repo install checks for and notifies of new versions out of the box. An
 * absent value receives that default; case-insensitive 'on' enables it, and every other
 * present token disables it. The Software page persists unchecked as canonical empty Off.
 */
function pfb_software_check_enabled(): bool {
	return pfb_software_check_config_read();
}

/*
 * The notify state machine: TRUE iff a `file_notice` should fire THIS tick.
 *
 * The single "Check for new versions" boolean ($enabled) gates notifications equally on every
 * channel: a notice fires ONLY when checking is enabled AND an update is available (latest >
 * installed) AND we have not already notified for this exact latest ($latest !== $last_notified).
 * The last clause is the per-version de-dupe (ADR-19 §2 "persist last-notified"): a daily cron at
 * the same latest does NOT renotify; a newer latest does.
 */
function pfb_should_notify(?string $installed, ?string $latest, ?string $last_notified, bool $enabled): bool {
	if (!$enabled) {
		return FALSE;
	}
	if (!pfb_update_available($installed, $latest)) {
		return FALSE;
	}
	return $latest !== $last_notified;
}

/*
 * ADR-19 — pkg IO wrapper + cron-driven update check (consumes the pure core).
 *
 * The pfb_pkg_*() functions below are the ONLY new code that shells to `pkg`; isolating
 * the shellout in thin wrappers keeps pfb_software_update_check() unit-testable (the
 * tests inject the installed/latest/installed-repo via its $io override rather than run
 * `pkg`). The pkg(8) port binary (libpkg) lives at /usr/local/sbin/pkg on every supported
 * target — this is the binary pfSense itself and our add-repo.sh/build-repo.sh shell to.
 * The base /usr/sbin/pkg bootstrap stub does NOT report the repository origin ('%R') the
 * same way, so the provenance gate read FALSE on a genuine our-repo install when it was
 * used; the port binary returns the recorded repo name (the legacy shared 'pfblockerng'
 * or one of the per-channel 'pfblockerng-<channel>' catalogues), which is now the
 * authoritative channel signal AND the repo latest is read from.
 */
define('PFB_PKG_BIN', '/usr/local/sbin/pkg');

/*
 * The installed pfBlockerNG package NAME (e.g. 'pfSense-pkg-pfBlockerNG-devel'), read
 * from `pkg query '%n'` filtered to our prefix; '' when not installed via pkg or the
 * query fails. Feeds pfb_channel_from_pkgname().
 */
function pfb_pkg_installed_name(): string {
	$out = array();
	$ret = -1;
	// -g: match the trailing '*' as a glob. pkg query treats the pattern as an EXACT
	// pkg-name without it, so 'pfSense-pkg-pfBlockerNG*' would match nothing and the
	// provenance gate would wrongly read the package as not-our-build on every install.
	exec(escapeshellarg(PFB_PKG_BIN) . " query -g '%n' " . escapeshellarg('pfSense-pkg-pfBlockerNG*') . ' 2>/dev/null', $out, $ret);
	if ($ret !== 0) {
		return '';
	}
	foreach ($out as $line) {
		$line = trim($line);
		if (pfb_channel_from_pkgname($line) !== null) {
			return $line;
		}
	}
	return '';
}

/*
 * The installed version of $pkgname via `pkg query '%v'`; '' when absent/failed.
 */
function pfb_pkg_installed_version(string $pkgname): string {
	if ($pkgname === '') {
		return '';
	}
	$out = array();
	$ret = -1;
	exec(escapeshellarg(PFB_PKG_BIN) . " query '%v' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
}

/*
 * The repo $pkgname was installed FROM via `pkg query '%R'` (the provenance signal the
 * gate keys on); '' when absent/failed. Fed to pfb_software_is_our_build().
 *
 * The recorded repo is the single authoritative signal: under one-repository-at-a-time
 * subscription the recorded repo is the ONLY repo the package can upgrade within, so it is
 * also the repo pfb_software_update_check() reads latest from and (via
 * pfb_channel_from_repo_name()) the channel it reports.
 */
function pfb_pkg_installed_repo(string $pkgname): string {
	if ($pkgname === '') {
		return '';
	}
	$out = array();
	$ret = -1;
	exec(escapeshellarg(PFB_PKG_BIN) . " query '%R' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
}

/*
 * The pfBlockerNG repo's latest version of $pkgname: `pkg update -r <repo>` (best-effort refresh of
 * just that repo's catalog DB) then `pkg rquery -r <repo> '%v' <pkgname>`. Reads ONLY that repo
 * ($reponame) — never -r pfSense / get_pkg_info (ADR-19 §2 "Read latest"). Returns ''
 * (the caller then serves cache) when:
 *   - $pkgname/$reponame is empty;
 *   - the pkg subsystem is locked (is_subsystem_dirty('pkg')) — never fight a base update;
 *   - DNS is unavailable (get_dnsavailable()) — never stall on a network read;
 *   - the rquery yields nothing (repo/conf absent).
 */
function pfb_pkg_latest(string $pkgname, string $reponame): string {
	if ($pkgname === '' || $reponame === '') {
		return '';
	}
	if (is_subsystem_dirty('pkg')) {
		return '';
	}
	if (function_exists('get_dnsavailable') && !get_dnsavailable()) {
		return '';
	}
	$bin = escapeshellarg(PFB_PKG_BIN);
	$repo = escapeshellarg($reponame);
	// Bound both networked pkg calls with timeout(1) (same idiom as the hook runner) so a
	// hung mirror can never stall the cron pass or the page's forced "Check now".
	$tmo = '/usr/bin/timeout -s TERM -k 5 60 ';
	// Best-effort catalog refresh of the pfBlockerNG repo only; ignore failures (stale DB still reads).
	exec("{$tmo}{$bin} update -r {$repo} 2>/dev/null");
	$out = array();
	$ret = -1;
	exec("{$tmo}{$bin} rquery -r {$repo} '%v' " . escapeshellarg($pkgname) . ' 2>/dev/null', $out, $ret);
	return ($ret === 0 && isset($out[0])) ? trim($out[0]) : '';
}

/*
 * Absolute path of the software-update cache (the page reads it; the cron writes it).
 */
function pfb_software_cache_file(): string {
	global $pfb;
	$dbdir = $pfb['dbdir'] ?? '/var/db/pfblockerng';
	return "{$dbdir}/software_update.json";
}

/*
 * Read the cache file as an assoc array (channel, installed, latest, last_checked,
 * last_notified); [] when absent/unreadable/corrupt.
 */
function pfb_software_read_cache(): array {
	$file = pfb_software_cache_file();
	if (!is_file($file)) {
		return array();
	}
	$raw = @file_get_contents($file);
	if ($raw === FALSE || $raw === '') {
		return array();
	}
	$data = json_decode($raw, TRUE);
	if (!is_array($data)) {
		return array();
	}
	// Every consumer reads these values through a (string) cast -- the orchestrator's
	// latest/last_notified, the page's displayed fields, the install matcher. A non-scalar
	// value (a hand-edit, a future writer) makes each of those casts emit "Array to string
	// conversion" once per call, so it is dropped HERE rather than guarded at each site,
	// where the next site added would be unguarded again (issue #2367). Every key the writer
	// stores is a scalar or NULL; a stored NULL drops too, which costs nothing because the
	// only nullable one ('channel') is recomputed live and never read back from here.
	return array_filter($data, static function ($value): bool {
		return is_scalar($value);
	});
}

/*
 * Persist the cache atomically (encode -> write). Best-effort; a write failure is
 * swallowed (the next tick retries) so it can never throw into the cron pass.
 */
function pfb_software_write_cache(array $cache): void {
	$json = json_encode($cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	if ($json === FALSE) {
		return;
	}
	// Stage to a temp file then rename() into place: a concurrent reader (which takes no
	// shared lock) then sees either the old or the new complete file, never a truncated one
	// that would decode to [] and drop last_notified (re-emitting a notice).
	$file = pfb_software_cache_file();
	$tmp = @tempnam(dirname($file), '.pfbsw_');
	if ($tmp === FALSE) {
		return;
	}
	if (@file_put_contents($tmp, $json . "\n", LOCK_EX) === FALSE || !@rename($tmp, $file)) {
		@unlink($tmp);
	}
}

/*
 * The cron-driven software-update check (ADR-19 §2 "Background check").
 *
 * Order is deliberate:
 *   1. Resolve installed name + version. These can be injected for unit tests via
 *      $io ['installed_name','installed','installed_repo','latest']; absent keys fall
 *      through to the live pfb_pkg_*() shellout.
 *   2. PROVENANCE GATE FIRST: gate on pfb_software_provenance_ok() — the SAME predicate
 *      that decides whether the Software PAGE is displayable (our-repo install, honouring
 *      the hidden CI/support override) — so a build that cannot show the page never runs
 *      the background check or raises an update notice, even if "Check for new versions"
 *      remains enabled from a prior our-repo install. Injectable via $io['provenance_ok']
 *      for off-box tests.
 *   3. Read latest from the repo the package was INSTALLED from (guarded inside
 *      pfb_pkg_latest()). An empty latest (pkg locked / no DNS / repo absent) preserves the
 *      cached latest so the page keeps showing the last-known value rather than regressing
 *      to ''.
 *   4. Refresh the cache (pkgname/repo/channel/installed/latest/last_checked) and, when
 *      pfb_should_notify() says so, raise a DE-DUPED file_notice and persist
 *      last_notified = latest (so repeated ticks at the same latest do not renotify).
 *
 * Best-effort throughout: it returns the cache array and never throws, so wiring it into
 * the cron pass can never break a feed update. $force (the page's "Check now" button) bypasses
 * the "Check for new versions" enable-gate so a manual check always runs; it never bypasses the
 * provenance gate, and notifications still require the setting enabled.
 */
function pfb_software_update_check(bool $force = FALSE, ?array $io = null): array {
	$io = is_array($io) ? $io : array();

	$pkgname = array_key_exists('installed_name', $io)
		? (string) $io['installed_name']
		: pfb_pkg_installed_name();
	$installed = array_key_exists('installed', $io)
		? (string) $io['installed']
		: pfb_pkg_installed_version($pkgname);

	// 2. Provenance gate FIRST — gate on the SAME predicate that decides whether the Software
	// PAGE is displayable (pfb_software_provenance_ok(): our-repo install, honouring the
	// hidden CI/support override), so a build that cannot show the page never runs the
	// background check or notifies — even if "Check for new versions" is still enabled from a
	// prior our-repo install. Injectable via $io['provenance_ok'] for off-box tests.
	$provenance_ok = array_key_exists('provenance_ok', $io)
		? (bool) $io['provenance_ok']
		: pfb_software_provenance_ok();
	if (!$provenance_ok) {
		return pfb_software_read_cache();
	}

	// The single "Check for new versions" setting (default ENABLED) gates the BACKGROUND
	// (cron) check + notifications. A manual "Check now" ($force) always runs, so a user can
	// do a one-off check without leaving background checking enabled.
	$enabled = pfb_software_check_enabled();
	if (!$enabled && !$force) {
		return pfb_software_read_cache();
	}

	// The INSTALLED REPOSITORY is authoritative — never a channel->repo mapping. All four
	// catalogues publish the ONE canonical identity 'pfSense-pkg-pfBlockerNG', and a box
	// subscribes to exactly one project repo at a time (all at priority 100, so pkg would not
	// order across them anyway), which makes the recorded '%R' both the only repo this
	// install can upgrade within and the channel it is on. Correct for legacy 'pfblockerng'
	// installs too: that is exactly where their upgrades come from.
	$repo = array_key_exists('installed_repo', $io)
		? (string) $io['installed_repo']
		: pfb_pkg_installed_repo($pkgname);
	// Repo-first, name-fallback, through the ONE shared accessor so the cached channel,
	// the notice text and the Software page label can never disagree.
	$channel = pfb_channel_for_install($repo, $pkgname);

	$cache = pfb_software_read_cache();

	// 3. Read latest from the installed repo; keep the cached value when the live read is
	// unavailable.
	if (array_key_exists('latest', $io)) {
		$latest = (string) $io['latest'];
	} else {
		$latest = pfb_pkg_latest($pkgname, $repo);
	}
	// Only reuse cached latest/last_notified when the cache belongs to the SAME install.
	// pfb_software_cache_matches_install() is the whole question — name AND repo — and the
	// Software page gates its DISPLAYED values on the identical call, so the two can never
	// disagree about which cache is current.
	$cache_matches_install = pfb_software_cache_matches_install($cache, $pkgname, $repo);
	if ($latest === '' && $cache_matches_install) {
		$latest = (string) ($cache['latest'] ?? '');
	}

	$last_notified = $cache_matches_install ? (string) ($cache['last_notified'] ?? '') : '';

	// 4. Refresh the cache. last_notified is written from the scoped value so a cache left
	// by a different install (a different package name OR a different catalogue) is reset
	// rather than carried forward.
	$cache['pkgname']       = $pkgname;
	$cache['repo']          = $repo;
	$cache['channel']       = $channel;
	$cache['installed']     = $installed;
	$cache['latest']        = $latest;
	$cache['last_notified'] = $last_notified;
	$cache['last_checked']  = time();

	if (pfb_should_notify($installed, $latest, $last_notified, $enabled)) {
		file_notice('pfBlockerNG', "pfBlockerNG {$latest} available ({$channel})", 'pfBlockerNG', '/pfblockerng/pfblockerng_software.php', 1);
		$cache['last_notified'] = $latest;
	}

	pfb_software_write_cache($cache);
	return $cache;
}

/*
 * ADR-19 — provenance gate for the shipped GUI surfaces.
 *
 * Live wrapper over the pure pfb_software_is_our_build(): reads the installed package's
 * provenance from `pkg query '%R'` and returns true ONLY when pfBlockerNG was installed
 * from one of OUR repos — the legacy shared `pfblockerng` or one of the four per-channel
 * catalogues `pfblockerng-stable|-testing|-edge|-nightly`. A Netgate-ports install (repo
 * 'pfSense'/unknown/'') returns false.
 *
 * The Software tab append and the pfblockerng_software.php top-of-file guard
 * both gate on this single predicate so a Netgate-installed add-on shows no
 * Software page anywhere (the static priv match line cannot gate by itself).
 */
// Hidden test/support override for the Software-page provenance gate. A file
// containing 'on' or 'off' FORCES the gate (case-insensitive, trimmed); absent or any other
// content => fall through to the auto-detect below. NOT a GUI knob: the webConfigurator never
// writes it. It lets CI render BOTH the enabled and disabled states deterministically (the
// Tier-A UI deploy is a sideloaded `pkg add`, whose %R is empty, so auto-detect alone could
// only ever show the hidden state), and gives support a force-on/off escape-hatch on a real box.
define('PFB_SOFTWARE_PANEL_OVERRIDE', '/var/db/pfblockerng/.pfb_software_panel');

/*
 * The forced Software-gate state, or NULL when not forced. Reads the hidden override sentinel
 * (PFB_SOFTWARE_PANEL_OVERRIDE; $path is injectable for off-box tests): 'on' => true,
 * 'off' => false, absent / any other content => NULL (the auto-detect applies).
 */
function pfb_software_panel_override(?string $path = null): ?bool {
	$path = $path ?? PFB_SOFTWARE_PANEL_OVERRIDE;
	if (!is_file($path)) {
		return null;
	}
	$v = strtolower(trim((string) @file_get_contents($path)));
	if ($v === 'on') {
		return TRUE;
	}
	if ($v === 'off') {
		return FALSE;
	}
	return null;
}

function pfb_software_provenance_ok(): bool {
	// A hidden override (CI / support) wins; otherwise auto-detect from the install's repo (%R).
	$forced = pfb_software_panel_override();
	if ($forced !== null) {
		return $forced;
	}
	return pfb_software_is_our_build(pfb_pkg_installed_repo(pfb_pkg_installed_name()));
}

/*
 * Append the "Software" tab to a page's $tab_array — ONLY when BOTH hold: an our-repo build
 * (pfb_software_provenance_ok()) AND the viewer holds the Package Manager "Installed" privilege
 * (isAllowedPage('pkg_mgr_installed.php')) — the SAME secondary gate pfblockerng_software.php
 * itself enforces, so a user without that priv never sees a tab that dead-ends at
 * /index.php. $provenance_ok is injectable for off-box unit tests (the real predicate reads
 * on-appliance state); NULL (the production default) reads it. Shared by every pfBlockerNG page
 * so the tab is consistently present or absent across the GUI. Call immediately before
 * display_top_tabs(); $active marks it the current tab.
 */
function pfb_software_add_tab(array &$tab_array, bool $active = FALSE, ?bool $provenance_ok = null): void {
	$provenance_ok = $provenance_ok ?? pfb_software_provenance_ok();
	if ($provenance_ok && isAllowedPage('pkg_mgr_installed.php')) {
		$tab_array[] = array(gettext('Software'), $active, '/pfblockerng/pfblockerng_software.php');
	}
}
