<?php
/*
 * pfblockerng_lint.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
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

// issue #1732: ajax-only JSON endpoint for the CodeMirror gutter's syntax-lint
// diagnostics. Compile/parse ONLY -- submitted content is never executed and never
// written to disk; a clean result here is advisory, not authoritative (save-time
// validation on the DNSBL/Edit-Hooks pages stays the real gate). Two-tier privilege
// model below: lang=regex only repeats the same bounded Python re pass the DNSBL save
// handler already runs, so it rides that page's own priv; lang=sh/py exec a real
// interpreter's parser, the same diag_command.php-equivalent trust class
// pfblockerng_edit_hooks.php gates on (issue #1669).
//
// csrf-magic validates every POST against the session token before this page ever runs
// (pfSense's global wiring) -- no manual CSRF check is added here.

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

/*
 * Single JSON-reply exit point -- every guard below routes through this so no branch
 * can fall through to rendering HTML.
 */
function pfb_lint_reply(int $status, array $payload): never {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	// JSON_INVALID_UTF8_SUBSTITUTE: a diagnostic message carrying invalid UTF-8 (e.g. a
	// mis-decoded stderr byte) would otherwise make json_encode() return FALSE, shipping
	// a 200 with an empty body instead of a diagnostic.
	echo json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE);
	exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
	pfb_lint_reply(405, ['error' => 'POST only']);
}

$lang = $_POST['lang'] ?? null;
if (!is_string($lang) || !in_array($lang, ['regex', 'sh', 'py'], TRUE)) {
	// A crafted lang[]= array fails is_string() before in_array() ever runs.
	pfb_lint_reply(400, ['error' => 'lang must be one of regex, sh, py']);
}

if ($lang === 'regex') {
	if (!isAllowedPage('pfblockerng/pfblockerng_dnsbl.php')) {
		pfb_lint_reply(403, ['error' => 'insufficient privilege']);
	}
} else {
	// sh/py exec a real interpreter's parser -- the same Command-Prompt-equivalent
	// trust class pfblockerng_edit_hooks.php gates on (issue #1669), not the ordinary
	// DNSBL page priv.
	if (!isAllowedPage('diag_command.php')) {
		pfb_lint_reply(403, ['error' => 'insufficient privilege']);
	}
}

$content = $_POST['content'] ?? '';
if (!is_string($content)) {
	pfb_lint_reply(400, ['error' => 'content must be a string']);
}
if (strlen($content) > 1048576) {
	pfb_lint_reply(413, ['error' => 'content too large']);
}

$cap = (($_POST['cap'] ?? '') === '1');

pfb_lint_reply(200, ['diagnostics' => pfb_lint_diagnostics($lang, $content, $cap)]);
