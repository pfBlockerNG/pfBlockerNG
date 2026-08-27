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
$pfb_lint_include = '/usr/local/pkg/pfblockerng/pfblockerng.inc';
if (!file_exists($pfb_lint_include)) {
	$pfb_lint_include = dirname(__DIR__, 2) . '/pkg/pfblockerng/pfblockerng.inc';
}
require_once($pfb_lint_include);

$pfb_lint_response = pfb_lint_response(
	$_SERVER,
	$_POST,
	static fn (string $page): bool => isAllowedPage($page),
	static fn (string $lang, string $content, bool $cap): array => pfb_lint_diagnostics($lang, $content, $cap)
);
http_response_code($pfb_lint_response['status']);
foreach ($pfb_lint_response['headers'] as $header) {
	header($header);
}
echo $pfb_lint_response['body'];
exit;
