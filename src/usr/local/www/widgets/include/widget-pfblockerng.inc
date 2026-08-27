<?php
/*
 * widget-pfblockerng.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2014-2024 BBcan177@gmail.com
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

//set variables for custom title and link
$pfblockerng_title = '<span title="Click to open Unified Log tab">pfBlockerNG</span>';
$pfblockerng_title_link = 'pfblockerng/pfblockerng_alerts.php?view=unified';
// issue #1777: pfSense dashboard widget-include convention (same family as
// $widgetname/$pfblockerng_title above); the widget is a singleton (fixed POST
// action URL, settings keyed off one installedpackages/pfblockerngglobal block).
$pfblockerng_allow_multiple_widget_copies = FALSE;

// issue #1050: the widget sets $nocsrf=TRUE (csrf-magic never runs here), so a
// mutating POST handler gates on this instead. DEFAULT-DENY on an absent header
// (issue #1650): a header-less/legacy client would otherwise bypass the guard
// entirely; every modern browser sends Sec-Fetch-Site, so the legitimate
// same-origin widget POST still passes.
function pfb_widget_post_allowed(array $server): bool {
	if (!isset($server['HTTP_SEC_FETCH_SITE'])) {
		return FALSE;
	}
	return in_array($server['HTTP_SEC_FETCH_SITE'], array('same-origin', 'none'), TRUE);
}

?>
