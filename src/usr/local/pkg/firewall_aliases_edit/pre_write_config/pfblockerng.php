<?php
/*
 * pfblockerng.php — pre_write_config hook for firewall_aliases_edit
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
 * pfBlockerNG — follow a firewall-alias rename into our stored Advanced
 * Inbound/Outbound references (issue #357). Included by
 * pfSense_handle_custom_code() in saveAlias(); $origname (old) and
 * $post['name'] (new) are in scope, and saveAlias persists via its own
 * write_config() right after this runs. Keep this file MINIMAL — it is the
 * only piece coupled to pfSense's internal save scope; the actual work lives
 * in pfb_alias_rename_followup() (pfblockerng_extra.inc), gateway-routed and
 * unit-tested.
 */

require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
if (isset($origname, $post['name']) && function_exists('pfb_alias_rename_followup')) {
	pfb_alias_rename_followup((string) $origname, (string) $post['name']);
}
