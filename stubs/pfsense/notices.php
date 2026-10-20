<?php
/**
 * pfSense notice queue stubs -- IDE static analysis only (Intelephense).
 *
 * Hand-maintained, like logging.php: file_notice() itself lives there. This file holds the reader of the same queue.
 * Reference (mirror is frozen at RELENG_2_7_2 -- no RELENG_2_8_0 tag/branch exists):
 * https://github.com/pfsense/pfsense/blob/RELENG_2_7_2/src/etc/inc/notices.inc (get_notices)
 */

// @codingStandardsIgnoreFile

/**
 * The notice queue file_notice() writes, keyed by time: each row carries id, notice, url, category and priority, with the
 * text fields htmlentities()-encoded as they are stored.
 *
 * @return array<int|string,array<string,string>>|false
 */
function get_notices(string $category = 'all'): array|false {}
