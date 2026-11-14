<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_core_update_serve')]
final class FeedPhaseTokenTest extends TestCase
{
	public function testUpdateTokenIsAvailableToTheFeedPassAndClearedAfterward(): void
	{
		$savedPfb = $GLOBALS['pfb'];
		$token = str_repeat('e', 64);
		$dir = sys_get_temp_dir() . '/pfb_feed_phase_token_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($dir, 0755, TRUE);
		$seen = NULL;
		try {
			$request = json_encode([
				'version' => 1,
				'trigger' => 'manual',
				'scope' => 'both',
				'force' => 'none',
				'feeds' => [],
				'extras' => [],
				'token' => $token,
			], JSON_THROW_ON_ERROR);
			$status = pfb_core_update_serve($request, "{$dir}/result.json", [
				'sync' => static function (array $options, ?string &$deferred) use (&$seen): bool {
					$seen = $GLOBALS['pfb']['feed_phase_token'] ?? NULL;
					return TRUE;
				},
			]);

			$this->assertSame(0, $status);
			$this->assertSame($token, $seen, 'the validated stdin token must reach the feed pass');
			$this->assertArrayNotHasKey('feed_phase_token', $GLOBALS['pfb'], 'the token must not survive the Update');
		} finally {
			$GLOBALS['pfb'] = $savedPfb;
			rmdir_recursive($dir);
		}
	}
}
