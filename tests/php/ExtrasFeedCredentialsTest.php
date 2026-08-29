<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1906 — every extras feed must reach PfbDownloadRequest with STRING credentials.
 *
 * pfblockerng_download_extras() normalized the per-feed credentials in a three-way branch
 * that gave the IPinfo ASN feeds no normalization at all: the 'geoip' arm assigned the
 * MaxMind account/key, the catch-all arm coerced whatever the feed carried, and the 'asn'
 * arm only appended the token to the URL. The ASN extras are built with url/file_dwn/file/
 * folder/type and nothing else, so $feed['username'] stayed an undefined array key — NULL —
 * and PfbDownloadRequest's non-nullable `string $username` turned that into an uncaught
 * TypeError that aborted the whole extras run (the reported crash: no ASN database refresh,
 * and on the 'dcc' cron path no MaxMind country-ISO regeneration either, because the fatal
 * lands before pfblockerng_uc_countries()).
 *
 * The normalization now happens ONCE, for every feed type, in pfb_extras_credentials() —
 * hosted in pfblockerng.inc rather than the www/ dispatcher so it is loadable by the PHPUnit
 * bootstrap (the ADR43-5 treatment pfblockerng_tick() received).
 *
 * Red→green: against the pre-change worktree every test below fails with
 * "Call to undefined function pfb_extras_credentials()"; testAsnFeedWithoutCredentialKeys*
 * are the defect's in-suite reproduction — the second one reconstructs the exact reported
 * failure by feeding the result to a real PfbDownloadRequest.
 *
 * Branch coverage:
 *   geoip            — credentials come from the MaxMind settings, not from the feed.
 *   asn              — no credential keys at all (the bug): empty strings, never NULL.
 *   blacklist w/ creds — a per-item username/password is passed through untouched.
 *   blacklist w/o creds / top1m — absent keys: empty strings.
 *   explicit NULLs   — a key present but NULL is coerced too, not just an absent key.
 *   falsy-but-real   — a literal "0" credential is reported, not blanked.
 */
#[CoversFunction('pfb_extras_credentials')]
final class ExtrasFeedCredentialsTest extends TestCase
{
	/** The MaxMind settings as pfb_global() leaves them for a configured box. */
	private const MAXMIND_ACCOUNT = '123456';
	private const MAXMIND_KEY     = 'aBcDeFgHiJkLmNoP';

	/**
	 * The reported defect, at the helper's boundary: $pfb['extras'][3]/[4] (IPinfo ASN)
	 * carry no username/password keys whatsoever, so the credentials must come back as
	 * empty STRINGS. assertSame pins the type — NULL is what crashed the extras run.
	 */
	public function testAsnFeedWithoutCredentialKeysYieldsEmptyStrings(): void
	{
		// Given: the ASN extras entry exactly as pfblockerng.php builds it.
		$feed = [
			'url'      => 'https://ipinfo.io/data/free/asn.mmdb?token=',
			'file_dwn' => 'asn.mmdb',
			'file'     => 'asn.mmdb',
			'folder'   => '/usr/local/share/GeoIP',
			'type'     => 'asn',
		];

		// When.
		[$username, $password] = pfb_extras_credentials($feed, self::MAXMIND_ACCOUNT, self::MAXMIND_KEY);

		// Then: strings, not NULL — and NOT the MaxMind credentials, which the ASN feed
		// authenticates with a URL token instead.
		$this->assertSame('', $username, 'an ASN feed carries no username; it must normalize to an empty string, never NULL');
		$this->assertSame('', $password, 'an ASN feed carries no password; it must normalize to an empty string, never NULL');
	}

	/**
	 * The same defect at the site that actually threw: PfbDownloadRequest's constructor.
	 * Before the fix this is the reported
	 * "Argument #10 ($username) must be of type string, null given" TypeError.
	 */
	public function testAsnFeedYieldsAConstructiblePfbDownloadRequest(): void
	{
		$feed = [
			'url'      => 'https://ipinfo.io/data/free/asn.csv.gz?token=',
			'file_dwn' => 'asn.csv.gz',
			'file'     => 'asn.csv',
			'folder'   => '/usr/local/share/GeoIP',
			'type'     => 'asn',
		];

		[$username, $password] = pfb_extras_credentials($feed, self::MAXMIND_ACCOUNT, self::MAXMIND_KEY);

		$request = new PfbDownloadRequest(
			listUrl: $feed['url'],
			downloadPath: "{$feed['folder']}/{$feed['file_dwn']}",
			flex: FALSE,
			header: "{$feed['folder']}/{$feed['file']}",
			format: '',
			logType: 3,
			versionType: '',
			timeout: 600,
			type: $feed['type'],
			username: $username,
			password: $password,
			sourceInterface: FALSE,
			extraHeaders: [],
		);

		$this->assertSame('', $request->username, 'the ASN download request must construct with an empty username');
		$this->assertSame('', $request->password, 'the ASN download request must construct with an empty password');
	}

	/**
	 * The MaxMind feeds authenticate with the account/key from the settings, which the feed
	 * array itself never carries — the helper must inject them, not read the feed.
	 */
	public function testGeoipFeedTakesTheMaxmindSettings(): void
	{
		$feed = [
			'url'      => 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz',
			'file_dwn' => 'GeoLite2-Country.tar.gz',
			'file'     => 'GeoLite2-Country.mmdb',
			'folder'   => '/usr/local/share/GeoIP',
			'type'     => 'geoip',
		];

		[$username, $password] = pfb_extras_credentials($feed, self::MAXMIND_ACCOUNT, self::MAXMIND_KEY);

		$this->assertSame(self::MAXMIND_ACCOUNT, $username, 'a GeoIP feed authenticates with the MaxMind account ID');
		$this->assertSame(self::MAXMIND_KEY, $password, 'a GeoIP feed authenticates with the MaxMind license key');
	}

	/**
	 * A DNSBL Blacklist category may carry its own credentials (pfblockerng.php copies them
	 * from the catalog item under an isset() guard). Those must survive untouched — the ASN
	 * fix must not start blanking real credentials.
	 */
	public function testBlacklistFeedKeepsItsOwnCredentials(): void
	{
		$feed = [
			'url'      => 'https://example.invalid/list.tar.gz',
			'name'     => 'ExampleCategory',
			'type'     => 'blacklist',
			'username' => 'feeduser',
			'password' => 'feedpass',
		];

		[$username, $password] = pfb_extras_credentials($feed, self::MAXMIND_ACCOUNT, self::MAXMIND_KEY);

		$this->assertSame('feeduser', $username, "a blacklist feed's own username must be passed through");
		$this->assertSame('feedpass', $password, "a blacklist feed's own password must be passed through");
	}

	/**
	 * The keyless feed types (TOP1M, and a blacklist category with no credentials in the
	 * catalog) reach the helper with no credential keys either.
	 */
	public function testKeylessFeedTypesYieldEmptyStrings(): void
	{
		foreach (['top1m', 'blacklist'] as $type) {
			[$username, $password] = pfb_extras_credentials(['type' => $type], self::MAXMIND_ACCOUNT, self::MAXMIND_KEY);

			$this->assertSame('', $username, "a credential-free '{$type}' feed must normalize its username to an empty string");
			$this->assertSame('', $password, "a credential-free '{$type}' feed must normalize its password to an empty string");
		}
	}

	/**
	 * A credential key that is PRESENT but NULL is the same TypeError as an absent one, so
	 * the coercion must cover it — an absent-key test alone would pass against a `??`-free
	 * isset() guard.
	 */
	public function testExplicitNullCredentialsAreCoerced(): void
	{
		$feed = ['type' => 'blacklist', 'username' => NULL, 'password' => NULL];

		[$username, $password] = pfb_extras_credentials($feed, self::MAXMIND_ACCOUNT, self::MAXMIND_KEY);

		$this->assertSame('', $username, 'a NULL username must be coerced to an empty string');
		$this->assertSame('', $password, 'a NULL password must be coerced to an empty string');
	}

	/**
	 * The replaced `?: ''` arm blanked every falsy value. This pins the helper's own contract:
	 * only NULL/absent means "no credential"; "0" is a credential and is reported as one.
	 */
	public function testFalsyButRealCredentialsSurvive(): void
	{
		$feed = ['type' => 'blacklist', 'username' => '0', 'password' => '0'];

		[$username, $password] = pfb_extras_credentials($feed, self::MAXMIND_ACCOUNT, self::MAXMIND_KEY);

		$this->assertSame('0', $username, 'a literal "0" username is a real credential, not an absent one');
		$this->assertSame('0', $password, 'a literal "0" password is a real credential, not an absent one');
	}
}
