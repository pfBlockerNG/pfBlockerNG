<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbDownloadInterfaceTest extends TestCase
{
	public function testRequestDefaultsAndFullMapping(): void
	{
		$defaults = new PfbDownloadRequest(
			listUrl: 'https://example.test/list',
			downloadPath: '/tmp/list',
			flex: FALSE,
			header: 'feed',
			format: 'plain',
			logType: 1,
		);

		$this->assertSame('', $defaults->versionType);
		$this->assertSame(300, $defaults->timeout);
		$this->assertSame('', $defaults->type);
		$this->assertSame('', $defaults->username);
		$this->assertSame('', $defaults->password);
		$this->assertFalse($defaults->sourceInterface);
		$this->assertSame(array(), $defaults->extraHeaders);

		$mapped = new PfbDownloadRequest(
			listUrl: 'rsync://host/module',
			downloadPath: '/var/db/feed',
			flex: TRUE,
			header: 'mapped',
			format: 'rsync',
			logType: 3,
			versionType: 'v4',
			timeout: 42,
			type: 'change_detect',
			username: 'user',
			password: 'pass',
			sourceInterface: 'wan',
			extraHeaders: array('Authorization: Bearer token'),
		);

		$this->assertSame('rsync://host/module', $mapped->listUrl);
		$this->assertSame('/var/db/feed', $mapped->downloadPath);
		$this->assertTrue($mapped->flex);
		$this->assertSame('mapped', $mapped->header);
		$this->assertSame('rsync', $mapped->format);
		$this->assertSame(3, $mapped->logType);
		$this->assertSame('v4', $mapped->versionType);
		$this->assertSame(42, $mapped->timeout);
		$this->assertSame('change_detect', $mapped->type);
		$this->assertSame('user', $mapped->username);
		$this->assertSame('pass', $mapped->password);
		$this->assertSame('wan', $mapped->sourceInterface);
		$this->assertSame(array('Authorization: Bearer token'), $mapped->extraHeaders);
	}

	public function testResultSuccessAndFailureExposeMetadata(): void
	{
		$success = PfbDownloadResult::success();
		$this->assertTrue($success->success);
		$this->assertNull($success->responseMeta);

		$metadata = array('status' => '304', 'etag' => '"tag"', 'lastmod' => 123);
		$failure = PfbDownloadResult::failure($metadata);
		$this->assertFalse($failure->success);
		$this->assertSame($metadata, $failure->responseMeta);
	}

	public function testDownloadFunctionHasRequestAndResultSignature(): void
	{
		$reflection = new ReflectionFunction('pfb_download');
		$this->assertCount(1, $reflection->getParameters());
		$this->assertSame(PfbDownloadRequest::class, $reflection->getParameters()[0]->getType()?->getName());
		$this->assertSame(PfbDownloadResult::class, $reflection->getReturnType()?->getName());
	}
}
