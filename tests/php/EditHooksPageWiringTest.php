<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Runtime contracts for the privilege-gated Edit Hooks page. */
final class EditHooksPageWiringTest extends TestCase
{
	private string $dir = '';

	protected function setUp(): void
	{
		require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc';
		$this->dir = sys_get_temp_dir() . '/pfb_edit_hooks_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	private function makeHook(string $name, string $body = "#!/bin/sh\nexit 0\n"): string
	{
		$path = $this->dir . '/' . $name;
		$this->assertNotFalse(file_put_contents($path, $body));
		$this->assertTrue(chmod($path, 0700));
		return $path;
	}

	public function testNoRequestSuperglobalReadBeforeGate(): void
	{
		$probed = FALSE;
		$probe = static function () use (&$probed): array {
			$probed = TRUE;
			return [];
		};
		$state = pfb_edit_hooks_controller(FALSE, $probe, $probe, $this->dir);
		$this->assertSame('/index.php', $state['redirect']);
		$this->assertFalse($probed, 'denied requests must not invoke POST/GET callbacks');
	}

	public function testGateRedirectsToIndexAndExits(): void
	{
		$path = $this->makeHook('hook_post_guarded.sh', "before\n");
		$state = pfb_edit_hooks_controller(
			FALSE,
			static fn (): array => ['pfb_eh_save' => '1', 'pfb_eh_cur_when' => 'post', 'pfb_eh_cur_script' => basename($path), 'pfb_eh_content' => 'after'],
			static fn (): array => [],
			$this->dir
		);
		$this->assertSame('/index.php', $state['redirect']);
		$this->assertSame("before\n", file_get_contents($path), 'privilege refusal must leave a valid save untouched');
	}

	public function testShippedPageDelegatesDeniedRequestToController(): void
	{
		$root = var_export(dirname(__DIR__, 2), TRUE);
		$page = var_export(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_edit_hooks.php', TRUE);
		$script = <<<PHP
require {$root} . '/tests/php/bootstrap.php';
\$shim = sys_get_temp_dir() . '/pfb_edit_hooks_shim_' . getmypid();
mkdir(\$shim, 0777, TRUE);
file_put_contents(\$shim . '/guiconfig.inc', "<?php");
set_include_path(\$shim . PATH_SEPARATOR . get_include_path());
error_reporting(E_ERROR | E_PARSE);
\$GLOBALS['pfb_test_allowed_pages'] = ['diag_command.php' => FALSE];
register_shutdown_function(static function (): void { echo 'shutdown'; });
require {$page};
echo 'after-page';
PHP;
		$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);

		$this->assertSame(0, $status, (string) $stderr);
		$this->assertSame('shutdown', $stdout, 'denied page must exit through the controller redirect');
	}

	public function testControllerReturnsSuccessNoticesFromGet(): void
	{
		$saved = pfb_edit_hooks_controller(TRUE, static fn (): array => [], static fn (): array => ['saved' => '1'], $this->dir);
		$deleted = pfb_edit_hooks_controller(TRUE, static fn (): array => [], static fn (): array => ['deleted' => 'hook_post_old.sh'], $this->dir);
		$this->assertSame('Hook script saved.', $saved['notice']);
		$this->assertSame('Hook script deleted.', $deleted['notice']);
	}

	public function testWarningBannerCallPresent(): void
	{
		$warning = pfb_edit_hooks_warning();
		$this->assertSame('danger', $warning['style']);
		$this->assertSame('Advanced Users Only', $warning['title']);
		$this->assertStringContainsString('Command Prompt', $warning['message']);
	}

	public function testPrivIncDoesNotMatchThisPage(): void
	{
		$priv_list = [];
		require dirname(__DIR__, 2) . '/src/etc/inc/priv/pfblockerng.priv.inc';
		$matches = $priv_list['page-firewall-pfblockerng']['match'] ?? [];
		$this->assertNotEmpty($matches);
		$this->assertNotContains('pfblockerng/pfblockerng_edit_hooks.php', $matches);
		foreach ($matches as $match) {
			$regex = str_replace(['.', '*', '?'], ['\\.', '.*', '\\?'], $match);
			$this->assertSame(0, preg_match("@^{$regex}$@", 'pfblockerng/pfblockerng_edit_hooks.php'));
		}
	}

	public function testPickerUsesPfbHookScripts(): void
	{
		$path = $this->makeHook('hook_pre_picker.sh');
		$state = pfb_edit_hooks_controller(
			TRUE,
			static fn (): array => [],
			fn (): array => ['when' => 'pre', 'script' => basename($path)],
			$this->dir
		);
		$this->assertSame([], $state['errors']);
		$this->assertSame(basename($path), $state['sel_script']);
		$this->assertSame("#!/bin/sh\nexit 0\n", $state['content']);
	}

	public function testSavePathUsesTheThreeHelpersNotInlineValidation(): void
	{
		$path = $this->makeHook('hook_post_existing.sh');
		$state = pfb_edit_hooks_request(
			['pfb_eh_save' => '1', 'pfb_eh_cur_when' => 'post', 'pfb_eh_cur_script' => basename($path), 'pfb_eh_content' => 'updated'],
			[],
			$this->dir
		);
		$this->assertSame([], $state['errors']);
		$this->assertSame('updated', file_get_contents($path));

		$state = pfb_edit_hooks_request(
			['pfb_eh_save' => '1', 'pfb_eh_cur_when' => 'post', 'pfb_eh_cur_script' => '../outside.sh', 'pfb_eh_content' => 'blocked'],
			[],
			$this->dir
		);
		$this->assertNotSame([], $state['errors']);
		$this->assertSame('updated', file_get_contents($path));
	}

	public function testTextareaContentPassedRawNotDoubleEscaped(): void
	{
		$value = 'echo "<quoted> & raw"';
		$this->assertSame($value, pfb_edit_hooks_form_value($value));
	}

	public function testNewCoreInputValuePassedRaw(): void
	{
		$value = 'name_&_<quoted>';
		$this->assertSame($value, pfb_edit_hooks_form_value($value));
	}

	public function testHiddenCurrentWhenAndScriptFieldsPassedRaw(): void
	{
		$this->assertSame('pre', pfb_edit_hooks_form_value('pre'));
		$this->assertSame('hook_pre_name.sh', pfb_edit_hooks_form_value('hook_pre_name.sh'));
	}

	public function testTextareaRoundTripFidelityThroughFrameworkEscapeAndBrowserDecode(): void
	{
		$original = pfb_hook_editor_template('pre', 'sh');
		$this->assertSame($original, html_entity_decode(htmlspecialchars(pfb_edit_hooks_form_value($original))));
	}

	public function testSubmitButtonsUseNativeNamesWithNoJsInjection(): void
	{
		$this->assertSame('pfb_eh_create', pfb_edit_hooks_submit_field('create'));
		$this->assertSame('pfb_eh_save', pfb_edit_hooks_submit_field('save'));
		$this->assertSame('', pfb_edit_hooks_submit_field('delete'));
	}

	public function testCreateFlowUsesAtomicOpenWithPartialWriteCleanup(): void
	{
		$state = pfb_edit_hooks_request(
			['pfb_eh_create' => '1', 'pfb_eh_new_when' => 'pre', 'pfb_eh_new_core' => 'created', 'pfb_eh_new_lang' => 'sh'],
			[],
			$this->dir
		);
		$path = $this->dir . '/hook_pre_created.sh';
		$this->assertSame([], $state['errors']);
		$this->assertSame('/pfblockerng/pfblockerng_edit_hooks.php?when=pre&script=hook_pre_created.sh', $state['redirect']);
		$this->assertFileExists($path);
		$this->assertSame(0700, fileperms($path) & 0777);
		$this->assertStringContainsString('#!/bin/sh', (string) file_get_contents($path));
	}

	public function testCreateFailureRestoresTheLoadedScriptAndBuffer(): void
	{
		$state = pfb_edit_hooks_request(
			[
				'pfb_eh_create' => '1', 'pfb_eh_new_when' => 'post', 'pfb_eh_new_core' => 'bad-name', 'pfb_eh_new_lang' => 'py',
				'pfb_eh_cur_when' => 'pre', 'pfb_eh_cur_script' => 'hook_pre_loaded.sh', 'pfb_eh_content' => "line\r\n",
			],
			[],
			$this->dir
		);
		$this->assertNotSame([], $state['errors']);
		$this->assertSame('pre', $state['sel_when']);
		$this->assertSame('hook_pre_loaded.sh', $state['sel_script']);
		$this->assertSame("line\n", $state['content']);
		$this->assertSame('bad-name', $state['new_core']);
		$this->assertSame('py', $state['new_lang']);
		$this->assertSame('post', $state['new_when']);
	}

	public function testEditHooksTabOnUpdatePage(): void
	{
		$tabs = pfb_edit_hooks_tabs('run');
		$this->assertSame(['Run', TRUE, '/pfblockerng/pfblockerng_update.php'], $tabs[0]);
		$this->assertSame(['Hooks', FALSE, '/pfblockerng/pfblockerng_hooks.php'], $tabs[1]);
		$this->assertSame(['Edit Hooks', FALSE, '/pfblockerng/pfblockerng_edit_hooks.php'], $tabs[2]);
	}

	public function testEditHooksTabOnHooksPage(): void
	{
		$tabs = pfb_edit_hooks_tabs('hooks');
		$this->assertSame(['Run', FALSE, '/pfblockerng/pfblockerng_update.php'], $tabs[0]);
		$this->assertSame(['Hooks', TRUE, '/pfblockerng/pfblockerng_hooks.php'], $tabs[1]);
		$this->assertSame(['Edit Hooks', FALSE, '/pfblockerng/pfblockerng_edit_hooks.php'], $tabs[2]);
	}

	public function testEditHooksTabOnItself(): void
	{
		$tabs = pfb_edit_hooks_tabs('edit');
		$this->assertSame(['Run', FALSE, '/pfblockerng/pfblockerng_update.php'], $tabs[0]);
		$this->assertSame(['Hooks', FALSE, '/pfblockerng/pfblockerng_hooks.php'], $tabs[1]);
		$this->assertSame(['Edit Hooks', TRUE, '/pfblockerng/pfblockerng_edit_hooks.php'], $tabs[2]);
	}

	public function testEditHooksTabIsActiveOnlyOnItself(): void
	{
		$active = array_map(static fn (array $tab): bool => $tab[1], pfb_edit_hooks_tabs('edit'));
		$this->assertSame([FALSE, FALSE, TRUE], $active);
	}

	public function testSavePathSanitizesContentBeforeWrite(): void
	{
		$path = $this->makeHook('hook_post_sanitize.sh');
		$content = "#!/bin/sh\r\necho ok  \r\n" . "bad\x01\r\n";
		$state = pfb_edit_hooks_request(
			['pfb_eh_save' => '1', 'pfb_eh_cur_when' => 'post', 'pfb_eh_cur_script' => basename($path), 'pfb_eh_content' => $content],
			[],
			$this->dir
		);
		$this->assertSame([], $state['errors']);
		$this->assertSame(pfb_sanitize_text_area($content), file_get_contents($path));
	}

	public function testSavePathNoLongerUsesTheHandRolledNormalizer(): void
	{
		$path = $this->makeHook('hook_post_shared.sh');
		$content = "a\r\nb  \r\n";
		$state = pfb_edit_hooks_request(
			['pfb_eh_save' => '1', 'pfb_eh_cur_when' => 'post', 'pfb_eh_cur_script' => basename($path), 'pfb_eh_content' => $content],
			[],
			$this->dir
		);
		$this->assertSame([], $state['errors']);
		$this->assertSame(pfb_sanitize_text_area($content), file_get_contents($path));
	}

	public function testSaveFlowWritesAtomicallyViaTempFileAndRename(): void
	{
		$path = $this->makeHook('hook_post_atomic.sh', "old\n");
		$before = fileinode($path);
		$state = pfb_edit_hooks_request(
			['pfb_eh_save' => '1', 'pfb_eh_cur_when' => 'post', 'pfb_eh_cur_script' => basename($path), 'pfb_eh_content' => "new\n"],
			[],
			$this->dir
		);
		$this->assertSame([], $state['errors']);
		$this->assertNotSame($before, fileinode($path));
		$this->assertSame("new\n", file_get_contents($path));
		$this->assertSame(0700, fileperms($path) & 0777);
		$this->assertSame([], glob($this->dir . '/.pfbeh_*') ?: []);
	}

	public function testLoadPathRejectsInvalidUtf8ContentBeforePopulatingEditor(): void
	{
		$path = $this->makeHook('hook_pre_invalid.sh', "#!/bin/sh\n\xFF\n");
		$state = pfb_edit_hooks_request([], ['when' => 'pre', 'script' => basename($path)], $this->dir);
		$this->assertNotSame([], $state['errors']);
		$this->assertSame('', $state['sel_script']);
		$this->assertSame('', $state['content']);
	}
}
