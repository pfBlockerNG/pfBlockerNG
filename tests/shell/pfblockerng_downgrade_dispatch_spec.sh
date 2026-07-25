#!/usr/bin/env shellspec

Describe 'pfblockerng.sh downgrade dispatch (#1675)'
	It 'forwards exact positional arguments to the long-lived PHP entrypoint'
		When call grep -A28 'downgrade)' "${PFB_PKGDIR}/pfblockerng.sh"
		The output should include "/usr/local/bin/php -r '"
		The output should include '["authorization_sha256" => $argv[2] ?? ""]'
		The output should include "' -- \"\$@\""
		The output should include 'exitnow "$?"'
	End

	It 'keeps the transition out of the www entrypoint'
		When call grep -A28 'downgrade)' "${PFB_PKGDIR}/pfblockerng.sh"
		The output should not include 'pfblockerng.php'
		The output should include 'require_once("/usr/local/pkg/pfblockerng/pfblockerng.inc")'
	End
End
