#shellcheck shell=sh
# issue #3167: per-feed _255_agg spawns paid mktemp/df/use_mfs_tmpvar grep on every
# invocation even when the verb never reads those values. Leave the fan-out; move
# that work behind the verbs that need it. #3144's config.xml grep rides along
# (only aliastables() consults USE_MFS_TMPVAR / DISK_TYPE).

init_block() {
	sed -n '/^if \[ -z "\${PFB_SOURCED:-}" \]; then/,/^fi$/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

star_arm() {
	sed -n '/^[[:space:]]*_\*)/,/^[[:space:]]*;;/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

aliastables_fn() {
	sed -n '/^aliastables() {/,/^}$/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

Describe 'pfblockerng.sh lazy init (issue #3167)'
	BeforeAll 'pfb_source'

	Describe 'always-init no longer pays per-spawn scratch or mfs probes'
		It 'does not mktemp in the PFB_SOURCED init block'
			When call init_block
			The output should not include 'pfb_make_tmpdir'
		End

		It 'does not grep use_mfs_tmpvar in the PFB_SOURCED init block'
			When call init_block
			The output should not include 'use_mfs_tmpvar'
		End

		It 'does not df in the PFB_SOURCED init block'
			When call init_block
			The output should not include '/bin/df'
		End
	End

	Describe 'verbs that need scratch call pfb_ensure_tmpdir'
		It 'the _255/_agg/_rep arm ensures tmpdir before the preprocess functions'
			When call star_arm
			The output should include 'pfb_ensure_tmpdir'
		End
	End

	Describe 'aliastables is the mfs/disk probe consumer'
		It 'ensures mfs/disk state before reading USE_MFS_TMPVAR'
			When call aliastables_fn
			The output should include 'pfb_ensure_mfs'
		End
	End

	Describe 'pfb_ensure_tmpdir'
		After 'rm -rf "${tmpdir:-}"'

		It 'creates the private tmpdir and xlsx scratch once'
			When call pfb_ensure_tmpdir
			The variable tmpdir should match pattern "*/pfb.*"
			The path "$tmpdir" should be directory
			The path "$tmpxlsx" should be directory
		End

		It 'is idempotent'
			pfb_ensure_tmpdir
			first="${tmpdir}"
			When call pfb_ensure_tmpdir
			The variable tmpdir should equal "${first}"
		End
	End

End
