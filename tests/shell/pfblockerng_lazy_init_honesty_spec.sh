#shellcheck shell=sh
# issue #3167 review pins: keep source-shape checks non-vacuous and ordered.

init_block() {
	sed -n '/^if \[ -z "\${PFB_SOURCED:-}" \]; then/,/^fi$/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

star_arm() {
	sed -n '/^[[:space:]]*_\*)/,/^[[:space:]]*;;/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

aliastables_fn() {
	sed -n '/^aliastables() {/,/^}$/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

exitnow_fn() {
	sed -n '/^exitnow() {/,/^}$/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

star_ensure_before_process255() {
	star_arm | awk '/pfb_ensure_tmpdir/{e=NR} /process255/{p=NR} END{if (e && p && e < p) print "ok"; else print "bad"}'
}

aliastables_ensure_before_read() {
	aliastables_fn | awk '/pfb_ensure_mfs/{e=NR} /USE_MFS_TMPVAR/{r=NR} END{if (e && r && e < r) print "ok"; else print "bad"}'
}

Describe 'pfblockerng.sh lazy init review pins (issue #3167)'
	BeforeAll 'pfb_source'

	It 'extracts a real init block without scratch or ensure work'
		When call init_block
		The output should include 'PFB_SOURCED'
		The output should not include 'pfb_ensure_tmpdir'
		The output should not include 'pfb_ensure_mfs'
		The output should not include 'mktemp'
	End

	It 'places pfb_ensure_tmpdir before process255 in the _*) arm'
		When call star_ensure_before_process255
		The output should equal 'ok'
	End

	It 'places pfb_ensure_mfs before USE_MFS_TMPVAR in aliastables'
		When call aliastables_ensure_before_read
		The output should equal 'ok'
	End

	It 'guards exitnow rm on a nonempty tmpdir'
		When call exitnow_fn
		The output should include '[ -n "${tmpdir:-}" ]'
	End

	Describe 'pfb_ensure_tmpdir sentinel'
		After 'rm -rf "${tmpdir:-}"; pfb_tmpdir_ready='

		It 'sets the ready sentinel after creating scratch'
			When call pfb_ensure_tmpdir
			The variable pfb_tmpdir_ready should equal 1
		End
	End
End
