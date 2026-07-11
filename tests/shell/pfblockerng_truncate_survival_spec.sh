#shellcheck shell=sh
# Legacy ": >" truncate-create sites (issue #1172).
#
# ":" is a POSIX special built-in (XCU 2.8.1): a redirection error on it exits a
# non-interactive strict-POSIX shell (ash/dash) ENTIRELY, skipping every abort/cleanup
# path below it. "true" is a regular built-in -- the same redirection error just fails
# that one command; the script continues. pfb_recompute() already made this swap (see
# its rationale comment); this spec pins the class fix for every remaining site.
#
# Probed this session (dash -c 'CMD > <directory>; echo rc=$?'):
#   ': >' on a directory  -> shell exits before the echo runs at all (no "rc=" line)
#   'true >' on a directory -> "rc=2" prints; the shell survives
#
# Because the pre-fix failure is a real shell exit, the two behavioural examples below
# run their target function via `When run` (a forked subshell, per the exitnow spec in
# pfblockerng_tempfile_spec.sh) -- never `When call`, which would take the whole
# shellspec process down with it.

# Structural guard: the exact class of legacy site, scoped to shipped shell sources
# (never tests/, which uses ": >" for ordinary fixture setup and is not part of this
# retirement).
_trunc_legacy_hits() {
	git -C "${PFB_ROOT}" grep -nE '(^|[;&|({[:space:]]):[[:space:]]*>' -- \
		src/usr/local/pkg/pfblockerng scripts
}

# process255(): truncate the dedupfile, then signal survival. `silently` swallows
# process255's own (irrelevant) stdout so only the marker is asserted.
_trunc255_run() {
	silently process255
	echo 'SURVIVED_255'
}

# pfb_aggregate(): union+swap into agg_tmp, then signal survival.
_truncagg_run() {
	silently pfb_aggregate agg v6 "${memberlist}" "${aggout}" "${consumer}"
	echo 'SURVIVED_AGG'
}

Describe 'legacy special-builtin truncate sites survive redirection failure (issue #1172)'
  BeforeAll 'pfb_source'

  Describe 'process255(): directory debris at its dedupfile truncate site'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/trunc255.XXXXXX")"
      pfbdeny="${work}/deny_"
      alias='Empty_v4'
      dedupfile="${work}/dedup"
      tempfile="${work}/t1"
      # Empty deny file -> data255 stays empty -> process255 never runs past the
      # truncate site under test into the octet-collapse body.
      : > "${pfbdeny}${alias}.txt"
      # Crash-leftover DIRECTORY at the dedupfile truncate target.
      mkdir "${dedupfile}"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'runs process255 to completion instead of exiting the shell on the truncate error'
      When run _trunc255_run
      The status should be success
      The output should include 'SURVIVED_255'
    End
  End

  Describe 'pfb_aggregate(): directory debris at its agg_tmp truncate site'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/truncagg.XXXXXX")"
      tempfile="${work}/t1"
      dedupfile="${work}/dedup"
      errorlog="${work}/err.log"
      memberlist="${work}/members"
      aggout="${work}/agg.txt"
      consumer="${work}/agg.lst"
      # No members -> the empty-union branch fires, which is the one guarded by
      # the agg_tmp truncate site under test.
      : > "${memberlist}"
      printf 'stale\n' > "${aggout}"
      # Crash-leftover DIRECTORY at agg_tmp ("${aggout}.tmp").
      mkdir "${aggout}.tmp"
    }
    cleanup() { rm -rf "$work"; }
    Before 'setup'
    After 'cleanup'

    It 'runs pfb_aggregate to completion (existing "keeping existing" abort path) instead of exiting the shell'
      When run _truncagg_run
      The status should be success
      The output should include 'SURVIVED_AGG'
      The contents of file "${errorlog}" should include 'failed; keeping existing'
      The contents of file "${aggout}" should equal 'stale'
    End
  End
End

Describe 'structural retirement guard: no legacy ": >" truncate sites remain in shipped shell sources (issue #1172)'
  # ADR-47 P5: scrub inherited GIT_* before the real `git grep` below -- an
  # inherited GIT_DIR (e.g. from the pre-commit hook) can override `-C` and
  # silently target the wrong repo.
  BeforeAll 'scrub_git_env'

  It 'has zero hits for the legacy special-builtin truncate pattern'
    When call _trunc_legacy_hits
    The status should be failure
    The output should equal ""
  End
End
