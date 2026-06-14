#shellcheck shell=sh
# pfblockerng.sh remove() entry guard — a path separator or '..' traversal in the
# alias/header must never reach the "rm -f ...${header}*" globs. The function
# self-defends instead of trusting the PHP caller to have sanitised the value.
#
# Both branches are pinned: a malicious alias aborts before any rm (sentinel
# survives); a malicious header is skipped (sentinel survives); a valid alias
# proceeds and removes its own files (before-state asserted: the file exists first).

Describe 'pfblockerng.sh remove() entry guard'
  BeforeAll 'pfb_source'

  # The variables below are consumed by the sourced remove() at runtime, which
  # ShellCheck cannot see — suppress the false "appears unused" (SC2034) reports.
  # shellcheck disable=SC2034
  setup_sandbox() {
    sandbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbrm.XXXXXX")"
    # remove() globs over these path prefixes.
    pfborig="${sandbox}/orig/"
    pfbdeny="${sandbox}/deny/"
    pfbmatch="${sandbox}/match/"
    pfbpermit="${sandbox}/permit/"
    pfbnative="${sandbox}/native/"
    mkdir -p "${pfborig}" "${pfbdeny}" "${pfbmatch}" "${pfbpermit}" "${pfbnative}"
    # An (empty) masterfile so the master-file bookkeeping is inert.
    masterfile="${sandbox}/master"
    mastercat="${sandbox}/mastercat"
    tempfile="${sandbox}/t1"
    tempfile2="${sandbox}/t2"
    : > "${masterfile}"
    # A sentinel OUTSIDE the sandbox that an unguarded traversal glob could delete.
    sentinel="${sandbox}/SENTINEL"
    : > "${sentinel}"
  }

  cleanup_sandbox() {
    rm -rf "${sandbox}"
  }

  It 'aborts before any rm when the alias contains a traversal sequence'
    setup_sandbox
    # When the alias escapes via '..' (header is irrelevant — entry guard fires first).
    alias='../evil'
    cc='Whatever_v4,'
    When call remove
    The status should equal 1
    The output should include 'Invalid alias'
    # Then the sentinel still exists — no rm ran.
    The path "${sentinel}" should be exist
    cleanup_sandbox
  End

  It 'aborts before any rm when the alias contains a path separator'
    setup_sandbox
    alias='etc/passwd'
    cc='Whatever_v4,'
    When call remove
    The status should equal 1
    The output should include 'Invalid alias'
    The path "${sentinel}" should be exist
    cleanup_sandbox
  End

  It 'skips a per-entry header that contains a traversal sequence'
    setup_sandbox
    # A benign alias passes the entry guard; the malicious value rides the header.
    alias='Benign'
    cc='../../SENTINEL,'
    When call remove
    The output should include 'Invalid header'
    # Then the sentinel survives — the malicious header never built an rm glob.
    The path "${sentinel}" should be exist
    cleanup_sandbox
  End

  # Wrapper: assert the file EXISTS before remove(), run remove(), report whether
  # it still exists after — so the test proves removal CAUSED the change.
  remove_valid_and_report() {
    if [ -f "${pfborig}GoodList_v4.txt" ]; then
      echo 'PRE:exists'
    else
      echo 'PRE:missing'
    fi
    remove
    if [ -f "${pfborig}GoodList_v4.txt" ]; then
      echo 'POST:exists'
    else
      echo 'POST:removed'
    fi
  }

  It 'proceeds and removes its own files for a valid alias/header'
    setup_sandbox
    # shellcheck disable=SC2034  # read by the sourced remove() via the wrapper
    alias='GoodList_v4'
    # shellcheck disable=SC2034
    cc='GoodList_v4,'
    : > "${pfborig}GoodList_v4.txt"
    When call remove_valid_and_report
    # Before-state: the file existed; After: it is gone (the valid path proceeds).
    The output should include 'PRE:exists'
    The output should include 'POST:removed'
    The output should include 'has been REMOVED'
    cleanup_sandbox
  End
End
