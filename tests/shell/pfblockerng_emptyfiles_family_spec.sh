#shellcheck shell=sh
# emptyfiles() must pad v6 aliases as ::<ip_placeholder>, matching apply.inc.
# A bare IPv4 write into *_v6.txt made the widget show 1 for an empty v6 feed.

Describe 'emptyfiles() pads v6 with a ::-prefixed placeholder'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/emptyfiles.XXXXXX")"
    pfbdeny="${work}/deny/"
    mkdir -p "$pfbdeny"
    ip_placeholder="127.1.7.7"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'writes the bare placeholder into a zero-byte v4 deny file'
    true > "${pfbdeny}Feed_v4.txt"
    When call emptyfiles
    The status should be success
    The contents of file "${pfbdeny}Feed_v4.txt" should include "${ip_placeholder}"
    The contents of file "${pfbdeny}Feed_v4.txt" should not include '::'
  End

  It 'writes a ::-prefixed placeholder into a zero-byte v6 deny file'
    true > "${pfbdeny}Feed_v6.txt"
    When call emptyfiles
    The status should be success
    The contents of file "${pfbdeny}Feed_v6.txt" should include "::${ip_placeholder}"
  End
End
