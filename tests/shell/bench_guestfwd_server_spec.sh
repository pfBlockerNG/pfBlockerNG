#shellcheck shell=sh
# bench_guestfwd_server_spec.sh — shellspec suite for
# tests/smoke/bench_guestfwd_server.sh, the inetd-style one-shot
# request/response server QEMU slirp's guestfwd -cmd: forks per connection
# (issue #584 Step 1 dual-path bench, wired into boot_vm.sh's net0).
#
# Feeds stdin directly (no QEMU involved) and asserts stdout + exit status.

Describe 'bench_guestfwd_server.sh'
  SCRIPT="${PFB_ROOT}/tests/smoke/bench_guestfwd_server.sh"

  It 'echoes a normal request line back prefixed with PFB_BENCH_OK'
    Data 'hello'
    When run script "$SCRIPT"
    The status should be success
    The output should equal 'PFB_BENCH_OK hello'
  End

  It 'responds with nothing on immediate EOF (no request line at all)'
    Data
    End
    When run script "$SCRIPT"
    The status should be success
    The output should equal ''
  End

  It 'responds with the empty payload on an empty request line'
    Data ''
    When run script "$SCRIPT"
    The status should be success
    The output should equal 'PFB_BENCH_OK '
  End

  It 'echoes a hostile shell-metacharacter payload back verbatim, unexecuted'
    Data '$(touch /tmp/pfb_bench_guestfwd_pwned) `id` "; rm -rf'
    When run script "$SCRIPT"
    The status should be success
    The output should equal 'PFB_BENCH_OK $(touch /tmp/pfb_bench_guestfwd_pwned) `id` "; rm -rf'
    The path "/tmp/pfb_bench_guestfwd_pwned" should not be exist
  End

  It 'echoes an oversized (~64KiB) line back intact'
    payload="$(awk 'BEGIN { for (i = 0; i < 65536; i++) s = s "a"; print s }')"
    Data "$payload"
    When run script "$SCRIPT"
    The status should be success
    The length of output should equal $((13 + 65536))
    The output should start with 'PFB_BENCH_OK aaaaaaaaaa'
    The output should end with 'aaaaaaaaaa'
  End

  It 'still responds when the final line has no trailing newline'
    # printf '%s' (no \n) reproduces a peer that closes mid-line; Data always
    # appends a trailing newline, so this case is driven by hand outside the
    # Data DSL to keep the input byte-exact.
    out="$(printf 'partial' | "$SCRIPT")"
    rc=$?
    The value "$rc" should equal 0
    The value "$out" should equal 'PFB_BENCH_OK partial'
  End
End
