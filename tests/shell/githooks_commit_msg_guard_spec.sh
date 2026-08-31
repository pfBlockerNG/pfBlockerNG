#shellcheck shell=sh

Describe 'commit-msg Co-authored-by trailer guard'
  hook="${PFB_ROOT}/.githooks/commit-msg"

  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/commit-msg-guard.XXXXXX")"
    message="${work}/message"
    expected_message="${work}/expected"
  }

  cleanup() {
    rm -rf "$work"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  message_identity() {
    if cmp -s "$expected_message" "$message"; then
      printf '%s\n' unchanged
    else
      printf '%s\n' changed
    fi
  }

  It 'passes a clean distinctive message byte-identical'
    printf '%s\n' 'commit-msg-guard-clean-7f9d3a' '' 'Distinctive body: keep every byte.' > "$message"
    cp "$message" "$expected_message"
    When run sh "$hook" "$message"
    The status should equal 0
    The stdout should equal ''
    The stderr should equal ''
    The result of function message_identity should equal unchanged
  End

  It 'rejects a canonical Co-authored-by trailer with the exact diagnostic'
    printf '%s\n' 'Guarded commit' '' 'Co-authored-by: Example Agent <agent@example.invalid>' > "$message"
    When run sh "$hook" "$message"
    The status should equal 1
    The stdout should equal ''
    The stderr should equal 'Co-authored-by trailers are forbidden'
  End

  It 'rejects a leading-whitespace mixed-case Co-authored-by token with the exact diagnostic'
    printf '\t  cO-aUtHoReD-bY: Example Agent <agent@example.invalid>\n' > "$message"
    When run sh "$hook" "$message"
    The status should equal 1
    The stdout should equal ''
    The stderr should equal 'Co-authored-by trailers are forbidden'
  End

  It 'rejects whitespace between Co-authored-by and its colon with the exact diagnostic'
    printf 'Co-authored-by \t: Example Agent <agent@example.invalid>\n' > "$message"
    When run sh "$hook" "$message"
    The status should equal 1
    The stdout should equal ''
    The stderr should equal 'Co-authored-by trailers are forbidden'
  End
End
