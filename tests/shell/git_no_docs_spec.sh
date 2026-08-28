#shellcheck shell=sh
# git_no_docs_spec.sh — pins scripts/git-no-docs.sh, the local companion to
# the linguist-documentation entries in .gitattributes: it runs a read-only
# git command (default `log -p`) with one ':(top,exclude)<pattern>' pathspec
# appended per linguist-documentation pattern, so doc-heavy commits show only
# their code lines locally (GitHub's linguist-documentation only affects
# language stats, never diff rendering — the script is the diff-side half of
# the pair).
#
# RED->GREEN evidence: the first four examples were authored before the
# script existed — every one failed ("cannot open .../git-no-docs.sh",
# nonzero status); all pass once the script landed. The hostile-input
# examples (subdirectory cwd, state-mutating subcommand, missing trailing
# newline, quoted pattern, CRLF, macro line) were authored against the
# first-cut script from PR #956's adversarial review findings and each
# failed on it before the corresponding fix.

Describe 'git-no-docs.sh'
  SCRIPT="${PFB_ROOT}/scripts/git-no-docs.sh"

  setup() {
    scrub_git_env
    repo=$(mktemp -d)
    git_fixture -C "$repo" init -q
    git_fixture -C "$repo" config user.name t
    git_fixture -C "$repo" config user.email t@t
    printf '%s\n' 'docsdir/** linguist-documentation' > "$repo/.gitattributes"
    mkdir -p "$repo/docsdir"
    printf 'doc line\n' > "$repo/docsdir/notes.md"
    printf 'code line\n' > "$repo/code.sh"
    git_fixture -C "$repo" add -A
    git_fixture -C "$repo" commit -qm 'mixed commit'
  }
  cleanup() {
    rm -rf "$repo"
  }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # shellcheck disable=SC2120  # args come from the `When call` DSL lines
  run_in_repo() {
    ( cd "$repo" && sh "$SCRIPT" "$@" )
  }

  It 'defaults to log -p and hides the documentation tree'
    When call run_in_repo
    The status should be success
    The output should include 'code.sh'
    The output should not include 'notes.md'
  End

  It 'still shows the doc-hidden commit itself'
    # Exclusion drops the doc LINES, never the commit from history.
    When call run_in_repo
    The output should include 'mixed commit'
  End

  It 'passes an explicit git command through with the excludes appended'
    When call run_in_repo show --stat HEAD
    The status should be success
    The output should include 'code.sh'
    The output should not include 'notes.md'
  End

  # Vacuity guard: without the loud failure the script would silently
  # degrade into plain `git log -p` and hide nothing.
  run_without_docattr() {
    printf '%s\n' 'docsdir/** linguist-generated' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'fails loudly when .gitattributes has no linguist-documentation entries'
    When call run_without_docattr
    The status should equal 1
    The stderr should include 'no linguist-documentation patterns'
  End

  # ── Hostile inputs (PR #956 review findings) ──────────────────────────────

  run_from_subdir() {
    mkdir -p "$repo/sub"
    ( cd "$repo/sub" && sh "$SCRIPT" )
  }

  It 'excludes the doc tree when run from a repo subdirectory'
    # ':(exclude)' without 'top' anchors at the cwd and silently stops
    # matching from anywhere but the repo root.
    When call run_from_subdir
    The status should be success
    The output should include 'code.sh'
    The output should not include 'notes.md'
  End

  It 'refuses state-mutating git subcommands'
    # `git add -A -- :(exclude)docsdir/**` really would skip the doc trees
    # from what git RECORDS — the tool must only ever affect the view.
    When call run_in_repo add -A
    The status should equal 1
    The stderr should include 'read-only git commands only'
  End

  run_without_trailing_newline() {
    printf '%s' 'docsdir/** linguist-documentation' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'honors a final .gitattributes line without a trailing newline'
    # Plain `while read` returns nonzero on EOF-without-newline and drops
    # the last line.
    When call run_without_trailing_newline
    The status should be success
    The output should include 'code.sh'
    The output should not include 'notes.md'
  End

  run_with_quoted_doc_pattern() {
    printf '%s\n' '"spacey dir/**" linguist-documentation' \
      'docsdir/** linguist-documentation' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'fails loudly on a quoted (space-containing) documentation pattern'
    # `read -r pattern attrs` mis-splits a C-quoted pattern into a dead
    # exclude; loud refusal beats a silent doc leak.
    When call run_with_quoted_doc_pattern
    The status should equal 1
    The stderr should include 'quoted pattern unsupported'
  End

  run_with_quoted_other_pattern() {
    printf '%s\n' '"spacey dir/**" linguist-vendored' \
      'docsdir/** linguist-documentation' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'skips a quoted pattern that does not carry linguist-documentation'
    When call run_with_quoted_other_pattern
    The status should be success
    The output should not include 'notes.md'
  End

  run_with_crlf() {
    printf 'docsdir/** linguist-documentation\r\n' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'parses CRLF line endings'
    When call run_with_crlf
    The status should be success
    The output should not include 'notes.md'
  End

  run_with_leading_slash() {
    printf '%s\n' '/docsdir/** linguist-documentation' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'honors a leading-slash (anchored) documentation pattern'
    # ':(top)' does not compose with a pattern's own leading slash — the
    # exclude silently matches nothing unless the slash is stripped.
    When call run_with_leading_slash
    The status should be success
    The output should include 'code.sh'
    The output should not include 'notes.md'
  End

  run_with_noglob_env() {
    ( cd "$repo" && GIT_NOGLOB_PATHSPECS=1 sh "$SCRIPT" )
  }

  It 'excludes the doc tree under GIT_NOGLOB_PATHSPECS (explicit glob magic)'
    # Without ':(glob)' magic the pattern inherits the ambient pathspec
    # mode and GIT_NOGLOB_PATHSPECS=1 turns the exclude into a dead
    # literal match.
    When call run_with_noglob_env
    The status should be success
    The output should include 'code.sh'
    The output should not include 'notes.md'
  End

  run_with_macro_only() {
    printf '%s\n' '[attr]mydoc linguist-documentation' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'does not count a macro definition line as a documentation pattern'
    # A macro line misread as a pattern would set found=1 and mask the
    # loud no-entries failure.
    When call run_with_macro_only
    The status should equal 1
    The stderr should include 'no linguist-documentation patterns'
  End

  run_with_false_value() {
    printf '%s\n' 'docsdir/** linguist-documentation=false' > "$repo/.gitattributes"
    run_in_repo
  }

  It 'does not treat linguist-documentation=false as a documentation pattern'
    When call run_with_false_value
    The status should equal 1
    The stderr should include 'no linguist-documentation patterns'
  End
End
