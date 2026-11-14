#shellcheck shell=sh
# whoisconvert() against the whois source-resolution corpus (issue #3974), schema 1: language-neutral JSON cases in
# tests/feedfetch/fixtures/whois. The shell is the oracle; Core's feedfetch.Whois is held to the same cases by
# go/pfb_core/feedfetch/whois_corpus_test.go, whose header documents the schema.
#
# Each case runs the REAL whoisconvert() with its own stand-ins on the path variables: a host(1) that answers from
# the case's table, a timeout(1) that records its argv and enforces with a real one, a php that counts the first-use
# asn.csv download (and writes the file when the case says the download makes it), and a temp asn.csv. The alias is
# always CorpusList. A blocking lookup waits on a fifo nobody writes, so only the batch deadline's own kill ends it.
# A lookup that "takes" N seconds moves a date(1) stand-in's clock instead of waiting. No duration is ever asserted.

# The batch's start time as ${now} holds it (1,000,000 s after the epoch, UTC): the corpus writes it as {now}.
WHOIS_NOW='1970-01-12 13:46:40'

WHOIS_CORPUS="${SHELLSPEC_PROJECT_ROOT}/tests/feedfetch/fixtures/whois"

whois_corpus_real_timeout() {
  # Issue #3615: uutils' timeout(1) kills only its direct child; GNU's, like the appliance's, kills the tree.
  whois_real_timeout="$(command -v gnutimeout || command -v timeout)"
  if [ -z "${whois_real_timeout}" ]; then
    echo "no timeout(1) on PATH: the corpus rows need a real one" >&2
    return 1
  fi
}

whois_corpus_stubs() {
  cat > "${pathhost}" <<'EOF'
#!/bin/sh
# host -t TYPE NAME, answering from ${HOST_TABLE} (name, kind, addresses, seconds taken; tab separated) and logging
# "TYPE NAME". Seconds taken move the clock file the date(1) stand-in reads.
printf '%s %s\n' "$2" "$3" >> "${HOST_LOG}"
row="$(NAME="$3" awk -F '\t' 'ENVIRON["NAME"] "" == $1 "" { print; exit }' "${HOST_TABLE}")"
if [ -z "${row}" ]; then
	echo "$3" >> "${HOST_UNLISTED}"
	exit 9
fi
taken="$(printf '%s\n' "${row}" | cut -f4)"
if [ "${taken:-0}" -gt 0 ]; then echo $(($(cat "${CLOCK_FILE}") + taken)) > "${CLOCK_FILE}"; fi
case "$(printf '%s\n' "${row}" | cut -f2)" in
answers)
	n=0
	for a in $(printf '%s\n' "${row}" | cut -f3); do
		case "${a}" in *:*) fam=AAAA ;; *) fam=A ;; esac
		[ "${fam}" = "$2" ] || continue
		if [ "${fam}" = A ]; then echo "$3 has address ${a}"; else echo "$3 has IPv6 address ${a}"; fi
		n=$((n + 1))
	done
	[ "${n}" -gt 0 ] || echo "$3 has no $2 record"
	exit 0 ;;
nxdomain) echo "Host $3 not found: 3(NXDOMAIN)"; exit 1 ;;
nxdomain-exit0) echo "Host $3 not found: 3(NXDOMAIN)"; exit 0 ;;
blocks) read -r _ < "${HOST_FIFO}"; exit 0 ;;
esac
exit 8
EOF
  cat > "${pathtimeout}" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${TIMEOUT_ARGS}"
exec "${REAL_TIMEOUT}" "$@"
EOF
  cat > "${pathphp}" <<'EOF'
#!/bin/sh
echo "$*" >> "${DOWNLOADS}"
if [ -n "${ASN_AFTER}" ]; then cp "${ASN_AFTER}" "${ASN_CSV}"; fi
exit 0
EOF
  cat > "${work}/bin/date" <<'EOF'
#!/bin/sh
case "$*" in
+%s) cat "${CLOCK_FILE}" ;;
*) exec "${REAL_DATE}" "$@" ;;
esac
EOF
  chmod +x "${pathhost}" "${pathtimeout}" "${pathphp}" "${work}/bin/date"
}

# whois_corpus_differ LABEL EXPECTED ACTUAL: record a mismatch with both sides on stderr.
whois_corpus_differ() {
  if [ "$2" != "$3" ]; then
    printf 'case %s: %s\n  expected: %s\n  actual:   %s\n' "${wc_name}" "$1" "$2" "$3" >&2
    wc_rc=1
  fi
}

# jq on the case; the one place a field is read.
whois_corpus_get() { "${pathjq}" "$@" "${wc_file}"; }

whois_corpus_has() { whois_corpus_get -e "$1" > /dev/null; }

whois_corpus_case() {
  wc_name="$1"
  wc_file="${WHOIS_CORPUS}/${wc_name}.json"
  wc_rc=0
  if [ ! -f "${wc_file}" ]; then
    echo "no corpus case ${wc_file}" >&2
    return 1
  fi
  whois_corpus_real_timeout || return 1

  work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoiscorpus.XXXXXX")"
  pfborig="${work}/orig/"
  mkdir -p "${pfborig}" "${work}/cwd" "${work}/bin"
  alias=CorpusList
  max="$(whois_corpus_get -r '.vtype')"
  dedup="$(whois_corpus_get -r '.list')"
  whoisbatchtimeout="$(whois_corpus_get -r '.whoisbatchtimeout // empty')"
  errorlog="${work}/error.log"
  pathasncsv="${work}/asn.csv"
  pathhost="${work}/host"
  pathtimeout="${work}/timeout"
  pathphp="${work}/php"
  pathpfbphp="${work}/pfblockerng.php"

  HOST_TABLE="${work}/hosts.tsv"
  HOST_LOG="${work}/lookups"
  HOST_UNLISTED="${work}/unlisted"
  HOST_FIFO="${work}/fifo"
  TIMEOUT_ARGS="${work}/timeout.args"
  DOWNLOADS="${work}/downloads"
  ASN_CSV="${pathasncsv}"
  ASN_AFTER=''
  REAL_TIMEOUT="${whois_real_timeout}"
  REAL_DATE="$(command -v date)"
  CLOCK_FILE="${work}/clock"
  export HOST_TABLE HOST_LOG HOST_UNLISTED HOST_FIFO TIMEOUT_ARGS DOWNLOADS ASN_CSV ASN_AFTER REAL_TIMEOUT REAL_DATE CLOCK_FILE
  echo 1000000 > "${CLOCK_FILE}"
  mkfifo "${HOST_FIFO}"
  true > "${HOST_LOG}"
  true > "${TIMEOUT_ARGS}"
  true > "${DOWNLOADS}"
  # A host's value: [addresses], a failure kind, or {addresses, takes}.
  whois_corpus_get -r '(.hosts // {}) | to_entries[] | .key as $name
    | (.value | if type == "array" then {kind: "answers", addresses: .}
        elif type == "object" then {kind: "answers"} + . else {kind: .} end)
    | [$name, .kind, ((.addresses // []) | join(" ")), ((.takes // 0) | tostring)] | join("\t")' > "${HOST_TABLE}"
  if whois_corpus_has '.asn_csv != null'; then whois_corpus_get -j '.asn_csv' > "${pathasncsv}"; fi
  if whois_corpus_has '.asn_csv_after_download != null'; then
    ASN_AFTER="${work}/asn.after"
    export ASN_AFTER
    whois_corpus_get -j '.asn_csv_after_download' > "${ASN_AFTER}"
  fi
  if whois_corpus_has '.seed != null'; then whois_corpus_get -j '.seed' > "${pfborig}${alias}.orig"; fi
  if whois_corpus_has '.seed_bk != null'; then whois_corpus_get -j '.seed_bk' > "${pfborig}${alias}.bk"; fi
  whois_corpus_stubs

  # Own cwd: an entry that executed would leave its file here. The date(1) stand-in is on the path only for a case
  # whose lookups take clock time; every other case reads the real clock.
  wc_path="${PATH}"
  if whois_corpus_has '[(.hosts // {})[] | select(type == "object" and has("takes"))] | length > 0'; then
    wc_path="${work}/bin:${PATH}"
  fi
  ( PATH="${wc_path}" && now="${WHOIS_NOW}" && cd "${work}/cwd" && whoisconvert > "${work}/stdout" 2> "${work}/stderr" )
  wc_status=$?
  whois_corpus_differ 'whoisconvert exit status' 0 "${wc_status}"
  whois_corpus_differ 'stderr' '' "$(cat "${work}/stderr")"
  whois_corpus_differ 'a host lookup the case does not list' '' "$(cat "${HOST_UNLISTED}" 2> /dev/null)"
  whois_corpus_differ 'files written outside the feed directory' '' "$(ls -A "${work}/cwd")"

  # The published copy, byte for byte.
  whois_corpus_get -j '.expect.orig' > "${work}/expect.orig"
  if [ ! -f "${pfborig}${alias}.orig" ]; then
    printf 'case %s: .orig is missing\n' "${wc_name}" >&2
    wc_rc=1
  elif ! cmp -s "${work}/expect.orig" "${pfborig}${alias}.orig"; then
    printf 'case %s: .orig differs (expected -> actual)\n' "${wc_name}" >&2
    diff -u "${work}/expect.orig" "${pfborig}${alias}.orig" >&2
    wc_rc=1
  fi

  # The update log, byte for byte; {now} stands for the batch's start time.
  whois_corpus_get -j --arg now "${WHOIS_NOW}" '.expect.log | gsub("\\{now\\}"; $now)' > "${work}/expect.log"
  if ! cmp -s "${work}/expect.log" "${work}/stdout"; then
    printf 'case %s: the update log differs (expected -> actual)\n' "${wc_name}" >&2
    diff -u "${work}/expect.log" "${work}/stdout" >&2
    wc_rc=1
  fi

  # Marker and leftovers: exactly .orig, plus .fail when expected; never .bk or .wk.
  wc_files="${alias}.orig"
  if [ "$(whois_corpus_get -r '.expect.fail')" = true ]; then
    wc_files="${alias}.fail
${alias}.orig"
  fi
  whois_corpus_differ 'files in the feed directory' "${wc_files}" "$(ls -A "${pfborig}")"

  whois_corpus_differ 'lookups' "$(whois_corpus_get -r '.expect.lookups[]?')" "$(cat "${HOST_LOG}")"
  whois_corpus_differ 'asn.csv downloads' "$(whois_corpus_get -r '.expect.downloads // 0')" "$(grep -c '' "${DOWNLOADS}")"
  whois_corpus_differ 'error.log' "$(whois_corpus_get -r '.expect.error_log[]?')" "$(cat "${errorlog}" 2> /dev/null)"

  # The first lookup's timeout argument sits in the window [lo, hi].
  wc_window="$(whois_corpus_get -r '(.expect.first_lookup_timeout // empty) | "\(.[0]) \(.[1])"')"
  if [ -n "${wc_window}" ]; then
    wc_first="$(sed -n "s|^-s TERM -k 5 \([0-9][0-9]*\) ${pathhost} -t .*|\1|p" "${TIMEOUT_ARGS}" | head -n 1)"
    wc_lo="${wc_window% *}"
    wc_hi="${wc_window#* }"
    if [ -z "${wc_first}" ] || [ "${wc_first}" -lt "${wc_lo}" ] || [ "${wc_first}" -gt "${wc_hi}" ]; then
      printf 'case %s: first lookup timeout\n  expected: %s..%s\n  actual:   %s\n' "${wc_name}" "${wc_lo}" "${wc_hi}" "${wc_first:-none}" >&2
      wc_rc=1
    fi
  fi

  # found: the log names a restored or empty copy exactly when no entry resolved.
  case "$(cat "${work}/stdout")" in
  *'... Restoring previous data'* | *'... Creating empty file'*) wc_found=false ;;
  *) wc_found=true ;;
  esac
  whois_corpus_differ 'found (at least one entry resolved)' "$(whois_corpus_get -r '.expect.found')" "${wc_found}"

  while IFS= read -r wc_needle; do
    [ -n "${wc_needle}" ] || continue
    case "$(cat "${work}/stdout")" in
    *"${wc_needle}"*) ;;
    *)
      printf 'case %s: the log lacks %s\n  log: %s\n' "${wc_name}" "${wc_needle}" "$(cat "${work}/stdout")" >&2
      wc_rc=1
      ;;
    esac
  done <<EOF
$(whois_corpus_get -r '.expect.log_includes[]?')
EOF
  return "${wc_rc}"
}

whois_corpus_names() { ls "${WHOIS_CORPUS}" | sed 's/\.json$//'; }

whois_corpus_cleanup() {
  rm -rf "${work:-}"
  work=
}

Describe 'whoisconvert() against the whois corpus (issue #3974)'
  BeforeAll 'pfb_source'
  After 'whois_corpus_cleanup'

  It 'has a corpus to run'
    When call whois_corpus_names
    The status should be success
    The output should include 'domain-v4'
  End

  Parameters:dynamic
    for whois_case_file in "${SHELLSPEC_PROJECT_ROOT}"/tests/feedfetch/fixtures/whois/*.json; do
      %data "$(basename "${whois_case_file}" .json)"
    done
  End

  It "keeps to case $1"
    When call whois_corpus_case "$1"
    The stderr should be blank
    The stdout should be blank
    The status should be success
  End
End
