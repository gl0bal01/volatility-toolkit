#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for vol-analyze.sh
# Run: make test  (or: bash tests/test_vol_analyze.sh)
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
SCRIPT="${PROJECT_DIR}/scripts/vol-analyze.sh"

# Disable -eu while sourcing so unset script-runtime globals don't abort
# the test harness. The BASH_SOURCE guard prevents main() from running.
set +eu
# shellcheck source-path=SCRIPTDIR/.. source=scripts/vol-analyze.sh
source "$SCRIPT"
set -eu

PASS=0
FAIL=0
TESTS_RUN=0

# ─── Test helpers ─────────────────────────────────────────────────────────────

pass() { (( ++PASS )); (( ++TESTS_RUN )); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
skip() { printf '  - skipped: %s\n' "$1"; }
fail() { (( ++FAIL )); (( ++TESTS_RUN )); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$label"
    else
        fail "$label (expected: '$expected', got: '$actual')"
    fi
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        pass "$label"
    else
        fail "$label (expected to contain: '$needle')"
    fi
}

assert_exit_code() {
    local label="$1" expected="$2"
    shift 2
    local actual=0
    "$@" &>/dev/null || actual=$?
    if (( actual == expected )); then
        pass "$label"
    else
        fail "$label (expected exit $expected, got $actual)"
    fi
}

# Re-source would hit `readonly` redeclaration errors; we source once at
# top-level and just reset colors here.
setup_harness() {
    NO_COLOR=1 setup_colors
}

# ─── Tests: safe_name ─────────────────────────────────────────────────────────

test_safe_name() {
    printf '\n\033[1msafe_name()\033[0m\n'
    setup_harness

    assert_eq "strips windows prefix" "pslist" "$(safe_name "windows.pslist")"
    assert_eq "strips linux prefix" "pslist" "$(safe_name "linux.pslist")"
    assert_eq "strips mac prefix" "pslist" "$(safe_name "mac.pslist")"
    assert_eq "converts dots to underscores" "registry_hivelist" "$(safe_name "windows.registry.hivelist")"
    assert_eq "handles nested dots" "proc_Maps" "$(safe_name "linux.proc.Maps")"
    assert_eq "strips malware namespace" "check_syscall" "$(safe_name "linux.malware.check_syscall")"
    assert_eq "no prefix passes through" "something" "$(safe_name "something")"
}

# ─── Tests: json_escape ──────────────────────────────────────────────────────

test_json_escape() {
    printf '\n\033[1mjson_escape()\033[0m\n'
    setup_harness

    assert_eq "plain string unchanged" "hello world" "$(json_escape "hello world")"
    assert_eq "escapes backslash" "foo\\\\bar" "$(json_escape 'foo\bar')"
    assert_eq "escapes double quote" 'foo\"bar' "$(json_escape 'foo"bar')"
    assert_eq "escapes newline" "line1\\nline2" "$(json_escape $'line1\nline2')"
    assert_eq "escapes tab" "col1\\tcol2" "$(json_escape $'col1\tcol2')"
    assert_eq "escapes carriage return" "a\\rb" "$(json_escape $'a\rb')"
    assert_eq "empty string" "" "$(json_escape "")"
    assert_eq "escapes backspace" "a\\bb" "$(json_escape $'a\bb')"
    assert_eq "escapes form feed" "a\\fb" "$(json_escape $'a\fb')"
}

# ─── Tests: resolve_path ─────────────────────────────────────────────────────

test_resolve_path() {
    printf '\n\033[1mresolve_path()\033[0m\n'
    setup_harness

    local resolved
    resolved=$(resolve_path "$SCRIPT")
    assert_eq "resolves to absolute path" "$SCRIPT" "$resolved"

    # Relative path should become absolute
    local rel_resolved
    rel_resolved=$(cd "$PROJECT_DIR" && resolve_path "tests/../scripts/vol-analyze.sh")
    assert_contains "relative path resolves" "/scripts/vol-analyze.sh" "$rel_resolved"
}

# ─── Tests: argument parsing (via script invocation) ─────────────────────────

test_arg_parsing() {
    printf '\n\033[1margument parsing\033[0m\n'

    # --help should exit 0
    assert_exit_code "--help exits 0" 0 bash "$SCRIPT" --help

    # --version should exit 0
    assert_exit_code "--version exits 0" 0 bash "$SCRIPT" --version

    # No arguments should exit 1
    assert_exit_code "no args exits 1" 1 bash "$SCRIPT"

    # Unknown option should exit 1
    assert_exit_code "unknown option exits 1" 1 bash "$SCRIPT" --bogus

    # Non-existent file should exit 1
    assert_exit_code "missing file exits 1" 1 bash "$SCRIPT" /nonexistent/file.raw

    # --version output contains version string
    local ver_output
    ver_output=$(bash "$SCRIPT" --version 2>&1)
    assert_contains "--version shows version" "v4.0.0" "$ver_output"
}

# ─── Tests: validation ───────────────────────────────────────────────────────

test_validation() {
    printf '\n\033[1mvalidation\033[0m\n'

    # Create a fake vol binary so validation gets past the command check
    local fake_bin
    fake_bin=$(mktemp -d)
    printf '#!/bin/sh\nexit 1\n' > "${fake_bin}/vol"
    chmod +x "${fake_bin}/vol"

    # Symlink rejection
    local tmpdir
    tmpdir=$(mktemp -d)
    touch "${tmpdir}/real.raw"
    ln -s "${tmpdir}/real.raw" "${tmpdir}/link.raw"
    local sym_output
    sym_output=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "${tmpdir}/link.raw" 2>&1) || true
    assert_contains "rejects symlink input" "symlink" "$sym_output"
    rm -rf "$tmpdir"

    # Invalid --os value. macOS mktemp doesn't accept --suffix, so create a
    # temp dir and stage a .raw file inside it.
    local tmpfile_dir tmpfile
    tmpfile_dir=$(mktemp -d)
    tmpfile="${tmpfile_dir}/sample.raw"
    : > "$tmpfile"
    local os_output
    os_output=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" --os bogus 2>&1) || true
    assert_contains "rejects invalid --os" "Invalid --os" "$os_output"

    # Invalid --jobs value
    local jobs_output
    jobs_output=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" --jobs abc 2>&1) || true
    assert_contains "rejects non-numeric --jobs" "Invalid --jobs" "$jobs_output"

    local sym_out
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" --symbols "${tmpfile_dir}/nope" 2>&1) || true
    assert_contains "rejects missing --symbols dir" "Symbols directory not found" "$sym_out"
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" --isf-url "http://example.com/banners.json" 2>&1) || true
    assert_contains "rejects plain-http --isf-url" "Invalid --isf-url" "$sym_out"
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" --isf-url "file://${tmpfile_dir}/none.json" 2>&1) || true
    assert_contains "rejects missing file:// ISF index" "ISF index not found" "$sym_out"
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" --isf-url $'https://x/a\nPlugins' 2>&1) || true
    assert_contains "rejects line breaks in --isf-url" "control characters" "$sym_out"
    # The check runs first: the name never reaches a message or the terminal.
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" $'mem\e]0;x\a.raw' 2>&1) || true
    assert_contains "rejects escape sequences in the dump path" "control characters" "$sym_out"
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" $'mem\xc2\x9b31m.raw' 2>&1) || true
    assert_contains "rejects C1 control characters (UTF-8 CSI)" "control characters" "$sym_out"
    # A symlinked parent directory can carry them in the resolved path.
    mkdir "${tmpfile_dir}/"$'ev\nMD5'
    : > "${tmpfile_dir}/"$'ev\nMD5/mem.raw'
    ln -s $'ev\nMD5' "${tmpfile_dir}/case"
    assert_contains "rejects control characters in the resolved dump path" "control characters" \
        "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "${tmpfile_dir}/case/mem.raw" 2>&1)"
    assert_contains "rejects control characters in the resolved output path" "control characters" \
        "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "${tmpfile_dir}/case/out" 2>&1)"
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" $'--x\e[31m' 2>&1) || true
    if [[ "$sym_out" == *"Unknown option"* && "$sym_out" != *$'\e'* ]]; then
        pass "unknown option is shown escaped"
    else
        fail "unknown option is shown escaped"
    fi
    mkdir "${tmpfile_dir}/a;b"
    sym_out=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" --symbols "${tmpfile_dir}/a;b" 2>&1) || true
    assert_contains "rejects ';' in --symbols path" "must not contain ';'" "$sym_out"

    # System directory rejection
    local sysdir_output
    sysdir_output=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o /etc/bad 2>&1) || true
    assert_contains "rejects /etc as output" "system directory" "$sysdir_output"

    local procdir_output
    procdir_output=$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o /proc/bad 2>&1) || true
    assert_contains "rejects /proc as output" "system directory" "$procdir_output"

    local top
    for top in /etc /etc/ / /usr /tmp/../etc; do
        assert_contains "rejects ${top} as output" "system directory" \
            "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "$top" 2>&1)"
    done
    ln -s /etc "${tmpfile_dir}/etclink"
    assert_contains "rejects a symlink to /etc as output" "system directory" \
        "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "${tmpfile_dir}/etclink" 2>&1)"
    # Parents still to be created: the nearest existing one is resolved.
    for top in "${tmpfile_dir}/etclink/a/b" /tmp/../etc/zz/yy; do
        assert_contains "rejects ${top} as output" "system directory" \
            "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "$top" 2>&1)"
    done
    assert_contains "rejects .. after a directory still to be created" "'..' after a directory" \
        "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "${tmpfile_dir}/nx/../../../../../../../etc/zz" 2>&1)"

    assert_contains "rejects an unexpected VOL3_CMD" "unexpected binary" \
        "$(VOL3_CMD=/bin/ls bash "$SCRIPT" "$tmpfile" 2>&1)"

    # A used directory could hold planted symlinks or another dump's results.
    mkdir "${tmpfile_dir}/used"
    : > "${tmpfile_dir}/used/pslist.txt"
    assert_contains "rejects a non-empty output dir" "not empty" \
        "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "${tmpfile_dir}/used" 2>&1)"
    chmod 300 "${tmpfile_dir}/used"   # ls -A fails, prints nothing
    if (( EUID == 0 )); then
        skip "unreadable output dir (root reads it anyway)"
    else
        assert_contains "rejects an unreadable output dir" "not readable" \
            "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "${tmpfile_dir}/used" 2>&1)"
    fi
    chmod 700 "${tmpfile_dir}/used"

    mkdir "${tmpfile_dir}/groupw"
    chmod 775 "${tmpfile_dir}/groupw"
    assert_contains "rejects group-writable existing output dir" "writable by group/others" \
        "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o "${tmpfile_dir}/groupw" 2>&1)"
    # /tmp: not ours (root) and world-writable — either check must refuse it.
    assert_contains "rejects /tmp as output" "Output directory is" \
        "$(PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" -o /tmp 2>&1)"

    assert_contains "rejects non-numeric VOL_DETECT_TIMEOUT" "Invalid VOL_DETECT_TIMEOUT" \
        "$(VOL_DETECT_TIMEOUT=abc PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" 2>&1)"

    rm -rf "$tmpfile_dir"
    rm -rf "$fake_bin"
}

# ─── Tests: end-to-end runs against a fake vol ───────────────────────────────

# Bound each run so a scheduler regression fails instead of hanging CI.
# -k: SIGKILL 5s later in case a regression makes the script ignore TERM.
# GNU timeout first: uutils timeout (Ubuntu 26.04's default) refuses
# arguments that are not UTF-8 (the latin-1 file name test).
with_timeout() {
    local t
    for t in gtimeout gnutimeout timeout; do
        command -v "$t" &>/dev/null && { "$t" -k 5 "$@"; return; }
    done
    shift; "$@"
}

# Symbolic mode string, e.g. drwx------ (GNU stat, then BSD/macOS stat).
mode_of() { stat -c %A "$1" 2>/dev/null || stat -f %Sp "$1"; }

# Fake vol: last argument is the plugin. check_idt fails the way vol does on
# an unsatisfied requirement; `slow` mode stands in for a long-running plugin
# and logs the signal that stops it to `sigs` (FAKE_ONLY_HANG: only that
# plugin is slow). `order` logs start/end; linux.pslist (first linux plugin)
# takes a second so a plugin started alongside it would show up before its end.
make_fake_vol() {
    local dir="$1" mode="${2:-fast}"
    if [[ "$mode" == slow ]]; then
        # linux.pslist, the first plugin, runs alone; let it finish so the
        # parallel phase starts.
        cat > "${dir}/vol" <<EOF
#!/bin/sh
for last; do :; done
[ "\$last" = linux.pslist ] && exit 0
[ -n "\${FAKE_ONLY_HANG:-}" ] && [ "\$last" != "\$FAKE_ONLY_HANG" ] && exit 0
trap 'kill \$! 2>/dev/null; echo INT >> "${dir}/sigs"; exit 130' INT
trap 'kill \$! 2>/dev/null; echo TERM >> "${dir}/sigs"; exit 143' TERM
echo "\$\$" >> "${dir}/pids"
sleep 30 &
wait
EOF
    else
        cat > "${dir}/vol" <<EOF
#!/bin/sh
for last; do :; done
prev=
for a; do
    [ "\$prev" = -l ] && echo "DEBUG    volatility3.framework.automagic.symbol_finder Using symbol library: file:///isf/fake.json.xz" >> "\$a"
    prev=\$a
done
echo "\$*" >> "${dir}/calls"
echo "start \$last" >> "${dir}/order"
[ "\$last" = linux.pslist ] && sleep 1
# Someone who can write to the parent swaps the output directory mid-run.
if [ "\$last" = linux.pslist ] && [ -n "\${FAKE_SWAP:-}" ]; then
    mv "\$FAKE_SWAP" "\$FAKE_SWAP.moved" && mkdir "\$FAKE_SWAP"
fi
trap 'echo "end \$last" >> "${dir}/order"' EXIT
case "\$last" in
    *check_idt) echo "Unsatisfied requirement"; echo "boom" >&2; exit 1 ;;
    *.pstree) [ -n "\${FAKE_ALL_FAIL:-}" ] && exit 1; echo "WARNING  volatility3: partial result" >&2 ;;
    --dump) printf 'Offset\tFile output\n'; exit 0 ;;
    windows.info) [ -n "\${FAKE_NOT_WINDOWS:-}" ] && exit 1 ;;
    *) [ -n "\${FAKE_ALL_FAIL:-}" ] && exit 1 ;;
esac
printf 'PID\tName\n1\tinit\n'
EOF
    fi
    chmod +x "${dir}/vol"
}

test_end_to_end() {
    printf '\n\033[1mend-to-end (fake vol)\033[0m\n'

    local work rc=0 out
    work=$(mktemp -d)
    make_fake_vol "$work"
    # Backslash in the name: GNU md5sum escapes it, which used to corrupt
    # the recorded hash and the JSON.
    local dump="${work}/case\\mem.raw"
    printf 'junk http://evil.com/payload c2.badguy.com c2.evil.sh connect 10.13.37.1... 931.331.331.353 1.3.6.1.4.1.311 System.Configuration ntdll.pdb run.sh libfoo-2.0.so junk\n' > "$dump"
    # Real hosts in odd forms, then noise seen in real dumps; 10.0.0.5.443 is
    # macOS netstat's address.port.
    printf 'LOGIN.EVIL-CORP.COM X.org t.me console.aws.amazon.com payload.example.com.EXE Shop.Allegro.pl 0.9.18.2 url=https%%3A%%2F%%2Fescaped.example.org q%%3Dleak.example.net u%%252Fdouble.example.org e.target Date.now this.data System.IO microsoft.windows Exploit:O97M/CVE-2017-0199.AL CMD.EXE-CD245F9E.pf PROVIDERDEFINITION.MICROSOFT.WINDOWS.INK.WORKSPACE .note.gnu.build-id .data.rel.ro .rela.got .text.hot .rela.gnu.linkonce.td GNU.sparse.map ftp.gnu.org self.c2-panel.top text.evil-cdn.net cdn.rel.ro com.apple.audio com.c2-panel.top 10.0.0.5.443\n' >> "$dump"
    # Hosts an attacker can register to look like noise; c2.trail.top_ ends
    # in an underscore, a word character for grep. Then a printable run
    # longer than the 8 KiB fold width.
    printf 'evil-c2.app 4444.top navigator.top q.ai EVILC2.COM Evil-C2.Top c2.trail.top_ host=c2.port.top_443 browser_win.cc\n%070000d\n' 0 >> "$dump"

    # Zero-padded -j also checks base-10 parsing ("08" is invalid octal).
    out=$(PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux \
        -o "${work}/out" -j 08 --json --extract-strings 2>&1) || rc=$?
    assert_eq "linux run exits 0" "0" "$rc"
    assert_contains "all plugins reported" "20/21 succeeded, 1 with errors" "$out"
    assert_eq "every plugin invoked once" "21" "$(wc -l < "${work}/calls" | tr -d ' ')"
    assert_eq "vol always called with -q" "21" "$(grep -c '^-q ' "${work}/calls")"
    assert_eq "only the first plugin writes vol.log" "1" "$(grep -c -- ' -l ' "${work}/calls")"
    assert_eq "first plugin runs alone (warms vol caches)" "end linux.pslist" "$(sed -n 2p "${work}/order")"
    assert_eq "new output dir is 700" "drwx------" "$(mode_of "${work}/out")"

    local report="${work}/out/analysis_summary.txt"
    assert_contains "text report marks failure" "FAILED   linux.malware.check_idt" "$(cat "$report")"
    assert_contains "text report marks success" "SUCCESS  linux.pslist" "$(cat "$report")"
    assert_contains "text report names the symbols vol used" "Symbols Used: file:///isf/fake.json.xz" "$(cat "$report")"
    assert_contains "text report marks exit 0 with stderr as warning" "WARNING  linux.pstree" "$(cat "$report")"
    local md5
    md5=$( (md5sum 2>/dev/null || md5 -q) < "$dump" | cut -d' ' -f1)
    if [[ -n "$md5" ]]; then
        assert_contains "text report has the dump's MD5" "MD5         : ${md5}" "$(cat "$report")"
    else
        skip "MD5 in the text report (no md5sum or md5)"
    fi
    if grep -qE 'MD5 +: N/A|SHA256 +: N/A' "$report"; then
        fail "checksums computed"
    else
        pass "checksums computed"
    fi

    local json="${work}/out/analysis_summary.json"
    if command -v python3 &>/dev/null; then
        assert_exit_code "JSON report is valid JSON" 0 python3 -m json.tool "$json"
    else
        fail "python3 not installed — required to validate the JSON report"
    fi
    assert_contains "JSON counts failures" '"plugins_failed": 1' "$(cat "$json")"
    assert_contains "JSON has per-plugin exit code" '"linux.malware.check_idt": {"status": "failed", "exit_code": 1' "$(cat "$json")"
    assert_contains "JSON names the symbols vol used" '"symbols_used": "file:///isf/fake.json.xz"' "$(cat "$json")"

    local domains host
    domains=$(cat "${work}/out/strings/domains.txt")
    # Leading space: the whole name, not a glued-on escape like 2Fescaped...
    for host in evil.com c2.evil.sh login.evil-corp.com x.org t.me console.aws.amazon.com \
            payload.example.com shop.allegro.pl ftp.gnu.org self.c2-panel.top text.evil-cdn.net cdn.rel.ro escaped.example.org leak.example.net double.example.org \
            c2.trail.top c2.port.top; do
        assert_contains "IOC: domain kept: ${host}" " ${host}" "$domains"
    done
    if [[ -n "$domains" ]] \
            && ! grep -qiE 'system|pdb|run\.sh|libfoo|target|now|this|windows|cve|cd245f9e|providerdefinition|note\.gnu|data\.rel\.ro|linkonce|rela\.got|text\.hot|sparse' <<< "$domains"; then
        pass "IOC: non-TLD names, file names, JS and signature names dropped from domains"
    else
        fail "IOC: non-TLD names, file names, JS and signature names dropped from domains"
    fi
    local lowconf
    lowconf=$(cat "${work}/out/strings/domains_lowconf.txt")
    for host in evil-c2.app 4444.top navigator.top q.ai evilc2.com evil-c2.top run.sh system.io; do
        if [[ "$lowconf" == *" ${host}"* && "$domains" != *" ${host}"* ]]; then
            pass "IOC: look-alike name kept in domains_lowconf.txt: ${host}"
        else
            fail "IOC: look-alike name kept in domains_lowconf.txt: ${host}"
        fi
    done
    if grep -q 'win\.cc' <<< "$domains$lowconf"; then
        fail "IOC: inner underscores do not split names (browser_win.cc)"
    else
        pass "IOC: inner underscores do not split names (browser_win.cc)"
    fi
    local rdns
    rdns=$(cat "${work}/out/strings/reverse_dns.txt")
    assert_contains "IOC: reverse-DNS IDs go to reverse_dns.txt" " com.apple.audio" "$rdns"
    assert_contains "IOC: a com.* host lands in reverse_dns.txt, not lost" " com.c2-panel.top" "$rdns"
    if grep -q ' com\.' <<< "$domains"; then
        fail "IOC: reverse-DNS IDs kept out of domains.txt"
    else
        pass "IOC: reverse-DNS IDs kept out of domains.txt"
    fi
    assert_exit_code "IOC: all.txt written" 0 test -s "${work}/out/strings/all.txt"
    assert_eq "IOC: all.txt folded at 8 KiB" "" "$(awk 'length > 8192 { print NR }' "${work}/out/strings/all.txt")"
    assert_contains "IOC: URL extracted" "http://evil.com/payload" "$(cat "${work}/out/strings/urls.txt")"
    assert_eq "IOC: only the valid IPv4 extracted (no address.port off macOS)" "10.13.37.1" "$(cat "${work}/out/strings/ipv4.txt")"

    PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os mac \
        -o "${work}/mac" --extract-strings &>/dev/null || true
    assert_eq "IOC: macOS address.port gives its address" "10.0.0.5 10.13.37.1" "$(tr '\n' ' ' < "${work}/mac/strings/ipv4.txt" | sed 's/ $//')"

    # Default path: no --os. windows.info fails, so the linux probe must win.
    out=$(FAKE_NOT_WINDOWS=1 PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" \
        -o "${work}/auto" 2>&1) || true
    assert_contains "auto-detects linux" "Detected: linux" "$out"
    assert_contains "auto-detect runs linux plugins" "21 plugins" "$out"

    # Relative VOL3_CMD (the script changes directory), an output dir that
    # looks like an option, and a backslash in it (awk -v would decode it).
    rc=0
    (cd "$work" && VOL3_CMD=./vol with_timeout 60 bash "$SCRIPT" "$dump" --os linux \
        -o '-rel\001' --extract-strings &>/dev/null) || rc=$?
    assert_eq "relative VOL3_CMD and -o -dir work" "0" "$rc"
    assert_exit_code "domains.txt written with a backslash in -o" 0 test -s "${work}/-rel\\001/strings/domains.txt"

    # An existing empty directory is used as is, without chmod.
    mkdir "${work}/shared"
    chmod 755 "${work}/shared"
    PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux -o "${work}/shared" &>/dev/null || true
    assert_eq "existing output dir keeps its mode" "drwxr-xr-x" "$(mode_of "${work}/shared")"
    assert_eq "files in existing dir are 600" "-rw-------" "$(mode_of "${work}/shared/pslist.txt")"
    assert_contains "re-run into a used output dir is refused" "not empty" \
        "$(PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux -o "${work}/shared" 2>&1)"

    # The run keeps writing to the directory it checked, not to whatever is
    # at that path later.
    FAKE_SWAP="${work}/swap" PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux \
        -o "${work}/swap" &>/dev/null || true
    assert_exit_code "outputs stay in the directory the run started in" 0 \
        test -f "${work}/swap.moved/analysis_summary.txt"
    assert_eq "a directory swapped in mid-run gets nothing" "" "$(ls -A "${work}/swap")"

    # JSON must be UTF-8 (APFS refuses such names, so macOS skips this).
    local latin="${work}/caf"$'\351'".raw"
    if cp "$dump" "$latin" 2>/dev/null; then
        PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$latin" --os linux \
            -o "${work}/latin" --json &>/dev/null || true
        assert_exit_code "JSON stays valid for a latin-1 file name" 0 \
            python3 -m json.tool "${work}/latin/analysis_summary.json"
    else
        skip "latin-1 file name (filesystem refuses it)"
    fi

    rc=0
    FAKE_ALL_FAIL=1 PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux \
        -o "${work}/allfail" &>/dev/null || rc=$?
    assert_eq "exits 1 when no plugin succeeds" "1" "$rc"

    # A copy without share/volatility-toolkit/tlds.txt beside it skips domains.
    mkdir "${work}/bare"
    cp "$SCRIPT" "${work}/bare/vol-analyze.sh"
    out=$(PATH="${work}:${PATH}" with_timeout 60 bash "${work}/bare/vol-analyze.sh" "$dump" --os linux \
        -o "${work}/notld" --extract-strings 2>&1) || true
    assert_contains "warns when the TLD list is missing" "TLD list not found" "$out"

    rm -rf "$work"
}

test_windows_strings() {
    printf '\n\033[1mWindows IOC strings\033[0m\n'

    local work rc=0
    work=$(mktemp -d)
    make_fake_vol "$work"
    {
        printf 'junk C:\\Windows\\Temp\\evil.exe junk\n'
        # UTF-16LE "wide.example.net" — the common encoding for Windows strings
        local s="wide.example.net" k
        for (( k=0; k<${#s}; k++ )); do printf '%s\0' "${s:k:1}"; done
    } > "${work}/mem.raw"

    # Relative paths: the script changes directory, and vol reads a path
    # like http:/x as a URL, so vol must get the absolute dump path. An
    # exported CDPATH must not send the run to another "out".
    mkdir -p "${work}/decoy/out"
    (cd "$work" && CDPATH="${work}/decoy" PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" mem.raw \
        --os windows -o out --extract-strings --dump-registry &>/dev/null) || rc=$?
    assert_eq "windows run exits 0" "0" "$rc"
    assert_eq "CDPATH is ignored" "" "$(ls -A "${work}/decoy/out")"
    assert_eq "vol always gets the absolute dump path" "$(wc -l < "${work}/calls" | tr -d ' ')" \
        "$(grep -c -- '-f /' "${work}/calls")"
    assert_eq "every windows plugin invoked" "32" "$(grep -cE ' windows\.[a-z.]+$' "${work}/calls")"
    assert_contains "registry dump keeps hivelist plugin output" "init" "$(cat "${work}/out/registry_hivelist.txt")"
    assert_contains "registry dump index written" "File output" "$(cat "${work}/out/registry_dump_index.txt")"
    assert_contains "IOC: Windows path extracted" 'C:\Windows\Temp\evil.exe' "$(cat "${work}/out/strings/windows_paths.txt")"
    if strings -e l /dev/null &>/dev/null; then
        assert_contains "IOC: UTF-16LE domain extracted" "wide.example.net" "$(cat "${work}/out/strings/domains.txt")"
    else
        skip "UTF-16LE extraction (strings has no -e l on this platform)"
    fi

    rm -rf "$work"
}

test_symbol_options() {
    printf '\n\033[1msymbol options\033[0m\n'

    local work isf url
    work=$(mktemp -d)
    make_fake_vol "$work"
    mkdir "${work}/isf"
    : > "${work}/mem.raw"
    isf=$(cd "${work}/isf" && pwd -P)   # the script records the resolved path
    url="file://${work}/banners.json"
    : > "${work}/banners.json"

    # Auto-detect (windows probe fails, linux wins): probes carry the options too.
    local rc=0
    FAKE_NOT_WINDOWS=1 PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "${work}/mem.raw" \
        -o "${work}/out" --json --symbols "${work}/isf" --isf-url "$url" &>/dev/null || rc=$?
    assert_eq "run with symbol options exits 0" "0" "$rc"
    assert_eq "2 probes + 21 plugins ran" "23" "$(wc -l < "${work}/calls" | tr -d ' ')"
    assert_eq "every vol call gets -s and -u" "23" "$(grep -cF -- "-q -s ${isf} -u ${url} -f " "${work}/calls")"
    assert_contains "text report records the ISF URL" "ISF URL     : ${url}" "$(cat "${work}/out/analysis_summary.txt")"
    assert_contains "JSON records the symbols dir" "\"symbol_dir\": \"${isf}\"" "$(cat "${work}/out/analysis_summary.json")"

    # Windows file and registry dumps carry them as well (32 plugins + 2 dumps).
    rm -f "${work}/calls"
    PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "${work}/mem.raw" --os windows -o "${work}/win" \
        --dump-files --dump-registry --symbols "${work}/isf" --isf-url "$url" &>/dev/null || true
    assert_eq "dump calls get -s and -u too" "34" "$(grep -cF -- "-q -s ${isf} -u ${url} " "${work}/calls")"

    rm -rf "$work"
}

test_completion() {
    printf '\n\033[1mbash completion\033[0m\n'

    # Readline splits words at ':' (COMP_WORDBREAKS) and replaces only the
    # text after it, so after "https:" the rest of the URL must be offered.
    local got
    got=$(bash -c '
        source "$1"
        COMP_WORDBREAKS=" :"
        COMP_LINE="vol-analyze --isf-url https:"; COMP_POINT=${#COMP_LINE}
        COMP_WORDS=(vol-analyze --isf-url https :); COMP_CWORD=3
        _vol_analyze; printf "%s" "${COMPREPLY[*]}"' _ "${PROJECT_DIR}/completions/vol-analyze.bash")
    assert_eq "--isf-url completes after https:" \
        "//github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json" "$got"
}

# Prefix that runs a command with SIGINT at its default: a background job
# ignores it (when started from a non-interactive shell) and bash cannot
# undo that, so the script's INT-first shutdown would not be tested. Python
# ignores SIGPIPE and SIGXFSZ, so those are reset too. An array, not a
# function: `func &` forks a subshell, and $! would not be the script.
WITH_SIGINT=(python3 -c 'import os, signal, sys
for s in (signal.SIGINT, signal.SIGPIPE, signal.SIGXFSZ): signal.signal(s, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])')

# Start the script against a vol that never finishes, SIGTERM it once
# $1 vols are running, and check it exits promptly without leaving any behind.
check_sigterm() {
    local label="$1" expect="$2"; shift 2
    local work rc=0 pid alive=0 p
    work=$(mktemp -d)
    make_fake_vol "$work" slow
    : > "${work}/mem.raw"
    : > "${work}/pids"
    : > "${work}/sigs"

    PATH="${work}:${PATH}" "${WITH_SIGINT[@]}" bash "$SCRIPT" "${work}/mem.raw" -o "${work}/out" "$@" &>/dev/null &
    pid=$!
    for _ in $(seq 1 50); do
        (( $(wc -l < "${work}/pids") >= expect )) && break
        sleep 0.2
    done
    sleep 1  # let a broken scheduler try to launch more
    kill -TERM "$pid"
    # A script that ignores TERM gets SIGKILLed after 10s (exit 137 → fail);
    # it gives vol 2s to exit, then sends INT.
    for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" || rc=$?
    sleep 0.5

    assert_eq "${label}: SIGTERM exits 143" "143" "$rc"
    assert_eq "${label}: nothing launched after SIGTERM" "$expect" "$(wc -l < "${work}/pids" | tr -d ' ')"
    # On INT, not TERM, vol runs its `finally` blocks (deletes a symbol file
    # it was still downloading).
    assert_eq "${label}: vol is stopped with SIGINT" "INT" "$(sort -u "${work}/sigs")"
    while read -r p; do
        if kill -0 "$p" 2>/dev/null; then alive=$(( alive + 1 )); kill "$p"; fi
    done < "${work}/pids"
    assert_eq "${label}: no orphaned vol processes" "0" "$alive"

    rm -rf "$work"
}

test_termination() {
    printf '\n\033[1mtermination\033[0m\n'
    check_sigterm "plugin run" 2 --os linux -j 2
    check_sigterm "OS auto-detect" 1

    # A probe that times out gets SIGINT too, and the next probe runs.
    local work out
    work=$(mktemp -d)
    make_fake_vol "$work" slow
    : > "${work}/mem.raw"
    out=$(VOL_DETECT_TIMEOUT=2 FAKE_ONLY_HANG=windows.info PATH="${work}:${PATH}" \
        with_timeout 60 bash "$SCRIPT" "${work}/mem.raw" -o "${work}/out" 2>&1) || true
    assert_contains "probe timeout reported" "timed out after 2s" "$out"
    assert_eq "a timed-out probe gets SIGINT" "INT" "$(cat "${work}/sigs")"
    assert_contains "the next probe runs after a timeout" "Detected: linux" "$out"
    rm -rf "$work"

    # Ctrl-C ends the script by SIGINT, not exit 130, so a calling shell
    # loop stops too (Python reports death by SIGINT as -2).
    work=$(mktemp -d)
    make_fake_vol "$work" slow
    : > "${work}/mem.raw"
    out=$(PATH="${work}:${PATH}" python3 -c 'import signal, subprocess, sys, time
p = subprocess.Popen(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
p.send_signal(signal.SIGINT)
print(p.wait(timeout=20))' bash "$SCRIPT" "${work}/mem.raw" --os linux -o "${work}/out") || true
    assert_eq "SIGINT ends the script by SIGINT" "-2" "$out"
    rm -rf "$work"

    # strings and fold are both jobs: none is left reading the dump.
    local work pid p alive=0
    work=$(mktemp -d)
    make_fake_vol "$work"
    : > "${work}/mem.raw"
    mkdir "${work}/bin"
    printf '#!/bin/sh\necho "$$" >> "%s/spids"\nexec sleep 30\n' "$work" > "${work}/bin/strings"
    chmod +x "${work}/bin/strings"
    PATH="${work}/bin:${work}:${PATH}" "${WITH_SIGINT[@]}" bash "$SCRIPT" "${work}/mem.raw" --os linux -o "${work}/out" \
        --extract-strings &>/dev/null &
    pid=$!
    for _ in $(seq 1 50); do [[ -s "${work}/spids" ]] && break; sleep 0.2; done
    kill -TERM "$pid"
    wait "$pid" || true
    sleep 0.5
    while read -r p; do
        if kill -0 "$p" 2>/dev/null; then alive=$(( alive + 1 )); kill "$p"; fi
    done < "${work}/spids"
    assert_eq "no strings process left after SIGTERM" "0" "$alive"
    rm -rf "$work"
}

# ─── Tests: script quality ───────────────────────────────────────────────────

test_script_quality() {
    printf '\n\033[1mscript quality\033[0m\n'

    # Bash syntax check
    assert_exit_code "bash -n syntax check passes" 0 bash -n "$SCRIPT"

    # ShellCheck — required dev dependency. Skipping it produces a false
    # sense of security; fail loudly if missing.
    if command -v shellcheck &>/dev/null; then
        assert_exit_code "shellcheck passes" 0 shellcheck "$SCRIPT"
    else
        fail "shellcheck not installed — required dev dependency (install: https://github.com/koalaman/shellcheck)"
    fi
}

# ─── Run all tests ───────────────────────────────────────────────────────────

main() {
    printf '\n\033[1m══ vol-analyze.sh — Unit Tests ══\033[0m\n'

    test_safe_name
    test_json_escape
    test_resolve_path
    test_arg_parsing
    test_validation
    test_end_to_end
    test_windows_strings
    test_symbol_options
    test_completion
    test_termination
    test_script_quality

    printf '\n\033[1m── Results ──\033[0m\n'
    printf '  Total: %d  Passed: \033[0;32m%d\033[0m  Failed: \033[0;31m%d\033[0m\n\n' "$TESTS_RUN" "$PASS" "$FAIL"

    if (( FAIL > 0 )); then
        exit 1
    fi
}

main
