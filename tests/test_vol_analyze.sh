#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for vol-analyze.sh
# Run: make test  (or: bash tests/test_vol_analyze.sh)
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
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
    rel_resolved=$(resolve_path "tests/../scripts/vol-analyze.sh")
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
    assert_contains "--version shows version" "v2.1.1" "$ver_output"
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

    assert_contains "rejects non-numeric VOL_DETECT_TIMEOUT" "Invalid VOL_DETECT_TIMEOUT" \
        "$(VOL_DETECT_TIMEOUT=abc PATH="${fake_bin}:${PATH}" bash "$SCRIPT" "$tmpfile" 2>&1)"

    rm -rf "$tmpfile_dir"
    rm -rf "$fake_bin"
}

# ─── Tests: end-to-end runs against a fake vol ───────────────────────────────

# Bound each run so a scheduler regression fails instead of hanging CI.
# -k: SIGKILL 5s later in case a regression makes the script ignore TERM.
with_timeout() {
    if command -v timeout &>/dev/null; then timeout -k 5 "$@"
    elif command -v gtimeout &>/dev/null; then gtimeout -k 5 "$@"
    else shift; "$@"
    fi
}

# Symbolic mode string, e.g. drwx------ (GNU stat, then BSD/macOS stat).
mode_of() { stat -c %A "$1" 2>/dev/null || stat -f %Sp "$1"; }

# Fake vol: last argument is the plugin. check_idt fails the way vol does on
# an unsatisfied requirement; `slow` mode stands in for a long-running plugin.
make_fake_vol() {
    local dir="$1" mode="${2:-fast}"
    if [[ "$mode" == slow ]]; then
        printf '#!/bin/sh\necho "$$" >> "%s/pids"\nexec sleep 30\n' "$dir" > "${dir}/vol"
    else
        cat > "${dir}/vol" <<EOF
#!/bin/sh
for last; do :; done
echo "\$*" >> "${dir}/calls"
case "\$last" in
    *check_idt) echo "Unsatisfied requirement"; echo "boom" >&2; exit 1 ;;
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
    printf 'junk http://evil.com/payload c2.badguy.com 10.13.37.1 junk\n' > "$dump"

    # Zero-padded -j also checks base-10 parsing ("08" is invalid octal).
    out=$(PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux \
        -o "${work}/out" -j 08 --json --extract-strings 2>&1) || rc=$?
    assert_eq "linux run exits 0" "0" "$rc"
    assert_contains "all plugins reported" "20/21 succeeded, 1 with errors" "$out"
    assert_eq "every plugin invoked once" "21" "$(wc -l < "${work}/calls" | tr -d ' ')"
    assert_eq "vol always called with -q" "21" "$(grep -c '^-q ' "${work}/calls")"
    assert_eq "new output dir is 700" "drwx------" "$(mode_of "${work}/out")"

    local report="${work}/out/analysis_summary.txt"
    assert_contains "text report marks failure" "FAILED   linux.malware.check_idt" "$(cat "$report")"
    assert_contains "text report marks success" "SUCCESS  linux.pslist" "$(cat "$report")"
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

    assert_contains "IOC: .com domains kept" "evil.com" "$(cat "${work}/out/strings/domains.txt")"
    assert_contains "IOC: URL extracted" "http://evil.com/payload" "$(cat "${work}/out/strings/urls.txt")"
    assert_contains "IOC: IPv4 extracted" "10.13.37.1" "$(cat "${work}/out/strings/ipv4.txt")"

    # Default path: no --os. windows.info fails, so the linux probe must win.
    out=$(FAKE_NOT_WINDOWS=1 PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" \
        -o "${work}/auto" 2>&1) || true
    assert_contains "auto-detects linux" "Detected: linux" "$out"
    assert_contains "auto-detect runs linux plugins" "21 plugins" "$out"

    # Re-running into an existing directory must not chmod it.
    mkdir "${work}/shared"
    chmod 755 "${work}/shared"
    PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux -o "${work}/shared" &>/dev/null || true
    assert_eq "existing output dir keeps its mode" "drwxr-xr-x" "$(mode_of "${work}/shared")"
    assert_eq "files in existing dir are 600" "-rw-------" "$(mode_of "${work}/shared/pslist.txt")"

    rc=0
    FAKE_ALL_FAIL=1 PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "$dump" --os linux \
        -o "${work}/allfail" &>/dev/null || rc=$?
    assert_eq "exits 1 when no plugin succeeds" "1" "$rc"

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

    PATH="${work}:${PATH}" with_timeout 60 bash "$SCRIPT" "${work}/mem.raw" --os windows \
        -o "${work}/out" --extract-strings &>/dev/null || rc=$?
    assert_eq "windows run exits 0" "0" "$rc"
    assert_contains "IOC: Windows path extracted" 'C:\Windows\Temp\evil.exe' "$(cat "${work}/out/strings/windows_paths.txt")"
    if strings -e l /dev/null &>/dev/null; then
        assert_contains "IOC: UTF-16LE domain extracted" "wide.example.net" "$(cat "${work}/out/strings/domains.txt")"
    else
        pass "IOC: UTF-16LE extraction n/a (strings has no -e l on this platform)"
    fi

    rm -rf "$work"
}

# Start the script against a vol that never finishes, SIGTERM it once
# $1 vols are running, and check it exits promptly without leaving any behind.
check_sigterm() {
    local label="$1" expect="$2"; shift 2
    local work rc=0 pid alive=0 p
    work=$(mktemp -d)
    make_fake_vol "$work" slow
    : > "${work}/mem.raw"
    : > "${work}/pids"

    PATH="${work}:${PATH}" bash "$SCRIPT" "${work}/mem.raw" -o "${work}/out" "$@" &>/dev/null &
    pid=$!
    for _ in $(seq 1 50); do
        (( $(wc -l < "${work}/pids") >= expect )) && break
        sleep 0.2
    done
    sleep 1  # let a broken scheduler try to launch more
    kill -TERM "$pid"
    # A script that ignores TERM gets SIGKILLed after 5s (exit 137 → fail).
    for _ in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" || rc=$?
    sleep 0.5

    assert_eq "${label}: SIGTERM exits 143" "143" "$rc"
    assert_eq "${label}: nothing launched after SIGTERM" "$expect" "$(wc -l < "${work}/pids" | tr -d ' ')"
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
    test_termination
    test_script_quality

    printf '\n\033[1m── Results ──\033[0m\n'
    printf '  Total: %d  Passed: \033[0;32m%d\033[0m  Failed: \033[0;31m%d\033[0m\n\n' "$TESTS_RUN" "$PASS" "$FAIL"

    if (( FAIL > 0 )); then
        exit 1
    fi
}

main
