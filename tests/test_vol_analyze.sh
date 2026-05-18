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
# shellcheck source=../scripts/vol-analyze.sh
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
    assert_eq "handles nested dots" "check_syscall" "$(safe_name "linux.check_syscall")"
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
    assert_contains "--version shows version" "v2.1.0" "$ver_output"
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

    # Invalid --os value
    local tmpfile
    tmpfile=$(mktemp --suffix=.raw)
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

    rm -f "$tmpfile"
    rm -rf "$fake_bin"
}

# ─── Tests: output directory permissions ──────────────────────────────────────

test_output_dir_permissions() {
    printf '\n\033[1moutput directory permissions\033[0m\n'

    # We can't run the full tool without vol, but we can check that
    # the script syntax includes chmod 700
    local chmod_present
    chmod_present=$(grep -c 'chmod 700 "$OUTPUT_DIR"' "$SCRIPT") || true
    if (( chmod_present > 0 )); then
        pass "chmod 700 on output directory present in script"
    else
        fail "chmod 700 on output directory missing from script"
    fi
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
    test_output_dir_permissions
    test_script_quality

    printf '\n\033[1m── Results ──\033[0m\n'
    printf '  Total: %d  Passed: \033[0;32m%d\033[0m  Failed: \033[0;31m%d\033[0m\n\n' "$TESTS_RUN" "$PASS" "$FAIL"

    if (( FAIL > 0 )); then
        exit 1
    fi
}

main
