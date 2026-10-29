#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# vol-analyze — Automated memory forensics for Windows, Linux, and macOS
# Copyright (C) 2025 gl0bal01
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. See <https://www.gnu.org/licenses/> for details.
#
# Commercial licensing available — contact gl0bal01 for details.
#
# https://github.com/gl0bal01/volatility-toolkit
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail
IFS=$'\n\t'
# cd into a relative path must not search CDPATH (main() enters the output
# directory by its relative name).
unset CDPATH
# Output holds credential material (hashdump, lsadump): files 600, dirs 700,
# even inside a pre-existing output directory.
umask 077

# declare -A and ${var,,} need bash 4; macOS ships 3.2 as /bin/bash.
if (( BASH_VERSINFO[0] < 4 )); then
    echo "vol-analyze requires bash 4.0+ (found ${BASH_VERSION}). On macOS: brew install bash" >&2
    exit 1
fi

# ─── Constants ───────────────────────────────────────────────────────────────

readonly VERSION="4.0.0"
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly DEFAULT_MAX_PARALLEL=4
readonly DEFAULT_OUTPUT_DIR="volatility_output"

# ─── Colors ──────────────────────────────────────────────────────────────────

setup_colors() {
    # Real ESC bytes ($'...'), not '\033' text: the codes are also embedded in
    # heredocs and %s arguments, which do not interpret backslash escapes.
    if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
        RED=$'\033[0;31m'
        GREEN=$'\033[0;32m'
        YELLOW=$'\033[1;33m'
        BLUE=$'\033[0;34m'
        CYAN=$'\033[0;36m'
        MAGENTA=$'\033[0;35m'
        BOLD=$'\033[1m'
        DIM=$'\033[2m'
        NC=$'\033[0m'
    else
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' DIM='' NC=''
    fi
}

# ─── Logging ─────────────────────────────────────────────────────────────────

info()    { printf '%b[*]%b %s\n' "${BLUE}" "${NC}" "$*"; }
success() { printf '%b[+]%b %s\n' "${GREEN}" "${NC}" "$*"; }
warn()    { printf '%b[!]%b %s\n' "${YELLOW}" "${NC}" "$*"; }
error()   { printf '%b[-]%b %s\n' "${RED}" "${NC}" "$*" >&2; }
fatal()   { error "$*"; exit 1; }
header()  { printf '\n%b══ %s%b\n\n' "${BOLD}${MAGENTA}" "$*" "${NC}"; }

# ─── Usage ───────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
${BOLD}${SCRIPT_NAME}${NC} v${VERSION} — Automated memory forensics with Volatility 3

${BOLD}USAGE${NC}
    ${SCRIPT_NAME} <memory_dump> [options]

${BOLD}ARGUMENTS${NC}
    <memory_dump>               Path to the memory dump file (.raw, .vmem, .dmp, .lime)

${BOLD}OPTIONS${NC}
        --os TYPE               Target OS: windows, linux, mac, auto (default: auto)
    -o, --output DIR            New or empty output directory (default: ${DEFAULT_OUTPUT_DIR})
    -j, --jobs N                Max parallel plugins (default: ${DEFAULT_MAX_PARALLEL})
        --symbols DIR           Extra Volatility 3 symbol directory (Linux/macOS ISF files)
        --isf-url URL           Remote ISF index to look up kernel symbols (https:// or file://)
        --dump-registry         Dump registry hives to disk (Windows only)
        --dump-files            Dump files from memory (Windows only)
        --extract-strings       Extract and categorize IOC strings
        --json                  Generate JSON summary report
        --interactive           Enable interactive prompts (disabled by default)
        --no-color              Disable colored output
    -h, --help                  Show this help message
    -v, --version               Show version

${BOLD}ENVIRONMENT${NC}
    VOL3_CMD                    Volatility 3 command (default: vol)
    MAX_PARALLEL                Default max parallel jobs (default: ${DEFAULT_MAX_PARALLEL})
    VOL_DETECT_TIMEOUT          Seconds per OS auto-detection probe (default: 60, 0: no limit)
    NO_COLOR                    Set to disable colored output (any non-empty value)

${BOLD}EXAMPLES${NC}
    ${SCRIPT_NAME} memory.raw                                    # auto-detect OS
    ${SCRIPT_NAME} memory.raw --os linux -o case-001/ -j 8
    ${SCRIPT_NAME} memory.raw --os windows --dump-files --json
    ${SCRIPT_NAME} memory.lime --os linux --extract-strings
    ${SCRIPT_NAME} memory.lime --symbols ~/isf/
    ${SCRIPT_NAME} memory.lime --isf-url https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json

${BOLD}SUPPORTED OS${NC}
    windows   32 plugins — processes, console history, network, registry, malware, drivers, services
    linux     21 plugins — processes, kernel modules, network, rootkit checks
    mac       20 plugins — processes, kernel, network, TrustedBSD, kauth

${BOLD}MORE INFO${NC}
    https://github.com/gl0bal01/volatility-toolkit
EOF
    exit 0
}

# ─── Argument Parsing ────────────────────────────────────────────────────────

MEMORY_DUMP=""
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
MAX_PARALLEL="${MAX_PARALLEL:-$DEFAULT_MAX_PARALLEL}"
TARGET_OS="auto"
DUMP_REGISTRY=false
DUMP_FILES=false
EXTRACT_STRINGS=false
JSON_OUTPUT=false
INTERACTIVE=false
SYMBOL_DIR=""
ISF_URL=""
# main() works inside the output directory (OUTPUT_DIR becomes "."):
# OUTPUT_PATH is its absolute path, for messages and reports.
OUTPUT_PATH=""
TLDS_FILE=""
# Options for every vol call. -q keeps progress bars out of .err, so a
# non-empty .err means real warnings.
VOL_OPTS=(-q)

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)            usage ;;
            -v|--version)         echo "${SCRIPT_NAME} v${VERSION}"; exit 0 ;;
            --os)                 TARGET_OS="${2:?Missing argument for $1}"; shift 2 ;;
            -o|--output)          OUTPUT_DIR="${2:?Missing argument for $1}"; shift 2 ;;
            -j|--jobs)            MAX_PARALLEL="${2:?Missing argument for $1}"; shift 2 ;;
            --symbols)            SYMBOL_DIR="${2:?Missing argument for $1}"; shift 2 ;;
            --isf-url)            ISF_URL="${2:?Missing argument for $1}"; shift 2 ;;
            --dump-registry)      DUMP_REGISTRY=true; shift ;;
            --dump-files)         DUMP_FILES=true; shift ;;
            --extract-strings)    EXTRACT_STRINGS=true; shift ;;
            --json)               JSON_OUTPUT=true; shift ;;
            --interactive)        INTERACTIVE=true; shift ;;
            --no-color)           NO_COLOR=1; setup_colors; shift ;;
            -*)                   fatal "Unknown option: $(printf '%q' "$1") (use --help)" ;;
            *)
                [[ -z "$MEMORY_DUMP" ]] || fatal "Unexpected argument: $(printf '%q' "$1")"
                MEMORY_DUMP="$1"; shift
                ;;
        esac
    done
}

# ─── Validation ──────────────────────────────────────────────────────────────

# Control characters (C0, DEL, C1 in UTF-8) would forge lines in the text
# report and reach the terminal raw (escape sequences); vol splits -s on ';'
# and newlines. Checked on the arguments, and again on the resolved paths: a
# symlinked parent directory can carry them in its target.
reject_cntrl() {
    local LC_ALL=C s
    printf -v s '%s' "$@"
    if [[ "$s" == *[[:cntrl:]]* || "$s" == *$'\xc2'[$'\x80'-$'\x9f']* ]]; then
        fatal "Arguments, paths and URLs must not contain control characters"
    fi
}

# Output directories that must never be written to, as physical absolute
# paths. /var and /run subtrees stay allowed: /var/tmp, macOS $TMPDIR
# (/var/folders) and udisks evidence-drive mounts (/run/media/$USER). On
# macOS /etc and /var are symlinks into /private.
system_dir() {
    case "$1" in
        /|/etc|/etc/*|/usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/boot|/boot/*|/dev|/dev/*|/proc|/proc/*|/sys|/sys/*|/var|/lib|/lib/*|/run|/private|/private/etc|/private/etc/*|/private/var)
            return 0 ;;
    esac
    return 1
}

validate() {
    [[ -z "$MEMORY_DUMP" ]] && fatal "No memory dump specified. Usage: ${SCRIPT_NAME} <memory_dump> [options]"
    reject_cntrl "$MEMORY_DUMP" "$OUTPUT_DIR" "$SYMBOL_DIR" "$ISF_URL" "$TARGET_OS" "$MAX_PARALLEL" \
        "$VOL" "$DETECT_TIMEOUT_SECS"
    [[ -f "$MEMORY_DUMP" ]]  || fatal "File not found: ${MEMORY_DUMP}"
    [[ -r "$MEMORY_DUMP" ]]  || fatal "File not readable: ${MEMORY_DUMP}"
    [[ -L "$MEMORY_DUMP" ]]  && fatal "Refusing to follow symlink: ${MEMORY_DUMP} — pass the real path"
    # Absolute: main() changes directory, and vol reads a relative path whose
    # first part looks like a URL scheme (http:/host/mem.raw) as a URL.
    MEMORY_DUMP=$(resolve_path "$MEMORY_DUMP")
    reject_cntrl "$MEMORY_DUMP"

    command -v "$VOL" &>/dev/null || fatal "Volatility 3 (${VOL}) not found in PATH. Install: https://github.com/volatilityfoundation/volatility3"
    # Absolute too (VOL3_CMD=./vol, a relative PATH entry): main() changes
    # directory.
    VOL=$(command -v "$VOL")
    [[ "$VOL" == /* ]] || VOL="${PWD}/${VOL}"

    # Validate that VOL resolves to an expected binary name
    local vol_base
    vol_base=$(basename "$VOL")
    case "$vol_base" in
        vol|vol3|volatility3|vol.py) ;;
        *) fatal "VOL3_CMD resolves to unexpected binary '${vol_base}' — expected vol, vol3, volatility3, or vol.py" ;;
    esac

    case "$TARGET_OS" in
        windows|linux|mac|auto) ;;
        *) fatal "Invalid --os value: ${TARGET_OS} (must be: windows, linux, mac, auto)" ;;
    esac

    # Reject system directories before mkdir -p creates anything: the path
    # as it will resolve, i.e. its nearest existing ancestor in physical form
    # (catches /tmp/../etc, a symlink to /etc, etclink/a/b) plus the parts
    # still to be created. main() checks again once inside.
    [[ "$OUTPUT_DIR" != -* ]] || OUTPUT_DIR="./${OUTPUT_DIR}"   # not an option to mkdir/cd
    local dir="$OUTPUT_DIR" rest="" resolved_output
    until resolved_output=$(cd -P -- "$dir" 2>/dev/null && pwd -P); do
        [[ "$dir" != "$(dirname -- "$dir")" ]] || fatal "Cannot resolve output directory: ${OUTPUT_DIR}"
        # ponytail: refused, not resolved; new/../../etc/x cannot be
        # resolved before mkdir creates new.
        [[ "$(basename -- "$dir")" != .. ]] \
            || fatal "Output directory path has '..' after a directory that does not exist yet: ${OUTPUT_DIR}"
        rest="/$(basename -- "$dir")${rest}"
        dir=$(dirname -- "$dir")
    done
    [[ -z "$rest" ]] || resolved_output="${resolved_output%/}${rest}"
    reject_cntrl "$resolved_output"
    if system_dir "$resolved_output"; then
        fatal "Refusing to use system directory as output: ${OUTPUT_DIR}"
    fi

    # 10# forces base 10: bare "08" is an invalid octal literal in (( )).
    if ! [[ "$MAX_PARALLEL" =~ ^[0-9]+$ ]] || (( 10#$MAX_PARALLEL < 1 )); then
        fatal "Invalid --jobs value: ${MAX_PARALLEL} (must be a positive integer)"
    fi
    MAX_PARALLEL=$(( 10#$MAX_PARALLEL ))

    [[ "$DETECT_TIMEOUT_SECS" =~ ^[0-9]+$ ]] \
        || fatal "Invalid VOL_DETECT_TIMEOUT: ${DETECT_TIMEOUT_SECS} (must be whole seconds)"

    # vol splits -s on ';', so the check runs on the resolved path. Plain
    # http is refused (vol itself still retries https without certificate
    # checks; a local --symbols dir is the tamper-proof option).
    VOL_OPTS=(-q)
    if [[ -n "$SYMBOL_DIR" ]]; then
        [[ -d "$SYMBOL_DIR" ]] || fatal "Symbols directory not found: ${SYMBOL_DIR}"
        [[ "$SYMBOL_DIR" == /* ]] || SYMBOL_DIR="./${SYMBOL_DIR}"   # keep "-dir" from parsing as an option
        SYMBOL_DIR=$(resolve_path "$SYMBOL_DIR")
        reject_cntrl "$SYMBOL_DIR"
        [[ "$SYMBOL_DIR" == *";"* ]] && fatal "Symbols directory path must not contain ';': ${SYMBOL_DIR}"
        VOL_OPTS+=(-s "$SYMBOL_DIR")
    fi
    if [[ -n "$ISF_URL" ]]; then
        [[ "$ISF_URL" =~ ^(https|file):// ]] \
            || fatal "Invalid --isf-url: ${ISF_URL} (must start with https:// or file://)"
        [[ "$ISF_URL" != file://* || -f "${ISF_URL#file://}" ]] \
            || fatal "ISF index not found: ${ISF_URL#file://}"
        VOL_OPTS+=(-u "$ISF_URL")
    fi

    # OS-specific flag validation
    if [[ "$TARGET_OS" != "windows" && "$TARGET_OS" != "auto" ]]; then
        if [[ "$DUMP_REGISTRY" == true ]]; then
            warn "--dump-registry is only available for Windows — ignoring"
            DUMP_REGISTRY=false
        fi
        if [[ "$DUMP_FILES" == true ]]; then
            warn "--dump-files is only available for Windows — ignoring"
            DUMP_FILES=false
        fi
    fi
}

# ─── Portability Helpers ─────────────────────────────────────────────────────

resolve_path() {
    if command -v realpath &>/dev/null; then
        realpath "$1"
    elif command -v readlink &>/dev/null && readlink -f "$1" &>/dev/null; then
        readlink -f "$1"
    else
        local dir base abs_dir
        dir=$(dirname "$1")
        base=$(basename "$1")
        abs_dir=$(cd "$dir" 2>/dev/null && pwd) || abs_dir=""
        if [[ -z "$abs_dir" ]]; then
            [[ "$dir" != /* ]] && dir="$(pwd)/$dir"
            abs_dir="$dir"
        fi
        printf '%s/%s\n' "$abs_dir" "$base"
    fi
}

# stat(1) size flag varies between GNU (-c%s) and BSD/macOS (-f%z).
file_size_bytes() {
    stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || echo "0"
}

# Start an external command as a background job (pid in $!). Unlike a
# plain `cmd &`, it does not ignore SIGINT, so cleanup() can stop it the way
# vol cleans up after itself (see cleanup()). Its stdin is /dev/null even
# with `start_job cmd < file`; output redirections on the call do apply.
start_job() {
    ( trap - INT; exec "$@" ) &
}

# Run an external command as a background job and wait for it. Unlike a
# foreground command, `wait` returns as soon as an INT/TERM trap fires, and
# cleanup() then finds the command via `jobs -p` and stops it.
run_job() {
    start_job "$@"
    wait $!
}

# jobs_gone <tenths of a second> <pid>...: true once all have exited.
jobs_gone() {
    local n="$1"; shift
    while (( n-- > 0 )); do
        kill -0 "$@" 2>/dev/null || return 0
        sleep 0.1
    done
    ! kill -0 "$@" 2>/dev/null
}

# Human-readable byte size (portable: avoids GNU numfmt dependency on macOS).
human_size() {
    local bytes="$1"
    if ! [[ "$bytes" =~ ^[0-9]+$ ]]; then
        echo "$bytes"
        return
    fi
    if command -v numfmt &>/dev/null; then
        numfmt --to=iec "$bytes" 2>/dev/null && return
    fi
    local -a units=(B K M G T P)
    local idx=0 val=$bytes
    while (( val >= 1024 && idx < ${#units[@]} - 1 )); do
        val=$(( val / 1024 ))
        (( ++idx ))
    done
    printf '%d%s\n' "$val" "${units[$idx]}"
}

# JSON RFC 8259 §7 string escaper. JSON must be UTF-8: a path with other
# bytes (latin-1 file names) is written shell-quoted instead ($'caf\351').
json_escape() {
    local s="$1"
    if command -v iconv &>/dev/null && ! iconv -f UTF-8 -t UTF-8 <<< "$s" &>/dev/null; then
        printf -v s '%q' "$s"
    fi
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"
    # Escape remaining U+0000..U+001F control characters as \uXXXX
    local out="" ch code i len="${#s}"
    for (( i=0; i<len; i++ )); do
        ch="${s:i:1}"
        printf -v code '%d' "'$ch"
        if (( code < 32 )); then
            printf -v ch '\\u%04x' "$code"
        fi
        out+="$ch"
    done
    printf '%s' "$out"
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────

# Jobs are stopped with SIGINT, and TERM only if they are still running 5 s
# later: on INT vol runs its `finally` blocks, which delete a symbol file it
# was still downloading (see detect_os); on TERM it leaves a broken one in
# its cache for every later run. A Ctrl-C in the terminal has already
# reached them, and a second INT could cut a `finally` short, so they get
# 2 s to exit first.
cleanup() {
    local pids
    pids=$(jobs -p 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        printf "\n"
        warn "Interrupted — stopping background jobs..."
        # shellcheck disable=SC2086 # word-split is intentional
        jobs_gone 20 $pids || { kill -INT $pids 2>/dev/null; jobs_gone 50 $pids; } \
            || kill $pids 2>/dev/null || true
        wait 2>/dev/null || true
    fi
    if [[ -n "${FIFO_DIR:-}" ]]; then
        rm -f -- "${FIFO_DIR}/strings"
        rmdir -- "$FIFO_DIR" 2>/dev/null || true
    fi
}
# INT/TERM must exit (which fires the EXIT trap); a handler that returns
# lets the scheduler loop resume and launch the remaining plugins. On INT
# the script then ends by SIGINT itself: a calling shell loop
# (for f in *.raw; do vol-analyze "$f"; done) stops only then, while exit
# status 130 tells it the interrupt was handled.
trap cleanup EXIT
trap 'cleanup; trap - INT EXIT; kill -INT $$' INT
trap 'exit 143' TERM

# ─── OS Detection ────────────────────────────────────────────────────────────

readonly DETECT_TIMEOUT_SECS="${VOL_DETECT_TIMEOUT:-60}"

# Sets TARGET_OS. Runs in the main shell, not `$(...)`, so a signal is
# handled at once instead of after the remaining probes.
detect_os() {
    local limit=$(( 10#$DETECT_TIMEOUT_SECS ))
    if (( limit > 0 )); then
        info "Auto-detecting OS from memory dump (${limit}s timeout per probe)..."
    else
        info "Auto-detecting OS from memory dump..."
    fi

    # A slow probe is stopped with SIGINT, not TERM: vol creates the Windows
    # symbol file before it downloads the PDB and deletes it on failure in a
    # `finally`, which runs on KeyboardInterrupt but not on TERM. A probe
    # killed mid-download would leave a broken ISF in vol's symbol directory
    # for every later run. KILL 10 s later if INT is ignored. Timed here,
    # not with timeout(1): uutils timeout (Ubuntu 26.04) does not deliver
    # -s INT.
    local probe os_name rc pid
    for probe in windows.info linux.pslist mac.pslist; do
        os_name="${probe%%.*}"
        info "  Probing as ${os_name}..."
        start_job "$VOL" "${VOL_OPTS[@]}" -f "$MEMORY_DUMP" "$probe" &>/dev/null
        pid=$!
        if (( limit > 0 )) && ! jobs_gone $(( limit * 10 )) "$pid"; then
            kill -INT "$pid" 2>/dev/null || true
            jobs_gone 100 "$pid" || kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            warn "  Probe for ${os_name} timed out after ${limit}s"
            continue
        fi
        rc=0
        wait "$pid" || rc=$?
        if (( rc == 0 )); then
            success "Detected: ${BOLD}${os_name}${NC}"
            TARGET_OS="$os_name"
            return
        fi
    done

    fatal "Could not auto-detect OS. Specify --os windows|linux|mac; Linux/macOS also need kernel symbols (--symbols DIR or --isf-url URL)"
}

# ─── Checksums ───────────────────────────────────────────────────────────────

CHECKSUM_MD5=""
CHECKSUM_SHA256=""

compute_checksums() {
    header "Chain of Custody — Checksums"

    local md5_tmp="${OUTPUT_DIR}/.md5"
    local sha256_tmp="${OUTPUT_DIR}/.sha256"
    local md5_pid="" sha256_pid=""
    local -a md5_cmd=() sha256_cmd=()

    # GNU coreutils, else the BSD/macOS built-ins. Hash stdin: GNU tools
    # prefix the hash with '\' when the file name contains a backslash.
    if command -v md5sum &>/dev/null; then md5_cmd=(md5sum)
    elif command -v md5 &>/dev/null;  then md5_cmd=(md5 -q)
    fi
    if command -v sha256sum &>/dev/null; then sha256_cmd=(sha256sum)
    elif command -v shasum &>/dev/null;  then sha256_cmd=(shasum -a 256)
    fi

    if (( ${#md5_cmd[@]} > 0 )); then
        ( trap - INT; exec "${md5_cmd[@]}" < "$MEMORY_DUMP" > "$md5_tmp" 2>/dev/null ) &
        md5_pid=$!
    fi
    if (( ${#sha256_cmd[@]} > 0 )); then
        ( trap - INT; exec "${sha256_cmd[@]}" < "$MEMORY_DUMP" > "$sha256_tmp" 2>/dev/null ) &
        sha256_pid=$!
    fi

    if [[ -n "$md5_pid" ]] && wait "$md5_pid" 2>/dev/null; then
        CHECKSUM_MD5=$(cut -d ' ' -f1 < "$md5_tmp")
        [[ "$CHECKSUM_MD5" =~ ^[0-9a-f]{32}$ ]] || CHECKSUM_MD5=""
    fi
    if [[ -n "$sha256_pid" ]] && wait "$sha256_pid" 2>/dev/null; then
        CHECKSUM_SHA256=$(cut -d ' ' -f1 < "$sha256_tmp")
        [[ "$CHECKSUM_SHA256" =~ ^[0-9a-f]{64}$ ]] || CHECKSUM_SHA256=""
    fi

    rm -f "$md5_tmp" "$sha256_tmp"

    if [[ -n "$CHECKSUM_MD5" ]]; then
        success "MD5:    ${CHECKSUM_MD5}"
    else
        warn "MD5 not computed — no md5sum/md5 available or hashing failed"
    fi
    if [[ -n "$CHECKSUM_SHA256" ]]; then
        success "SHA256: ${CHECKSUM_SHA256}"
    else
        warn "SHA256 not computed — no sha256sum/shasum available or hashing failed"
    fi
}

# ─── Plugin Definitions ─────────────────────────────────────────────────────

readonly WINDOWS_PLUGINS=(
    "windows.info"
    "windows.pslist"
    "windows.psscan"
    "windows.pstree"
    "windows.cmdline"
    "windows.cmdscan"
    "windows.consoles"
    "windows.sessions"
    "windows.getsids"
    "windows.privileges"
    "windows.envars"
    "windows.dlllist"
    "windows.vadinfo"
    "windows.handles"
    "windows.netscan"
    "windows.netstat"
    "windows.filescan"
    "windows.registry.hivelist"
    "windows.registry.printkey"
    "windows.registry.userassist"
    "windows.registry.hashdump"
    "windows.registry.lsadump"
    "windows.driverscan"
    "windows.modscan"
    "windows.modules"
    "windows.ssdt"
    "windows.callbacks"
    "windows.malware.malfind"
    "windows.mutantscan"
    "windows.svcscan"
    "windows.mbrscan"
    "windows.thrdscan"
)

readonly LINUX_PLUGINS=(
    "linux.pslist"
    "linux.pstree"
    "linux.psaux"
    "linux.bash"
    "linux.envars"
    "linux.lsmod"
    "linux.lsof"
    "linux.proc.Maps"
    "linux.sockstat"
    "linux.mountinfo"
    "linux.kmsg"
    "linux.iomem"
    "linux.elfs"
    "linux.malware.malfind"
    "linux.malware.check_syscall"
    "linux.malware.check_idt"
    "linux.malware.check_modules"
    "linux.malware.check_creds"
    "linux.malware.check_afinfo"
    "linux.malware.tty_check"
    "linux.malware.keyboard_notifiers"
)

readonly MAC_PLUGINS=(
    "mac.pslist"
    "mac.pstree"
    "mac.psaux"
    "mac.bash"
    "mac.lsmod"
    "mac.lsof"
    "mac.malfind"
    "mac.mount"
    "mac.netstat"
    "mac.proc_maps"
    "mac.socket_filters"
    "mac.check_syscall"
    "mac.check_sysctl"
    "mac.check_trap_table"
    "mac.ifconfig"
    "mac.kauth_listeners"
    "mac.kauth_scopes"
    "mac.kevents"
    "mac.list_files"
    "mac.trustedbsd"
)

# Active plugin list — set at runtime by select_plugins()
PLUGINS=()

select_plugins() {
    case "$TARGET_OS" in
        windows) PLUGINS=("${WINDOWS_PLUGINS[@]}") ;;
        linux)   PLUGINS=("${LINUX_PLUGINS[@]}") ;;
        mac)     PLUGINS=("${MAC_PLUGINS[@]}") ;;
    esac
}

# ─── Plugin Execution ────────────────────────────────────────────────────────

ANALYSIS_DURATION=0
PLUGINS_SUCCEEDED=0
PLUGINS_FAILED=0
SYMBOLS_USED=""
# Per-plugin exit code and wall-clock seconds, keyed by plugin name.
declare -A PLUGIN_RC=() PLUGIN_SECS=()

# Derive a safe filename from a plugin name (strip OS prefix, dots to underscores)
safe_name() {
    local name="$1"
    name="${name#windows.}"
    name="${name#linux.}"
    name="${name#mac.}"
    name="${name#malware.}"
    name="${name//./_}"
    echo "$name"
}

# success | warning (exit 0 with stderr output) | failed | missing (never ran)
plugin_status() {
    local rc="${PLUGIN_RC[$1]:-}"
    if [[ -z "$rc" ]]; then
        echo "missing"
    elif (( rc != 0 )); then
        echo "failed"
    elif [[ -s "${OUTPUT_DIR}/$(safe_name "$1").err" ]]; then
        echo "warning"
    else
        echo "success"
    fi
}

run_all_plugins() {
    local total=${#PLUGINS[@]}
    local completed=0
    local succeeded=0
    local failed=0
    local start_time=$SECONDS

    header "Analyzing ${TARGET_OS} dump — ${total} plugins (${MAX_PARALLEL} parallel)"

    # vol runs as a direct child (start_job execs it) so cleanup()'s
    # `kill $(jobs -p)` reaches it. The `${arr[@]+"${arr[@]}"}` idiom
    # on `survivors` is the bash-`set -u`-safe way to expand a possibly-empty
    # array.
    local -A pid_plugin=() pid_start=()
    local -a active_pids=()
    # The first plugin runs alone: it fills vol's caches (Windows PDB
    # download, --isf-url index and ISF). Parallel runs on a cold cache read
    # each other's half-written cache files and fail (JSONDecodeError).
    # It also writes vol's debug log, which names the symbol file vol really
    # used: a remote ISF it cached on an earlier run counts even without -u.
    local i=0 plugin sname pid slots=1
    local -a log_opt=(-l "${OUTPUT_DIR}/vol.log")

    while (( i < total )) || (( ${#active_pids[@]} > 0 )); do
        while (( ${#active_pids[@]} < slots )) && (( i < total )); do
            plugin="${PLUGINS[$i]}"
            sname=$(safe_name "$plugin")
            start_job "$VOL" "${VOL_OPTS[@]}" -f "$MEMORY_DUMP" ${log_opt[@]+"${log_opt[@]}"} "$plugin" \
                > "${OUTPUT_DIR}/${sname}.txt" 2> "${OUTPUT_DIR}/${sname}.err"
            pid=$!
            log_opt=()
            pid_plugin[$pid]="$plugin"
            pid_start[$pid]=$SECONDS
            active_pids+=("$pid")
            (( ++i ))
        done

        # ponytail: 1s poll instead of `wait -n`, which ignores jobs that
        # exited before it was called and so leaves freed slots idle until a
        # slow plugin ends. Plugins run for seconds to minutes; poll is noise.
        sleep 1

        local -a survivors=()
        local p
        for p in "${active_pids[@]}"; do
            if kill -0 "$p" 2>/dev/null; then
                survivors+=("$p")
                continue
            fi
            local exit_code=0
            wait "$p" 2>/dev/null || exit_code=$?
            local pname="${pid_plugin[$p]}"
            local duration=$(( SECONDS - pid_start[$p] ))
            PLUGIN_RC[$pname]=$exit_code
            PLUGIN_SECS[$pname]=$duration
            (( ++completed ))
            slots=$MAX_PARALLEL
            if (( exit_code == 0 )); then
                (( ++succeeded ))
                printf '  %b✓%b %b[%2d/%d]%b %-42s %b%ss%b\n' \
                    "${GREEN}" "${NC}" "${DIM}" "$completed" "$total" "${NC}" "$pname" "${DIM}" "$duration" "${NC}"
            else
                (( ++failed ))
                printf '  %b!%b %b[%2d/%d]%b %-42s %b%ss (exit %d, see .err)%b\n' \
                    "${YELLOW}" "${NC}" "${DIM}" "$completed" "$total" "${NC}" "$pname" "${DIM}" "$duration" "$exit_code" "${NC}"
            fi
            unset 'pid_plugin[$p]' 'pid_start[$p]'
        done
        active_pids=(${survivors[@]+"${survivors[@]}"})
    done

    ANALYSIS_DURATION=$(( SECONDS - start_time ))
    PLUGINS_SUCCEEDED=$succeeded
    PLUGINS_FAILED=$failed
    SYMBOLS_USED=$(awk -F 'Using symbol library: ' 'NF > 1 { print $2; exit }' \
        "${OUTPUT_DIR}/vol.log" 2>/dev/null) || true

    echo ""
    if (( failed == 0 )); then
        success "All ${total} plugins completed (${ANALYSIS_DURATION}s)"
    else
        success "${succeeded}/${total} succeeded, ${failed} with errors (${ANALYSIS_DURATION}s)"
    fi
}

# ─── IOC String Extraction ──────────────────────────────────────────────────

# strings, folded at 8 KiB (busybox fold allows up to 10000): grep and sed
# hold a whole line in memory, and an image can hold a printable run of
# gigabytes. Both are jobs of this shell, so cleanup() stops both; it fails
# if either fails. They are joined by a FIFO in a private temporary
# directory (the output directory can be on exFAT, which has none). The
# redirections run inside the jobs: opening a FIFO blocks until the other
# end opens.
FIFO_DIR=""
strings_folded() {
    local spid rc=0
    FIFO_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vol-analyze.XXXXXX") || return
    mkfifo "${FIFO_DIR}/strings" || { rmdir -- "$FIFO_DIR"; FIFO_DIR=""; return 1; }
    ( trap - INT; exec strings -a -n 6 "$@" > "${FIFO_DIR}/strings" ) &
    spid=$!
    ( trap - INT; exec fold -b -w 8192 < "${FIFO_DIR}/strings" ) &
    wait $! || rc=$?
    wait "$spid" || rc=$?
    rm -f -- "${FIFO_DIR}/strings"
    rmdir -- "$FIFO_DIR"
    FIFO_DIR=""
    return "$rc"
}

extract_strings() {
    header "Extracting IOC strings"

    local strings_dir="${OUTPUT_DIR}/strings"
    mkdir -p "$strings_dir"

    info "Running strings on memory dump (this may take a while for large dumps)..."
    local rc=0
    strings_folded "$MEMORY_DUMP" > "${strings_dir}/all.txt" 2>/dev/null || rc=$?
    if [[ ! -s "${strings_dir}/all.txt" ]]; then
        warn "strings command failed or produced no output"
        return
    fi
    (( rc == 0 )) || warn "strings exited with status ${rc} — all.txt may be incomplete"
    # Windows stores most paths, URLs and registry data as UTF-16LE.
    if [[ "$TARGET_OS" == "windows" ]]; then
        if strings -e l /dev/null &>/dev/null; then
            strings_folded -e l "$MEMORY_DUMP" >> "${strings_dir}/all.txt" 2>/dev/null \
                || warn "strings -e l failed — UTF-16LE strings may be incomplete"
        else
            warn "strings lacks -e l (GNU binutils) — UTF-16LE strings skipped"
        fi
    fi

    local total_strings
    total_strings=$(wc -l < "${strings_dir}/all.txt")
    info "Found ${total_strings} raw strings — categorizing IOCs..."

    # ── Universal patterns (all OSes) ──

    # IPv4: whole dotted-quad tokens only (not pieces of OIDs or version
    # strings like 1.3.6.1.4.1), octets <= 255, no leading zeros. 0.0.0.0/8
    # is never a host (on Linux dumps it is a third of the hits, all
    # versions); so are 255.255.255.255 and 127.0.0.x. macOS netstat writes
    # address.port (10.0.0.5.443), so a fifth part is cut off there (5-part
    # OIDs such as 1.3.6.1.4 then give false hits); on Windows and Linux
    # dumps it is always an OID or a version.
    local ip_re='([0-9]{1,3}\.){3}[0-9]{1,3}'
    [[ "$TARGET_OS" == "mac" ]] && ip_re+='(\.[1-9][0-9]{0,4})?'
    LC_ALL=C tr -c '0-9.\n' '\n' < "${strings_dir}/all.txt" \
        | sed -E 's/^\.+//; s/\.+$//' \
        | grep -xE "$ip_re" \
        | awk -F. '$1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255 && (NF == 4 || $5 <= 65535) {
                print $1 "." $2 "." $3 "." $4 }' \
        | grep -vE '(^|\.)0[0-9]|^(0\.|255\.255\.255\.255|127\.0\.0\.)' \
        | sort -u > "${strings_dir}/ipv4.txt" 2>/dev/null || true

    # URLs
    grep -oE 'https?://[^[:space:]"'\''<>]+' "${strings_dir}/all.txt" \
        | sort -u > "${strings_dir}/urls.txt" 2>/dev/null || true

    # Email addresses
    grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${strings_dir}/all.txt" \
        | sort -u > "${strings_dir}/emails.txt" 2>/dev/null || true

    # Domains: RFC 1035 labels ending in an IANA TLD, counted lower-cased.
    # Names that look like code or file names go to domains_lowconf.txt, so
    # a host an attacker picks to look like one (evil.app, navigator.top,
    # 4444.top) is never lost; only names that cannot be registered (no
    # IANA TLD, closed brand TLDs such as .windows) are dropped. Low
    # confidence, all seen as noise in real dumps:
    #   - all-caps names with 2 labels or a TLD over 3 letters: Defender
    #     signatures (Exploit:O97M/CVE-2017-0199.AL), COMMAND.COM
    #     (LOGIN.LIVE.COM stays a domain)
    #   - mixed-case TLDs: .NET names (System.IO); a name the TLD case cut
    #     short is kept (payload.example.com.EXE -> payload.example.com)
    #   - minified JS: this.id, t.name (one-letter names stay domains on
    #     .com/.net/.org/.me: x.org, t.me; e.target and Date.now end in brand
    #     TLDs). Rules on a first label apply to 2-label names only:
    #     self.c2.top stays a domain.
    #   - all-numeric names (0.9.18.2.top), ELF section and GNU tar header
    #     names by exact name (note.gnu.build, data.rel.ro, GNU.sparse.map)
    #   - on TLDs that are also file extensions, file names (run.sh,
    #     libfoo-2.0.so, CMD.EXE-CD245F9E.pf) but not hosts (c2.evil.sh)
    # Reverse-DNS identifiers (com.apple.audio, a third of all hits on a macOS
    # dump) go to reverse_dns.txt. URL escapes (%2F, %252F, backslash-u002F)
    # are blanked first so they don't glue onto names, and so are
    # underscores ending a word or before a number (c2.evil.top_,
    # c2.evil.top_443). Before letters they stay: that is an identifier
    # (browser_win.cc is no win.cc, koadic.work.make_url no koadic.work.make).
    # Output files are passed through ENVIRON: awk -v decodes backslashes.
    if [[ -s "$TLDS_FILE" ]]; then
        LC_ALL=C sed -E 's/%(25)*[0-9A-Fa-f]{2}|\\(u00|x)[0-9A-Fa-f]{2}/ /g; s/_+([^_A-Za-z0-9]|$)/ \1/g; s/_+([0-9]+([^_A-Za-z0-9.-]|$))/ \1/g' "${strings_dir}/all.txt" \
            | LC_ALL=C grep -oE '\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,63}|[xX][nN]--[a-zA-Z0-9-]{1,59})\b' \
            | RDNS="${strings_dir}/.reverse_dns" LOWCONF="${strings_dir}/.domains_lowconf" LC_ALL=C awk -F. \
                -v ext="app ax cab cat ci ht java la map md mo mov ms page pf pid pl pm properties ps py rs sh so zip" \
                -v brand="azure bing call data microsoft next now office search shell skype target windows xbox" \
                -v js="this self window document globalThis Date Math Object Array JSON Promise Symbol Number String Reflect Function console navigator location" '
                function low(s,   n, p) {
                    s = tolower(s); n = split(s, p, ".")
                    if ((p[n] in tld) && !(p[n] in is_brand)) print s > lowconf
                }
                BEGIN {
                    n = split(ext, w, " "); for (i = 1; i <= n; i++) is_ext[w[i]]
                    n = split(brand, w, " "); for (i = 1; i <= n; i++) is_brand[w[i]]
                    n = split(js, w, " "); for (i = 1; i <= n; i++) is_js[w[i]]
                    rdns = ENVIRON["RDNS"]; lowconf = ENVIRON["LOWCONF"]
                }
                NR == FNR { if ($0 !~ /^#/) tld[tolower($0)]; next }
                !/[a-z]/ && (NF == 2 || length($NF) > 3) { low($0); next }
                /[a-z]/ && $NF !~ /^([a-z]+|xn--[a-z0-9-]+)$/ {
                    low($0)
                    while (NF > 1 && $NF !~ /^([a-z]+|xn--[a-z0-9-]+)$/) sub(/\.[^.]*$/, "")
                    if (NF < 2) next
                }
                ($1 in is_js) && NF == 2 { low($0); next }
                NF == 2 && length($1) == 1 && $NF !~ /^(com|net|org|me)$/ { low($0); next }
                { file_case = substr($0, 1, length($0) - length($NF)) !~ /[a-z]/; $0 = tolower($0) }
                !($NF in tld) || ($NF in is_brand) { next }
                /^[0-9.]+\.[a-z]+$/ { low($0); next }
                /^((note\.)?gnu\.build|note\.gnu\.(gold|property)|text\.hot|rela?\.got|gnu\.sparse\.(map|name))$/ { low($0); next }
                /^(rela?\.)?(gnu\.linkonce\.[a-z][a-z]?(\.rel\.ro)?|l?data\.rel\.ro|rel\.ro)$/ { low($0); next }
                ($NF in is_ext) && (NF == 2 || $(NF - 1) ~ /^[0-9]+$/ || file_case) { low($0); next }
                $1 ~ /^(com|org|net)$/ { print > rdns; next }
                { print }' "$TLDS_FILE" - \
            | sort | uniq -c | sort -rn > "${strings_dir}/domains.txt" 2>/dev/null || true
        local f
        for f in reverse_dns domains_lowconf; do
            LC_ALL=C sort "${strings_dir}/.${f}" 2>/dev/null | uniq -c | sort -rn \
                > "${strings_dir}/${f}.txt" || true
            rm -f "${strings_dir}/.${f}"
        done
    else
        warn "TLD list not found at ${TLDS_FILE} — skipping domains.txt"
    fi

    local path_categories=()
    case "$TARGET_OS" in
        windows)
            grep -oE '[A-Za-z]:\\[^[:space:]"'\''<>:*?|]+' "${strings_dir}/all.txt" \
                | sort -u > "${strings_dir}/windows_paths.txt" 2>/dev/null || true
            path_categories=(windows_paths)
            ;;
        linux|mac)
            grep -oE '/(bin|sbin|lib|lib64|etc|home|tmp|var|opt|usr|root|proc|dev|sys|boot|run|mnt|media|srv|Library|Applications|System|Users|Volumes)/[^[:space:]"'\''<>]+' \
                "${strings_dir}/all.txt" \
                | sort -u > "${strings_dir}/unix_paths.txt" 2>/dev/null || true
            path_categories=(unix_paths)
            ;;
    esac

    echo ""
    for category in ipv4 urls emails domains domains_lowconf reverse_dns "${path_categories[@]}"; do
        local count=0
        [[ -f "${strings_dir}/${category}.txt" ]] && count=$(wc -l < "${strings_dir}/${category}.txt")
        printf '  %b%-20s%b %d unique entries\n' "${CYAN}" "$category" "${NC}" "$count"
    done

    echo ""
    success "Strings extracted to ${OUTPUT_PATH}/strings/"
}

# ─── File Dumping (Windows only) ─────────────────────────────────────────────

dump_files() {
    if [[ "$TARGET_OS" != "windows" ]]; then
        warn "--dump-files is only supported for Windows dumps — skipping"
        return
    fi

    header "Dumping files from memory"

    local dump_dir="${OUTPUT_DIR}/dump_files"
    mkdir -p "$dump_dir"

    info "Running windows.dumpfiles (this may take a while)..."
    if run_job "$VOL" "${VOL_OPTS[@]}" -o "$dump_dir/" -f "$MEMORY_DUMP" windows.dumpfiles > "${OUTPUT_DIR}/dumpfiles_index.txt" 2>"${OUTPUT_DIR}/dumpfiles.err"; then
        local count
        count=$(find "$dump_dir" -type f 2>/dev/null | wc -l)
        success "Dumped ${count} files to ${OUTPUT_PATH}/dump_files/"
    else
        warn "windows.dumpfiles completed with errors (check dumpfiles.err)"
    fi
}

# ─── Registry Dump (Windows only) ───────────────────────────────────────────

dump_registry() {
    if [[ "$TARGET_OS" != "windows" ]]; then
        warn "--dump-registry is only supported for Windows dumps — skipping"
        return
    fi

    header "Dumping registry hives"

    local reg_dir="${OUTPUT_DIR}/registry_dump"
    mkdir -p "$reg_dir"

    info "Dumping registry hives via windows.registry.hivelist --dump..."
    if run_job "$VOL" "${VOL_OPTS[@]}" -o "$reg_dir/" -f "$MEMORY_DUMP" windows.registry.hivelist --dump \
            > "${OUTPUT_DIR}/registry_dump_index.txt" 2>"${OUTPUT_DIR}/registry_dump.err"; then
        local count
        count=$(find "$reg_dir" -type f 2>/dev/null | wc -l)
        success "Dumped ${count} registry hives to ${OUTPUT_PATH}/registry_dump/"
        info "Analyze offline with RegRipper, Registry Explorer, or regipy"
    else
        warn "Registry dump had errors (check registry_dump.err)"
    fi
}

# ─── Report Generation ──────────────────────────────────────────────────────

generate_text_report() {
    local report="${OUTPUT_DIR}/analysis_summary.txt"
    local analysis_date
    analysis_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local file_size
    file_size=$(file_size_bytes "$MEMORY_DUMP")

    cat > "$report" <<-REPORT
	═══════════════════════════════════════════════════════════════
	  Volatility 3 — Analysis Summary
	  Generated by vol-analyze v${VERSION}
	═══════════════════════════════════════════════════════════════

	Target OS   : ${TARGET_OS}
	Memory Dump : ${MEMORY_DUMP}
	File Size   : ${file_size} bytes
	MD5         : ${CHECKSUM_MD5:-N/A}
	SHA256      : ${CHECKSUM_SHA256:-N/A}
	Date (UTC)  : ${analysis_date}
	Duration    : ${ANALYSIS_DURATION}s
	Output Dir  : ${OUTPUT_PATH}
	Symbols Dir : ${SYMBOL_DIR:-none}
	ISF URL     : ${ISF_URL:-none}
	Symbols Used: ${SYMBOLS_USED:-unknown}

	───────────────────────────────────────────────────────────────
	  Plugins (${PLUGINS_SUCCEEDED}/${#PLUGINS[@]} succeeded)
	───────────────────────────────────────────────────────────────
	REPORT

    for plugin in "${PLUGINS[@]}"; do
        local status output_file lines="-"
        status=$(plugin_status "$plugin")
        output_file="${OUTPUT_DIR}/$(safe_name "$plugin").txt"
        [[ -f "$output_file" ]] && lines=$(wc -l < "$output_file")
        printf "  %-8s %-40s %6s lines\n" "${status^^}" "$plugin" "$lines" >> "$report"
    done

    cat >> "$report" <<-REPORT

	───────────────────────────────────────────────────────────────
	  https://github.com/gl0bal01/volatility-toolkit
	═══════════════════════════════════════════════════════════════
	REPORT

    success "Text report:  ${OUTPUT_PATH}/${report#./}"
}

generate_json_report() {
    [[ "$JSON_OUTPUT" != true ]] && return

    local report="${OUTPUT_DIR}/analysis_summary.json"
    local analysis_date
    analysis_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local file_size
    file_size=$(file_size_bytes "$MEMORY_DUMP")

    {
        printf '{\n'
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "target_os": "%s",\n' "$TARGET_OS"
        printf '  "analysis_date": "%s",\n' "$analysis_date"
        printf '  "memory_dump": {\n'
        printf '    "path": "%s",\n' "$(json_escape "$MEMORY_DUMP")"
        printf '    "size_bytes": %s,\n' "$file_size"
        printf '    "md5": "%s",\n' "${CHECKSUM_MD5:-}"
        printf '    "sha256": "%s"\n' "${CHECKSUM_SHA256:-}"
        printf '  },\n'
        printf '  "execution": {\n'
        printf '    "duration_seconds": %d,\n' "$ANALYSIS_DURATION"
        printf '    "max_parallel": %d,\n' "$MAX_PARALLEL"
        printf '    "symbol_dir": "%s",\n' "$(json_escape "$SYMBOL_DIR")"
        printf '    "isf_url": "%s",\n' "$(json_escape "$ISF_URL")"
        printf '    "symbols_used": "%s",\n' "$(json_escape "$SYMBOLS_USED")"
        printf '    "plugins_total": %d,\n' "${#PLUGINS[@]}"
        printf '    "plugins_succeeded": %d,\n' "$PLUGINS_SUCCEEDED"
        printf '    "plugins_failed": %d\n' "$PLUGINS_FAILED"
        printf '  },\n'
        printf '  "plugins": {\n'

        local first=true
        for plugin in "${PLUGINS[@]}"; do
            local status output_file lines=0
            status=$(plugin_status "$plugin")
            output_file="${OUTPUT_DIR}/$(safe_name "$plugin").txt"
            [[ -f "$output_file" ]] && lines=$(wc -l < "$output_file")

            [[ "$first" == true ]] && first=false || printf ',\n'
            printf '    "%s": {"status": "%s", "exit_code": %s, "duration_seconds": %s, "output_lines": %d}' \
                "$plugin" "$status" "${PLUGIN_RC[$plugin]:-null}" "${PLUGIN_SECS[$plugin]:-null}" "$lines"
        done

        printf '\n  },\n'
        printf '  "output_directory": "%s"\n' "$(json_escape "$OUTPUT_PATH")"
        printf '}\n'
    } > "$report"

    success "JSON report:  ${OUTPUT_PATH}/${report#./}"
}

# ─── Banner ──────────────────────────────────────────────────────────────────

print_banner() {
    printf '%b' "${BOLD}${CYAN}"
    cat <<'BANNER'

  __     __   _  _____           _ _    _ _
  \ \   / /__|_||_   _|__   ___|_| | _(_) |_
   \ \ / / _ \ |  | |/ _ \ / _ \ | |/ / | __|
    \ V / (_) | |  | | (_) | (_) | |   <| | |_
     \_/ \___/|_|  |_|\___/ \___/|_|_|\_\_|\__|

BANNER
    printf '%b' "${NC}"
    printf '  %bMemory Forensics v%s — %s%b\n' "${DIM}" "${VERSION}" "${TARGET_OS}" "${NC}"
    printf '  %bhttps://github.com/gl0bal01/volatility-toolkit%b\n\n' "${DIM}" "${NC}"
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    setup_colors

    VOL="${VOL3_CMD:-vol}"

    parse_args "$@"
    validate
    readonly VOL

    # The TLD list sits at <prefix>/share/volatility-toolkit beside
    # <prefix>/bin (scripts/../share in a checkout). Found before the cd.
    TLDS_FILE="$(dirname -- "$(resolve_path "${BASH_SOURCE[0]}")")/../share/volatility-toolkit/tlds.txt"

    # umask 077 makes a new directory 700. An existing one keeps its mode:
    # chmod on it (-o /tmp) would strip a sticky bit or lock users out.
    mkdir -p -- "$OUTPUT_DIR"

    # Work inside the output directory from here on (vol inherits it): a
    # path is resolved again on every write, so someone who can write to a
    # parent directory could swap it mid-run and receive the hashdump. The
    # checks run after mkdir and cd, on the directory actually used: it must
    # be ours and closed to others, and then empty, so nobody can have
    # planted files or symlinks in it and no earlier run's results get mixed
    # with this dump's.
    cd -P -- "$OUTPUT_DIR" || fatal "Cannot enter output directory: ${OUTPUT_DIR}"
    OUTPUT_PATH=$(pwd -P)
    if system_dir "$OUTPUT_PATH"; then
        fatal "Refusing to use system directory as output: ${OUTPUT_DIR}"
    fi
    reject_cntrl "$OUTPUT_PATH"
    [[ -O . ]] || fatal "Output directory is not owned by you: ${OUTPUT_DIR} — pick a new directory"
    if [[ -n "$(find . -prune \( -perm -020 -o -perm -002 \))" ]]; then
        fatal "Output directory is writable by group/others: ${OUTPUT_DIR} — chmod go-w it or pick a new directory"
    fi
    [[ -r . ]] || fatal "Output directory is not readable: ${OUTPUT_DIR} — pick a new directory"
    [[ -z "$(ls -A)" ]] || fatal "Output directory is not empty: ${OUTPUT_DIR} — pick a new directory"
    OUTPUT_DIR=.

    # ── OS detection ──
    if [[ "$TARGET_OS" == "auto" ]]; then
        detect_os
    else
        info "Target OS: ${BOLD}${TARGET_OS}${NC}"
    fi

    select_plugins

    print_banner

    local file_size human_size_str
    file_size=$(file_size_bytes "$MEMORY_DUMP")
    human_size_str=$(human_size "$file_size")

    info "Memory dump: ${BOLD}${MEMORY_DUMP}${NC} (${human_size_str})"
    info "Output dir:  ${BOLD}${OUTPUT_PATH}${NC}"
    info "Plugins:     ${#PLUGINS[@]} (${TARGET_OS}), ${MAX_PARALLEL} parallel"

    # ── Phase 1: Chain of custody ──
    compute_checksums

    # ── Phase 2: Core analysis ──
    run_all_plugins

    # ── Phase 3: Optional operations ──
    if [[ "$DUMP_FILES" == true ]];       then dump_files;       fi
    if [[ "$EXTRACT_STRINGS" == true ]];  then extract_strings;  fi
    if [[ "$DUMP_REGISTRY" == true ]];    then dump_registry;    fi

    # ── Phase 4: Interactive prompts (only with --interactive) ──
    if [[ "$INTERACTIVE" == true ]]; then
        echo ""
        if [[ "$EXTRACT_STRINGS" != true ]]; then
            read -rp "$(printf '%b[?]%b Extract IOC strings? (y/N) ' "${YELLOW}" "${NC}")" answer || answer=""
            [[ "${answer,,}" == "y" ]] && extract_strings
        fi
        if [[ "$TARGET_OS" == "windows" ]]; then
            if [[ "$DUMP_FILES" != true ]]; then
                read -rp "$(printf '%b[?]%b Dump files from memory? (y/N) ' "${YELLOW}" "${NC}")" answer || answer=""
                [[ "${answer,,}" == "y" ]] && dump_files
            fi
            if [[ "$DUMP_REGISTRY" != true ]]; then
                read -rp "$(printf '%b[?]%b Dump registry hives? (y/N) ' "${YELLOW}" "${NC}")" answer || answer=""
                [[ "${answer,,}" == "y" ]] && dump_registry
            fi
        fi
    fi

    # ── Phase 5: Reports ──
    header "Reports"
    generate_text_report
    generate_json_report

    echo ""
    # Non-zero exit for automation: nothing ran usefully (wrong --os, or no
    # kernel symbols for Linux/macOS).
    if (( PLUGINS_SUCCEEDED == 0 )); then
        fatal "No plugin succeeded — check --os and, for Linux/macOS, kernel symbols (--symbols / --isf-url; see .err files in ${OUTPUT_PATH}/)"
    fi
    success "Analysis complete — results in ${BOLD}${OUTPUT_PATH}/${NC}"
}

# Allow sourcing without auto-running main (used by the test harness).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
