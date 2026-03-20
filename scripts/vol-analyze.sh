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

# ─── Constants ───────────────────────────────────────────────────────────────

readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly DEFAULT_MAX_PARALLEL=4
readonly DEFAULT_OUTPUT_DIR="volatility_output"

# ─── Colors ──────────────────────────────────────────────────────────────────

setup_colors() {
    if [[ -t 1 ]] && [[ -z "${NO_COLOR+set}" ]]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        CYAN='\033[0;36m'
        MAGENTA='\033[0;35m'
        BOLD='\033[1m'
        DIM='\033[2m'
        NC='\033[0m'
    else
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' DIM='' NC=''
    fi
}

# ─── Logging ─────────────────────────────────────────────────────────────────

info()    { printf "${BLUE}[*]${NC} %s\n" "$*"; }
success() { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
error()   { printf "${RED}[-]${NC} %s\n" "$*" >&2; }
fatal()   { error "$*"; exit 1; }
header()  { printf "\n${BOLD}${MAGENTA}══ %s${NC}\n\n" "$*"; }

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
    -o, --output DIR            Output directory (default: ${DEFAULT_OUTPUT_DIR})
    -j, --jobs N                Max parallel plugins (default: ${DEFAULT_MAX_PARALLEL})
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
    NO_COLOR                    Set to disable colored output (any value)

${BOLD}EXAMPLES${NC}
    ${SCRIPT_NAME} memory.raw                                    # auto-detect OS
    ${SCRIPT_NAME} memory.raw --os linux -o case-001/ -j 8
    ${SCRIPT_NAME} memory.raw --os windows --dump-files --json
    ${SCRIPT_NAME} memory.lime --os linux --extract-strings

${BOLD}SUPPORTED OS${NC}
    windows   30 plugins — processes, network, registry, malware, drivers, services
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

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)            usage ;;
            -v|--version)         echo "${SCRIPT_NAME} v${VERSION}"; exit 0 ;;
            --os)                 TARGET_OS="${2:?Missing argument for $1}"; shift 2 ;;
            -o|--output)          OUTPUT_DIR="${2:?Missing argument for $1}"; shift 2 ;;
            -j|--jobs)            MAX_PARALLEL="${2:?Missing argument for $1}"; shift 2 ;;
            --dump-registry)      DUMP_REGISTRY=true; shift ;;
            --dump-files)         DUMP_FILES=true; shift ;;
            --extract-strings)    EXTRACT_STRINGS=true; shift ;;
            --json)               JSON_OUTPUT=true; shift ;;
            --interactive)        INTERACTIVE=true; shift ;;
            --no-color)           NO_COLOR=1; setup_colors; shift ;;
            -*)                   fatal "Unknown option: $1 (use --help)" ;;
            *)
                [[ -z "$MEMORY_DUMP" ]] || fatal "Unexpected argument: $1"
                MEMORY_DUMP="$1"; shift
                ;;
        esac
    done
}

# ─── Validation ──────────────────────────────────────────────────────────────

validate() {
    [[ -z "$MEMORY_DUMP" ]] && fatal "No memory dump specified. Usage: ${SCRIPT_NAME} <memory_dump> [options]"
    [[ -f "$MEMORY_DUMP" ]]  || fatal "File not found: ${MEMORY_DUMP}"
    [[ -r "$MEMORY_DUMP" ]]  || fatal "File not readable: ${MEMORY_DUMP}"

    command -v "$VOL" &>/dev/null || fatal "Volatility 3 (${VOL}) not found in PATH. Install: https://github.com/volatilityfoundation/volatility3"

    case "$TARGET_OS" in
        windows|linux|mac|auto) ;;
        *) fatal "Invalid --os value: ${TARGET_OS} (must be: windows, linux, mac, auto)" ;;
    esac

    # Reject dangerous output paths
    local resolved_output
    resolved_output=$(cd "$(dirname "$OUTPUT_DIR")" 2>/dev/null && pwd)/$(basename "$OUTPUT_DIR") || resolved_output="$OUTPUT_DIR"
    case "$resolved_output" in
        /|/etc|/etc/*|/usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/boot|/boot/*|/dev|/dev/*)
            fatal "Refusing to use system directory as output: ${OUTPUT_DIR}" ;;
    esac

    if ! [[ "$MAX_PARALLEL" =~ ^[0-9]+$ ]] || (( MAX_PARALLEL < 1 )); then
        fatal "Invalid --jobs value: ${MAX_PARALLEL} (must be a positive integer)"
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
        local dir base
        dir=$(cd "$(dirname "$1")" && pwd) || dir="$(dirname "$1")"
        base=$(basename "$1")
        echo "${dir}/${base}"
    fi
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────

cleanup() {
    local pids
    pids=$(jobs -p 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        printf "\n"
        warn "Interrupted — killing background jobs..."
        echo "$pids" | xargs kill 2>/dev/null || true
        wait 2>/dev/null || true
    fi
    rm -rf "${OUTPUT_DIR:?}/.timing" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ─── OS Detection ────────────────────────────────────────────────────────────

detect_os() {
    info "Auto-detecting OS from memory dump..."

    # Try each OS in order (most common first)
    if "$VOL" -f "$MEMORY_DUMP" windows.info &>/dev/null; then
        success "Detected: ${BOLD}Windows${NC}"
        echo "windows"
        return
    fi
    if "$VOL" -f "$MEMORY_DUMP" linux.pslist &>/dev/null; then
        success "Detected: ${BOLD}Linux${NC}"
        echo "linux"
        return
    fi
    if "$VOL" -f "$MEMORY_DUMP" mac.pslist &>/dev/null; then
        success "Detected: ${BOLD}macOS${NC}"
        echo "mac"
        return
    fi

    echo ""
}

# ─── Checksums ───────────────────────────────────────────────────────────────

CHECKSUM_MD5=""
CHECKSUM_SHA256=""

compute_checksums() {
    header "Chain of Custody — Checksums"

    local md5_tmp="${OUTPUT_DIR}/.md5"
    local sha256_tmp="${OUTPUT_DIR}/.sha256"
    local md5_pid="" sha256_pid=""

    if command -v md5sum &>/dev/null; then
        md5sum "$MEMORY_DUMP" > "$md5_tmp" 2>/dev/null &
        md5_pid=$!
    fi
    if command -v sha256sum &>/dev/null; then
        sha256sum "$MEMORY_DUMP" > "$sha256_tmp" 2>/dev/null &
        sha256_pid=$!
    fi

    if [[ -n "$md5_pid" ]]; then
        if wait "$md5_pid" 2>/dev/null; then
            CHECKSUM_MD5=$(cut -d ' ' -f1 < "$md5_tmp")
        fi
    fi
    if [[ -n "$sha256_pid" ]]; then
        if wait "$sha256_pid" 2>/dev/null; then
            CHECKSUM_SHA256=$(cut -d ' ' -f1 < "$sha256_tmp")
        fi
    fi

    rm -f "$md5_tmp" "$sha256_tmp"

    [[ -n "$CHECKSUM_MD5" ]]    && success "MD5:    ${CHECKSUM_MD5}" || true
    [[ -n "$CHECKSUM_SHA256" ]] && success "SHA256: ${CHECKSUM_SHA256}" || true
}

# ─── Plugin Definitions ─────────────────────────────────────────────────────

readonly WINDOWS_PLUGINS=(
    "windows.info"
    "windows.pslist"
    "windows.psscan"
    "windows.pstree"
    "windows.cmdline"
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
    "windows.hashdump"
    "windows.lsadump"
    "windows.driverscan"
    "windows.modscan"
    "windows.modules"
    "windows.ssdt"
    "windows.callbacks"
    "windows.malfind"
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
    "linux.malfind"
    "linux.check_syscall"
    "linux.check_idt"
    "linux.check_modules"
    "linux.check_creds"
    "linux.check_afinfo"
    "linux.tty_check"
    "linux.keyboard_notifiers"
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

# Derive a safe filename from a plugin name (strip OS prefix, dots to underscores)
safe_name() {
    local name="$1"
    name="${name#windows.}"
    name="${name#linux.}"
    name="${name#mac.}"
    name="${name//./_}"
    echo "$name"
}

run_all_plugins() {
    local total=${#PLUGINS[@]}
    local completed=0
    local succeeded=0
    local failed=0
    local start_time
    start_time=$(date +%s)

    header "Analyzing ${TARGET_OS} dump — ${total} plugins (${MAX_PARALLEL} parallel)"

    mkdir -p "${OUTPUT_DIR}/.timing"

    local i=0
    while (( i < total )); do
        local -a batch_pids=()
        local -a batch_names=()
        local -a batch_safe=()
        local batch_end=$(( i + MAX_PARALLEL ))
        (( batch_end > total )) && batch_end=$total

        while (( i < batch_end )); do
            local plugin="${PLUGINS[$i]}"
            local sname
            sname=$(safe_name "$plugin")
            local output_file="${OUTPUT_DIR}/${sname}.txt"
            local err_file="${OUTPUT_DIR}/${sname}.err"

            (
                _t_start=$(date +%s)
                "$VOL" -f "$MEMORY_DUMP" "$plugin" > "$output_file" 2>"$err_file"
                _t_end=$(date +%s)
                echo $(( _t_end - _t_start )) > "${OUTPUT_DIR}/.timing/${sname}"
            ) &

            batch_pids+=($!)
            batch_names+=("$plugin")
            batch_safe+=("$sname")
            (( i++ ))
        done

        for j in "${!batch_pids[@]}"; do
            local exit_code=0
            wait "${batch_pids[$j]}" 2>/dev/null || exit_code=$?

            (( completed++ ))

            local duration="?"
            local tfile="${OUTPUT_DIR}/.timing/${batch_safe[$j]}"
            [[ -f "$tfile" ]] && duration=$(cat "$tfile")

            if (( exit_code == 0 )); then
                (( succeeded++ ))
                printf "  ${GREEN}✓${NC} ${DIM}[%2d/%d]${NC} %-42s ${DIM}%ss${NC}\n" \
                    "$completed" "$total" "${batch_names[$j]}" "$duration"
            else
                (( failed++ ))
                printf "  ${YELLOW}!${NC} ${DIM}[%2d/%d]${NC} %-42s ${DIM}%ss (see .err)${NC}\n" \
                    "$completed" "$total" "${batch_names[$j]}" "$duration"
            fi
        done
    done

    local end_time
    end_time=$(date +%s)
    ANALYSIS_DURATION=$(( end_time - start_time ))
    PLUGINS_SUCCEEDED=$succeeded
    PLUGINS_FAILED=$failed

    rm -rf "${OUTPUT_DIR}/.timing"

    echo ""
    if (( failed == 0 )); then
        success "All ${total} plugins completed (${ANALYSIS_DURATION}s)"
    else
        success "${succeeded}/${total} succeeded, ${failed} with errors (${ANALYSIS_DURATION}s)"
    fi
}

# ─── IOC String Extraction ──────────────────────────────────────────────────

extract_strings() {
    header "Extracting IOC strings"

    local strings_dir="${OUTPUT_DIR}/strings"
    mkdir -p "$strings_dir"

    info "Running strings on memory dump (this may take a while for large dumps)..."
    if ! strings -n 6 "$MEMORY_DUMP" > "${strings_dir}/all.txt" 2>/dev/null; then
        warn "strings command failed or produced no output"
        return
    fi

    local total_strings
    total_strings=$(wc -l < "${strings_dir}/all.txt")
    info "Found ${total_strings} raw strings — categorizing IOCs..."

    # ── Universal patterns (all OSes) ──

    # IPv4 addresses
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "${strings_dir}/all.txt" \
        | grep -vE '^(0\.0\.0\.0|255\.255\.255\.255|127\.0\.0\.)' \
        | sort -u > "${strings_dir}/ipv4.txt" 2>/dev/null || true

    # URLs
    grep -oE 'https?://[^[:space:]"'\''<>]+' "${strings_dir}/all.txt" \
        | sort -u > "${strings_dir}/urls.txt" 2>/dev/null || true

    # Email addresses
    grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${strings_dir}/all.txt" \
        | sort -u > "${strings_dir}/emails.txt" 2>/dev/null || true

    # Domains (heuristic — sorted by frequency)
    grep -oE '\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(com|net|org|io|ru|cn|de|uk|info|biz|xyz|top|cc|su|tk)\b' \
        "${strings_dir}/all.txt" \
        | sort | uniq -c | sort -rn > "${strings_dir}/domains.txt" 2>/dev/null || true

    # ── OS-specific patterns ──

    local path_categories=()
    case "$TARGET_OS" in
        windows)
            grep -oE '[A-Z]:\\[^[:space:]"'\''<>:*?|]+' "${strings_dir}/all.txt" \
                | sort -u > "${strings_dir}/windows_paths.txt" 2>/dev/null || true
            path_categories=(windows_paths)
            ;;
        linux|mac)
            grep -oE '/(etc|home|tmp|var|opt|usr|root|proc|dev|Library|Applications)/[^[:space:]"'\''<>]+' \
                "${strings_dir}/all.txt" \
                | sort -u > "${strings_dir}/unix_paths.txt" 2>/dev/null || true
            path_categories=(unix_paths)
            ;;
    esac

    echo ""
    for category in ipv4 urls emails domains "${path_categories[@]}"; do
        local count=0
        [[ -f "${strings_dir}/${category}.txt" ]] && count=$(wc -l < "${strings_dir}/${category}.txt")
        printf "  ${CYAN}%-20s${NC} %'d unique entries\n" "$category" "$count"
    done

    echo ""
    success "Strings extracted to ${strings_dir}/"
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
    if "$VOL" -o "$dump_dir/" -f "$MEMORY_DUMP" windows.dumpfiles > "${OUTPUT_DIR}/dumpfiles_index.txt" 2>"${OUTPUT_DIR}/dumpfiles.err"; then
        local count
        count=$(find "$dump_dir" -type f 2>/dev/null | wc -l)
        success "Dumped ${count} files to ${dump_dir}/"
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
    if "$VOL" -o "$reg_dir/" -f "$MEMORY_DUMP" windows.registry.hivelist --dump \
            > "${OUTPUT_DIR}/registry_hivelist.txt" 2>"${OUTPUT_DIR}/registry_dump.err"; then
        local count
        count=$(find "$reg_dir" -type f 2>/dev/null | wc -l)
        success "Dumped ${count} registry hives to ${reg_dir}/"
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
    file_size=$(stat -c%s "$MEMORY_DUMP" 2>/dev/null || stat -f%z "$MEMORY_DUMP" 2>/dev/null || echo "unknown")

    cat > "$report" <<-REPORT
	═══════════════════════════════════════════════════════════════
	  Volatility 3 — Analysis Summary
	  Generated by vol-analyze v${VERSION}
	═══════════════════════════════════════════════════════════════

	Target OS   : ${TARGET_OS}
	Memory Dump : $(resolve_path "$MEMORY_DUMP")
	File Size   : ${file_size} bytes
	MD5         : ${CHECKSUM_MD5:-N/A}
	SHA256      : ${CHECKSUM_SHA256:-N/A}
	Date (UTC)  : ${analysis_date}
	Duration    : ${ANALYSIS_DURATION}s
	Output Dir  : $(resolve_path "$OUTPUT_DIR")

	───────────────────────────────────────────────────────────────
	  Plugins (${PLUGINS_SUCCEEDED}/${#PLUGINS[@]} succeeded)
	───────────────────────────────────────────────────────────────
	REPORT

    for plugin in "${PLUGINS[@]}"; do
        local sname
        sname=$(safe_name "$plugin")
        local output_file="${OUTPUT_DIR}/${sname}.txt"
        local err_file="${OUTPUT_DIR}/${sname}.err"

        if [[ -f "$output_file" ]]; then
            local lines
            lines=$(wc -l < "$output_file")
            local status="OK"
            if [[ -f "$err_file" ]] && [[ -s "$err_file" ]]; then
                status="WARN"
            fi
            printf "  %-6s %-40s %6d lines\n" "$status" "$plugin" "$lines" >> "$report"
        else
            printf "  %-6s %-40s %6s\n" "MISS" "$plugin" "-" >> "$report"
        fi
    done

    cat >> "$report" <<-REPORT

	───────────────────────────────────────────────────────────────
	  https://github.com/gl0bal01/volatility-toolkit
	═══════════════════════════════════════════════════════════════
	REPORT

    success "Text report:  ${report}"
}

generate_json_report() {
    [[ "$JSON_OUTPUT" != true ]] && return

    local report="${OUTPUT_DIR}/analysis_summary.json"
    local analysis_date
    analysis_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local file_size
    file_size=$(stat -c%s "$MEMORY_DUMP" 2>/dev/null || stat -f%z "$MEMORY_DUMP" 2>/dev/null || echo "0")

    json_escape() {
        local s="$1"
        s="${s//\\/\\\\}"
        s="${s//\"/\\\"}"
        s="${s//$'\n'/\\n}"
        s="${s//$'\t'/\\t}"
        printf '%s' "$s"
    }

    local dump_path
    dump_path=$(resolve_path "$MEMORY_DUMP")
    local out_path
    out_path=$(resolve_path "$OUTPUT_DIR")

    {
        printf '{\n'
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "target_os": "%s",\n' "$TARGET_OS"
        printf '  "analysis_date": "%s",\n' "$analysis_date"
        printf '  "memory_dump": {\n'
        printf '    "path": "%s",\n' "$(json_escape "$dump_path")"
        printf '    "size_bytes": %s,\n' "$file_size"
        printf '    "md5": "%s",\n' "${CHECKSUM_MD5:-}"
        printf '    "sha256": "%s"\n' "${CHECKSUM_SHA256:-}"
        printf '  },\n'
        printf '  "execution": {\n'
        printf '    "duration_seconds": %d,\n' "$ANALYSIS_DURATION"
        printf '    "max_parallel": %d,\n' "$MAX_PARALLEL"
        printf '    "plugins_total": %d,\n' "${#PLUGINS[@]}"
        printf '    "plugins_succeeded": %d,\n' "$PLUGINS_SUCCEEDED"
        printf '    "plugins_failed": %d\n' "$PLUGINS_FAILED"
        printf '  },\n'
        printf '  "plugins": {\n'

        local first=true
        for plugin in "${PLUGINS[@]}"; do
            local sname
            sname=$(safe_name "$plugin")
            local output_file="${OUTPUT_DIR}/${sname}.txt"
            local err_file="${OUTPUT_DIR}/${sname}.err"
            local status="missing" lines=0

            if [[ -f "$output_file" ]]; then
                lines=$(wc -l < "$output_file")
                if [[ -f "$err_file" ]] && [[ -s "$err_file" ]]; then
                    status="warning"
                else
                    status="success"
                fi
            fi

            [[ "$first" == true ]] && first=false || printf ',\n'
            printf '    "%s": {"status": "%s", "output_lines": %d}' "$plugin" "$status" "$lines"
        done

        printf '\n  },\n'
        printf '  "output_directory": "%s"\n' "$(json_escape "$out_path")"
        printf '}\n'
    } > "$report"

    success "JSON report:  ${report}"
}

# ─── Banner ──────────────────────────────────────────────────────────────────

print_banner() {
    printf "${BOLD}${CYAN}"
    cat <<'BANNER'

  __     __   _  _____           _ _    _ _
  \ \   / /__|_||_   _|__   ___|_| | _(_) |_
   \ \ / / _ \ |  | |/ _ \ / _ \ | |/ / | __|
    \ V / (_) | |  | | (_) | (_) | |   <| | |_
     \_/ \___/|_|  |_|\___/ \___/|_|_|\_\_|\__|

BANNER
    printf "${NC}"
    printf "  ${DIM}Memory Forensics v${VERSION} — ${TARGET_OS}${NC}\n"
    printf "  ${DIM}https://github.com/gl0bal01/volatility-toolkit${NC}\n\n"
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    setup_colors

    VOL="${VOL3_CMD:-vol}"

    parse_args "$@"
    validate

    mkdir -p "$OUTPUT_DIR"

    # ── OS detection ──
    if [[ "$TARGET_OS" == "auto" ]]; then
        TARGET_OS=$(detect_os)
        if [[ -z "$TARGET_OS" ]]; then
            fatal "Could not auto-detect OS. Specify manually with --os windows|linux|mac"
        fi
    else
        info "Target OS: ${BOLD}${TARGET_OS}${NC}"
    fi

    select_plugins

    print_banner

    local file_size
    file_size=$(stat -c%s "$MEMORY_DUMP" 2>/dev/null || stat -f%z "$MEMORY_DUMP" 2>/dev/null || echo "unknown")
    local human_size
    human_size=$(numfmt --to=iec "$file_size" 2>/dev/null || echo "${file_size} bytes") || true

    info "Memory dump: ${BOLD}${MEMORY_DUMP}${NC} (${human_size})"
    info "Output dir:  ${BOLD}${OUTPUT_DIR}${NC}"
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
            read -rp "$(printf "${YELLOW}[?]${NC} Extract IOC strings? (y/N) ")" answer
            [[ "${answer,,}" == "y" ]] && extract_strings
        fi
        if [[ "$TARGET_OS" == "windows" ]]; then
            if [[ "$DUMP_FILES" != true ]]; then
                read -rp "$(printf "${YELLOW}[?]${NC} Dump files from memory? (y/N) ")" answer
                [[ "${answer,,}" == "y" ]] && dump_files
            fi
            if [[ "$DUMP_REGISTRY" != true ]]; then
                read -rp "$(printf "${YELLOW}[?]${NC} Dump registry hives? (y/N) ")" answer
                [[ "${answer,,}" == "y" ]] && dump_registry
            fi
        fi
    fi

    # ── Phase 5: Reports ──
    header "Reports"
    generate_text_report
    generate_json_report

    echo ""
    success "Analysis complete — results in ${BOLD}${OUTPUT_DIR}/${NC}"
}

main "$@"
