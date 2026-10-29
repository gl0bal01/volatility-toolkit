#!/usr/bin/env bash
# End-to-end test with the real Volatility 3 on public memory images: runs
# vol-analyze on a Linux, a Windows 10 and a macOS 10.9 image the default way
# (OS auto-detection) and fails when the OS is misdetected, a plugin fails,
# the reports miss the symbols used, or the IOC lists lose a known host.
# Catches upstream changes (plugin renames, CLI changes) that the fake-vol
# unit tests cannot.
#
# Runs monthly in .github/workflows/real-dumps.yml; locally: make real-test.
# Needs ~2 GB of downloads and ~10 GB of free disk. REAL_TEST_DIR=dir keeps
# downloads and images between runs (default: a fresh temp dir, removed on
# success; on failure or interrupt the downloads, images, symbols and caches
# are removed, and the logs, reports and plugin outputs kept).

set -uo pipefail
unset CDPATH

cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd)
command -v vol >/dev/null || { echo "vol (Volatility 3) not found in PATH" >&2; exit 1; }
KEEP="${REAL_TEST_DIR:+1}"
WORK="${REAL_TEST_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vol-real.XXXXXX")}"
mkdir -p "${WORK}/dl" "${WORK}/img" "${WORK}/sym"

# Drops the ~11 GB a failed or interrupted run no longer needs.
drop_bulk() {
    [[ -n "$KEEP" ]] || rm -rf "${WORK}/dl" "${WORK}/img" "${WORK}/sym" "${WORK}"/cache-*
}
trap 'drop_bulk; exit 130' INT
trap 'drop_bulk; exit 143' TERM

TD=https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1
ISF=https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download
# Pinned: a changed file fails the run instead of being trusted.
# name | url | sha256
DOWNLOADS=(
    "linux-sample-1.bin.gz|${TD}/linux-sample-1.bin.gz|910f272e5eeecdbf229e648d7b136a6722a11a5000f3995647364339417dfddd"
    "linux.zip|${TD}/linux.zip|58bb7da2ed1e491ce922d04a59881d201e233b5605c9fd5a7f0c08ee528253c6"
    "win-10_19041-2025_03.dmp.gz|${TD}/win-10_19041-2025_03.dmp.gz|b377ecd13bf40c90f59a8c41ffc8bc81166462627a7800ec82a67a73520c7f9d"
    "symbols_win-10_19041-2025_03.zip|${TD}/symbols_win-10_19041-2025_03.zip|abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e"
    "MacDump.zip|https://www.osforensics.com/downloads/MacDump.zip|8fb14571624f0b3759932fa0eeec7dd2d513e0ca9e33ff847d7639990a4d6a9b"
    "macOS_KDK_10.9.3_build-13D65.json.xz|${ISF}/isf-macOS-10.9/macOS_KDK_10.9.3_build-13D65.json.xz|240064f37de4f16e50219d1850cd138392c0a7dd813107b7ef85a712bb92f6e3"
)

sha256_of() { { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1; }

fetch() {
    local name="$1" url="$2" sum="$3" file="${WORK}/dl/$1"
    if [[ ! -f "$file" ]]; then
        curl -fsSL --retry 3 -o "${file}.part" "$url" && mv "${file}.part" "$file" || return 1
    fi
    [[ "$(sha256_of "$file")" == "$sum" ]] && return
    echo "checksum mismatch: ${name}" >&2
    rm -f "$file"   # fetched again on the next run
    return 1
}

# unpack <dest> <command...>: writes the command's output to dest once. A
# failed unpack (disk full, bad archive) never leaves a file under dest's
# name for later runs to reuse.
unpack() {
    local dest="$1"; shift
    [[ -f "$dest" ]] && return
    "$@" > "${dest}.part" && mv "${dest}.part" "$dest" && return
    rm -f "${dest}.part"
    return 1
}

# Images are big, so they are deleted after use unless kept.
prepare() {
    local dl="${WORK}/dl" img="${WORK}/img" sym="${WORK}/sym"
    case "$1" in
        linux)
            unpack "${img}/linux.bin" gunzip -c "${dl}/linux-sample-1.bin.gz" \
                && unzip -oq "${dl}/linux.zip" -d "${sym}/linux" ;;
        windows)
            unpack "${img}/win10.dmp" gunzip -c "${dl}/win-10_19041-2025_03.dmp.gz" \
                && mkdir -p "${sym}/windows/windows" \
                && unzip -oq "${dl}/symbols_win-10_19041-2025_03.zip" -d "${sym}/windows/windows" ;;
        mac)
            unpack "${img}/mac.dmp" unzip -p "${dl}/MacDump.zip" MacDump.dmp \
                && mkdir -p "${sym}/mac/mac" \
                && cp "${dl}/macOS_KDK_10.9.3_build-13D65.json.xz" "${sym}/mac/mac/" ;;
    esac
}

no_download() { [[ -s "$1" ]] && ! grep -q msdl.microsoft.com "$1"; }

# Fails unless the JSON lists <count> plugins, each a success, a warning
# (exit 0 with stderr, e.g. a missing registry key) or a known failure;
# notes known failures that now pass (drop them from the list).
only_known_failures() {
    local json="$1" count="$2" known=" ${3} " statuses bad fixed
    statuses=$(grep -oE '"[A-Za-z0-9_.]+": \{"status": "[a-z]+"' "$json" | awk -F'"' '{ print $2, $6 }')
    (( $(grep -c . <<< "$statuses") == count )) || { echo "        expected ${count} plugin statuses"; return 1; }
    bad=$(awk -v known="$known" '$2 !~ /^(success|warning)$/ && index(known, " " $1 " ") == 0 { printf " %s", $1 }' <<< "$statuses")
    fixed=$(awk -v known="$known" '$2 ~ /^(success|warning)$/ && index(known, " " $1 " ") > 0 { printf " %s", $1 }' <<< "$statuses")
    [[ -z "$fixed" ]] || echo "  NOTE  known failure(s) now pass:${fixed}"
    [[ -z "$bad" ]] || { echo "        unexpected failure(s):${bad}"; return 1; }
}

# check <case> <description> <command...>: one line per assertion.
check() {
    local name="$1" what="$2"; shift 2
    if "$@"; then
        printf '  PASS  %-8s %s\n' "$name" "$what"
    else
        printf '  FAIL  %-8s %s\n' "$name" "$what"
        FAILED=$(( FAILED + 1 ))
    fi
}

# run_case <os> <image> <plugin count> <known host in domains.txt> <known failures> [options]
run_case() {
    local os="$1" image="${WORK}/img/$2" plugins="$3" host="$4" known="$5"
    local out="${WORK}/out-${os}" log="${WORK}/${os}.log" rc=0
    shift 5
    prepare "$os" || { check "$os" "image and symbols unpacked" false; return; }
    rm -rf "$out"
    # A private cache per run: symbols must come from --symbols, not from
    # whatever an earlier run left in ~/.cache/volatility3.
    XDG_CACHE_HOME="${WORK}/cache-${os}" bash "${REPO}/scripts/vol-analyze.sh" "$image" "$@" \
        --symbols "${WORK}/sym/${os}" -o "$out" --json --extract-strings --no-color \
        > "$log" 2>&1 || rc=$?
    check "$os" "vol-analyze exits 0 (log: ${log})" test "$rc" -eq 0
    check "$os" "detected as ${os}" grep -q "\"target_os\": \"${os}\"" "${out}/analysis_summary.json"
    check "$os" "all ${plugins} plugins succeed${known:+ except known: ${known}}" \
        only_known_failures "${out}/analysis_summary.json" "$plugins" "$known"
    check "$os" "report names the symbols used" \
        grep -q '"symbols_used": "[^"]' "${out}/analysis_summary.json"
    check "$os" "symbols came from --symbols, not a download" no_download "${out}/vol.log"
    check "$os" "domains.txt has ${host}" grep -q " ${host}\$" "${out}/strings/domains.txt"
    check "$os" "ipv4.txt is not empty" test -s "${out}/strings/ipv4.txt"
    if [[ -z "$KEEP" ]]; then
        rm -f "$image" "${out}/strings/all.txt"
    fi
}

FAILED=0
echo "Volatility: $(vol -h 2>&1 | sed -n 1p)"
echo "Work dir:   ${WORK}"
for entry in "${DOWNLOADS[@]}"; do
    IFS='|' read -r name url sum <<< "$entry"
    check download "$name" fetch "$name" "$url" "$sum"
done

if (( FAILED == 0 )); then
    run_case linux   linux.bin 21 debian.org ""
    run_case windows win10.dmp 32 github.com "" --dump-registry
    check windows "registry hives dumped" test -n "$(ls -A "${WORK}/out-windows/registry_dump" 2>/dev/null)"
    # Volatility 3 bug on this 10.9 image: "The value of the enumeration is
    # outside the possible choices" (socket protocol) after partial output.
    run_case mac     mac.dmp   20 apple.com "mac.lsof mac.netstat"
fi

if (( FAILED > 0 )); then
    drop_bulk
    echo "${FAILED} real-dump check(s) failed — logs in ${WORK}"
    exit 1
fi
[[ -n "$KEEP" ]] || rm -rf "$WORK"
echo "All real-dump checks passed"
