# Volatility Toolkit

[![Lint](https://github.com/gl0bal01/volatility-toolkit/actions/workflows/lint.yml/badge.svg)](https://github.com/gl0bal01/volatility-toolkit/actions/workflows/lint.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Volatility 3](https://img.shields.io/badge/Volatility-3-blue)](https://github.com/volatilityfoundation/volatility3)
[![Shell](https://img.shields.io/badge/Shell-Bash%204%2B-green)](scripts/vol-analyze.sh)
[![DFIR](https://img.shields.io/badge/DFIR-Toolkit-critical)](https://gl0bal01.com/intel-codex/category/analysis)

**Memory forensics automation for Windows, Linux, and macOS.** Auto-detects the OS, runs the right plugins in parallel, extracts IOCs, and generates structured reports.

> Built for DFIR practitioners who are tired of running the same 20+ `vol` commands manually on every case.
>
> **Note:** Windows dumps work out of the box. Linux and macOS analysis requires [kernel symbols](#linuxmacos-memory-dumps) to be installed first.

## Quick Start

```bash
git clone https://github.com/gl0bal01/volatility-toolkit.git
cd volatility-toolkit

# Option A: install system-wide
sudo make install
vol-analyze memory.raw                         # auto-detects OS

# Option B: run directly
chmod +x scripts/vol-analyze.sh
./scripts/vol-analyze.sh memory.raw
```

> **Prerequisite:** Volatility 3 must be installed and available as `vol` in your PATH — install it with extras (`pipx install "volatility3[full]"`) so credential plugins like `windows.registry.hashdump` load. For Linux/macOS memory dumps, you also need matching [kernel symbols](#linuxmacos-memory-dumps).

## What It Does

1. **Auto-detects** whether the dump is Windows, Linux, or macOS
2. Computes MD5 + SHA256 for chain of custody
3. Runs all relevant plugins in parallel (`-j` workers)
4. Separates stdout from stderr (errors never corrupt output)
5. Shows per-plugin timing and success/failure status
6. Generates a structured summary report (text + optional JSON)
7. Optionally extracts IOC strings (IPs, URLs, domains, emails, file paths)
8. Optionally dumps files and registry hives (Windows)

## Platform Support

| OS | Plugins | Highlights | Prerequisites |
|----|---------|------------|---------------|
| **Windows** | 32 | Processes, console history, DLLs, network, registry, services, malware detection, kernel drivers, SSDT | None (Volatility 3 fetches kernel symbols from Microsoft on first use) |
| **Linux** | 21 | Processes, bash history, kernel modules, network, rootkit checks (syscall/IDT/creds) | [Kernel symbols required](#linuxmacos-memory-dumps) |
| **macOS** | 20 | Processes, kexts, network, TrustedBSD, kauth listeners, syscall/sysctl checks | [Kernel symbols required](#linuxmacos-memory-dumps) |

## Features

| Feature | Description |
|---------|-------------|
| **OS auto-detection** | Probes the dump to select the right plugin set |
| **Parallel execution** | Run up to N plugins simultaneously (`-j 8`) |
| **Colored output** | Green for success, yellow for warnings, per-plugin timing |
| **IOC extraction** | Pull IPs, URLs, domains, emails, and file paths from strings |
| **JSON reports** | Machine-readable summary with per-plugin status, exit code, and duration |
| **Chain of custody** | MD5 + SHA256 computed before analysis begins |
| **Non-interactive** | No prompts by default — safe for scripts and CI |
| **Registry export** | Dump raw hive files for offline analysis (Windows) |
| **Error isolation** | stderr captured to `.err` files; plugin status comes from vol's exit code |

## Usage

```
vol-analyze <memory_dump> [options]

OPTIONS
        --os TYPE               Target OS: windows, linux, mac, auto (default: auto)
    -o, --output DIR            New or empty output directory (default: volatility_output)
    -j, --jobs N                Max parallel plugins (default: 4)
        --symbols DIR           Extra Volatility 3 symbol directory (Linux/macOS ISF files)
        --isf-url URL           Remote ISF index to look up kernel symbols (https:// or file://)
        --dump-registry         Dump registry hives to disk (Windows only)
        --dump-files            Dump files from memory (Windows only)
        --extract-strings       Extract and categorize IOC strings
        --json                  Generate JSON summary report
        --interactive           Enable interactive prompts
        --no-color              Disable colored output
    -h, --help                  Show help
    -v, --version               Show version

ENVIRONMENT
    VOL3_CMD                    Volatility 3 command (default: vol)
    MAX_PARALLEL                Default parallel jobs (default: 4)
    VOL_DETECT_TIMEOUT          Seconds per OS auto-detection probe (default: 60)
    NO_COLOR                    Set to disable colors (any non-empty value)
```

### Examples

```bash
# Auto-detect OS, default output
vol-analyze memory.raw

# Windows analysis with all extras
vol-analyze memory.raw --os windows \
    -o case-001/ -j 8 \
    --dump-files --dump-registry --extract-strings --json

# Linux dump (LiME format) — requires kernel symbols
vol-analyze memory.lime --os linux --extract-strings --json

# Linux dump, kernel symbols looked up online (common distro kernels)
vol-analyze memory.lime --isf-url https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json

# Linux dump, your own ISF files
vol-analyze memory.lime --symbols ~/cases/isf/

# macOS analysis — requires kernel symbols
vol-analyze memory.raw --os mac -o mac-case/

# CI-friendly — no colors, JSON output
vol-analyze memory.raw --json --no-color 2>/dev/null
```

## Output Structure

```
volatility_output/
├── info.txt                     # OS info plugin output
├── pslist.txt                   # Process listing
├── pstree.txt                   # Process tree
├── netscan.txt / sockstat.txt   # Network (OS-dependent)
├── malfind.txt                  # Malware detection
├── *.err                        # Per-plugin error logs
├── vol.log                      # Volatility debug log of the first plugin (symbol lookup)
├── dumpfiles_index.txt / .err   # (Windows --dump-files)
├── registry_dump_index.txt / .err  # (Windows --dump-registry)
├── ...                          # (all plugin outputs)
├── strings/                     # (with --extract-strings)
│   ├── all.txt                  # Raw strings
│   ├── ipv4.txt                 # IPv4 addresses
│   ├── urls.txt                 # URLs
│   ├── domains.txt              # Domain names, IANA TLDs only, lower-cased (by frequency)
│   ├── domains_lowconf.txt      # Names that look like code or file names (this.id, run.sh)
│   ├── reverse_dns.txt          # Reverse-DNS IDs split out of domains (com.apple.audio)
│   ├── emails.txt               # Email addresses
│   └── windows_paths.txt        # Windows paths  (Windows)
│   └── unix_paths.txt           # Unix paths     (Linux/macOS)
├── dump_files/                  # (Windows --dump-files)
├── registry_dump/               # (Windows --dump-registry)
├── analysis_summary.txt         # Human-readable report
└── analysis_summary.json        # (with --json)
```

The output directory must be new or empty: results of two dumps are never mixed, and nothing planted in a shared directory is written through. Run it on a directory only you can write to.

The IOC lists in `strings/` are triage aids built with heuristics tuned on real dumps (IANA TLDs, noise filters for code and file names). A name that matches a noise filter goes to `domains_lowconf.txt`, not away: an attacker can register a host that looks like noise (`evil.app`, `navigator.top`). The lists can still miss an indicator. For evidence work, search `strings/all.txt`, which keeps every string, or use dedicated tools such as [bulk_extractor](https://github.com/simsong/bulk_extractor) or YARA.

## Documentation

Practical, opinionated guides — not just command references.

- **[Windows Cheatsheet](docs/vol3-cheatsheet.md)** — 32 plugins with workflow context
- **[Linux Cheatsheet](docs/linux-cheatsheet.md)** — 21 plugins including rootkit detection
- **[macOS Cheatsheet](docs/mac-cheatsheet.md)** — 20 plugins including TrustedBSD and kauth
- **[Malware Analysis Guide](docs/vol3-malware-analysis.md)** — Hunting malware in memory
- **[Investigation Methodology](docs/investigation-methodology.md)** — Structured DFIR workflow

## Tab Completion

Bash and Zsh completions are included — completes flags, `--os` values, and memory dump files.

```bash
# Both are installed by `make install` (bash-completion and zsh site-functions dirs).
# Without installing — Bash:
source completions/vol-analyze.bash

# Zsh — copy to a directory in your fpath:
cp completions/vol-analyze.zsh ~/.zsh/completions/_vol-analyze
```

## External Resources

- [SOP: Malware Analysis](https://gl0bal01.com/intel-codex/Security/Analysis/sop-malware-analysis) — Standard operating procedures
- [Analysis Knowledge Base](https://gl0bal01.com/intel-codex/category/analysis) — Guides and writeups
- [Binary Refinery — Practical Guide](https://gl0bal01.com/reverse/binary-refinery-practical-guide) — Binary analysis workflows
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility Foundation](https://volatilityfoundation.org/)

## Requirements

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) 2.26.2+ (current plugin names) — `vol` in PATH (or set `VOL3_CMD`); install `volatility3[full]` for the hashdump/lsadump plugins (pycryptodome)
- Bash 4.0+ (macOS ships 3.2: `brew install bash`)
- Standard Unix tools: `strings`, `md5sum`/`md5`, `sha256sum`/`shasum`, `awk`, `sed`, `grep`, `tr`, `fold`, `sort`, `uniq`, `find`, `stat`, `mktemp`, `mkfifo`
- `timeout` (GNU coreutils; `gtimeout` from Homebrew on macOS) to time-limit OS auto-detection (optional)
- GNU binutils `strings` for UTF-16LE string extraction on Windows dumps (optional)
- `iconv` to keep the JSON report valid for file names that are not UTF-8 (optional)

### Linux/macOS Memory Dumps

Linux and macOS analysis requires matching kernel symbols (ISF): pass a directory with `--symbols DIR`, put the files in `~/.cache/volatility3/symbols/{linux,mac}/`, or let `--isf-url URL` look the kernel up in a remote index (needs internet access; the URL is recorded in the reports). The reports also name the symbol table Volatility actually used ("Symbols Used"), which can be a remote ISF it cached on an earlier `--isf-url` run. Prebuilt ISFs for common distro kernels and macOS 10.6–10.15: [Abyss-W4tcher/volatility3-symbols](https://github.com/Abyss-W4tcher/volatility3-symbols). See the cheatsheets for lookup and generation:
- [Linux symbols](docs/linux-cheatsheet.md#symbol-requirements)
- [macOS symbols](docs/mac-cheatsheet.md#symbol-requirements)

## Contributing

Issues, feature requests, and pull requests are welcome. Report security problems privately, as described in [SECURITY.md](SECURITY.md).

Tests:
- `make ci` runs every push check locally: lint (ShellCheck), dependency probes, and the unit and end-to-end tests with a fake `vol`. `make hooks` runs it before every `git push`.
- `make real-test` runs `vol-analyze` with the real Volatility 3 on public Linux, Windows 10 and macOS 10.9 images (~2 GB download). GitHub runs it monthly with the latest Volatility 3 release, together with `make check-tlds`, which fails when IANA's TLD list has changed (refresh with `make update-tlds`). GitHub pauses scheduled workflows after 60 days without repository activity; re-enable "Real dumps" in the Actions tab.

## License

**[AGPL-3.0](LICENSE)** — Free for open-source and personal use.

If you want to use this in a commercial product or closed-source service without releasing your modifications, a commercial license is available. Contact [@gl0bal01](https://github.com/gl0bal01) for details.

---

Built by [@gl0bal01](https://github.com/gl0bal01) | [gl0bal01.com](https://gl0bal01.com)
