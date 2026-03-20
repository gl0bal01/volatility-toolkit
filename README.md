# Volatility Toolkit

[![Lint](https://github.com/gl0bal01/volatility-toolkit/actions/workflows/lint.yml/badge.svg)](https://github.com/gl0bal01/volatility-toolkit/actions/workflows/lint.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Volatility 3](https://img.shields.io/badge/Volatility-3-blue)](https://github.com/volatilityfoundation/volatility3)
[![Shell](https://img.shields.io/badge/Shell-Bash%204%2B-green)](scripts/vol-analyze.sh)
[![DFIR](https://img.shields.io/badge/DFIR-Toolkit-critical)](https://gl0bal01.com/intel-codex/category/analysis)

**Automated memory forensics for Windows, Linux, and macOS.** Auto-detects the OS, runs the right plugins in parallel, extracts IOCs, generates structured reports — one command.

> Built for DFIR practitioners who are tired of running the same 20+ `vol` commands manually on every case.

## Demo

<!-- Replace this with your asciinema recording or GIF -->
<!-- To record: asciinema rec demo.cast -c './scripts/vol-analyze.sh memory.raw --os windows --extract-strings --json' -->
<!-- To embed: [![asciicast](https://asciinema.org/a/YOUR_ID.svg)](https://asciinema.org/a/YOUR_ID) -->

> **TODO:** Record a demo with a real memory dump, then replace this section.

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

## What It Does

1. **Auto-detects** whether the dump is Windows, Linux, or macOS
2. Computes MD5 + SHA256 for chain of custody
3. Runs all relevant plugins in parallel batches
4. Separates stdout from stderr (errors never corrupt output)
5. Shows per-plugin timing and success/failure status
6. Generates a structured summary report (text + optional JSON)
7. Optionally extracts IOC strings (IPs, URLs, domains, emails, file paths)
8. Optionally dumps files and registry hives (Windows)

## Platform Support

| OS | Plugins | Highlights |
|----|---------|------------|
| **Windows** | 30 | Processes, DLLs, network, registry, services, malware detection, kernel drivers, SSDT |
| **Linux** | 21 | Processes, bash history, kernel modules, network, rootkit checks (syscall/IDT/creds) |
| **macOS** | 20 | Processes, kexts, network, TrustedBSD, kauth listeners, syscall/sysctl checks |

## Features

| Feature | Description |
|---------|-------------|
| **OS auto-detection** | Probes the dump to select the right plugin set |
| **Parallel execution** | Run up to N plugins simultaneously (`-j 8`) |
| **Colored output** | Green for success, yellow for warnings, per-plugin timing |
| **IOC extraction** | Pull IPs, URLs, domains, emails, and file paths from strings |
| **JSON reports** | Machine-readable summary with per-plugin status |
| **Chain of custody** | MD5 + SHA256 computed before analysis begins |
| **Non-interactive** | No prompts by default — safe for scripts and CI |
| **Registry export** | Dump raw hive files for offline analysis (Windows) |
| **Error isolation** | stderr captured to `.err` files — never mixed into results |

## Usage

```
vol-analyze <memory_dump> [options]

OPTIONS
        --os TYPE               Target OS: windows, linux, mac, auto (default: auto)
    -o, --output DIR            Output directory (default: volatility_output)
    -j, --jobs N                Max parallel plugins (default: 4)
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
    NO_COLOR                    Set to disable colors (any value)
```

### Examples

```bash
# Auto-detect OS, default output
vol-analyze memory.raw

# Windows analysis with all extras
vol-analyze memory.raw --os windows \
    -o case-001/ -j 8 \
    --dump-files --dump-registry --extract-strings --json

# Linux dump (LiME format)
vol-analyze memory.lime --os linux --extract-strings --json

# macOS analysis
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
├── ...                          # (all plugin outputs)
├── strings/                     # (with --extract-strings)
│   ├── all.txt                  # Raw strings
│   ├── ipv4.txt                 # IPv4 addresses
│   ├── urls.txt                 # URLs
│   ├── domains.txt              # Domain names (by frequency)
│   ├── emails.txt               # Email addresses
│   └── windows_paths.txt        # Windows paths  (Windows)
│   └── unix_paths.txt           # Unix paths     (Linux/macOS)
├── dump_files/                  # (Windows --dump-files)
├── registry_dump/               # (Windows --dump-registry)
├── analysis_summary.txt         # Human-readable report
└── analysis_summary.json        # (with --json)
```

## Documentation

Practical, opinionated guides — not just command references.

- **[Windows Cheatsheet](docs/vol3-cheatsheet.md)** — 30 plugins with workflow context
- **[Linux Cheatsheet](docs/linux-cheatsheet.md)** — 21 plugins including rootkit detection
- **[macOS Cheatsheet](docs/mac-cheatsheet.md)** — 20 plugins including TrustedBSD and kauth
- **[Malware Analysis Guide](docs/vol3-malware-analysis.md)** — Hunting malware in memory
- **[Investigation Methodology](docs/investigation-methodology.md)** — Structured DFIR workflow

## Tab Completion

Bash and Zsh completions are included — completes flags, `--os` values, and memory dump files.

```bash
# Bash — installed automatically by `make install`, or source manually:
source completions/vol-analyze.bash

# Zsh — copy to your fpath:
cp completions/vol-analyze.zsh ~/.zsh/completions/_vol-analyze
```

## External Resources

- [SOP: Malware Analysis](https://gl0bal01.com/intel-codex/Security/Analysis/sop-malware-analysis) — Standard operating procedures
- [Analysis Knowledge Base](https://gl0bal01.com/intel-codex/category/analysis) — Guides and writeups
- [Binary Refinery — Practical Guide](https://gl0bal01.com/reverse/binary-refinery-practical-guide) — Binary analysis workflows
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility Foundation](https://volatilityfoundation.org/)

## Requirements

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) — `vol` in PATH (or set `VOL3_CMD`)
- Bash 4.0+
- Standard Unix tools: `strings`, `md5sum`, `sha256sum`, `grep`, `sort`, `uniq`

### Linux/macOS Memory Dumps

Linux and macOS analysis requires matching kernel symbols. See the cheatsheets for setup:
- [Linux symbol generation](docs/linux-cheatsheet.md#symbol-requirements)
- [macOS symbol generation](docs/mac-cheatsheet.md#symbol-requirements)

## Contributing

Issues, feature requests, and pull requests are welcome.

## License

**[AGPL-3.0](LICENSE)** — Free for open-source and personal use.

If you want to use this in a commercial product or closed-source service without releasing your modifications, a commercial license is available. Contact [@gl0bal01](https://github.com/gl0bal01) for details.

---

Built by [@gl0bal01](https://github.com/gl0bal01) | [gl0bal01.com](https://gl0bal01.com)
