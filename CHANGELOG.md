# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-04-12

### Added
- Unit test suite with 31 tests covering core functions, argument parsing, and validation
- `make test` target for running tests
- Test stage in CI pipeline

### Changed
- Pinned `actions/checkout` to commit SHA for supply chain hardening
- Output directory now created with `chmod 700` to protect forensic data
- Expanded system directory blocklist with `/proc`, `/sys`, `/var`, `/lib`, `/run`
- Improved `json_escape()` to handle `\r`, `\b`, `\f` and prefer `jq` when available

### Security
- Added `VOL3_CMD` binary name validation to prevent command injection via environment
- Added symlink rejection on memory dump input path
- Added empty `OUTPUT_DIR` guard on cleanup `rm -rf`

## [2.0.0] - 2025-03-20

### Added
- Multi-OS memory forensics support (Windows, Linux, macOS)
- 71 Volatility 3 plugins across three OS targets
- Parallel plugin execution with configurable concurrency
- Auto-detection of target OS from memory dump
- Chain of custody checksums (MD5, SHA256)
- IOC string extraction (IPs, URLs, emails, domains, file paths)
- Windows-specific: file dumping and registry hive extraction
- Text and JSON report generation
- Interactive mode with optional prompts
- Bash and Zsh shell completions
- GNU Make install/uninstall/lint/check targets
- ShellCheck CI via GitHub Actions
- Documentation: cheatsheets for Windows, Linux, macOS, malware hunting, and DFIR methodology
- AGPL-3.0 license with commercial licensing option
