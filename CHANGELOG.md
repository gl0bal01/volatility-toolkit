# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] - 2026-05-18

### Added
- macOS runner in CI matrix for cross-platform validation
- `zsh -n` syntax check for zsh completion in CI
- `make check` runtime dependency probe in CI
- 60s timeout per probe in `detect_os()` (configurable via `VOL_DETECT_TIMEOUT`)
- Continuous worker pool in `run_all_plugins()` via `wait -n` — slow plugins no longer stall their batch
- Portable `human_size()` helper (replaces direct `numfmt` dependency on macOS)
- `BASH_SOURCE`/`$0` guard so the script can be sourced by the test harness without invoking `main()`

### Changed
- `actions/checkout` now genuinely pinned to commit SHA `34e114876b0b11c390a56381ad16ebd13914f8d5` (previously a mutable `@v4` tag despite changelog claim)
- `json_escape()` moved to top-level scope and rewritten to escape all U+0000–U+001F control characters as `\uXXXX` (fixes malformed JSON for paths containing exotic bytes); dropped fragile `jq | sed` path
- `detect_os()` diagnostics routed to stderr — `$(detect_os)` now returns a clean OS name (fixes latent bug where status messages corrupted the captured value)
- IOC domain regex broadened to general TLD pattern with a file-extension blocklist (was a hardcoded list of 15 TLDs)
- Windows path regex accepts lowercase drive letters; Unix path regex now covers `/bin`, `/sbin`, `/lib`, `/lib64`, `/sys`, `/boot`, `/run`, `/mnt`, `/media`, `/srv`, `/System`, `/Users`, `/Volumes`
- `cleanup()` uses `kill $pids` directly (dropped `xargs` indirection)
- `resolve_path()` fallback always returns an absolute path
- Test harness sources the script directly instead of duplicating function bodies (eliminates drift between tests and implementation)
- Job completions (`-j`/`--jobs`) accept any positive integer instead of a hardcoded set
- Removed README "Demo TODO" placeholder

### Security
- `VOL` declared `readonly` after validation
- `.claude/` and `.omc/` added to `.gitignore` to prevent leaking AI-tool session artifacts
- Missing `shellcheck` now fails the test suite instead of silently passing (no more false sense of security in local runs)

### CI
- New `test` job runs `make test` on `ubuntu-latest` and `macos-latest`

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
