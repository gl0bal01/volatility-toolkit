# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Breaking:** the output directory must be new or empty, the default `volatility_output` included: a second plain `vol-analyze` run in the same directory stops with "Output directory is not empty". Pass a new `-o` directory per dump. Why: see the first two Security entries.

### Security
- The output directory is entered once and then written through relative paths. Every write used to resolve the path again, so someone who can write to a parent directory (a shared case folder, or the current directory of a `sudo` run) could swap in a directory with planted symlinks mid-run: it received the hashdump, and `strings/all.txt` could overwrite any file the analyst can write.
- An existing output directory must be empty, as with bulk_extractor. Entries planted earlier (symlinks, world-readable files) were written through, and a second run into the same directory mixed two dumps' results: the text report named the new dump while `analysis_summary.json` kept the old one's hashes. **Scripts that reuse an output directory must pass a new one.**
- `strings/domains_lowconf.txt`: names that match a noise filter (minified JS, file names, all-numeric, all-caps or mixed-case TLDs, ELF section names) are kept there instead of being dropped, so a host registered to look like noise (`evil.app`, `navigator.top`, `4444.top`, `q.ai`, `Evil-C2.Top`) is never lost. Only names that cannot be registered (no IANA TLD, closed brand TLDs) are dropped. 28,277 entries on Windows 10, 1,058 on Windows 7, 8,029 on Debian 7, 5,121 on macOS 10.9.
- Control characters (C0, DEL, and C1 as UTF-8) in any argument (dump, output, `--symbols` and `--isf-url` paths, option values, `VOL3_CMD`) are refused, also when a symlinked directory brings them into a resolved path: a file name with newlines forged lines (MD5, plugin status) in the text report, and escape sequences reached the terminal. Unknown options are shown shell-quoted.
- A relative dump path is made absolute before `vol` sees it: `vol` read `http://host/mem.raw` (a local directory named `http:`) as a URL and fetched it, so the recorded hashes and the analysis covered different data.
- `-o` through a symlink to a system directory (`/etc`), or to a directory below one that did not exist yet (`/tmp/../etc/new/dir`), got past the blocklist; the nearest existing parent is resolved to its physical path now (macOS `/private/etc` included), and the directory is checked again once entered. `..` after a directory that does not exist yet (`-o new/../../etc/x`) is refused, as it cannot be resolved before `mkdir`.
- A backslash in the output path (`-o 'case\001'`) silently emptied `domains.txt` (awk `-v` decodes escapes) and could redirect a temporary file outside the output directory.
- CI checkouts no longer keep the `GITHUB_TOKEN` in `.git/config` (`persist-credentials: false`).

### Added
- Monthly "Real dumps" workflow (`make real-test` locally, `make ci-real` for every CI step): runs `vol-analyze` with the latest Volatility 3 release on public Linux (Debian), Windows 10 and macOS 10.9 images, all pinned by SHA-256, with OS auto-detection, as in the Quick Start, and fails when the OS is misdetected, a plugin fails (outside a short list of known Volatility 3 bugs), the reports miss the symbols used, or the IOC lists lose a known host. The fake-vol tests cannot catch upstream plugin or CLI changes; this does.
- `make check-tlds` fails when IANA's TLD list has changed since the last `make update-tlds`; it runs in the monthly workflow.
- `strings/reverse_dns.txt`: reverse-DNS identifiers (`com.apple.audio`, `org.example.app`) are split out of `domains.txt` instead of being dropped. On a macOS 10.9 image they were 36% of all domain hits (`com.apple` alone 43,596): 537 names move out, leaving 20,136 domains.
- `SECURITY.md` with private vulnerability reporting, and a bug report form.
- `make hooks` runs `make ci` before every `git push` (versioned `.githooks/pre-push`).
- Release tags are SSH-signed, starting with v4.0.0.
- The text and JSON reports name the symbol table Volatility actually used ("Symbols Used" / `execution.symbols_used`): the ISF file or URL on Linux/macOS, the kernel PDB name and GUID on Windows. It is read from the first plugin's debug log (`vol.log`). "ISF URL: none" could hide a remote ISF that Volatility had cached on an earlier `--isf-url` run and kept using.
- `strings/domains.txt` matches all-caps hosts with three or more labels and a 2–3 letter TLD (`LOGIN.LIVE.COM`). Names are counted lower-cased, so `GitHub.com` and `github.com` add up.
- `strings/ipv4.txt` on macOS dumps reads netstat's `address.port` form (`10.0.0.5.443` → `10.0.0.5`).

### Fixed
- OS auto-detection stopped a slow probe with SIGTERM, which kills `vol` without running its cleanup: a probe cut short while `vol` downloaded the Windows kernel PDB could leave a broken symbol file behind for every later run. Probes are now stopped with SIGINT (and killed 10 s later if that is ignored). Likewise, Ctrl-C or SIGTERM to `vol-analyze` stops running `vol` processes with SIGINT (after 2 s, which a Ctrl-C in the terminal needs to reach them first), and with SIGTERM only if they are still running 5 s after that.
- `analysis_summary.json` was not valid UTF-8 for a file name in another encoding (`caf\xe9.raw`); such a path is written shell-quoted (`$'caf\351.raw'`).
- `strings` output is folded into lines of at most 8 KiB: one printable run of gigabytes in the image made `grep` and `sed` hold all of it in memory. An interrupted run stops `strings` too, and a `strings` failure partway through is reported.
- `-o` with a directory name starting with `-` failed in `mkdir`.
- Ctrl-C did not stop a shell loop over several dumps (`for f in *.raw; do vol-analyze "$f" -o "$f.out"; done`): `vol-analyze` exited with status 130, which tells the calling shell the interrupt was handled; it now ends by SIGINT.
- A name followed by an underscore, alone or before a number (`c2.evil.top_`, `c2.evil.top_443`), was lost from `domains.txt`.
- Bash completion of `--isf-url` offered nothing once the URL contained `:` (`https:`), because readline splits words at colons.
- `strings/domains.txt` noise on real dumps (Windows 10, Windows 7 CTF image, Debian 7). Moved to `domains_lowconf.txt`: minified JavaScript (`this.id`, `t.name`; one-letter names stay domains on .com/.net/.org/.me: `x.org`, `t.me`), Windows prefetch names (`CMD.EXE-CD245F9E.pf`), .NET names (`System.IO`), ELF section and GNU tar header names by exact name (`note.gnu.build`, `data.rel.ro`, `gnu.linkonce.td`, `rela.got`, `text.hot`, `gnu.sparse.map`). Dropped: closed brand TLDs that clash with code names (`e.target`, `Date.now`, `microsoft.windows`, `wscript.shell`). URL escapes no longer glue onto names (`2Fwww.w3.org`, `%252F` double encoding included). Rules keyed on a first label (JS globals such as `self`, `window`) only apply to two-label names, so a subdomain an attacker picks (`self.c2-panel.top`) stays in `domains.txt`. 81,370 → 78,781 entries on Windows 10, 810 → 761 on Windows 7, 9,327 → 9,147 on Debian 7 (reverse-DNS identifiers now go to `reverse_dns.txt`: 190, 0 and 30).
- `strings/ipv4.txt` kept 0.x.x.x addresses, which are version strings: 784 → 511 entries on Debian 7, 2,531 → 2,503 on Windows 10, 269 → 266 on Windows 7.

## [3.0.0] - 2026-10-25

Every analysis run since 2.0.0 aborted when the first plugin launched; this release fixes that and was validated end to end on real dumps (MemLabs Lab 0 CTF image, Volatility 3 test-data Windows 10 and Debian 7 samples).

### Breaking
- Volatility 3 2.26.2+ is required (current plugin names). Output files `hashdump.txt` / `lsadump.txt` are now `registry_hashdump.txt` / `registry_lsadump.txt`.
- An existing output directory that is group/world-writable or not owned by you (including `-o /tmp`) is refused.
- Exit status is 1 when no plugin succeeds.
- Text report status column: `OK` / `WARN` → `SUCCESS` / `WARNING` / `FAILED` / `MISSING`.
- `--dump-registry` writes its index to `registry_dump_index.txt`; `registry_hivelist.txt` is the plugin output again.

### Added
- Windows: `windows.cmdscan` and `windows.consoles` (console command history and output) — 32 Windows plugins.
- `--symbols DIR` and `--isf-url URL` pass kernel symbols to every `vol` call (`-s` / `-u`), OS auto-detection included, so Linux/macOS dumps work without copying ISF files into Volatility's directories. `--isf-url` takes `https://` or `file://` only (a local `--symbols` directory is the tamper-proof option: Volatility retries a failed TLS verification unverified). Both are recorded in the text and JSON reports.
- `make update-tlds` refreshes the IANA TLD list used for domain IOCs; `make install` installs it to `$(BINDIR)/../share/volatility-toolkit/`.

### Fixed
- Plugins started in parallel on a cold Volatility cache (first Windows run with `--os`, which downloads the kernel PDB, or `--isf-url` without auto-detection) could read each other's half-written cache files and fail with `JSONDecodeError` (seen on `linux.lsmod`). The first plugin now runs alone and fills the cache.
- `--dump-registry` overwrote the `windows.registry.hivelist` plugin output (`registry_hivelist.txt`) with its own index. When hive extraction stops early (paged-out hive on a Windows 10 dump), the hive list and its report line count were lost. The dump index now goes to `registry_dump_index.txt`.
- `strings/ipv4.txt` kept invalid addresses and pieces of OIDs and version strings (`931.331.331.353`, `1.3.6.1` from `1.3.6.1.4.1.311`): 510 of 779 entries on a Windows 7 CTF image. Only whole dotted quads (trailing dots allowed) with octets up to 255 and no leading zeros are kept; `address.port` forms such as `10.0.0.5.443` are not matched.
- `strings/domains.txt` was mostly file names and .NET type names on real dumps. A name must now end in a lower-case IANA TLD (`share/volatility-toolkit/tlds.txt`, internationalised `xn--` TLDs included). For TLDs that double as file extensions (`.sh`, `.py`, `.zip`…), file-like names (`run.sh`, `libfoo-2.0.so`) are dropped and hosts (`c2.evil.sh`) kept: 18,778 → 810 entries on a Windows 7 CTF image, 370,609 → 81,370 on Windows 10, 47,674 → 9,327 on Debian 7. Upper-case host names are no longer matched.
- Analysis aborted when the first plugin launched: `(( i++ ))` evaluates to 0, which `set -e` treats as failure. The same pattern in `human_size()` aborted runs on macOS without `numfmt`. Use pre-increment.
- `-j 08` (zero-padded) made the scheduler spin forever without launching a plugin (octal parse error inside `(( ))`). Values are now parsed as base 10.
- Ctrl-C / SIGTERM no longer resumes the scheduler loop or leaves orphaned `vol` processes: INT/TERM exit, and `vol` runs as a direct child so cleanup can kill it. OS auto-detection, `strings`, `--dump-files` and `--dump-registry` also stop at once (they used to run to completion, up to 3×60s for detection).
- Every plugin was reported as WARN/"warning": vol's progress bar went to `.err`. vol now runs with `-q`, and status comes from its exit code.
- Freed worker slots could idle until a slow plugin finished (`wait -n` ignores jobs that already exited). Replaced with a 1s poll.
- Colors printed as literal `\033[...]` text in `--help` and status lines on a TTY.
- `chmod 700` was applied to pre-existing output directories (`-o /tmp` as root stripped the sticky bit). Replaced by `umask 077`: new directories are 700 and every output file is 600, including inside an existing directory (hashdump/lsadump output is no longer group-readable under umask 002).
- An existing output directory that is not owned by the user, or is group/world-writable, is refused: another user could pre-create output files or symlinks and receive the hashdump/lsadump results.
- The system-directory blocklist never matched top-level paths: `-o /etc`, `-o /`, `-o /usr`, `-o /tmp/../etc` were accepted (the path was built as `//etc`).
- A backslash in the dump's file name corrupted the recorded MD5/SHA256 (GNU tools prefix the hash with `\`) and made the JSON invalid. Hashes are computed from stdin and validated as hex.
- `.com` domains were dropped from `strings/domains.txt` (`com` was in the file-extension blocklist).
- Interactive prompts aborted the run on EOF instead of treating it as "no".
- zsh completion file filter used brace syntax, which never matches in a glob; bash completion offered no dump files without `extglob`, and inserted names with spaces unescaped.

### Changed
- Plugin names updated for Volatility 3 2.26.2+; the old aliases are past their removal dates: `windows.malware.malfind`, `windows.registry.hashdump`, `windows.registry.lsadump`, `linux.malware.*` (malfind, check_syscall, check_idt, check_modules, check_creds, check_afinfo, tty_check, keyboard_notifiers). Output files: `hashdump.txt` → `registry_hashdump.txt`, `lsadump.txt` → `registry_lsadump.txt`; malware plugins keep their old names.
- Linux/macOS docs: prebuilt ISFs from Abyss-W4tcher/volatility3-symbols (banner lookup or `--remote-isf-url`), and `~/.cache/volatility3/symbols/` instead of the install directory.
- Docs updated for current plugin names and options (YARA, hashdump extras, removed `mac.timecounter`, no Volatility 2 `imageinfo`).
- Report statuses: `SUCCESS` / `WARNING` (exit 0 with stderr) / `FAILED` / `MISSING`. JSON adds per-plugin `exit_code` and `duration_seconds`.
- Checksums fall back to `md5` / `shasum -a 256` (stock macOS), with a warning if a hash cannot be computed.
- Exit status is 1 when no plugin succeeds (wrong `--os`, missing kernel symbols); reports are still written.
- `VOL_DETECT_TIMEOUT` is validated; a warning is shown when no `timeout`/`gtimeout` exists to enforce it.
- Windows `--extract-strings` also extracts UTF-16LE strings (GNU `strings -e l`).
- Output-dir blocklist no longer rejects `/var/*` and `/run/*` subtrees (`/var/tmp`, macOS `$TMPDIR`, `/run/media/$USER` evidence drives).
- `VOL3_CMD` accepts `vol.py`; dropped `python`/`python3`, which could never work without a script argument.
- `NO_COLOR` follows no-color.org: only a non-empty value disables color.
- Explicit bash 4.0+ check with a clear error (macOS `/bin/bash` is 3.2).
- `make install` supports `DESTDIR` and installs bash completion to `$(PREFIX)/share/bash-completion/completions` (replaces the legacy `/etc/bash_completion.d`) and zsh completion to `$(PREFIX)/share/zsh/site-functions`. `make uninstall` removes only the files it installed (no more `rm -rf $(DOCDIR)`).
- `VOL_DETECT_TIMEOUT` documented in `--help` and the README.

### CI
- `actions/checkout` bumped to v7.0.1 (pinned SHA); CI steps call `make lint` / `make check` / `make test`; `permissions: contents: read` and job timeouts.
- `make lint` now covers the tests, the bash completion and `scripts/ci-local.sh`.
- macOS job installs Homebrew bash (the script needs bash 4+).
- New `make ci` (`scripts/ci-local.sh`) mirrors CI locally.
- Tests: the grep-for-`chmod` stub was replaced by end-to-end runs against a fake `vol` (scheduler, exit codes, reports, JSON validity, file modes, top-level `-o` rejection, IOC extraction, auto-detection, SIGTERM during plugins and detection).

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
