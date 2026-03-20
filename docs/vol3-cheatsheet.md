# Volatility 3 — Complete Cheatsheet

Practical command reference organized by investigation phase. Every plugin includes what it does, when to reach for it, and what to look for in the output.

> **Syntax**: `vol -f <memory_dump> <plugin> [options]`
>
> Output to file: `vol -f <dump> <plugin> > output.txt 2>errors.txt`
>
> Dump artifacts to directory: `vol -o <output_dir>/ -f <dump> <plugin>`

---

## Table of Contents

- [System Information](#system-information)
- [Process Analysis](#process-analysis)
- [DLLs and Loaded Libraries](#dlls-and-loaded-libraries)
- [Network Analysis](#network-analysis)
- [File System](#file-system)
- [Registry Analysis](#registry-analysis)
- [Credential Extraction](#credential-extraction)
- [Malware Detection](#malware-detection)
- [Kernel and Driver Analysis](#kernel-and-driver-analysis)
- [Services](#services)
- [Dumping Artifacts](#dumping-artifacts)
- [Crash Dumps](#crash-dumps)
- [Timeline Analysis](#timeline-analysis)
- [YARA Integration](#yara-integration)
- [Hibernation and Page Files](#hibernation-and-page-files)
- [Tips and Tricks](#tips-and-tricks)

---

## System Information

### windows.info

Get the OS version, build, architecture, and kernel base address. **Always run first** — it validates that Volatility can parse the dump and tells you what you're dealing with.

```bash
vol -f memory.raw windows.info
```

**Look for:** OS version (helps identify which artifacts to expect), system time (anchor for timeline analysis), number of processors.

---

## Process Analysis

### windows.pslist

List processes from the `ActiveProcessLinks` doubly-linked list in the EPROCESS structure. This is the "official" process list that Windows maintains.

```bash
vol -f memory.raw windows.pslist
```

**Look for:** Unfamiliar process names, processes with abnormal PIDs (PID 4 should always be System), processes spawned at odd times, misspelled system process names (e.g., `scvhost.exe` instead of `svchost.exe`).

### windows.psscan

Scan physical memory for EPROCESS structures using pool tag scanning. Finds processes that unlinked themselves from the active list (a classic rootkit technique).

```bash
vol -f memory.raw windows.psscan
```

**When to use:** Always. Compare against `pslist` — processes that appear in `psscan` but not `pslist` are likely hiding.

**Look for:** Any process in `psscan` that's missing from `pslist`. Also catches terminated processes whose memory hasn't been reclaimed.

### windows.pstree

Display processes as a parent-child tree. Critical for understanding process lineage.

```bash
vol -f memory.raw windows.pstree
```

**Look for:** Unusual parent-child relationships. `svchost.exe` should always be a child of `services.exe`. `cmd.exe` spawned by `winword.exe` is suspicious. `explorer.exe` should have exactly one instance per interactive session and its parent should be `userinit.exe`.

### windows.cmdline

Show the full command line arguments for each process.

```bash
vol -f memory.raw windows.cmdline
```

**Look for:** Encoded PowerShell commands (`-enc`, `-EncodedCommand`), unusual flags on system binaries, `cmd.exe /c` chains, references to temp directories or network paths, LOLBin abuse patterns.

### windows.sessions

Show session information for each process (which logon session a process belongs to).

```bash
vol -f memory.raw windows.sessions
```

**Look for:** Processes running in unexpected sessions. Session 0 is services; Session 1+ are interactive users. A "user" process running in Session 0 may indicate a service-based backdoor.

### windows.getsids

Display the Security Identifiers (SIDs) associated with each process.

```bash
vol -f memory.raw windows.getsids
```

**Look for:** Processes running as SYSTEM (S-1-5-18) that shouldn't be, or user-level processes that have elevated SIDs. Helps identify privilege escalation.

### windows.privileges

Show enabled and present privileges for each process.

```bash
vol -f memory.raw windows.privileges
```

**Look for:** `SeDebugPrivilege` on processes that don't need it (used for process injection), `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeTcbPrivilege` — all can indicate compromise.

### windows.envars

Display environment variables for each process.

```bash
vol -f memory.raw windows.envars
```

**Look for:** Custom environment variables set by malware, modified PATH variables, variables pointing to attacker-controlled directories, `TEMP`/`TMP` pointing to unusual locations.

---

## DLLs and Loaded Libraries

### windows.dlllist

List DLLs loaded by each process from the PEB (Process Environment Block).

```bash
vol -f memory.raw windows.dlllist

# Filter to a specific process
vol -f memory.raw windows.dlllist | grep -i "1234"

# Look for a specific DLL across all processes
vol -f memory.raw windows.dlllist | grep -i "suspicious.dll"
```

**Look for:** DLLs loaded from unusual paths (temp folders, user directories, network shares), DLLs with names mimicking system libraries, unsigned DLLs in system processes.

### windows.handles

List open handles (files, registry keys, mutexes, events, etc.) for each process.

```bash
vol -f memory.raw windows.handles

# Filter by PID
vol -f memory.raw windows.handles --pid 1234
```

**Look for:** Handles to sensitive registry keys, mutexes used as infection markers (common in malware), handles to other processes (may indicate injection), file handles to unusual locations.

### windows.vadinfo

Show Virtual Address Descriptor (VAD) details for each process. VADs describe memory regions.

```bash
vol -f memory.raw windows.vadinfo
```

**Look for:** Memory regions with `PAGE_EXECUTE_READWRITE` protection (common in injected code), private memory regions with executable permissions, large committed regions that could be unpacked payloads.

---

## Network Analysis

### windows.netscan

Scan for network artifacts in memory — active connections, listening sockets, and recently closed connections.

```bash
vol -f memory.raw windows.netscan
```

**Look for:** Connections to known-bad IPs, unusual listening ports, established connections from processes that shouldn't be network-active (e.g., `notepad.exe`), connections on high-numbered ports, connections to external IPs from internal services.

### windows.netstat

Show network connections from kernel structures (like running `netstat` at the time of capture).

```bash
vol -f memory.raw windows.netstat
```

**Difference from netscan:** `netstat` reads active kernel structures; `netscan` scans memory for remnants. Use both — `netscan` may find connections that closed before the dump.

---

## File System

### windows.filescan

Scan memory for FILE_OBJECT structures. Finds every file the OS had open or recently accessed.

```bash
vol -f memory.raw windows.filescan

# Find specific files
vol -f memory.raw windows.filescan | grep -i "password"
vol -f memory.raw windows.filescan | grep -i "\.exe"
vol -f memory.raw windows.filescan | grep -iE "\.(bat|ps1|vbs|js)"
```

**Look for:** Executables in temp directories, scripts in user folders, known malware filenames, files dropped in `\Windows\Temp\`, `\AppData\Local\Temp\`, or startup locations.

### windows.dumpfiles

Dump file contents from memory using their physical offset or by scanning.

```bash
# Dump all files (slow, large output)
vol -o dump_dir/ -f memory.raw windows.dumpfiles

# Dump by physical or virtual address (get offset from filescan)
vol -o dump_dir/ -f memory.raw windows.dumpfiles --physaddr 0x3fc77360
vol -o dump_dir/ -f memory.raw windows.dumpfiles --virtaddr 0x8a0f1070
```

---

## Registry Analysis

### windows.registry.hivelist

List registry hives loaded in memory and their virtual/physical offsets.

```bash
vol -f memory.raw windows.registry.hivelist
```

**Look for:** Non-standard hives loaded from unusual paths — malware sometimes loads its own registry hives.

### windows.registry.printkey

Print a specific registry key and its subkeys/values.

```bash
# Print root keys
vol -f memory.raw windows.registry.printkey

# Print specific key
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Recurse into subkeys
vol -f memory.raw windows.registry.printkey \
    --key "Software\Microsoft\Windows\CurrentVersion\Run" --recurse
```

**Common keys to check:**

| Key | Purpose |
|-----|---------|
| `Software\Microsoft\Windows\CurrentVersion\Run` | User autostart |
| `Software\Microsoft\Windows\CurrentVersion\RunOnce` | One-time autostart |
| `SYSTEM\CurrentControlSet\Services` | Service registration |
| `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | Shell/Userinit hijacking |
| `Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` | Special folder redirects |

### windows.registry.userassist

Parse UserAssist registry entries — tracks GUI programs executed by each user.

```bash
vol -f memory.raw windows.registry.userassist
```

**Look for:** Executables run from unusual paths, recently run tools that indicate attacker activity (PsExec, mimikatz, recon tools), ROT13-encoded entries (pre-Win7).

---

## Credential Extraction

### windows.hashdump

Extract NTLM password hashes from the SAM registry hive.

```bash
vol -f memory.raw windows.hashdump
```

**Output format:** `username:RID:LM_hash:NTLM_hash:::`

Use the hashes with tools like `hashcat` or `john` for cracking, or check against rainbow tables.

### windows.lsadump

Dump LSA secrets — may contain cached domain credentials, service account passwords, and other sensitive data.

```bash
vol -f memory.raw windows.lsadump
```

**Look for:** Cleartext passwords, cached credentials, VPN passwords, auto-logon credentials.

---

## Malware Detection

### windows.malfind

Find potentially injected or hidden code in process memory. Detects memory regions that are executable, private, and not backed by a file on disk.

```bash
vol -f memory.raw windows.malfind

# Dump suspicious regions for further analysis
vol -o malfind_dumps/ -f memory.raw windows.malfind
```

**Look for:** `MZ` headers (PE files injected into memory), shellcode patterns, regions tagged `VadS` with `PAGE_EXECUTE_READWRITE` protection. Not every hit is malicious — verify with static analysis.

### windows.mutantscan

Scan for mutex (mutant) objects in memory. Many malware families use specific mutexes to prevent multiple infections.

```bash
vol -f memory.raw windows.mutantscan
```

**Look for:** Known malware mutex names (check threat intel databases), mutexes created by suspicious processes, mutex names that look like random strings or encoded data.

### windows.mbrscan

Scan for Master Boot Record structures. Detects bootkits that modify the MBR.

```bash
vol -f memory.raw windows.mbrscan
```

**Look for:** Multiple MBR copies (indicates modification), MBRs with non-standard boot code, signatures of known bootkits.

---

## Kernel and Driver Analysis

### windows.driverscan

Scan for driver objects in memory.

```bash
vol -f memory.raw windows.driverscan
```

**Look for:** Drivers loaded from unusual paths (not `\SystemRoot\system32\drivers\`), drivers with suspicious names, unsigned drivers.

### windows.modscan

Scan physical memory for kernel module structures using pool tag scanning. Like `psscan` for modules — finds unlinked kernel modules.

```bash
vol -f memory.raw windows.modscan
```

**Look for:** Modules present in `modscan` but missing from `modules` (loaded module list) — they may be hiding.

### windows.modules

List kernel modules from the loaded module list (official kernel view).

```bash
vol -f memory.raw windows.modules
```

**Compare with `modscan`:** Differences suggest a rootkit is manipulating the module list.

### windows.ssdt

Show the System Service Descriptor Table. Rootkits hook SSDT entries to intercept system calls.

```bash
vol -f memory.raw windows.ssdt
```

**Look for:** SSDT entries pointing outside `ntoskrnl.exe` or `win32k.sys` address ranges — these indicate hooks.

### windows.callbacks

List kernel callbacks. Malware registers callbacks to get notified of system events (process creation, image loading, registry changes).

```bash
vol -f memory.raw windows.callbacks
```

**Look for:** Callbacks registered by non-standard drivers, callbacks pointing to memory regions outside known modules.

---

## Services

### windows.svcscan

Scan for Windows service information in memory.

```bash
vol -f memory.raw windows.svcscan
```

**Look for:** Services with unusual binary paths (especially `cmd.exe`, PowerShell, or paths in temp directories), services set to auto-start that shouldn't be, services with modified `ImagePath` values, services running as SYSTEM with user-level binaries.

---

## Dumping Artifacts

### Dump process memory

```bash
# Dump the full memory space of PID 1640
vol -o dump_dir/ -f memory.raw windows.memmap.Memmap --pid 1640 --dump
```

Then analyze the dump:

```bash
# Search for strings in the process dump
strings pid.1640.dmp | grep -i "password"
strings pid.1640.dmp | grep -oE 'https?://[^ ]+'

# Search for DLLs referenced in memory
strings pid.1640.dmp | grep -i '\.dll' | sort -u
```

### Dump a file by offset

```bash
# Get the offset from filescan
vol -f memory.raw windows.filescan | grep "suspicious.exe"

# Dump by physical address
vol -o dump_dir/ -f memory.raw windows.dumpfiles --physaddr 0x3fc77360
```

---

## Thread Analysis

### windows.thrdscan

Scan for ETHREAD structures in memory. Finds threads that may have been unlinked from their owning process.

```bash
vol -f memory.raw windows.thrdscan
```

**Look for:** Orphaned threads (threads without a valid owning process), threads in unexpected processes, threads whose start address points outside any loaded module (potential injection).

---

## Crash Dumps

### windows.crashinfo

Extract information from Windows crash dump files.

```bash
vol -f crashdump.dmp windows.crashinfo
```

---

## Timeline Analysis

### timeliner

Generate a timeline of system events from multiple sources.

```bash
vol -f memory.raw timeliner
```

**Pro tip:** Pipe to a file and sort by timestamp for chronological analysis:

```bash
vol -f memory.raw timeliner > timeline.txt
```

---

## YARA Integration

### yarascan

Scan process or kernel memory with YARA rules.

```bash
# Scan with a YARA rules file
vol -f memory.raw yarascan --yara-file rules.yar

# Scan a specific process
vol -f memory.raw yarascan --yara-file rules.yar --pid 1234

# Scan kernel memory
vol -f memory.raw yarascan --yara-file rules.yar --kernel
```

---

## Hibernation and Page Files

These aren't Volatility plugins but are essential parts of memory forensics.

### Extract and analyze hiberfil.sys

```bash
# 1. Extract hiberfil.sys using FTK Imager from C:\
# 2. Convert with Hibernation Recon to .raw format
# 3. Analyze with Volatility as a normal memory dump
vol -f hiberfil.raw windows.info
```

### Analyze pagefile.sys

```bash
# 1. Extract pagefile.sys using FTK Imager from C:\
# 2. Extract strings
strings pagefile.sys > pagefile_strings.txt

# 3. Or use bulk_extractor for structured extraction
bulk_extractor -o pagefile_output/ pagefile.sys
```

---

## Tips and Tricks

### Filtering output

```bash
# Find processes by name
vol -f memory.raw windows.pslist | grep -i "cmd.exe"

# Find network connections by port
vol -f memory.raw windows.netscan | grep ":4444"

# Find files by extension
vol -f memory.raw windows.filescan | grep -iE "\.(exe|dll|sys)"
```

### Combining plugins for context

```bash
# 1. Find suspicious process in pstree
vol -f memory.raw windows.pstree | grep -A2 -B2 "suspicious.exe"

# 2. Get its command line
vol -f memory.raw windows.cmdline | grep "1234"

# 3. Check its network activity
vol -f memory.raw windows.netscan | grep "1234"

# 4. Check its DLLs
vol -f memory.raw windows.dlllist | grep "1234"

# 5. Dump its memory for deeper analysis
vol -o dump/ -f memory.raw windows.memmap.Memmap --pid 1234 --dump
```

### Dump registry hives for offline analysis

Export raw binary hive files from memory for use with specialized tools:

```bash
vol -o registry_output/ -f memory.raw windows.registry.hivelist --dump
```

Output files are named `registry.{hive_name}.{offset}.hive` and can be analyzed with:

- **RegRipper** — automated registry analysis with plugins
- **Registry Explorer** — GUI-based registry browsing (SANS)
- **regipy** — Python library for programmatic analysis

```bash
# Example with regipy
pip install regipy
regipy parse registry_output/registry.SAM.0x12345678.hive > sam_parsed.txt
```

### Performance

- Use `-j` (jobs) flag in the analysis script to tune parallelism
- `windows.handles` and `windows.filescan` are typically the slowest plugins
- `strings` on large dumps (8GB+) can take several minutes — be patient
- If `vol` crashes on a plugin, the dump may be corrupted in that region — try other plugins

---

## Further Reading

- [SOP: Malware Analysis](https://gl0bal01.com/intel-codex/Security/Analysis/sop-malware-analysis)
- [Analysis Knowledge Base](https://gl0bal01.com/intel-codex/category/analysis)
- [Binary Refinery Guide](https://gl0bal01.com/reverse/binary-refinery-practical-guide)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility Foundation](https://volatilityfoundation.org/)
