# Windows Memory Forensics — Investigation Methodology

A structured DFIR workflow for analyzing Windows memory dumps. This document covers the process from receiving the dump to delivering findings.

> This methodology is tool-aware but not tool-dependent. The commands use Volatility 3, but the thinking applies to any memory forensics toolchain.

---

## Table of Contents

- [Before You Start](#before-you-start)
- [Phase 1: Intake and Preservation](#phase-1-intake-and-preservation)
- [Phase 2: Triage](#phase-2-triage)
- [Phase 3: Deep Analysis](#phase-3-deep-analysis)
- [Phase 4: IOC Extraction](#phase-4-ioc-extraction)
- [Phase 5: Timeline Reconstruction](#phase-5-timeline-reconstruction)
- [Phase 6: Reporting](#phase-6-reporting)
- [Decision Trees](#decision-trees)
- [Common Investigation Scenarios](#common-investigation-scenarios)

---

## Before You Start

### What is a memory dump?

A memory dump is a snapshot of the contents of a computer's RAM at a specific point in time. It contains everything that was loaded in memory: running processes, open files, network connections, registry hives, user credentials, and malware that only exists in memory.

### Why memory forensics?

Memory is where fileless malware lives, where decrypted data exists, and where artifacts remain even after disk-level anti-forensics. If an attacker runs something in memory and never writes to disk, the disk image has nothing — but the memory dump does.

### Your toolkit

| Tool | Purpose |
|------|---------|
| **Volatility 3** | Primary memory analysis framework |
| **Volatility 2** | Legacy support, deeper registry analysis |
| **strings** | Raw string extraction from binary data |
| **YARA** | Pattern matching with custom or community rules |
| **bulk_extractor** | Automated artifact extraction (emails, URLs, credit cards) |
| **FTK Imager** | Acquiring memory dumps and extracting files |
| **Hibernation Recon** | Converting hiberfil.sys to analyzable format |

---

## Phase 1: Intake and Preservation

**Goal:** Establish chain of custody and validate the dump before any analysis.

### 1.1 Document the evidence

Before touching the file:

- Record who provided the dump, when, and how it was acquired
- Note the acquisition method (live capture tool, crash dump, hibernation file)
- Document the system context: hostname, OS version, role (workstation, server, DC)
- Record the reason for acquisition (what triggered the investigation)

### 1.2 Compute hashes

```bash
md5sum memory.raw
sha256sum memory.raw
```

Record both hashes in your case notes. Every copy of the dump should match these hashes.

### 1.3 Validate the dump

```bash
vol -f memory.raw windows.info
```

If this succeeds, Volatility can parse the dump. Note the OS version, architecture, and system time from the output — you'll reference these throughout the investigation.

**If it fails:** The dump may be corrupt, truncated, or in a format Volatility can't parse. Try `imageinfo` in Volatility 2.

---

## Phase 2: Triage

**Goal:** Within 15-30 minutes, determine if there's evidence of compromise and identify the highest-priority leads.

This is where the [analysis script](../scripts/vol-analyze.sh) earns its keep. Run it to generate baseline output for all major plugins.

```bash
./scripts/vol-analyze.sh memory.raw -o case-001/ --extract-strings --json
```

Then manually review the outputs in priority order:

### 2.1 Malware scan

```bash
cat case-001/malfind.txt
```

**If malfind finds injected code:** You have a strong lead. Note the process name, PID, and memory address. Proceed to [Phase 3](#phase-3-deep-analysis) for that process.

**If malfind is clean:** Not conclusive. Many attacks don't trigger `malfind`. Continue with process analysis.

### 2.2 Process tree review

```bash
cat case-001/pstree.txt
```

Questions to answer:
- Does the process hierarchy match the expected Windows layout?
- Are there any processes with unexpected parents?
- Are there processes that shouldn't exist on this type of system?
- Do any process names look like deliberate mimicry of system processes?

### 2.3 Network review

```bash
cat case-001/netscan.txt
```

Questions to answer:
- Are there connections to external IPs from non-browser processes?
- Are any processes listening on unexpected ports?
- Are there connections to known-bad IP ranges?
- Do any processes show lateral movement (connections to internal hosts on admin ports)?

### 2.4 Quick string IOCs

```bash
# If you ran --extract-strings
cat case-001/strings/urls.txt | head -50
cat case-001/strings/ipv4.txt | head -50
```

### 2.5 Triage decision

After triage, you should have one of these conclusions:

| Finding | Next Step |
|---------|-----------|
| **Strong indicators** (injected code, known malware, C2) | Phase 3: focus on the specific artifacts |
| **Suspicious anomalies** (odd processes, unexpected network) | Phase 3: investigate each anomaly |
| **Nothing obvious** | Phase 3: systematic deep analysis |
| **Confirmed clean** (rare — requires thorough check) | Document and report |

---

## Phase 3: Deep Analysis

**Goal:** Investigate each lead from triage to confirm or rule out compromise.

### 3.1 For a suspicious process

Follow this sequence for each suspicious PID:

```bash
# 1. What is it and who started it?
vol -f memory.raw windows.cmdline | grep "<PID>"
vol -f memory.raw windows.pstree | grep -A2 -B2 "<PID>"

# 2. What's it connected to?
vol -f memory.raw windows.netscan | grep "<PID>"

# 3. What DLLs does it have loaded?
vol -f memory.raw windows.dlllist | grep "<PID>"

# 4. What's it touching? (files, registry, mutexes)
vol -f memory.raw windows.handles --pid <PID>

# 5. What privileges does it have?
vol -f memory.raw windows.privileges | grep "<PID>"

# 6. Is there injected code?
vol -f memory.raw windows.malfind | grep -A20 "<PID>"

# 7. Dump its memory for offline analysis
vol -o dump/ -f memory.raw windows.memmap.Memmap --pid <PID> --dump
```

### 3.2 For a suspicious network connection

```bash
# Identify the process behind the connection (from netscan output)
# Then follow the process investigation above for that PID

# Additionally, check if other processes connect to the same destination
vol -f memory.raw windows.netscan | grep "<IP_ADDRESS>"
```

### 3.3 For persistence verification

Check all standard persistence locations:

```bash
# Autorun registry keys
vol -f memory.raw windows.registry.printkey \
    --key "Software\Microsoft\Windows\CurrentVersion\Run" --recurse

# Services
vol -f memory.raw windows.svcscan

# Userassist (GUI execution history)
vol -f memory.raw windows.registry.userassist

# Winlogon
vol -f memory.raw windows.registry.printkey \
    --key "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### 3.4 For rootkit investigation

```bash
# Compare visible vs scanned processes
vol -f memory.raw windows.pslist > pslist.txt
vol -f memory.raw windows.psscan > psscan.txt

# Compare visible vs scanned modules
vol -f memory.raw windows.modules > modules.txt
vol -f memory.raw windows.modscan > modscan.txt

# Check for SSDT hooks
vol -f memory.raw windows.ssdt

# Check kernel callbacks
vol -f memory.raw windows.callbacks
```

---

## Phase 4: IOC Extraction

**Goal:** Collect every actionable indicator of compromise for containment, hunting, and attribution.

### Types of IOCs from memory

| IOC Type | Where to Find It |
|----------|-----------------|
| IP addresses | `netscan`, `netstat`, process memory strings |
| Domains/URLs | Process memory strings, `filescan` |
| File hashes | Dump malicious files/processes, then hash them |
| File paths | `cmdline`, `dlllist`, `filescan`, `svcscan` |
| Registry keys | `printkey`, `userassist`, `svcscan` |
| Mutex names | `mutantscan`, `handles` |
| User accounts | `hashdump`, `getsids` |
| Service names | `svcscan` |
| Strings/patterns | Process memory dumps, YARA matches |

### Extract IOCs from process memory

```bash
# Dump the malicious process
vol -o dump/ -f memory.raw windows.memmap.Memmap --pid <PID> --dump

# Extract indicators
strings dump/pid.<PID>.dmp | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
strings dump/pid.<PID>.dmp | grep -oE 'https?://[^ ]+' | sort -u
strings dump/pid.<PID>.dmp | grep -oE '[A-Z]:\\[^ "]+' | sort -u
```

### YARA scanning

```bash
vol -f memory.raw yarascan.YaraScan --yara-file rules.yar
```

---

## Phase 5: Timeline Reconstruction

**Goal:** Establish the sequence of events to understand how the attack progressed.

### Build the timeline

Collect timestamps from:

1. **Process creation times** from `pslist` / `psscan`
2. **Network connection timestamps** from `netscan`
3. **Registry key timestamps** from `printkey`
4. **File timestamps** from `filescan`
5. **Volatility timeliner** for a consolidated view

```bash
vol -f memory.raw timeliner.Timeliner > timeline.txt
```

### Reconstruct the narrative

With the timeline data, answer:

1. **Initial access:** What was the first malicious process? When did it start?
2. **Execution:** What did the attacker run? In what order?
3. **Persistence:** When were persistence mechanisms installed?
4. **Lateral movement:** Are there connections to other internal hosts?
5. **Exfiltration:** Is there evidence of data leaving the network?

---

## Phase 6: Reporting

### Structure your report

1. **Executive summary** — one paragraph: what happened, how bad is it, what needs to happen next
2. **Scope** — what was analyzed, what wasn't, limitations of the analysis
3. **Findings** — chronological narrative of the attack, with evidence references
4. **IOCs** — full list of indicators for hunting and blocking
5. **Recommendations** — containment, eradication, and prevention actions
6. **Evidence chain** — hashes, tool versions, analysis steps for reproducibility

### Key reporting principles

- **State facts, not opinions.** "Process X connected to IP Y at time Z" not "the attacker probably..."
- **Include evidence for every claim.** Reference specific plugin output, offsets, and timestamps.
- **Note uncertainties.** If you can't determine something, say so.
- **Separate IOCs from narrative.** Responders need actionable data fast.

---

## Decision Trees

### "Is this process suspicious?"

```
Process in pslist?
├─ No (found only in psscan) → SUSPICIOUS: process hiding
└─ Yes
   ├─ Name matches known system process?
   │  ├─ Yes → Check parent, path, session, count
   │  │  ├─ Wrong parent → SUSPICIOUS: masquerading
   │  │  ├─ Wrong path → SUSPICIOUS: masquerading
   │  │  ├─ Wrong session → SUSPICIOUS: misplaced
   │  │  ├─ Too many instances → SUSPICIOUS: duplicate
   │  │  └─ All normal → LIKELY CLEAN
   │  └─ No → Check command line, network, privileges
   │     ├─ Has network connections to external IPs → INVESTIGATE
   │     ├─ Has SeDebugPrivilege → INVESTIGATE
   │     ├─ Spawned from unusual parent → INVESTIGATE
   │     └─ Normal user application → LIKELY CLEAN
   └─ (continue analysis based on context)
```

### "Is this network connection suspicious?"

```
Connection to external IP?
├─ No (internal only)
│  ├─ Admin ports (445, 3389, 5985) → Possible lateral movement
│  └─ Normal internal traffic → LIKELY CLEAN
└─ Yes
   ├─ Process is browser, update service, or known app → Check destination reputation
   ├─ Process is system binary not expected to connect out → SUSPICIOUS
   ├─ Port is common C2 (4444, 5555, 1337, 8443) → SUSPICIOUS
   ├─ Multiple processes connecting to same IP → SUSPICIOUS: coordinated C2
   └─ Single connection from user app → Check reputation, investigate if unknown
```

---

## Common Investigation Scenarios

### Scenario: "We got a phishing alert"

1. Look for Office processes (`winword.exe`, `excel.exe`) that spawned children
2. Check `cmdline` for PowerShell, cmd, or scripting engines spawned by Office
3. Follow the child process chain to identify what was downloaded/executed
4. Check `netscan` for the Office process and its children
5. Extract URLs from process memory for the download location

### Scenario: "EDR flagged a suspicious process"

1. Find the process in `pslist` by name or PID
2. Full process investigation (cmdline, network, DLLs, handles, malfind)
3. Check if it has persistence
4. Check if it spawned other processes
5. Look for lateral movement indicators

### Scenario: "We suspect data exfiltration"

1. Focus on `netscan` — look for large data transfers or connections to cloud storage IPs
2. Check for archive/compression utilities in `pslist` (7z, rar, zip)
3. Look for `cmdline` showing file collection or staging
4. Check `filescan` for recently accessed sensitive file paths
5. Examine process handles to see what files were open

### Scenario: "Ransomware incident"

1. Identify the ransomware process (high handle count, unusual name)
2. Check how it was delivered (process tree, parent analysis)
3. Look for lateral movement (network connections to internal hosts)
4. Check for exfiltration before encryption (double extortion)
5. Extract the ransom note path and any C2 communication
6. Check `svcscan` and `printkey` for disabled security services

### Scenario: "Routine compromise assessment"

Run the full analysis script and methodically check:
1. Process tree for anomalies
2. `malfind` for injections
3. Network for unexpected external connections
4. Services for persistence
5. Registry autorun keys
6. Credentials that may have been dumped

---

## Further Reading

- [SOP: Malware Analysis](https://gl0bal01.com/intel-codex/Security/Analysis/sop-malware-analysis)
- [Analysis Knowledge Base](https://gl0bal01.com/intel-codex/category/analysis)
- [Binary Refinery Guide](https://gl0bal01.com/reverse/binary-refinery-practical-guide)
- [Malware Analysis Guide](vol3-malware-analysis.md)
- [Volatility 3 Cheatsheet](vol3-cheatsheet.md)
