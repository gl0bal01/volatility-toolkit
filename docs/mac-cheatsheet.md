# Volatility 3 — macOS Memory Analysis Cheatsheet

Practical reference for analyzing macOS memory dumps with Volatility 3.

> **Syntax**: `vol -f <memory_dump> <plugin>`
>
> **Note**: macOS memory analysis requires matching kernel symbols (ISF). Generate with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) from the target's kernel debug kit (KDK).

---

## Process Analysis

### mac.pslist

List processes from the kernel's process list.

```bash
vol -f memory.raw mac.pslist
```

**Look for:** Unexpected processes, processes running as root, unsigned binaries, processes with suspicious names or paths.

### mac.pstree

Display the process hierarchy.

```bash
vol -f memory.raw mac.pstree
```

**Look for:** Shell processes spawned by applications (malware/exploitation indicators), `osascript` spawned by non-user apps, unusual children of `launchd`.

### mac.psaux

List processes with full command-line arguments.

```bash
vol -f memory.raw mac.psaux
```

**Look for:** Python/Ruby/osascript payloads, processes running from `/tmp` or user cache directories, download cradles (`curl | sh`), crypto miners.

### mac.bash

Recover bash/zsh command history from memory.

```bash
vol -f memory.raw mac.bash
```

**Look for:** Reconnaissance commands, attempts to disable Gatekeeper or SIP, `csrutil` status checks, `launchctl` persistence setup, `security` keychain access.

---

## Kernel Modules

### mac.lsmod

List loaded kernel extensions (kexts).

```bash
vol -f memory.raw mac.lsmod
```

**Look for:** Unknown kexts, unsigned extensions, kexts loaded from non-standard paths. On modern macOS, third-party kexts are increasingly rare — their presence may be suspicious.

---

## Network

### mac.netstat

List network connections.

```bash
vol -f memory.raw mac.netstat
```

**Look for:** Connections to external IPs from non-browser processes, listening services on unusual ports, connections from system processes to unexpected destinations.

### mac.ifconfig

List network interfaces.

```bash
vol -f memory.raw mac.ifconfig
```

**Look for:** Promiscuous mode interfaces (sniffing), unexpected tunnel interfaces (VPN backdoors), bridge interfaces.

### mac.socket_filters

Enumerate socket filters attached to network sockets.

```bash
vol -f memory.raw mac.socket_filters
```

**Look for:** Unexpected socket filters — can be used by malware to intercept or modify network traffic.

---

## File System

### mac.lsof

List open file descriptors.

```bash
vol -f memory.raw mac.lsof
```

**Look for:** Files open from temp directories, access to keychain files, access to browser credential stores, open handles to `/etc/authorization`.

### mac.list_files

Enumerate files known to the kernel.

```bash
vol -f memory.raw mac.list_files
```

### mac.mount

List mounted file systems.

```bash
vol -f memory.raw mac.mount
```

**Look for:** Unusual mounts, DMG files mounted from temp directories, network shares mounted to unexpected locations.

---

## Memory Analysis

### mac.proc_maps

Show process memory mappings.

```bash
vol -f memory.raw mac.proc_maps
```

**Look for:** Executable anonymous regions, RWX mappings, Mach-O headers in unexpected memory regions.

### mac.malfind

Find suspicious or injected memory regions.

```bash
vol -f memory.raw mac.malfind
```

**Look for:** Executable memory not backed by files, Mach-O headers injected into processes, shellcode patterns.

---

## Security Framework Analysis

### mac.check_syscall

Verify the system call table for hooks.

```bash
vol -f memory.raw mac.check_syscall
```

**Look for:** Syscall handlers pointing outside the kernel — indicates rootkit-level tampering.

### mac.check_sysctl

Check sysctl handlers for tampering.

```bash
vol -f memory.raw mac.check_sysctl
```

**Look for:** Modified sysctl handlers — rootkits use this to hide processes, files, or network connections from userspace tools.

### mac.check_trap_table

Examine the Mach trap table for hooks.

```bash
vol -f memory.raw mac.check_trap_table
```

**Look for:** Mach trap entries pointing to unexpected addresses.

### mac.trustedbsd

List TrustedBSD MAC (Mandatory Access Control) policies.

```bash
vol -f memory.raw mac.trustedbsd
```

**Look for:** Unexpected policies — malware can register TrustedBSD policies to intercept security decisions or hide its activities.

### mac.kauth_listeners

Enumerate Kauth listeners.

```bash
vol -f memory.raw mac.kauth_listeners
```

**Look for:** Unknown listeners on the `vnode`, `fileop`, or `process` scopes. Kauth listeners can monitor or intercept file access, process execution, and other security-relevant operations.

### mac.kauth_scopes

List registered Kauth scopes.

```bash
vol -f memory.raw mac.kauth_scopes
```

---

## Other

### mac.kevents

List process kevents (kernel event notifications).

```bash
vol -f memory.raw mac.kevents
```

### mac.timecounter

Show timecounter information.

```bash
vol -f memory.raw mac.timecounter
```

---

## Symbol Requirements

macOS analysis requires matching symbols from Apple's Kernel Debug Kit (KDK):

1. Download the KDK matching the target's macOS version from [Apple Developer](https://developer.apple.com/download/all/)
2. Generate symbols with dwarf2json:
   ```bash
   dwarf2json mac --macho /Library/Developer/KDKs/KDK_<version>/System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/kernel > mac-symbols.json
   ```
3. Place in Vol3 symbols directory:
   ```bash
   cp mac-symbols.json /path/to/volatility3/volatility3/symbols/mac/
   ```

---

## Further Reading

- [SOP: Malware Analysis](https://gl0bal01.com/intel-codex/Security/Analysis/sop-malware-analysis)
- [Analysis Knowledge Base](https://gl0bal01.com/intel-codex/category/analysis)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Apple Kernel Debug Kits](https://developer.apple.com/download/all/)
