# Volatility 3 — Linux Memory Analysis Cheatsheet

Practical reference for analyzing Linux memory dumps with Volatility 3.

> **Syntax**: `vol -f <memory_dump> <plugin>`
>
> **Note**: Linux memory analysis in Vol3 often requires a symbols file (ISF). Generate one with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) from the target system's kernel debug symbols.

---

## Process Analysis

### linux.pslist

List processes from the kernel's task list.

```bash
vol -f memory.lime linux.pslist
```

**Look for:** Unexpected processes, processes running as root that shouldn't be, multiple instances of single-instance daemons, processes with suspicious names.

### linux.pstree

Display the process hierarchy as a tree.

```bash
vol -f memory.lime linux.pstree
```

**Look for:** Shell processes spawned by web servers (webshell indicators), reverse shells (`/bin/sh` spawned by network services), unexpected child processes of `systemd` or `init`.

### linux.psaux

List processes with full command-line arguments (like `ps aux`).

```bash
vol -f memory.lime linux.psaux
```

**Look for:** Base64-encoded commands, processes running from `/tmp`, `/dev/shm`, or `/var/tmp`, crypto miners (`xmrig`, pool URLs), netcat/socat reverse shells, Python/Perl one-liner payloads.

### linux.bash

Recover bash command history from memory.

```bash
vol -f memory.lime linux.bash
```

**Look for:** Reconnaissance commands (`whoami`, `id`, `uname -a`, `cat /etc/passwd`), privilege escalation attempts, data exfiltration commands, lateral movement (SSH to other hosts), evidence cleanup (`history -c`, `rm -rf /var/log`).

### linux.envars

List environment variables for each process.

```bash
vol -f memory.lime linux.envars
```

**Look for:** Modified `PATH`, `LD_PRELOAD` set (library injection), custom variables set by malware, credentials stored in env vars.

---

## Kernel Modules

### linux.lsmod

List loaded kernel modules.

```bash
vol -f memory.lime linux.lsmod
```

**Look for:** Unknown modules, modules loaded from non-standard paths, rootkit modules (often hide from `lsmod` on a live system but are visible in memory).

### linux.check_modules

Compare the module list against sysfs. Finds hidden kernel modules.

```bash
vol -f memory.lime linux.check_modules
```

**Look for:** Any module present in one source but not the other — this indicates a rootkit hiding a kernel module.

---

## Network

### linux.sockstat

List network connections and listening sockets.

```bash
vol -f memory.lime linux.sockstat
```

**Look for:** Unexpected listening ports, connections to external IPs from non-network processes, reverse shell patterns (established connections on unusual ports), connections from web servers to internal hosts (pivot).

---

## File System

### linux.lsof

List open file descriptors for all processes.

```bash
vol -f memory.lime linux.lsof
```

**Look for:** Files open from `/tmp`, `/dev/shm`, deleted files still held open (common malware technique), processes with open sockets, access to sensitive files (`/etc/shadow`, SSH keys).

### linux.mountinfo

List mounted file systems.

```bash
vol -f memory.lime linux.mountinfo
```

**Look for:** Unusual mounts, tmpfs mounted in unexpected locations, NFS/CIFS mounts to external hosts.

### linux.elfs

List ELF binaries mapped into process memory.

```bash
vol -f memory.lime linux.elfs
```

**Look for:** ELF files loaded from temp directories, unnamed memory-mapped executables, ELFs not matching known system libraries.

---

## Memory Analysis

### linux.proc.Maps

Show memory mappings for each process (like `/proc/<pid>/maps`).

```bash
vol -f memory.lime linux.proc.Maps
```

**Look for:** Executable anonymous mappings (potential shellcode), RWX regions, memory-mapped files from unusual locations.

### linux.malfind

Find potentially injected or suspicious memory regions.

```bash
vol -f memory.lime linux.malfind
```

**Look for:** Executable anonymous memory regions, ELF headers in unexpected locations, regions with `rwx` permissions not backed by a file.

---

## Rootkit Detection

### linux.check_syscall

Verify the system call table for hooks.

```bash
vol -f memory.lime linux.check_syscall
```

**Look for:** System call handlers pointing outside the kernel text segment — indicates a syscall table hook (rootkit).

### linux.check_idt

Check the Interrupt Descriptor Table for hooks.

```bash
vol -f memory.lime linux.check_idt
```

**Look for:** IDT entries pointing to unexpected addresses.

### linux.check_afinfo

Check network protocol structures for hooks.

```bash
vol -f memory.lime linux.check_afinfo
```

**Look for:** Hooked network protocol handlers — used by rootkits to hide connections from `netstat`.

### linux.check_creds

Analyze credential structures for anomalies.

```bash
vol -f memory.lime linux.check_creds
```

**Look for:** Processes with unexpected UID/GID values, processes that gained root credentials.

### linux.tty_check

Check TTY devices for hooks.

```bash
vol -f memory.lime linux.tty_check
```

**Look for:** Hooked TTY operations — used by rootkits for keylogging or to hide terminal output.

### linux.keyboard_notifiers

Examine the keyboard notifier chain.

```bash
vol -f memory.lime linux.keyboard_notifiers
```

**Look for:** Unexpected notifiers — rootkit keyloggers register here to capture keystrokes.

---

## Kernel Messages

### linux.kmsg

Dump the kernel log buffer (like `dmesg`).

```bash
vol -f memory.lime linux.kmsg
```

**Look for:** Module load messages, security warnings, OOM killer events, segfaults, audit messages, USB device connections.

### linux.iomem

Display I/O memory map (like `/proc/iomem`).

```bash
vol -f memory.lime linux.iomem
```

---

## Symbol Requirements

Linux memory analysis requires matching kernel symbols. Generate an ISF (Intermediate Symbol Format) file:

```bash
# On the target system (or matching kernel):
sudo apt install linux-image-$(uname -r)-dbgsym  # Debian/Ubuntu
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > linux-symbols.json

# Place in Vol3 symbols directory:
cp linux-symbols.json /path/to/volatility3/volatility3/symbols/linux/
```

---

## Further Reading

- [SOP: Malware Analysis](https://gl0bal01.com/intel-codex/Security/Analysis/sop-malware-analysis)
- [Analysis Knowledge Base](https://gl0bal01.com/intel-codex/category/analysis)
- [dwarf2json — Symbol Generation](https://github.com/volatilityfoundation/dwarf2json)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
