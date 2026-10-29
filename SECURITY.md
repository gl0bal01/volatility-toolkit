# Security Policy

## Supported versions

Only the latest release gets fixes.

## Reporting a vulnerability

Report it privately through GitHub: **Security → [Report a vulnerability](https://github.com/gl0bal01/volatility-toolkit/security/advisories/new)**. Please don't open a public issue.

Include the `vol-analyze --version` output, the Volatility 3 version (first line of `vol -h`), your OS, and the steps to reproduce. This is a single-maintainer project; reports are answered on a best-effort basis.

## Scope

`vol-analyze` runs Volatility 3 on memory images that may come from compromised systems, so the image, the strings in it, and file names are untrusted input. In scope:

- a crafted memory image, file name, or option value that makes `vol-analyze` run commands, write outside the output directory, or follow a planted symlink
- reports (text or JSON) that a crafted input can corrupt or inject into
- IOC filters that an attacker can steer to hide an indicator they control: a name they can register must land in `strings/domains.txt`, `domains_lowconf.txt` or `reverse_dns.txt`, and an address in `strings/ipv4.txt`

Out of scope: bugs in Volatility 3 itself (report them to [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)), and indicators that the heuristic IOC lists miss without an attacker steering them (open a normal issue).
