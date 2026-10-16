# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.x (latest) | Yes |
| < 1.0 | No |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's private disclosure feature: [Report a vulnerability](https://github.com/Karib0u/rustinel/security/advisories/new)

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Affected versions
- Any suggested mitigations if known

Rustinel is a solo-maintained project with no dedicated security team.
Response times are best-effort: expect an acknowledgement within a few days and a resolution timeline within a few weeks.
There is no on-call rotation.

## Scope

Rustinel runs as root / with elevated privileges and processes untrusted rule files and IOC feeds.
Reports are particularly welcome for:

- Rule or IOC file parsing that leads to code execution or privilege escalation
- eBPF program issues that could be exploited from userspace
- Detection bypass via crafted process or network events
- Unsafe handling of external data (YARA rules, Sigma rules, IOC feeds)
