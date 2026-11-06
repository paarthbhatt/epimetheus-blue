# Security policy

Epimetheus Blue is experimental, single-user Arch Linux security tooling. It is
not Microsoft Defender-equivalent, and no independent security audit or
comparative detection benchmark is claimed. Do not rely on it as your only
protection or recovery mechanism.

## Report vulnerabilities privately

Use [GitHub private vulnerability reporting](https://github.com/paarthbhatt/epimetheus-blue/security/advisories/new).
**Do not disclose suspected vulnerabilities in public issues or pull requests.**
If the private form is unavailable, do not fall back to a public disclosure.

Include the release/commit, installation method, relevant OS/runtime versions,
affected trust boundary, impact, and a minimal harmless reproducer. Share only
manually reviewed, sanitized diagnostic excerpts.

Never post API keys, passwords, private keys, malware samples, browsing history,
browser profiles, or unsanitized state/configuration/log archives publicly. Use
dummy credentials and inert fixtures; do not send live samples unless a
maintainer first agrees on a safe private handling method. Rotate any exposed
credentials rather than merely removing them from a report.

## Scope and maintenance

Reports about privilege boundaries, firewall transactions, DNS handling,
quarantine/restore, cleanup paths, credentials, or native messaging are welcome.
Report against the latest experimental release or current source when possible.
There is no guaranteed response time, fix deadline, or older-release backport
policy.

Read [known limitations](docs/LIMITATIONS.md) and the
[optional firewall contract](docs/FIREWALL-CONTRACT.md) before deployment.
Functional tests are not an independent audit or proof that a workstation is
uncompromised.
