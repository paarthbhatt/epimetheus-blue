# Contributing

Keep changes small, testable, and consistent with the experimental scope.
Suspected vulnerabilities belong in [private reporting](SECURITY.md), not a
public issue. Read [limitations](docs/LIMITATIONS.md) and the
[firewall contract](docs/FIREWALL-CONTRACT.md) before changing safety boundaries.

## Build and check

Work as an ordinary user in a checkout. Use Rust/Cargo with rustfmt and clippy
that can build the locked dependency graph. The workspace declares Rust 1.85;
that declaration alone does not establish the minimum for every dependency.
The GUI needs a usable Wayland/X11 and OpenGL environment to run; Node.js is
needed for the browser validator, not the native app.

From the repository root:

```bash
cargo build --workspace --locked
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
./scripts/check-invariants.sh
node browser-extension/scripts/validate.mjs
bash -n scripts/install-firewall.sh
```

Use `cargo fmt --all` to format your own changes. Review intentional lockfile
updates; do not silently resolve a different graph to make a check pass.
Run `bash -n` on each other shell script you change.

## Firewall and integration testing

Helper unit tests use fake commands and temporary state. For real nftables
enforcement checks, use only the provided disposable, **unprivileged user and
network namespace** harness:

```bash
./scripts/test-firewall-netns.sh
```

It requires cached Cargo dependencies, `unshare`, `ip`, `nft`, Python 3, and the
Rust tools. Exit **77 means SKIP**, not PASS; record the reason if tools or
namespaces are unavailable. Never retry with sudo or remove the isolation.

Do not run host privileged mutations during development: no sudo/pkexec helper
activation, host nftables changes, setcap, system DNS/NetworkManager changes,
package installation, service activation, or system cleanup. Do not install
privileged components merely to satisfy a verifier. Check packaging syntax and
Polkit XML; verify systemd units in an offline temporary systemd root with an
inert helper placeholder, as described in [FIREWALL.md](docs/FIREWALL.md).

Use temporary state, harmless fixtures (EICAR only in an isolated test area),
and disposable browser profiles for other integration checks. Never use real
malware, API keys, personal browsing history, or production cleanup candidates.

## Pull requests

Explain the behavior change, affected boundaries, and failure/rollback cases.
Include relevant tests, OS/toolchain/runtime versions, and exact PASS/FAIL/SKIP
results. Update docs for changed defaults or limitations. Do not turn a smoke
test into a detection-parity, audit, performance, or compatibility claim.
