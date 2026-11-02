# Epimetheus Blue

A personal, single-machine defence suite for Arch Linux: on-access malware
scanning, integrity and persistence auditing, and DNS-level ad/tracker/malware
blocking, behind one binary, one database and one local dashboard.

> **Status: working Phase 0 + Phase 1.** Scanning, quarantine, the EICAR drill,
> the DNS sinkhole and the dashboard all run today. `guard` (FIM/persistence) and
> `feeds` (dataset updates) are designed but not implemented.
> See [the design document](docs/DESIGN.md).

## What it is

| Layer | Function | Status |
|---|---|---|
| `blue scan` | Scan files/directories with YARA-X and ClamAV, tier the result | working |
| `blue watch` | Watch roots, scan new files as they appear | working |
| `blue dns` | Local sinkhole resolver with suffix blocklists | working |
| `blue daemon` | JSON API + local dashboard + kill switch | working |
| `blue quarantine` | Reversible quarantine, list and restore | working |
| `blue drill` | End-to-end EICAR proof that the wiring works | working |
| `blue guard` | File integrity + persistence audit | designed |
| `blue feeds` | Fetch/verify/rollback datasets | designed |

## What it is not

Not a replacement for judgement, not a kernel driver, not a TLS-intercepting
proxy, and not a source of "100% protected" claims. Detection primitives are
borrowed from projects that already do them well; the work here is orchestration,
policy, and an honest evidence model.

## Principles

1. **Nothing is deleted automatically.** Everything is quarantined and reversible.
   The only delete in the codebase is the drill's own EICAR cleanup, marked
   `allowed-delete` and enforced by `scripts/check-invariants.sh`.
2. **Detection is tiered.** A single weak signal is a *candidate* (T1), never an
   infection. Quarantine is gated on T2 corroboration.
3. **Security failures are visible, not fatal.** With no `clamd` running the
   scanner reports `DEGRADED` and keeps scanning with YARA instead of blocking.
4. **Root is borrowed, briefly, for named verbs.** No long-running root daemon.
5. **Every claim is testable.** `blue drill` exits non-zero if the pipeline breaks.

## Quickstart

```bash
cargo build --release

# Prove the pipeline end to end with the EICAR test string
./target/release/blue drill

# Scan something
./target/release/blue scan ~/Downloads

# Watch configured roots (ctrl-c to stop)
./target/release/blue watch

# Local dashboard on http://127.0.0.1:8471
./target/release/blue daemon

# DNS sinkhole (needs lists in ~/.local/share/blue/lists)
./target/release/blue dns
```

State, rules, quarantine and the database live under `~/.local/share/blue` by
default. `--state-dir` overrides it, `--config` adds a config file after
`/etc/blue/config.toml` and `~/.config/blue/config.toml`.

### Optional: ClamAV

```bash
sudo pacman -S clamav
sudo systemctl enable --now clamav-daemon clamav-freshclam
```

Without it the suite runs YARA-only and says so. With it, a ClamAV signature
match is corroboration on its own.

## Tests

```bash
cargo test --workspace      # 52 tests
./scripts/check-invariants.sh
./target/debug/blue drill
```

## Read next

- [`docs/DESIGN.md`](docs/DESIGN.md) — architecture, threat model, data model,
  failure modes, delivery plan, acceptance criteria.
