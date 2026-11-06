# Privileged firewall helper

This executable depends only on `blue-firewall` and small support crates, never
the GUI. Development binaries refuse privileged execution. Tests inject fake
nft/systemd commands and temporary state; do not run the installed helper while
validating a build.

## Fixed interface

Install at `/usr/lib/epimetheus-blue/blue-firewall-helper`, owned by `root:root`,
mode `0755`, with protected root-owned ancestors. No setuid bits or GUI file
capabilities. Both real and effective UID must be zero. Mutations are invoked by
the client through Polkit `auth_admin` for this exact executable.

Exactly one argument is accepted: `apply`, `confirm`, `rollback`, `disable`, or
`boot`. Only `apply` accepts a policy: strict JSON on stdin, at most 65,536 bytes,
using the contract's `FirewallPolicy` fields. Close stdin for every invocation;
other verbs accept only EOF/whitespace. There are no paths, scripts, shell
commands, status verb, or environment configuration options. Stdout contains a
fixed success message; failures return nonzero with sanitized stderr.

Only `table inet epimetheus_blue` is replaced. A pending apply saves that table
alone, arms a systemd rollback timer **before** nft mutation, checks the batch,
then deletes/recreates the owned table in one atomic nft transaction. Another
pending apply is rejected. Explicit confirmation durably saves the policy and
clears pending state before running `systemctl enable blue-firewall.service`.
This does not start or restart the service. Apply and boot never enable it.
Rollback restores the prior owned table or removes it if previously absent.
Disable clears pending recovery safely, removes only the owned table and its
confirmed policy, and runs `systemctl disable blue-firewall.service` (without
stopping it). Boot replays only an already-confirmed policy, using the same
rollback-protected transaction; it never selects a default policy itself.

Boot-enable failure leaves the explicitly confirmed live table and durable
policy intact, but returns nonzero and reports the partial failure in sanitized
status. Explicit `confirm` can retry enablement without a new live apply. Disable
attempts both service disablement and owned-table/policy cleanup, reporting each
partial outcome visibly; it does not silently claim complete success.

## Packaging requirements

- Required protected executables: `/usr/bin/nft`, `/usr/bin/systemd-run`, and
  `/usr/bin/systemctl`. The runner clears its environment, uses absolute paths,
  bounded output, and a 15-second timeout per command.
- `/etc/epimetheus-blue` and `/run/epimetheus-blue`: root-owned `0755`.
  `/etc/epimetheus-blue/firewall` and `/run/epimetheus-blue/firewall`: root-owned
  `0700`. Existing insecure permissions, symlinks, and linked state files are
  refused rather than repaired. Private files are `0600`.
- The client reads sanitized `FirewallStatus` JSON from
  `/run/epimetheus-blue/firewall-status.json` (`root:root`, `0644`). Never expose
  pending policy, prior nft text, command output, or rule details there.
- The fixed transient unit is `epimetheus-blue-firewall-rollback.timer` plus
  `.service`, created with a 60-second delay, 1-second accuracy, root identity,
  and failure retries. Reserve these names; do not ship conflicting static units.
  The rollback verb waits for the process lock, and does not stop its own
  service. Other operations cancel stale services before a new transaction.
- Install the fixed `blue-firewall.service` **disabled**, with an `[Install]`
  target for reboot. Only explicit helper confirmation enables it, after durable
  policy persistence. Neither the installer nor apply may start/restart it.
  The root service should invoke this exact helper with `boot` and null
  stdin. It must run in the **host network namespace**, have `CAP_NET_ADMIN`,
  access the system systemd bus, and be able to write the fixed state roots.
  `RuntimeDirectoryMode=0755` is required if systemd creates the runtime parent;
  keep runtime state until pending recovery finishes (`RuntimeDirectoryPreserve`).
- A separate explicit confirmation-gated installer must install the helper,
  Polkit action and boot service. Building/testing must not install or activate
  any privileged component. The workspace owner must update `Cargo.lock` for the
  new crate/dependency; this worker does not change files outside this crate.
