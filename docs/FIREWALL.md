# Optional host firewall

Epimetheus Blue provides a **Windows-style incoming-firewall baseline**, not
Microsoft Defender malware-detection parity. It is not an antivirus detector,
an outbound application firewall, or a guarantee against intrusion.

The native GUI continues to run as your desktop user, without root, setuid, or
file capabilities. Installing the normal app with `scripts/install-local.sh`
does not install or activate privileged firewall components. The optional
firewall installer below is deliberately separate.

## Public and Private profiles

Both profiles use stateful IPv4/IPv6 incoming filtering in exactly
`table inet epimetheus_blue`:

| Traffic | Public | Private |
|---|---|---|
| Loopback and established/related incoming connections | Allowed | Allowed |
| ICMP/ICMPv6 and DHCP needed for network operation | Allowed | Allowed |
| Bounded LAN discovery | Not added | Allowed |
| Explicit, validated inbound TCP/UDP rules | Allowed as configured | Allowed as configured |
| Other unsolicited incoming traffic | Blocked | Blocked |
| Outgoing and forwarded traffic | Unchanged | Unchanged |

Choose **Public** for an untrusted network. **Private** adds LAN discovery;
it does not allow arbitrary inbound services or trust every packet from a LAN.
Open a listening service only through an explicit inbound rule, optionally
limited to a validated source address/CIDR. Changing profiles is a staged
policy change, not an automatic response to a network name.

The helper never flushes the global ruleset or replaces foreign tables. Rules
from nftables, firewalld, UFW, VPN software, or other tools can still affect
connectivity independently of Blue.

## Inspect and install — without activation

Prerequisites are `nft` (nftables), a reachable systemd system manager,
`systemctl`, `systemd-run`, Polkit (`pkexec`, `pkaction`, and `polkit.service`),
and `sudo`. Your desktop also needs a Polkit authentication agent for graphical
administrator prompts. Missing prerequisites are reported; the installer does
not install packages or start Polkit.

From the repository root:

```bash
./scripts/install-firewall.sh plan
```

This only prints paths and checks availability. It does not build, download,
create files, invoke sudo/pkexec, or change service activation. Availability
checks do not prove that a future policy is safe for your remote access.

Build the **standalone helper**, not the GUI, as your ordinary user:

```bash
cargo build --release --locked --package blue-firewall-helper
```

Then, only after reviewing the plan:

```bash
./scripts/install-firewall.sh install --confirm-firewall-install
```

The exact confirmation flag is required before sudo is invoked. Run the
installer as your desktop user; running the whole installer as root is
rejected. It copies the prebuilt ELF helper and packaging files with these
fixed destinations:

| Path | Ownership / mode | Purpose |
|---|---|---|
| `/usr/lib/epimetheus-blue/blue-firewall-helper` | `root:root`, `0755` | Standalone privileged executable |
| `/usr/share/polkit-1/actions/com.epimetheus.blue.firewall.policy` | `root:root`, `0644` | Exact-path administrator authorization |
| `/etc/systemd/system/blue-firewall.service` | `root:root`, `0644` | Optional confirmed-policy boot restore |
| `/etc/epimetheus-blue/firewall/` | `root:root`, `0700` | Private persistent configuration |
| `/run/epimetheus-blue/` | `root:root`, `0755` | Runtime state and readable sanitized status |

Application parent directories are root-owned and non-user-writable. Unsafe
ownership, group/other-writable destination trees, and destination symlinks are
rejected rather than repaired. The helper is copied to a root-owned regular
file, never symlinked into the user-writable build tree. Only the fixed
installation fragment runs as root; neither the compiler nor helper is executed
during installation.

Installation reloads systemd definitions only. It **does not enable or start
the boot service, apply rules, create a default policy, alter existing saved
policy/runtime files, grant GUI capabilities, or change DNS**. Existing service
enablement and already-active firewall rules are left as they were.

## Apply, then explicitly confirm

The rootless client reads sanitized status from
`/run/epimetheus-blue/firewall-status.json`. Explicit changes use Polkit for
exactly `/usr/lib/epimetheus-blue/blue-firewall-helper`; authorization is
`auth_admin`, not retained `auth_admin_keep`. The helper accepts only the fixed
verbs `apply`, `confirm`, `rollback`, `disable`, and `boot`. Policy input is
bounded, validated JSON over stdin, never a shell command or privileged path
chosen by the caller. Non-root helper mutations are refused.

1. Select Public or Private and review the proposed inbound rules before
   explicitly applying the policy.
2. The helper validates the policy and nftables transaction with `nft --check`
   and saves only Blue's previous table, or records that it was absent.
3. A **60-second systemd rollback timer is armed before mutation**. If the
   rollback protection cannot be armed, the helper must not apply the change.
   The owned-table change is an atomic nftables transaction.
4. Check connectivity and explicitly **confirm** within the pending window.
   Authorizing Apply is not confirmation. Only confirmation persists the new
   policy for reboot and disarms rollback.
5. Without confirmation, rollback restores Blue's previous table, or removes
   Blue's table if none existed before. Closing the GUI does not confirm it.
   Another Apply is refused while a change is pending.

Keep a local recovery path when changing remote-access rules. Administrator
prompt time is not an extension of the rollback window. If rollback or status
reports an error, investigate it; do not assume connectivity or protection.

## Confirmed boot persistence

Explicit confirmation durably saves the policy and enables the fixed
`blue-firewall.service` for subsequent boots. It does not start or restart that
service. If enablement fails, the helper reports the partial outcome and an
explicit Confirm can retry it. Apply alone never enables boot persistence.

The root-owned oneshot service runs
`/usr/lib/epimetheus-blue/blue-firewall-helper boot`, in the host network
namespace, to restore **only confirmed policy**. No unconfirmed policy becomes
a reboot default. With no confirmed policy, boot must not invent a baseline.
Runtime directories are recreated by systemd after reboot; private config
stays under `/etc/epimetheus-blue/firewall/`.

## Disable and boundaries

Use the client's explicit **Disable** operation to remove **only**
`table inet epimetheus_blue`. Foreign firewall tables are untouched. This is
not a global firewall-off switch; other tools may still filter traffic. Disable
also disables the fixed boot service. Merely running this command does not
remove live rules:

```bash
sudo systemctl disable blue-firewall.service
```

Disabling/stopping the service alone is not removal of live rules: the unit
has no rule-changing `ExecStop`. Use the helper's Disable operation for the
owned table and review the reported policy status before rebooting.

- **DNS is unchanged:** no resolver, NetworkManager, DNS Shield, or system DNS
  setting is rewritten by firewall installation or policy changes.
- **Forwarded Docker/container traffic is not covered.** Published container
  ports using forwarding do not pass through this incoming host filter. Secure
  those paths separately; Blue leaves forwarding/output and foreign Docker/VPN
  tables alone.
- There is no automatic default-deny outbound policy, TLS interception, remote
  telemetry, or Defender detection-parity claim.

## Development validation

See [`FIREWALL-CONTRACT.md`](FIREWALL-CONTRACT.md) for the implementation
contract. Validate packaging with `bash -n`, an XML parser, and
`systemd-analyze verify`. Use an offline temporary systemd root with an inert
helper placeholder if the fixed ExecStart path is intentionally uninstalled.
Do not install privileged components just to satisfy the verifier, and never
run sudo, pkexec, real nftables mutations, or live activation during tests.
These syntax checks are not a live firewall/connectivity test.
