# Firewall implementation contract

This release implements a Windows-style baseline, not malware-detection parity.
No live rules or system DNS changes during development.

## Policy/client public API

`FirewallProfile { Public, Private }` and `Protocol { Tcp, Udp }` are serde enums.
`InboundRule { name: String, protocol: Protocol, port: u16, source: Option<String> }`.
`FirewallPolicy { profile: FirewallProfile, inbound: Vec<InboundRule> }`.
Methods: `new(profile)`, `validate() -> Result<()>`, `render_nft() -> Result<String>`.

Stateful IPv4/IPv6 incoming filtering. Allow loopback, established/related,
ICMP/ICMPv6 and DHCP before blocking unsolicited traffic. Outgoing and forwarding
are unchanged. Private permits LAN discovery only. Never flush global rules.
Own exactly `table inet epimetheus_blue`; validate all input and prevent injection.

`FirewallStatus { installed: bool, active: bool, pending: bool,
profile: Option<FirewallProfile>, message: String }` is serde + Default.
`FirewallClient::new()`, `status() -> Result<FirewallStatus>`,
`apply(&FirewallPolicy) -> Result<String>`, `confirm() -> Result<String>`,
`disable() -> Result<String>`. Only explicit mutations call pkexec with fixed
`/usr/lib/epimetheus-blue/blue-firewall-helper` and fixed verbs. Policy goes through
bounded JSON stdin, never a command or arbitrary privileged path.

## Privileged helper

Separate executable depends on blue-firewall, not the GUI. It must be installed
root-owned and refuse non-root mutations. Fixed verbs: apply, confirm, rollback,
disable, boot. Save only this app's previous table before changes. Validate nft
with `--check`; apply transactions atomically. Arm a 60-second systemd rollback
timer BEFORE mutation. If not explicitly confirmed, restore the previous owned
table (or remove it when previously absent). Never replace foreign tables.
Reject another pending change. Persist confirmed policy for reboot; never
persist an unconfirmed policy. Expose sanitized status at
`/run/epimetheus-blue/firewall-status.json`. Config/state are root-owned under
`/etc/epimetheus-blue/firewall/` and `/run/epimetheus-blue/`.

## Packaging

Polkit auth_admin for the exact root-owned helper, a boot service, and a separate
confirmation-gated installer. Do not install or activate privileged components
on the real machine while building. No file capabilities on the user GUI binary.
No nftables flush ruleset, DNS changes, remote telemetry or auto default-deny
outbound rules. Preserve VPN/Docker forwarding by leaving forward/output alone.
Tests must use fake commands/temp state, never real host nft mutations.
