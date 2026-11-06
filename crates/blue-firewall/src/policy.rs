//! Validated, deterministic rules for the firewall's one owned nftables table.
//!
//! Rendering is deliberately pure: applying or replacing the table is the
//! privileged helper's responsibility, not this module's.

use anyhow::{anyhow, ensure, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{fmt::Write as _, net::IpAddr};

const MAX_INBOUND_RULES: usize = 256;
const MAX_RULE_NAME_BYTES: usize = 64;
const MAX_SOURCE_BYTES: usize = 64;

const TABLE_START: &str = concat!(
    "table inet epimetheus_blue {\n",
    "    chain input {\n",
    "        type filter hook input priority 0; policy drop;\n",
    "        iifname \"lo\" accept\n",
    "        ct state { established, related } accept\n",
    "        ct state invalid drop\n",
    "        ip protocol icmp accept\n",
    "        meta nfproto ipv6 meta l4proto ipv6-icmp accept\n",
    "        meta nfproto ipv4 udp sport 67 udp dport 68 accept\n",
    "        meta nfproto ipv6 udp sport 547 udp dport 546 accept\n"
);

// Discovery, not file sharing or arbitrary services on a trusted subnet.
const PRIVATE_DISCOVERY: &str = concat!(
    "        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } udp dport { 137, 138, 1900, 3702, 5353, 5355 } accept comment \"Private LAN discovery\"\n",
    "        ip6 saddr { fc00::/7, fe80::/10 } udp dport { 1900, 3702, 5353, 5355 } accept comment \"Private LAN discovery\"\n",
    "        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } tcp dport 5355 accept comment \"Private LLMNR\"\n",
    "        ip6 saddr { fc00::/7, fe80::/10 } tcp dport 5355 accept comment \"Private LLMNR\"\n"
);

/// The network's trust profile; both profiles deny unsolicited inbound traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallProfile {
    Public,
    Private,
}

/// Transport protocols supported by explicit inbound exceptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// An inbound exception, optionally limited to one IP address or CIDR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundRule {
    pub name: String,
    pub protocol: Protocol,
    pub port: u16,
    pub source: Option<String>,
}

/// A policy for `table inet epimetheus_blue`, with no output or forward hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallPolicy {
    pub profile: FirewallProfile,
    pub inbound: Vec<InboundRule>,
}

impl FirewallPolicy {
    pub fn new(profile: FirewallProfile) -> Self {
        Self {
            profile,
            inbound: Vec::new(),
        }
    }

    /// Validate even directly constructed policies before serialization/rendering.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.inbound.len() <= MAX_INBOUND_RULES,
            "at most {MAX_INBOUND_RULES} inbound rules are allowed"
        );
        for (index, rule) in self.inbound.iter().enumerate() {
            ensure!(rule.port != 0, "inbound rule {index}: port must not be 0");
            ensure!(
                !rule.name.trim().is_empty() && rule.name.len() <= MAX_RULE_NAME_BYTES,
                "inbound rule {index}: name must contain 1 to {MAX_RULE_NAME_BYTES} bytes"
            );
            // Names enter an nft comment. A small printable ASCII alphabet
            // avoids quoting, control characters, and both nft/shell syntax.
            ensure!(
                rule.name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.')
                }),
                "inbound rule {index}: name may contain only ASCII letters, digits, spaces, '.', '_' and '-'"
            );
            if let Some(source) = &rule.source {
                parse_source(source).map_err(|_| {
                    anyhow!("inbound rule {index}: source must be an IPv4/IPv6 address or CIDR")
                })?;
            }
        }
        Ok(())
    }

    /// Render a complete table declaration, never a global flush or host command.
    pub fn render_nft(&self) -> Result<String> {
        self.validate()?;
        let mut rendered = String::from(TABLE_START);
        if self.profile == FirewallProfile::Private {
            rendered.push_str(PRIVATE_DISCOVERY);
        }
        for rule in &self.inbound {
            rendered.push_str("        ");
            if let Some(source) = &rule.source {
                let source = parse_source(source)?;
                let family = match source {
                    IpNet::V4(_) => "ip",
                    IpNet::V6(_) => "ip6",
                };
                write!(rendered, "{family} saddr {source} ")?;
            }
            let protocol = match rule.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };
            writeln!(
                rendered,
                "{protocol} dport {} accept comment \"{}\"",
                rule.port, rule.name
            )?;
        }
        rendered.push_str("    }\n}\n");
        Ok(rendered)
    }
}

fn parse_source(source: &str) -> Result<IpNet> {
    ensure!(
        !source.is_empty() && source.len() <= MAX_SOURCE_BYTES && source == source.trim(),
        "invalid source address length or whitespace"
    );
    // Only parsed numeric addresses reach the renderer: never interpolate the
    // original source string. Mask host bits for a canonical, stable CIDR.
    source
        .parse::<IpNet>()
        .or_else(|_| source.parse::<IpAddr>().map(IpNet::from))
        .map(|network| network.trunc())
        .map_err(|_| anyhow!("source must be an IPv4/IPv6 address or CIDR"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, protocol: Protocol, port: u16, source: Option<&str>) -> InboundRule {
        InboundRule {
            name: name.into(),
            protocol,
            port,
            source: source.map(str::to_owned),
        }
    }

    #[test]
    fn public_dual_stack_baseline_is_deterministic() {
        let policy = FirewallPolicy::new(FirewallProfile::Public);
        let expected = concat!(
            "table inet epimetheus_blue {\n",
            "    chain input {\n",
            "        type filter hook input priority 0; policy drop;\n",
            "        iifname \"lo\" accept\n",
            "        ct state { established, related } accept\n",
            "        ct state invalid drop\n",
            "        ip protocol icmp accept\n",
            "        meta nfproto ipv6 meta l4proto ipv6-icmp accept\n",
            "        meta nfproto ipv4 udp sport 67 udp dport 68 accept\n",
            "        meta nfproto ipv6 udp sport 547 udp dport 546 accept\n",
            "    }\n}\n"
        );
        assert_eq!(policy.render_nft().unwrap(), expected);
        assert_eq!(policy.render_nft().unwrap(), policy.render_nft().unwrap());
    }

    #[test]
    fn private_only_adds_lan_scoped_discovery() {
        let public = FirewallPolicy::new(FirewallProfile::Public)
            .render_nft()
            .unwrap();
        let private = FirewallPolicy::new(FirewallProfile::Private)
            .render_nft()
            .unwrap();
        let expected_discovery = concat!(
            "        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } udp dport { 137, 138, 1900, 3702, 5353, 5355 } accept comment \"Private LAN discovery\"\n",
            "        ip6 saddr { fc00::/7, fe80::/10 } udp dport { 1900, 3702, 5353, 5355 } accept comment \"Private LAN discovery\"\n",
            "        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } tcp dport 5355 accept comment \"Private LLMNR\"\n",
            "        ip6 saddr { fc00::/7, fe80::/10 } tcp dport 5355 accept comment \"Private LLMNR\"\n"
        );
        assert_eq!(
            private,
            public.replace("    }\n}\n", &format!("{expected_discovery}    }}\n}}\n"))
        );
        assert!(!public.contains("LAN discovery"));
        assert!(!private.contains("dport 139"));
        assert!(!private.contains("dport 445"));
        assert!(!private.contains("saddr { 0.0.0.0/0"));
        assert!(!private.contains("saddr { ::/0"));
    }

    #[test]
    fn allow_rules_render_canonical_cidrs_and_correct_protocols() {
        let mut policy = FirewallPolicy::new(FirewallProfile::Public);
        policy.inbound = vec![
            rule("SSH LAN", Protocol::Tcp, 22, Some("192.168.10.99/24")),
            rule("DNS ULA", Protocol::Udp, 53, Some("fd12:3456::abcd/64")),
            rule("HTTPS", Protocol::Tcp, 443, None),
            rule("Single IPv4", Protocol::Udp, 65535, Some("203.0.113.7")),
            rule("Single IPv6", Protocol::Tcp, 1, Some("2001:db8::7")),
        ];
        let rendered = policy.render_nft().unwrap();
        for expected in [
            "ip saddr 192.168.10.0/24 tcp dport 22 accept comment \"SSH LAN\"",
            "ip6 saddr fd12:3456::/64 udp dport 53 accept comment \"DNS ULA\"",
            "tcp dport 443 accept comment \"HTTPS\"",
            "ip saddr 203.0.113.7/32 udp dport 65535 accept comment \"Single IPv4\"",
            "ip6 saddr 2001:db8::7/128 tcp dport 1 accept comment \"Single IPv6\"",
        ] {
            assert!(rendered.contains(expected), "{expected}");
        }
    }

    #[test]
    fn port_zero_is_rejected_before_rendering() {
        for profile in [FirewallProfile::Public, FirewallProfile::Private] {
            let mut policy = FirewallPolicy::new(profile);
            policy.inbound.push(rule("Invalid", Protocol::Tcp, 0, None));
            assert!(policy.validate().is_err());
            assert!(policy.render_nft().is_err());
        }
    }

    #[test]
    fn injection_and_invalid_cidrs_are_rejected() {
        for name in [
            "\"; flush ruleset; #",
            "test\naccept",
            "test\\\"",
            "$(id)",
            "`id`",
            "test;id",
            "test\rtest",
            "test\0test",
            "test\u{1b}[31m",
        ] {
            let mut policy = FirewallPolicy::new(FirewallProfile::Public);
            policy.inbound.push(rule(name, Protocol::Tcp, 22, None));
            assert!(policy.render_nft().is_err(), "{name:?}");
        }
        for source in [
            "192.168.0.0/24; accept",
            "192.168.0.0/24\nflush ruleset",
            "\"; delete table inet other; #",
            "$(id)",
            "localhost",
            "192.168.1.0/33",
            "2001:db8::/129",
            "fe80::1%eth0",
            " 10.0.0.0/8",
            "10.0.0.0/8 ",
            "",
        ] {
            let mut policy = FirewallPolicy::new(FirewallProfile::Private);
            policy
                .inbound
                .push(rule("Test", Protocol::Udp, 53, Some(source)));
            assert!(policy.render_nft().is_err(), "{source:?}");
        }
    }

    #[test]
    fn policy_and_rule_json_reject_unknown_fields_and_protocols() {
        for json in [
            r#"{"profile":"Public","inbound":[],"command":"flush ruleset"}"#,
            r#"{"profile":"Public","inbound":[{"name":"SSH","protocol":"Tcp","port":22,"source":null,"nft":"accept"}]}"#,
            r#"{"profile":"Public","inbound":[{"name":"SSH","protocol":"tcp; accept","port":22,"source":null}]}"#,
            r#"{"profile":"Public; accept","inbound":[]}"#,
            r#"{"profile":"Public","inbound":[{"name":"SSH","protocol":"Tcp","port":65536,"source":null}]}"#,
        ] {
            assert!(serde_json::from_str::<FirewallPolicy>(json).is_err());
        }
        let policy = FirewallPolicy::new(FirewallProfile::Public);
        assert_eq!(
            serde_json::from_str::<FirewallPolicy>(&serde_json::to_string(&policy).unwrap())
                .unwrap(),
            policy
        );
    }

    #[test]
    fn validation_bounds_rule_count_names_and_sources() {
        let mut policy = FirewallPolicy::new(FirewallProfile::Public);
        policy.inbound = vec![rule("Test", Protocol::Tcp, 80, None); MAX_INBOUND_RULES];
        assert!(policy.validate().is_ok());
        policy.inbound.push(rule("Extra", Protocol::Tcp, 80, None));
        assert!(policy.validate().is_err());
        for name in [
            "".to_owned(),
            " ".to_owned(),
            "a".repeat(MAX_RULE_NAME_BYTES + 1),
        ] {
            policy.inbound = vec![rule(&name, Protocol::Tcp, 80, None)];
            assert!(policy.validate().is_err());
        }
        policy.inbound = vec![rule(
            "Long source",
            Protocol::Tcp,
            80,
            Some(&"1".repeat(MAX_SOURCE_BYTES + 1)),
        )];
        assert!(policy.validate().is_err());
    }

    #[test]
    fn only_the_owned_input_table_is_rendered() {
        for profile in [FirewallProfile::Public, FirewallProfile::Private] {
            let rendered = FirewallPolicy::new(profile).render_nft().unwrap();
            assert_eq!(rendered.matches("table inet ").count(), 1);
            assert!(rendered.starts_with("table inet epimetheus_blue {\n"));
            assert_eq!(rendered.matches("hook ").count(), 1);
            for forbidden in [
                "flush",
                "delete",
                "ruleset",
                "hook output",
                "hook forward",
                "chain output",
                "chain forward",
            ] {
                assert!(!rendered.contains(forbidden), "{forbidden}");
            }
        }
    }
}
