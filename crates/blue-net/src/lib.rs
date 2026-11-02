//! Read-only Linux egress observation from procfs socket tables.

use anyhow::{bail, Context, Result};
use blue_core::{now_ms, Config, Db, Tier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

const BASELINE_KEY: &str = "net:remote-baseline";

/// Configuration for one network observation pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetConfig {
    pub ignore_private: bool,
    pub max_connections: usize,
}

impl NetConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            ignore_private: config.network.ignore_private,
            max_connections: config.network.max_connections,
        }
    }
}

/// One connected socket observed in procfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: String,
    pub inode: u64,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

/// Results from one network observation pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetReport {
    pub baseline: bool,
    pub observed: usize,
    pub new_remote: usize,
    pub findings: usize,
    pub truncated: bool,
    pub connections: Vec<Connection>,
}

/// A read-only observer for established TCP and connected UDP sockets.
pub struct NetObserver {
    db: Arc<Db>,
    config: NetConfig,
}

impl NetObserver {
    pub fn new(db: Arc<Db>, config: NetConfig) -> Self {
        Self { db, config }
    }

    /// Read the Linux procfs socket tables without changing network state.
    pub fn run_once(&self) -> Result<NetReport> {
        let raw_connections = read_proc_connections()?;
        let (mut connections, truncated) = self.filter_and_limit(raw_connections);
        populate_processes(&mut connections);
        self.record_snapshot(connections, truncated)
    }

    /// Run the persistence and finding logic against an injected snapshot.
    ///
    /// This keeps baseline behavior testable without depending on the host's
    /// live procfs contents.
    #[allow(dead_code)] // Deliberate crate-local seam for deterministic snapshot tests.
    pub(crate) fn run_from_connections(&self, connections: Vec<Connection>) -> Result<NetReport> {
        let (connections, truncated) = self.filter_and_limit(connections);
        self.record_snapshot(connections, truncated)
    }

    fn filter_and_limit(&self, connections: Vec<Connection>) -> (Vec<Connection>, bool) {
        let mut kept = Vec::with_capacity(self.config.max_connections.min(connections.len()));
        let mut truncated = false;

        for connection in connections {
            if ignore_remote(connection.remote.ip(), self.config.ignore_private) {
                continue;
            }
            if kept.len() < self.config.max_connections {
                kept.push(connection);
            } else {
                truncated = true;
            }
        }

        (kept, truncated)
    }

    fn record_snapshot(&self, connections: Vec<Connection>, truncated: bool) -> Result<NetReport> {
        let stored = self.db.get_meta(BASELINE_KEY)?;
        let mut is_baseline = stored.is_none();
        let mut known = match stored {
            Some(value) => serde_json::from_str::<BTreeSet<String>>(&value)
                .context("parsing stored network remote baseline")?,
            None => BTreeSet::new(),
        };
        // v1 included process attribution in the identity. A mount namespace
        // can temporarily hide attribution and make every endpoint look new.
        // Migrate once without emitting false-positive findings.
        if known.iter().any(|key| !key.starts_with("v2/")) {
            known.clear();
            is_baseline = true;
        }

        let mut current = BTreeMap::new();
        for (index, connection) in connections.iter().enumerate() {
            current.entry(remote_key(connection)).or_insert(index);
        }

        let mut new_remote = 0;
        let mut findings = 0;
        if !is_baseline {
            for (key, index) in &current {
                if known.contains(key) {
                    continue;
                }
                let connection = &connections[*index];
                record_new_destination(&self.db, connection, key, now_ms())?;
                new_remote += 1;
                findings += 1;
            }

            if truncated {
                let detail = serde_json::to_string(&json!({
                    "observation": "network connection list truncated",
                    "max_connections": self.config.max_connections,
                }))?;
                self.db.add_finding(
                    "network",
                    Tier::Candidate,
                    "network observation truncated",
                    &detail,
                    now_ms(),
                )?;
                findings += 1;
            }
        }

        known.extend(current.into_keys());
        let encoded = serde_json::to_string(&known)?;
        self.db.set_meta(BASELINE_KEY, &encoded)?;

        let report = NetReport {
            baseline: is_baseline,
            observed: connections.len(),
            new_remote,
            findings,
            truncated,
            connections,
        };
        record_summary_event(&self.db, &report, now_ms())?;
        Ok(report)
    }
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}` table.
///
/// TCP rows are limited to state `01` (established). UDP rows are retained
/// only when their remote address and port identify a connected peer.
pub fn parse_proc_table(text: &str, protocol: &str, v6: bool) -> Result<Vec<Connection>> {
    let normalized_protocol = protocol.to_ascii_lowercase();
    let is_tcp = matches!(normalized_protocol.as_str(), "tcp" | "tcp6");
    let is_udp = matches!(normalized_protocol.as_str(), "udp" | "udp6");
    if !is_tcp && !is_udp {
        bail!("unsupported procfs socket protocol {protocol:?}");
    }

    let mut connections = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() || fields.first() == Some(&"sl") {
            continue;
        }
        if fields.len() <= 9 {
            bail!(
                "malformed procfs {protocol} row at line {}: expected at least 10 fields",
                line_index + 1
            );
        }

        let raw_state = fields[3].to_ascii_uppercase();
        if is_tcp && raw_state != "01" {
            continue;
        }

        let remote = parse_endpoint(fields[2], v6).with_context(|| {
            format!(
                "parsing remote endpoint in procfs {protocol} row at line {}",
                line_index + 1
            )
        })?;
        if remote.port() == 0 || remote.ip().is_unspecified() {
            continue;
        }
        let local = parse_endpoint(fields[1], v6).with_context(|| {
            format!(
                "parsing local endpoint in procfs {protocol} row at line {}",
                line_index + 1
            )
        })?;
        let inode = fields[9].parse::<u64>().with_context(|| {
            format!(
                "parsing inode in procfs {protocol} row at line {}",
                line_index + 1
            )
        })?;

        connections.push(Connection {
            protocol: normalized_protocol.clone(),
            local,
            remote,
            state: if is_tcp {
                "ESTABLISHED".to_owned()
            } else {
                "CONNECTED".to_owned()
            },
            inode,
            pid: None,
            process: None,
        });
    }

    Ok(connections)
}

fn read_proc_connections() -> Result<Vec<Connection>> {
    const TABLES: [(&str, &str, bool); 4] = [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp6", true),
    ];

    let mut connections = Vec::new();
    for (path, protocol, v6) in TABLES {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading procfs socket table {path}"));
            }
        };
        connections.extend(parse_proc_table(&text, protocol, v6)?);
    }
    Ok(connections)
}

fn parse_endpoint(value: &str, v6: bool) -> Result<SocketAddr> {
    let (encoded_address, encoded_port) = value
        .split_once(':')
        .with_context(|| format!("socket endpoint {value:?} has no port separator"))?;
    let port = u16::from_str_radix(encoded_port, 16)
        .with_context(|| format!("invalid hexadecimal socket port {encoded_port:?}"))?;
    let ip = if v6 {
        IpAddr::V6(parse_proc_ipv6(encoded_address)?)
    } else {
        IpAddr::V4(parse_proc_ipv4(encoded_address)?)
    };
    Ok(SocketAddr::new(ip, port))
}

fn parse_proc_ipv4(value: &str) -> Result<Ipv4Addr> {
    if value.len() != 8 || !value.is_ascii() {
        bail!("invalid procfs IPv4 address {value:?}");
    }
    let encoded = u32::from_str_radix(value, 16)
        .with_context(|| format!("invalid hexadecimal procfs IPv4 address {value:?}"))?;
    Ok(Ipv4Addr::from(encoded.to_le_bytes()))
}

fn parse_proc_ipv6(value: &str) -> Result<Ipv6Addr> {
    if value.len() != 32 || !value.is_ascii() {
        bail!("invalid procfs IPv6 address {value:?}");
    }

    let mut octets = [0_u8; 16];
    for word_index in 0..4 {
        let start = word_index * 8;
        let end = start + 8;
        let word = u32::from_str_radix(&value[start..end], 16)
            .with_context(|| format!("invalid hexadecimal procfs IPv6 address {value:?}"))?;
        octets[word_index * 4..word_index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(Ipv6Addr::from(octets))
}

fn ignore_remote(ip: IpAddr, ignore_private: bool) -> bool {
    match ip {
        IpAddr::V4(address) => ignore_ipv4(address, ignore_private),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return ignore_ipv4(mapped, ignore_private);
            }
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (ignore_private
                    && (address.is_unique_local() || address.is_unicast_link_local()))
        }
    }
}

fn ignore_ipv4(address: Ipv4Addr, ignore_private: bool) -> bool {
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (ignore_private && (address.is_private() || address.is_link_local()))
}

fn populate_processes(connections: &mut [Connection]) {
    let wanted: BTreeSet<u64> = connections
        .iter()
        .map(|connection| connection.inode)
        .filter(|inode| *inode != 0)
        .collect();
    if wanted.is_empty() {
        return;
    }

    let owners = socket_owners(&wanted);
    for connection in connections {
        if let Some(owner) = owners.get(&connection.inode) {
            connection.pid = Some(owner.pid);
            connection.process.clone_from(&owner.process);
        }
    }
}

#[derive(Debug)]
struct SocketOwner {
    pid: u32,
    process: Option<String>,
}

fn socket_owners(wanted: &BTreeSet<u64>) -> BTreeMap<u64, SocketOwner> {
    let Some(own_uid) = fs::metadata("/proc/self")
        .ok()
        .map(|metadata| metadata.uid())
    else {
        return BTreeMap::new();
    };
    let Ok(entries) = fs::read_dir("/proc") else {
        return BTreeMap::new();
    };

    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(text) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = text.parse::<u32>() else {
            continue;
        };
        processes.push((pid, entry.path()));
    }
    processes.sort_by_key(|(pid, _)| *pid);

    let mut owners = BTreeMap::new();
    for (pid, process_path) in processes {
        if owners.len() == wanted.len() {
            break;
        }
        let Ok(metadata) = fs::metadata(&process_path) else {
            continue;
        };
        if metadata.uid() != own_uid {
            continue;
        }

        let process = read_process_name(&process_path);
        let Ok(descriptors) = fs::read_dir(process_path.join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let Some(inode) = socket_inode(&target) else {
                continue;
            };
            if wanted.contains(&inode) {
                owners.entry(inode).or_insert_with(|| SocketOwner {
                    pid,
                    process: process.clone(),
                });
            }
        }
    }
    owners
}

fn read_process_name(process_path: &Path) -> Option<String> {
    let name = fs::read_to_string(process_path.join("comm")).ok()?;
    let trimmed = name.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn socket_inode(target: &Path) -> Option<u64> {
    let text = target.as_os_str().to_str()?;
    text.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn remote_key(connection: &Connection) -> String {
    format!(
        "v2/{}/{}/{}",
        connection.protocol,
        connection.remote.ip(),
        connection.remote.port()
    )
}

fn record_new_destination(
    db: &Db,
    connection: &Connection,
    key: &str,
    timestamp: i64,
) -> Result<()> {
    let process = connection.process.as_deref().unwrap_or("unknown");
    let detail = serde_json::to_string(&json!({
        "observation": "new egress destination",
        "key": key,
        "protocol": connection.protocol,
        "remote": connection.remote,
        "process": process,
        "pid": connection.pid,
    }))?;
    let subject = format!("new egress destination: {}", connection.remote);
    db.add_finding("network", Tier::Candidate, &subject, &detail, timestamp)?;
    Ok(())
}

fn record_summary_event(db: &Db, report: &NetReport, timestamp: i64) -> Result<()> {
    let payload = serde_json::to_string(&json!({
        "baseline": report.baseline,
        "observed": report.observed,
        "new_remote": report.new_remote,
        "findings": report.findings,
        "truncated": report.truncated,
        "read_only": true,
    }))?;
    db.event("network", "info", None, &payload, timestamp)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode";

    fn connection(
        protocol: &str,
        remote: SocketAddr,
        process: Option<&str>,
        inode: u64,
    ) -> Connection {
        Connection {
            protocol: protocol.to_owned(),
            local: "10.0.0.2:40000".parse().unwrap(),
            remote,
            state: "01".to_owned(),
            inode,
            pid: process.map(|_| 1000),
            process: process.map(str::to_owned),
        }
    }

    fn observer(db: Arc<Db>, ignore_private: bool, max_connections: usize) -> NetObserver {
        NetObserver::new(
            db,
            NetConfig {
                ignore_private,
                max_connections,
            },
        )
    }

    #[test]
    fn parses_ipv4_tcp_fixture_and_keeps_only_established() {
        let fixture = format!(
            "{HEADER}\n\
               0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 02:00000000 00000000 1000 0 12345\n\
               1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 98765\n"
        );

        let parsed = parse_proc_table(&fixture, "tcp", false).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(parsed[0].remote, "8.8.8.8:443".parse().unwrap());
        assert_eq!(parsed[0].state, "ESTABLISHED");
        assert_eq!(parsed[0].inode, 12345);
    }

    #[test]
    fn parses_ipv6_fixture_in_linux_word_byte_order() {
        let fixture = format!(
            "{HEADER}\n\
               0: 00000000000000000000000001000000:C350 B80D0120000000000000000001000000:01BB 01 00000000:00000000 02:00000000 00000000 1000 0 42\n"
        );

        let parsed = parse_proc_table(&fixture, "tcp6", true).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].local, "[::1]:50000".parse().unwrap());
        assert_eq!(parsed[0].remote, "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(parsed[0].protocol, "tcp6");
    }

    #[test]
    fn filters_private_and_always_non_egress_addresses() {
        let db = Arc::new(Db::open_memory().unwrap());
        let observer = observer(db, true, 20);
        let snapshot = vec![
            connection(
                "tcp",
                "192.168.1.20:443".parse().unwrap(),
                Some("private"),
                1,
            ),
            connection("tcp", "169.254.1.2:443".parse().unwrap(), Some("link"), 2),
            connection("tcp", "127.0.0.1:443".parse().unwrap(), Some("loop"), 3),
            connection("udp", "224.0.0.1:5353".parse().unwrap(), Some("multi"), 4),
            connection("tcp", "8.8.8.8:443".parse().unwrap(), Some("public"), 5),
        ];

        let report = observer.run_from_connections(snapshot).unwrap();

        assert!(report.baseline);
        assert_eq!(report.observed, 1);
        assert_eq!(report.connections[0].remote, "8.8.8.8:443".parse().unwrap());
        assert_eq!(report.findings, 0);
    }

    #[test]
    fn baseline_then_new_destination_alerts_once() {
        let db = Arc::new(Db::open_memory().unwrap());
        let observer = observer(Arc::clone(&db), true, 20);
        let first = connection("tcp", "1.1.1.1:443".parse().unwrap(), Some("browser"), 10);
        let second = connection("udp", "8.8.8.8:53".parse().unwrap(), Some("resolver"), 11);

        let baseline = observer.run_from_connections(vec![first.clone()]).unwrap();
        assert!(baseline.baseline);
        assert_eq!(baseline.findings, 0);
        assert!(db.get_meta(BASELINE_KEY).unwrap().is_some());

        let changed = observer
            .run_from_connections(vec![first.clone(), second.clone()])
            .unwrap();
        assert!(!changed.baseline);
        assert_eq!(changed.new_remote, 1);
        assert_eq!(changed.findings, 1);

        let findings = db.list_findings(10, true).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "network");
        assert_eq!(findings[0].tier, Tier::Candidate);
        assert!(findings[0].subject.contains("new egress destination"));
        assert!(findings[0].detail.contains("new egress destination"));

        let repeated = observer.run_from_connections(vec![first, second]).unwrap();
        assert_eq!(repeated.new_remote, 0);
        assert_eq!(repeated.findings, 0);
        assert_eq!(db.list_findings(10, true).unwrap().len(), 1);
    }

    #[test]
    fn process_key_v1_baseline_migrates_without_alerting() {
        let db = Arc::new(Db::open_memory().unwrap());
        db.set_meta(
            BASELINE_KEY,
            r#"["tcp/browser/1.1.1.1/443","tcp/unknown/8.8.8.8/443"]"#,
        )
        .unwrap();
        let observer = observer(Arc::clone(&db), true, 20);
        let report = observer
            .run_from_connections(vec![connection(
                "tcp",
                "1.1.1.1:443".parse().unwrap(),
                Some("browser"),
                10,
            )])
            .unwrap();
        assert!(report.baseline);
        assert_eq!(report.findings, 0);
        assert!(db.list_findings(10, true).unwrap().is_empty());
        assert!(db.get_meta(BASELINE_KEY).unwrap().unwrap().contains("v2/"));
    }

    #[test]
    fn truncation_adds_one_nonbaseline_candidate_finding() {
        let db = Arc::new(Db::open_memory().unwrap());
        let observer = observer(Arc::clone(&db), true, 1);
        let first = connection("tcp", "1.1.1.1:443".parse().unwrap(), Some("browser"), 10);
        let omitted = connection("tcp", "8.8.8.8:443".parse().unwrap(), Some("browser"), 11);

        observer.run_from_connections(vec![first.clone()]).unwrap();
        let report = observer.run_from_connections(vec![first, omitted]).unwrap();

        assert!(report.truncated);
        assert_eq!(report.observed, 1);
        assert_eq!(report.new_remote, 0);
        assert_eq!(report.findings, 1);
        let findings = db.list_findings(10, true).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tier, Tier::Candidate);
        assert_eq!(findings[0].subject, "network observation truncated");
    }

    #[test]
    fn connected_udp_requires_a_nonzero_remote_endpoint() {
        let fixture = format!(
            "{HEADER}\n\
               0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 7\n\
               1: 0200000A:14E9 08080808:0035 01 00000000:00000000 00:00000000 00000000 1000 0 8\n"
        );

        let parsed = parse_proc_table(&fixture, "udp", false).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].remote, "8.8.8.8:53".parse().unwrap());
        assert_eq!(parsed[0].inode, 8);
    }
}
