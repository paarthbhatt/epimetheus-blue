//! UDP sinkhole and forwarding resolver with UDP and DNS-over-TLS upstreams.
//!
//! Each datagram is parsed just far enough to read the first question. Blocked
//! names are answered locally (`NXDOMAIN`, or an A/AAAA zero answer); everything
//! else is forwarded verbatim to a round-robin upstream and the raw reply is
//! relayed back. There is no cache and no per-client policy yet.
//!
//! DNS-over-TLS follows RFC 7858 framing and authenticates the configured DNS
//! name against the WebPKI root set. Each DoT request currently opens a fresh
//! TCP/TLS connection. Keeping connection management inside [`forward_tls`] is
//! an intentional performance seam for a future pooled/persistent transport.
//!
//! Malformed input never panics: it is counted in [`DnsStats::errors`] and
//! dropped.

use crate::blocklist::Blocklist;
use anyhow::{bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// How long to wait for an upstream reply.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest UDP payload we will read from either side.
const MAX_DATAGRAM: usize = 65_535;

/// TTL on synthetic `0.0.0.0`/`::` answers.
const SINKHOLE_TTL: u32 = 60;

const RCODE_NOERROR: u16 = 0;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// A recursive DNS server used for unblocked queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsUpstream {
    /// Plaintext DNS over UDP.
    Udp(SocketAddr),
    /// DNS over TLS, with `server_name` used for SNI and certificate validation.
    Tls {
        addr: SocketAddr,
        server_name: String,
    },
}

impl DnsUpstream {
    /// Parse `IP:PORT` as UDP or `tls://IP:PORT#dns-name` as DNS-over-TLS.
    pub fn parse(value: &str) -> Result<Self> {
        if let Some(value) = value.strip_prefix("tls://") {
            let (addr, server_name) = value
                .split_once('#')
                .context("TLS DNS upstream must be tls://IP:PORT#dns-name")?;
            if server_name.is_empty() {
                bail!("TLS DNS upstream requires a nonempty DNS name");
            }
            if server_name.contains('#') {
                bail!("TLS DNS upstream must contain exactly one '#' separator");
            }

            let addr = addr
                .parse::<SocketAddr>()
                .with_context(|| format!("invalid TLS DNS upstream socket {addr:?}"))?;
            tls_server_name(server_name)?;
            return Ok(Self::Tls {
                addr,
                server_name: server_name.to_owned(),
            });
        }

        if let Some((scheme, _)) = value.split_once("://") {
            bail!("unsupported DNS upstream scheme {scheme:?}");
        }

        value
            .parse::<SocketAddr>()
            .map(Self::Udp)
            .with_context(|| format!("invalid UDP DNS upstream socket {value:?}"))
    }
}

impl FromStr for DnsUpstream {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl From<SocketAddr> for DnsUpstream {
    fn from(addr: SocketAddr) -> Self {
        Self::Udp(addr)
    }
}

impl fmt::Display for DnsUpstream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => addr.fmt(formatter),
            Self::Tls { addr, server_name } => {
                write!(formatter, "tls://{addr}#{server_name}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub bind: SocketAddr,
    pub upstreams: Vec<DnsUpstream>,
    pub block_response: BlockResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    /// Answer with RCODE 3.
    NxDomain,
    /// Answer A/AAAA with the unspecified address.
    Zero,
}

/// Atomic counters for the resolver. Cheap to share behind an `Arc`.
#[derive(Debug, Default)]
pub struct DnsStats {
    pub total: AtomicU64,
    pub blocked: AtomicU64,
    pub errors: AtomicU64,
}

/// Point-in-time copy of [`DnsStats`], safe to serialize into the API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsStatsSnapshot {
    pub total: u64,
    pub blocked: u64,
    pub errors: u64,
}

impl DnsStats {
    pub fn snapshot(&self) -> DnsStatsSnapshot {
        DnsStatsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Bind `cfg.bind` and serve until `stop` flips to `true` (or its sender drops).
pub async fn run(
    cfg: DnsConfig,
    blocklist: Arc<Blocklist>,
    stop: watch::Receiver<bool>,
) -> Result<()> {
    run_with_stats(cfg, blocklist, Arc::new(DnsStats::default()), stop).await
}

/// Run with caller-owned counters. Native control surfaces use this to show
/// live totals without an HTTP side channel.
pub async fn run_with_stats(
    cfg: DnsConfig,
    blocklist: Arc<Blocklist>,
    stats: Arc<DnsStats>,
    stop: watch::Receiver<bool>,
) -> Result<()> {
    let DnsConfig {
        bind,
        upstreams,
        block_response,
    } = cfg;
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("binding DNS socket on {bind}"))?;
    serve(
        Arc::new(socket),
        upstreams,
        block_response,
        blocklist,
        stats,
        stop,
    )
    .await
}

/// Serve on an already-bound socket. Split out from [`run`] so tests can bind
/// `:0` and learn the port.
async fn serve(
    socket: Arc<UdpSocket>,
    upstreams: Vec<DnsUpstream>,
    block_response: BlockResponse,
    blocklist: Arc<Blocklist>,
    stats: Arc<DnsStats>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    if *stop.borrow() {
        return Ok(());
    }

    let round_robin = Arc::new(AtomicUsize::new(0));
    let mut buf = vec![0u8; MAX_DATAGRAM];

    loop {
        let received = tokio::select! {
            changed = stop.changed() => {
                match changed {
                    Ok(()) if !*stop.borrow() => continue,
                    Ok(()) | Err(_) => return Ok(()),
                }
            }
            received = socket.recv_from(&mut buf) => received,
        };

        let (len, peer) = match received {
            Ok(pair) => pair,
            Err(err) => {
                // A UDP socket can surface ICMP errors here; they are transient.
                stats.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %err, "dns receive failed");
                continue;
            }
        };
        stats.total.fetch_add(1, Ordering::Relaxed);

        let query = match parse_query(&buf[..len]) {
            Some(query) => query,
            None => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%peer, bytes = len, "dropping malformed dns packet");
                continue;
            }
        };

        if let Some(list) = blocklist.is_blocked(&query.qname) {
            stats.blocked.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, qname = %query.qname, list, "blocked dns query");
            let response = blocked_response(&query, block_response);
            if let Err(err) = socket.send_to(&response, peer).await {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%peer, error = %err, "sending blocked dns response failed");
            }
            continue;
        }

        if upstreams.is_empty() {
            stats.errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, qname = %query.qname, "no upstream configured");
            let response =
                build_response(query.id, query.flags, &query.question, RCODE_SERVFAIL, None);
            if let Err(err) = socket.send_to(&response, peer).await {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%peer, error = %err, "sending servfail failed");
            }
            continue;
        }

        // Round-robin one upstream per query. A forwarder hop is allowed to take
        // up to the timeout, so it must not stall the receive loop.
        let index = round_robin.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        let upstream = upstreams[index].clone();
        let raw = buf[..len].to_vec();
        let (id, flags, question) = (query.id, query.flags, query.question);
        let socket = Arc::clone(&socket);
        let stats = Arc::clone(&stats);
        let qname = query.qname;
        tokio::spawn(async move {
            match forward(&raw, &upstream).await {
                Ok(response) => {
                    if let Err(err) = socket.send_to(&response, peer).await {
                        stats.errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%peer, error = %err, "relaying upstream dns response failed");
                    }
                }
                Err(err) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%peer, %upstream, qname = %qname, error = %err, "upstream query failed");
                    let response = build_response(id, flags, &question, RCODE_SERVFAIL, None);
                    if let Err(send_err) = socket.send_to(&response, peer).await {
                        stats.errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%peer, error = %send_err, "sending servfail failed");
                    }
                }
            }
        });
    }
}

/// Send one raw query to one upstream and return its raw reply.
async fn forward(query: &[u8], upstream: &DnsUpstream) -> Result<Vec<u8>> {
    let query_id = query
        .get(..2)
        .context("cannot forward a DNS query without a two-byte ID")?;

    let response = match upstream {
        DnsUpstream::Udp(addr) => forward_udp(query, *addr).await?,
        DnsUpstream::Tls { addr, server_name } => forward_tls(query, *addr, server_name).await?,
    };

    if response.len() < 12 {
        bail!("upstream {upstream} returned a truncated header");
    }
    if &response[..2] != query_id {
        bail!("upstream {upstream} returned a mismatched query id");
    }
    Ok(response)
}

/// Preserve the original UDP forwarding behavior, including its receive timeout.
async fn forward_udp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let local: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0"
            .parse()
            .context("building IPv4 wildcard bind address")?
    } else {
        "[::]:0"
            .parse()
            .context("building IPv6 wildcard bind address")?
    };
    let socket = UdpSocket::bind(local)
        .await
        .with_context(|| format!("binding forwarder socket for {upstream}"))?;
    socket
        .connect(upstream)
        .await
        .with_context(|| format!("connecting forwarder socket to {upstream}"))?;
    socket
        .send(query)
        .await
        .with_context(|| format!("sending query to {upstream}"))?;

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let len = timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf))
        .await
        .with_context(|| format!("upstream {upstream} timed out"))?
        .with_context(|| format!("reading reply from {upstream}"))?;
    buf.truncate(len);
    Ok(buf)
}

/// Perform one complete DoT exchange under a single overall timeout.
async fn forward_tls(query: &[u8], addr: SocketAddr, server_name: &str) -> Result<Vec<u8>> {
    timeout(
        UPSTREAM_TIMEOUT,
        forward_tls_inner(query, addr, server_name),
    )
    .await
    .with_context(|| format!("upstream tls://{addr}#{server_name} timed out"))?
}

async fn forward_tls_inner(query: &[u8], addr: SocketAddr, server_name: &str) -> Result<Vec<u8>> {
    let server_name = tls_server_name(server_name)?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Select the provider explicitly so workspace feature unification cannot
    // make rustls' process-wide provider selection ambiguous.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting safe TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting TCP to DoT upstream {addr}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("establishing authenticated TLS with DoT upstream {addr}"))?;

    exchange_dot_frame(&mut tls, query)
        .await
        .with_context(|| format!("exchanging framed DNS message with DoT upstream {addr}"))
}

/// Write and read one RFC 7858 two-byte-length-prefixed DNS message.
async fn exchange_dot_frame<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let query_len = u16::try_from(query.len()).context("DoT query exceeds 65535 bytes")?;
    stream
        .write_all(&query_len.to_be_bytes())
        .await
        .context("writing DoT query length")?;
    stream.write_all(query).await.context("writing DoT query")?;
    stream.flush().await.context("flushing DoT query")?;

    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .context("reading DoT response length")?;
    // The wire field is a u16, so this allocation is capped at 65,535 bytes.
    let response_len = usize::from(u16::from_be_bytes(length));
    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .with_context(|| format!("reading {response_len}-byte DoT response"))?;
    Ok(response)
}

fn tls_server_name(server_name: &str) -> Result<ServerName<'static>> {
    let parsed = ServerName::try_from(server_name.to_owned())
        .map_err(|_| anyhow::anyhow!("invalid TLS DNS name {server_name:?}"))?;
    if !matches!(&parsed, ServerName::DnsName(_)) {
        bail!("TLS certificate name must be a DNS name, not an IP address");
    }
    Ok(parsed)
}

/// The pieces of a query we need to answer or attribute it.
struct Query {
    id: u16,
    flags: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
    /// Raw question section (name + type + class), echoed back verbatim.
    question: Vec<u8>,
}

/// Parse the header and first question of a DNS query.
///
/// Returns `None` for anything malformed: short header, response bit set, zero
/// questions, compression pointers where a question name must be literal,
/// overlength names, or a truncated question section.
fn parse_query(packet: &[u8]) -> Option<Query> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    if u16::from_be_bytes([packet[4], packet[5]]) == 0 {
        return None;
    }

    let mut offset = 12usize;
    let mut labels: Vec<String> = Vec::new();
    let mut name_len = 0usize;
    loop {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression is not valid in a first question name
        }
        name_len += len + 1;
        if name_len > 255 {
            return None;
        }
        let end = offset.checked_add(len)?;
        let label = packet.get(offset..end)?;
        labels.push(
            label
                .iter()
                .map(|b| (*b as char).to_ascii_lowercase())
                .collect(),
        );
        offset = end;
    }

    let qtype = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
    let qclass = u16::from_be_bytes([*packet.get(offset + 2)?, *packet.get(offset + 3)?]);
    let question = packet.get(12..offset + 4)?.to_vec();

    Some(Query {
        id,
        flags,
        qname: labels.join("."),
        qtype,
        qclass,
        question,
    })
}

/// Build a locally-generated response mirroring the query header and question.
fn blocked_response(query: &Query, mode: BlockResponse) -> Vec<u8> {
    match mode {
        BlockResponse::NxDomain => {
            build_response(query.id, query.flags, &query.question, RCODE_NXDOMAIN, None)
        }
        BlockResponse::Zero => {
            let answer = match (query.qtype, query.qclass) {
                (TYPE_A, CLASS_IN) => Some((TYPE_A, &[0u8, 0, 0, 0][..])),
                (TYPE_AAAA, CLASS_IN) => Some((TYPE_AAAA, &[0u8; 16][..])),
                _ => None,
            };
            build_response(
                query.id,
                query.flags,
                &query.question,
                RCODE_NOERROR,
                answer,
            )
        }
    }
}

/// Assemble a response: copied id, QR/opcode/RD copied, RA set, zero NS/AR.
fn build_response(
    id: u16,
    query_flags: u16,
    question: &[u8],
    rcode: u16,
    answer: Option<(u16, &[u8])>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + question.len() + 32);
    out.extend_from_slice(&id.to_be_bytes());
    let flags = 0x8000             // QR
        | (query_flags & 0x7800)   // opcode
        | (query_flags & 0x0100)   // RD
        | 0x0080                   // RA
        | (rcode & 0x000F);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(answer.is_some() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(question);

    if let Some((rtype, rdata)) = answer {
        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&SINKHOLE_TTL.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn query_bytes(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn test_blocklist(entries: &str) -> Arc<Blocklist> {
        let mut bl = Blocklist::new();
        bl.add_list("ads", entries);
        Arc::new(bl)
    }

    async fn start(
        blocklist: Arc<Blocklist>,
        upstreams: Vec<DnsUpstream>,
        mode: BlockResponse,
    ) -> (
        SocketAddr,
        Arc<DnsStats>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let stats = Arc::new(DnsStats::default());
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve(socket, upstreams, mode, blocklist, stats.clone(), rx));
        (addr, stats, tx, handle)
    }

    async fn ask(client: &UdpSocket, addr: SocketAddr, query: &[u8]) -> Vec<u8> {
        client.send_to(query, addr).await.unwrap();
        let mut buf = [0u8; 512];
        let len = timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("timed out waiting for dns response")
            .unwrap();
        buf[..len].to_vec()
    }

    #[test]
    fn upstream_parser_accepts_udp_and_tls() {
        assert_eq!(
            DnsUpstream::parse("9.9.9.9:53").unwrap(),
            DnsUpstream::Udp("9.9.9.9:53".parse().unwrap())
        );
        assert_eq!(
            DnsUpstream::parse("[2620:fe::fe]:53").unwrap(),
            DnsUpstream::Udp("[2620:fe::fe]:53".parse().unwrap())
        );
        assert_eq!(
            DnsUpstream::parse("tls://1.1.1.1:853#cloudflare-dns.com").unwrap(),
            DnsUpstream::Tls {
                addr: "1.1.1.1:853".parse().unwrap(),
                server_name: "cloudflare-dns.com".to_owned(),
            }
        );
        assert_eq!(
            DnsUpstream::parse("tls://[2606:4700:4700::1111]:853#cloudflare-dns.com")
                .unwrap()
                .to_string(),
            "tls://[2606:4700:4700::1111]:853#cloudflare-dns.com"
        );
    }

    #[test]
    fn upstream_parser_rejects_malformed_values_and_other_schemes() {
        for value in [
            "",
            "dns.example:53",
            "udp://9.9.9.9:53",
            "https://9.9.9.9:443",
            "TLS://1.1.1.1:853#cloudflare-dns.com",
            "tls://1.1.1.1:853",
            "tls://1.1.1.1:853#",
            "tls://dns.example:853#dns.example",
            "tls://1.1.1.1:853#not a dns name",
            "tls://1.1.1.1:853#1.1.1.1",
            "tls://1.1.1.1:853#dns.example#extra",
        ] {
            assert!(
                DnsUpstream::parse(value).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn dot_framing_uses_two_byte_lengths_and_reads_exact_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let query = query_bytes(0xA1B2, "example.org", TYPE_A);
        let reply = query_with_qr(&query);
        let expected_query = query.clone();
        let expected_reply = reply.clone();

        let helper = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await.unwrap();
            let length = usize::from(u16::from_be_bytes(length));
            assert_eq!(length, expected_query.len());

            let mut received = vec![0u8; length];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_query);

            let mut framed = Vec::new();
            framed.extend_from_slice(&(expected_reply.len() as u16).to_be_bytes());
            framed.extend_from_slice(&expected_reply);
            // A following frame must not become part of this response.
            framed.extend_from_slice(&[0, 3, b'n', b'e', b'x']);
            stream.write_all(&framed).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let response = exchange_dot_frame(&mut stream, &query).await.unwrap();
        assert_eq!(response, reply);
        helper.await.unwrap();
    }

    #[tokio::test]
    async fn dot_framing_rejects_queries_larger_than_u16() {
        let (mut stream, _peer) = tokio::io::duplex(1);
        let oversized = vec![0u8; usize::from(u16::MAX) + 1];
        let error = exchange_dot_frame(&mut stream, &oversized)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 65535"));
    }

    #[tokio::test]
    async fn blocked_query_gets_nxdomain() {
        let (addr, stats, stop, handle) = start(
            test_blocklist("ads.example.com"),
            vec![],
            BlockResponse::NxDomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let response = ask(
            &client,
            addr,
            &query_bytes(0x1234, "x.ads.example.com", TYPE_A),
        )
        .await;

        assert_eq!(&response[0..2], &[0x12, 0x34], "id must be echoed");
        assert_ne!(response[2] & 0x80, 0, "QR must be set");
        assert_eq!(response[3] & 0x0F, RCODE_NXDOMAIN as u8);
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);

        let snap = stats.snapshot();
        assert_eq!(snap.blocked, 1);
        assert_eq!(snap.total, 1);
        assert_eq!(snap.errors, 0);

        let _ = stop.send(true);
        assert!(timeout(Duration::from_secs(2), handle).await.is_ok());
    }

    #[tokio::test]
    async fn zero_mode_answers_a_and_aaaa() {
        let (addr, _stats, stop, handle) = start(
            test_blocklist("tracker.example.net"),
            vec![],
            BlockResponse::Zero,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let a = ask(
            &client,
            addr,
            &query_bytes(7, "a.tracker.example.net", TYPE_A),
        )
        .await;
        assert_eq!(a[3] & 0x0F, RCODE_NOERROR as u8);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1, "one answer");
        assert_eq!(&a[a.len() - 4..], &[0, 0, 0, 0], "0.0.0.0");

        let aaaa = ask(
            &client,
            addr,
            &query_bytes(8, "a.tracker.example.net", TYPE_AAAA),
        )
        .await;
        assert_eq!(u16::from_be_bytes([aaaa[6], aaaa[7]]), 1);
        assert_eq!(&aaaa[aaaa.len() - 16..], &[0u8; 16], "::");

        let _ = stop.send(true);
        assert!(timeout(Duration::from_secs(2), handle).await.is_ok());
    }

    #[tokio::test]
    async fn allowed_query_is_forwarded_and_relayed() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let mut reply = buf[..len].to_vec();
            reply[2] |= 0x80; // QR
            upstream.send_to(&reply, peer).await.unwrap();
        });

        let (addr, stats, stop, handle) = start(
            test_blocklist("ads.example.com"),
            vec![upstream_addr.into()],
            BlockResponse::NxDomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let query = query_bytes(0xBEEF, "ok.example.org", TYPE_A);
        let response = ask(&client, addr, &query).await;

        assert_eq!(&response[0..2], &[0xBE, 0xEF]);
        assert_ne!(response[2] & 0x80, 0);
        assert_eq!(response, query_with_qr(&query));

        let snap = stats.snapshot();
        assert_eq!(snap.total, 1);
        assert_eq!(snap.blocked, 0);
        assert_eq!(snap.errors, 0);

        let _ = stop.send(true);
        assert!(timeout(Duration::from_secs(2), handle).await.is_ok());
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn mixed_round_robin_does_not_fallback_when_tls_fails() {
        let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let tls_task = tokio::spawn(async move {
            let (stream, _) = tls_listener.accept().await.unwrap();
            // Dropping a plaintext connection makes the TLS handshake fail fast.
            drop(stream);
        });

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..2], &[0x20, 0x02], "only the second query is UDP");
            buf[2] |= 0x80;
            udp.send_to(&buf[..len], peer).await.unwrap();
        });

        let upstreams = vec![
            DnsUpstream::Tls {
                addr: tls_addr,
                server_name: "dns.example".to_owned(),
            },
            DnsUpstream::Udp(udp_addr),
        ];
        let (addr, stats, stop, handle) = start(
            test_blocklist("ads.example.com"),
            upstreams,
            BlockResponse::NxDomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let failed = ask(
            &client,
            addr,
            &query_bytes(0x2001, "first.example.org", TYPE_A),
        )
        .await;
        assert_eq!(failed[3] & 0x0F, RCODE_SERVFAIL as u8);

        let relayed = ask(
            &client,
            addr,
            &query_bytes(0x2002, "second.example.org", TYPE_A),
        )
        .await;
        assert_eq!(&relayed[..2], &[0x20, 0x02]);
        assert_ne!(relayed[2] & 0x80, 0);

        let snap = stats.snapshot();
        assert_eq!(snap.total, 2);
        assert_eq!(snap.errors, 1);

        let _ = stop.send(true);
        assert!(timeout(Duration::from_secs(2), handle).await.is_ok());
        tls_task.await.unwrap();
        udp_task.await.unwrap();
    }

    /// The fake upstream only flips QR; mirror that expectation.
    fn query_with_qr(query: &[u8]) -> Vec<u8> {
        let mut expected = query.to_vec();
        expected[2] |= 0x80;
        expected
    }

    #[tokio::test]
    async fn malformed_packets_are_counted_not_fatal() {
        let (addr, stats, stop, handle) = start(
            test_blocklist("ads.example.com"),
            vec![],
            BlockResponse::NxDomain,
        )
        .await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Truncated header, then a compression pointer in the question name.
        client.send_to(b"\x00\x01\x01\x00", addr).await.unwrap();
        let mut pointer = query_bytes(9, "x.ads.example.com", TYPE_A);
        pointer[12] = 0xC0;
        client.send_to(&pointer, addr).await.unwrap();

        // A valid query behind them proves both were consumed and the loop lives.
        let response = ask(
            &client,
            addr,
            &query_bytes(0x0A0B, "x.ads.example.com", TYPE_A),
        )
        .await;
        assert_eq!(response[3] & 0x0F, RCODE_NXDOMAIN as u8);

        let snap = stats.snapshot();
        assert_eq!(snap.errors, 2);
        assert_eq!(snap.blocked, 1);
        assert_eq!(snap.total, 3);

        let _ = stop.send(true);
        assert!(timeout(Duration::from_secs(2), handle).await.is_ok());
    }

    #[test]
    fn parse_query_rejects_truncation() {
        let query = query_bytes(1, "example.com", TYPE_A);
        for len in 0..query.len() {
            assert!(
                parse_query(&query[..len]).is_none(),
                "len {len} should fail"
            );
        }
        let parsed = parse_query(&query).expect("valid query should parse");
        assert_eq!(parsed.qname, "example.com");
        assert_eq!(parsed.question, query[12..]);
    }
}
