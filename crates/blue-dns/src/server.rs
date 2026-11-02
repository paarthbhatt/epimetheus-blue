//! UDP sinkhole and forwarding resolver.
//!
//! Each datagram is parsed just far enough to read the first question. Blocked
//! names are answered locally (`NXDOMAIN`, or an A/AAAA zero answer); everything
//! else is forwarded verbatim to an upstream over plaintext UDP and the raw
//! reply is relayed back. There is no cache and no per-client policy yet.
//!
//! **Plaintext UDP is deliberate for this phase.** The next phase adds a DoT
//! upstream client ([`forward`] is the seam: it takes the raw query and returns
//! the raw response) and a `tls://` variant of [`DnsConfig::upstreams`].
//!
//! Malformed input never panics: it is counted in [`DnsStats::errors`] and
//! dropped.

use crate::blocklist::Blocklist;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;

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

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub bind: SocketAddr,
    pub upstreams: Vec<SocketAddr>,
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
    let DnsConfig {
        bind,
        upstreams,
        block_response,
    } = cfg;
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("binding DNS socket on {bind}"))?;
    let stats = Arc::new(DnsStats::default());
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
    upstreams: Vec<SocketAddr>,
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
        let upstream = upstreams[index];
        let raw = buf[..len].to_vec();
        let (id, flags, question) = (query.id, query.flags, query.question);
        let socket = Arc::clone(&socket);
        let stats = Arc::clone(&stats);
        let qname = query.qname;
        tokio::spawn(async move {
            match forward(&raw, upstream).await {
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
///
/// This is the seam for DoT: the caller does not care whether the bytes travelled
/// over UDP or a TLS stream.
async fn forward(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
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

    if buf.len() < 12 {
        anyhow::bail!("upstream {upstream} returned a truncated header");
    }
    if buf[0..2] != query[0..2] {
        anyhow::bail!("upstream {upstream} returned a mismatched query id");
    }
    Ok(buf)
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
        upstreams: Vec<SocketAddr>,
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
            vec![upstream_addr],
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
