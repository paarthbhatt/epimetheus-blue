//! `blue-dns` — local DNS sinkhole and forwarder.
//!
//! Two pieces, deliberately separate:
//!
//! - [`Blocklist`]: pure, network-free suffix matcher with per-list attribution.
//! - [`run`]: a tokio UDP resolver that answers blocked names locally and
//!   forwards everything else to a round-robin UDP or DNS-over-TLS upstream.
//!
//! There is no cache, zone-file support, or per-client policy yet; see the
//! module docs on [`server`].

pub mod blocklist;
pub mod server;

pub use blocklist::Blocklist;
pub use server::{run, run_with_stats, BlockResponse, DnsConfig, DnsStats, DnsUpstream};
