//! `blue-dns` — local DNS sinkhole and forwarder.
//!
//! Two pieces, deliberately separate:
//!
//! - [`Blocklist`]: pure, network-free suffix matcher with per-list attribution.
//! - [`run`]: a tokio UDP resolver that answers blocked names locally and
//!   forwards everything else to a round-robin upstream.
//!
//! No cache, no DoT client, no zone files, no per-client policy yet. Upstreams
//! are plaintext UDP in this phase; see the module docs on [`server`].

pub mod blocklist;
pub mod server;

pub use blocklist::Blocklist;
pub use server::{run, run_with_stats, BlockResponse, DnsConfig, DnsStats};
