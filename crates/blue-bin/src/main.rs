//! `blue` — one binary, several roles.
//!
//! Long-running roles are separate subcommands so each can be supervised by its
//! own systemd unit without a supervisor process of our own.

use anyhow::{bail, Context, Result};
use blue_core::{Config, Db, Quarantine, Tier};
use blue_scan::{ScanConfig, ScanEngine};
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The industry-standard EICAR test string. Harmless by construction.
const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const RULE_EICAR: &str = include_str!("../../blue-scan/rules/eicar.yar");
const RULE_WEBSHELLS: &str = include_str!("../../blue-scan/rules/webshells.yar");

#[derive(Parser)]
#[command(
    name = "blue",
    version,
    about = "Personal defence suite: scan, block, verify"
)]
struct Cli {
    /// Explicit config file, applied after the standard locations.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Override the state directory (useful for tests and drills).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    /// With no subcommand, open the native desktop control center.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Chromium native-messaging entrypoint (read-only, stdio protocol).
    #[command(hide = true)]
    NativeHost,
    /// Scan a file or directory once and print the verdicts.
    Scan(ScanArgs),
    /// Watch configured roots and scan files as they appear.
    Watch,
    /// Open the native desktop control center.
    App,
    /// Run the DNS sinkhole resolver.
    Dns,
    /// Quarantine maintenance.
    Quarantine(QArgs),
    /// Run the integrity and persistence check once.
    Guard,
    /// Observe current public egress destinations without changing the firewall.
    Network,
    /// Filter feed maintenance.
    Feeds(FeedArgs),
    /// Local and optional hash-only reputation checks.
    Reputation(ReputationArgs),
    /// Analyze and explicitly apply bounded storage cleanup candidates.
    Cleanup(CleanupArgs),
    /// Windows-style inbound firewall with approval and rollback.
    Firewall(FirewallArgs),
    /// Prove the pipeline works end to end with the EICAR string.
    Drill,
    /// Check configuration, state, rules and detectors.
    Verify,
}

#[derive(Args)]
struct ScanArgs {
    path: PathBuf,
    /// Print only the summary line, no table.
    #[arg(long)]
    quiet: bool,
}

#[derive(Args)]
struct QArgs {
    #[command(subcommand)]
    cmd: QCmd,
}

#[derive(Subcommand)]
enum QCmd {
    /// List quarantined items.
    Ls {
        /// Include items already restored.
        #[arg(long)]
        all: bool,
    },
    /// Put a quarantined file back where it came from.
    Restore { id: i64 },
}

#[derive(Args)]
struct FeedArgs {
    #[command(subcommand)]
    cmd: FeedCmd,
}

#[derive(Args)]
struct ReputationArgs {
    #[command(subcommand)]
    cmd: ReputationCmd,
}

#[derive(Subcommand)]
enum ReputationCmd {
    /// Download and validate configured local SHA-256 feeds.
    Sync,
    /// Show loaded local hash counts and online-provider state.
    Status,
    /// Check one file. Online queries are hash-only and require explicit --online.
    Check {
        path: PathBuf,
        #[arg(long)]
        online: bool,
    },
    /// Restore the previous version of a local hash feed.
    Rollback { name: String },
}

#[derive(Args)]
struct CleanupArgs {
    #[command(subcommand)]
    cmd: CleanupCmd,
}

#[derive(Args)]
struct FirewallArgs {
    #[command(subcommand)]
    cmd: FirewallCmd,
}

#[derive(Subcommand)]
enum FirewallCmd {
    /// Read sanitized local firewall status; no privilege prompt.
    Status,
    /// Render a policy without applying it.
    Plan {
        #[arg(long, default_value = "public")]
        profile: String,
    },
    /// Stage rules for 60 seconds; explicit confirmation and polkit required.
    Apply {
        #[arg(long, default_value = "public")]
        profile: String,
        #[arg(long)]
        confirm: String,
    },
    /// Keep the staged policy and persist it for reboot.
    Confirm {
        #[arg(long)]
        confirm: String,
    },
    /// Restore the policy saved before the staged change.
    Rollback,
    /// Remove only Blue's firewall table.
    Disable {
        #[arg(long)]
        confirm: String,
    },
}

#[derive(Subcommand)]
enum CleanupCmd {
    /// Analyze only. Nothing is selected or deleted.
    Scan {
        #[arg(long)]
        json: bool,
    },
    /// Delete only freshly revalidated candidate IDs after exact confirmation.
    Apply {
        #[arg(long = "id", required = true)]
        ids: Vec<String>,
        #[arg(long)]
        confirm: String,
    },
    /// Print the exact confirmation phrase for reviewed candidate IDs.
    Phrase {
        #[arg(long = "id", required = true)]
        ids: Vec<String>,
    },
    /// Show memory pressure and the largest resident processes.
    Performance,
}

#[derive(Subcommand)]
enum FeedCmd {
    /// Download, validate and atomically activate configured filter lists.
    Sync,
    /// Show locally installed lists.
    Ls,
    /// Restore the previous version of one list.
    Rollback { name: String },
}

struct Ctx {
    cfg: Config,
    db: Arc<Db>,
    quarantine: Arc<Quarantine>,
}

fn main() {
    let native_alias = std::env::args_os()
        .next()
        .as_deref()
        .and_then(|argument| Path::new(argument).file_name())
        .is_some_and(|name| name == "blue-native-host");
    let result = if native_alias {
        run_native_alias()
    } else {
        run()
    };
    if let Err(e) = result {
        eprintln!("blue: {e:#}");
        std::process::exit(1);
    }
}

fn run_native_alias() -> Result<()> {
    let config = Config::load(None)?;
    let db = Arc::new(Db::open(&config.db_path())?);
    blue_native_host::run(&config, db)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let ctx = Ctx::open(cli.config.as_deref(), cli.state_dir)?;
    init_tracing(&ctx.cfg.general.log_level);

    match cli.cmd {
        None | Some(Cmd::App) => cmd_app(ctx),
        Some(Cmd::NativeHost) => blue_native_host::run(&ctx.cfg, ctx.db.clone()),
        Some(Cmd::Scan(a)) => cmd_scan(&ctx, a),
        Some(Cmd::Watch) => cmd_watch(ctx),
        Some(Cmd::Dns) => cmd_dns(ctx),
        Some(Cmd::Quarantine(q)) => cmd_quarantine(&ctx, q),
        Some(Cmd::Guard) => cmd_guard(&ctx),
        Some(Cmd::Network) => cmd_network(&ctx),
        Some(Cmd::Feeds(args)) => cmd_feeds(&ctx, args),
        Some(Cmd::Reputation(args)) => cmd_reputation(&ctx, args),
        Some(Cmd::Cleanup(args)) => cmd_cleanup(&ctx, args),
        Some(Cmd::Firewall(args)) => cmd_firewall(args),
        Some(Cmd::Drill) => cmd_drill(&ctx),
        Some(Cmd::Verify) => cmd_verify(&ctx),
    }
}

impl Ctx {
    fn open(explicit: Option<&Path>, state_override: Option<PathBuf>) -> Result<Ctx> {
        let mut cfg = Config::load(explicit)?;
        if let Some(dir) = state_override {
            cfg.general.state_dir = dir.to_string_lossy().into_owned();
        }
        // Rules ship inside the binary. Materialise them into the state dir so
        // they are visible, editable and reloadable like any other dataset.
        let rules_dir = cfg.state_dir().join("rules");
        install_default_rules(&rules_dir)?;
        cfg.scan.yara.rule_dirs = vec![rules_dir.to_string_lossy().into_owned()];

        std::fs::create_dir_all(cfg.state_dir())?;
        let db = Arc::new(Db::open(&cfg.db_path())?);
        let quarantine = Arc::new(Quarantine::new(cfg.quarantine_dir(), db.clone())?);
        Ok(Ctx {
            cfg,
            db,
            quarantine,
        })
    }

    fn engine(&self) -> Result<ScanEngine> {
        let sc = ScanConfig::from_config(&self.cfg);
        ScanEngine::new(self.db.clone(), self.quarantine.clone(), sc)
    }
}

fn install_default_rules(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    for (name, body) in [("eicar.yar", RULE_EICAR), ("webshells.yar", RULE_WEBSHELLS)] {
        let path = dir.join(name);
        if !path.exists() {
            std::fs::write(&path, body)
                .with_context(|| format!("writing default rule {}", path.display()))?;
        }
    }
    Ok(())
}

fn cmd_scan(ctx: &Ctx, args: ScanArgs) -> Result<()> {
    let engine = ctx.engine()?;
    if let Some(reason) = engine.degraded() {
        eprintln!("warning: degraded — {reason}");
    }
    let mut files = Vec::new();
    collect_files(&args.path, &mut files)?;
    if files.is_empty() {
        bail!("no regular files under {}", args.path.display());
    }

    let mut counts: Vec<usize> = vec![0; 4];
    let mut quarantined = 0usize;
    for path in &files {
        match engine.scan_path(path) {
            Ok(out) => {
                counts[out.tier.as_i64() as usize] += 1;
                if out.quarantined.is_some() {
                    quarantined += 1;
                }
                if !args.quiet && out.tier >= Tier::Candidate {
                    println!(
                        "{:<11} {}  {}",
                        out.tier.label(),
                        short_hash(&out.sha256),
                        path.display()
                    );
                }
            }
            Err(e) => eprintln!("skip {}: {e:#}", path.display()),
        }
    }
    println!(
        "scanned {} file(s): {} observed, {} candidate, {} corroborated, {} confirmed; {} quarantined",
        files.len(),
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        quarantined
    );
    Ok(())
}

fn cmd_watch(ctx: Ctx) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let engine = Arc::new(ctx.engine()?);
        if let Some(reason) = engine.degraded() {
            eprintln!("warning: degraded — {reason}");
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let roots = ctx.cfg.roots();
        println!("watching {} root(s) — ctrl-c to stop", roots.len());
        blue_scan::watch(engine, roots, ctx.cfg.scan.debounce_ms, rx)?;
        tokio::signal::ctrl_c().await?;
        let _ = tx.send(true);
        // Give the blocking watcher thread one tick to observe shutdown.
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        Ok(())
    })
}

fn cmd_app(ctx: Ctx) -> Result<()> {
    blue_ui::run(blue_ui::AppDeps {
        config: ctx.cfg,
        db: ctx.db,
        quarantine: ctx.quarantine,
    })
}

fn cmd_dns(ctx: Ctx) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut list = blue_dns::Blocklist::new();
        let dir = blue_core::config::expand_tilde(&ctx.cfg.feeds.lists_dir);
        if dir.exists() {
            let n = list.load_dir(&dir)?;
            println!("loaded {n} list entries from {}", dir.display());
        } else {
            println!("no lists at {} — starting permissive", dir.display());
        }
        let bind: std::net::SocketAddr = ctx
            .cfg
            .dns
            .bind
            .parse()
            .with_context(|| format!("bad bind address {}", ctx.cfg.dns.bind))?;
        let mut upstreams = Vec::new();
        for u in &ctx.cfg.dns.upstreams {
            upstreams.push(u.parse().with_context(|| format!("bad upstream {u}"))?);
        }
        let block_response = match ctx.cfg.dns.block_response.as_str() {
            "zero" => blue_dns::BlockResponse::Zero,
            _ => blue_dns::BlockResponse::NxDomain,
        };
        let cfg = blue_dns::DnsConfig {
            bind,
            upstreams,
            block_response,
        };
        let (_tx, rx) = tokio::sync::watch::channel(false);
        println!("resolver on {bind} ({} entries)", list.len());
        blue_dns::run(cfg, Arc::new(list), rx).await
    })
}

fn cmd_quarantine(ctx: &Ctx, q: QArgs) -> Result<()> {
    match q.cmd {
        QCmd::Ls { all } => {
            let items = ctx.quarantine.list(all)?;
            if items.is_empty() {
                println!("quarantine empty");
                return Ok(());
            }
            for it in items {
                let state = if it.restored_at_ms.is_some() {
                    "restored"
                } else {
                    "held"
                };
                println!(
                    "{:>4}  {:<9} {:<8} {}  ({})",
                    it.id,
                    it.tier.label(),
                    state,
                    it.original_path,
                    it.reason
                );
            }
        }
        QCmd::Restore { id } => {
            let path = ctx.quarantine.restore(id)?;
            println!("restored {} -> {}", id, path.display());
        }
    }
    Ok(())
}

fn cmd_guard(ctx: &Ctx) -> Result<()> {
    let guard = blue_guard::Guard::new(
        ctx.db.clone(),
        blue_guard::GuardConfig::from_config(&ctx.cfg),
    );
    let report = guard.run_once()?;
    if report.baseline {
        println!(
            "baseline established: {} entries (this is not a clean bill of health)",
            report.entries
        );
    } else {
        println!(
            "integrity check: {} entries, {} added, {} modified, {} removed, {} finding(s)",
            report.entries, report.added, report.modified, report.removed, report.findings
        );
    }
    Ok(())
}

fn cmd_network(ctx: &Ctx) -> Result<()> {
    let observer =
        blue_net::NetObserver::new(ctx.db.clone(), blue_net::NetConfig::from_config(&ctx.cfg));
    let report = observer.run_once()?;
    if report.baseline {
        println!(
            "network baseline established: {} public connection(s)",
            report.observed
        );
    } else {
        println!(
            "network observation: {} public connection(s), {} new destination(s), {} finding(s){}",
            report.observed,
            report.new_remote,
            report.findings,
            if report.truncated { " (truncated)" } else { "" }
        );
    }
    for connection in report.connections.iter().take(25) {
        println!(
            "{:<5} {:<20} -> {:<22} {}",
            connection.protocol,
            connection.process.as_deref().unwrap_or("unknown"),
            connection.remote,
            connection.state
        );
    }
    if report.connections.len() > 25 {
        println!("… and {} more", report.connections.len() - 25);
    }
    Ok(())
}

fn cmd_feeds(ctx: &Ctx, args: FeedArgs) -> Result<()> {
    let feeds = blue_feeds::Feeds::new(
        ctx.db.clone(),
        blue_feeds::FeedsConfig::from_config(&ctx.cfg),
    );
    match args.cmd {
        FeedCmd::Sync => {
            let report = feeds.sync()?;
            for name in &report.updated {
                println!("updated {name}");
            }
            for (name, reason) in &report.failed {
                eprintln!("failed {name}: {reason}");
            }
            println!(
                "{} list(s) updated, {} failed, {} usable lines",
                report.updated.len(),
                report.failed.len(),
                report.total_lines
            );
            if !report.failed.is_empty() && report.updated.is_empty() {
                bail!("no filter source updated successfully");
            }
        }
        FeedCmd::Ls => {
            let lists = feeds.list()?;
            if lists.is_empty() {
                println!("no local filter lists");
            }
            for list in lists {
                println!(
                    "{:<24} {:>9} lines  {:>8} KiB  {}",
                    list.name,
                    list.lines,
                    list.bytes / 1024,
                    list.path.display()
                );
            }
        }
        FeedCmd::Rollback { name } => {
            feeds.rollback(&name)?;
            println!("rolled {name} back to the previous version");
        }
    }
    Ok(())
}

fn cmd_reputation(ctx: &Ctx, args: ReputationArgs) -> Result<()> {
    let engine = blue_reputation::ReputationEngine::new(
        ctx.db.clone(),
        blue_reputation::ReputationConfig::from_config(&ctx.cfg),
    )?;
    match args.cmd {
        ReputationCmd::Sync => {
            let report = engine.sync()?;
            for name in &report.updated {
                println!("updated {name}");
            }
            for (name, reason) in &report.failed {
                eprintln!("failed {name}: {reason}");
            }
            println!(
                "{} hash source(s) updated, {} failed, {} SHA-256 hashes",
                report.updated.len(),
                report.failed.len(),
                report.total_hashes
            );
            if report.updated.is_empty() && !report.failed.is_empty() {
                bail!("no reputation source updated successfully");
            }
        }
        ReputationCmd::Status => {
            let status = engine.status();
            println!(
                "local reputation: {} SHA-256 hashes from {} source(s)",
                status.local_hashes, status.local_sources
            );
            println!(
                "VirusTotal: {} (key env: {})",
                if ctx.cfg.reputation.virustotal_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                ctx.cfg.reputation.virustotal_api_key_env
            );
        }
        ReputationCmd::Check { path, online } => {
            let result = engine.check_file(&path, online)?;
            println!("sha256: {}", result.sha256);
            println!(
                "local: {}",
                result.local_match.as_deref().unwrap_or("not listed")
            );
            if let Some(vt) = &result.virustotal {
                println!(
                    "VirusTotal: {} (malicious {}, suspicious {}, harmless {})",
                    vt.verdict, vt.malicious, vt.suspicious, vt.harmless
                );
            } else if online && !ctx.cfg.reputation.virustotal_enabled {
                println!("VirusTotal: disabled by configuration; no query sent");
            }
            println!(
                "verdict signal: {}",
                result
                    .detector
                    .as_ref()
                    .and_then(|value| value.signature.as_deref())
                    .unwrap_or("none")
            );
        }
        ReputationCmd::Rollback { name } => {
            engine.rollback(&name)?;
            println!("rolled {name} back to the previous hash feed");
        }
    }
    Ok(())
}

fn cmd_firewall(args: FirewallArgs) -> Result<()> {
    use blue_firewall::{FirewallClient, FirewallPolicy};
    let client = FirewallClient::new();
    match args.cmd {
        FirewallCmd::Status => println!("{}", serde_json::to_string_pretty(&client.status()?)?),
        FirewallCmd::Plan { profile } => println!(
            "{}",
            FirewallPolicy::new(parse_firewall_profile(&profile)?).render_nft()?
        ),
        FirewallCmd::Apply { profile, confirm } => {
            require_firewall_confirmation(&confirm, "APPLY FIREWALL")?;
            println!(
                "{}",
                client.apply(&FirewallPolicy::new(parse_firewall_profile(&profile)?))?
            );
        }
        FirewallCmd::Confirm { confirm } => {
            require_firewall_confirmation(&confirm, "KEEP FIREWALL")?;
            println!("{}", client.confirm()?);
        }
        FirewallCmd::Rollback => println!("{}", client.rollback()?),
        FirewallCmd::Disable { confirm } => {
            require_firewall_confirmation(&confirm, "DISABLE FIREWALL")?;
            println!("{}", client.disable()?);
        }
    }
    Ok(())
}

fn parse_firewall_profile(profile: &str) -> Result<blue_firewall::FirewallProfile> {
    match profile {
        "public" => Ok(blue_firewall::FirewallProfile::Public),
        "private" => Ok(blue_firewall::FirewallProfile::Private),
        _ => bail!("profile must be public or private"),
    }
}

fn require_firewall_confirmation(actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        bail!("confirmation must exactly match `{expected}`");
    }
    Ok(())
}

fn cmd_cleanup(ctx: &Ctx, args: CleanupArgs) -> Result<()> {
    let engine = blue_cleanup::CleanupEngine::new(
        ctx.db.clone(),
        blue_cleanup::CleanupConfig::from_config(&ctx.cfg),
    );
    match args.cmd {
        CleanupCmd::Scan { json } => {
            let report = engine.scan()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            println!(
                "cleanup inventory: safe {}, review {}, protected {} item(s) (not sized){}",
                human_bytes(report.safe_bytes),
                human_bytes(report.review_bytes),
                report
                    .candidates
                    .iter()
                    .filter(|candidate| candidate.risk == blue_cleanup::CleanupRisk::Protected)
                    .count(),
                if report.truncated { " (truncated)" } else { "" }
            );
            for candidate in &report.candidates {
                println!(
                    "{:<9} {:>10}  {}{}",
                    format!("{:?}", candidate.risk).to_lowercase(),
                    if candidate.risk == blue_cleanup::CleanupRisk::Protected
                        && candidate.bytes == 0
                    {
                        "not sized".to_owned()
                    } else {
                        human_bytes(candidate.bytes)
                    },
                    candidate.label,
                    if candidate.supported {
                        ""
                    } else {
                        " [list-only]"
                    }
                );
                println!("           id={} · {}", candidate.id, candidate.reason);
                if let Some(path) = &candidate.path {
                    println!("           {}", path.display());
                }
            }
            if !report.diagnostics.is_empty() {
                println!("diagnostics:");
                for diagnostic in &report.diagnostics {
                    println!("  - {diagnostic}");
                }
            }
            println!("Nothing selected. Use candidate IDs with `blue cleanup apply` after review.");
        }
        CleanupCmd::Apply { ids, confirm } => {
            let report = engine.apply(&ids, &confirm)?;
            for receipt in &report.receipts {
                println!(
                    "{}  {} ({}){}",
                    if receipt.success { "removed" } else { "failed" },
                    receipt.label,
                    human_bytes(receipt.bytes_before),
                    receipt
                        .error
                        .as_ref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                );
            }
            println!(
                "estimated reclaimed: {}",
                human_bytes(report.reclaimed_estimate)
            );
        }
        CleanupCmd::Phrase { ids } => {
            let report = engine.scan()?;
            let mut selected = Vec::new();
            for id in &ids {
                let candidate = report
                    .candidates
                    .iter()
                    .find(|candidate| &candidate.id == id)
                    .with_context(|| format!("unknown or stale cleanup candidate ID: {id}"))?;
                if !candidate.supported
                    || candidate.requires_root
                    || candidate.risk == blue_cleanup::CleanupRisk::Protected
                {
                    bail!("candidate {id} is list-only, protected, or requires root");
                }
                selected.push(candidate.clone());
            }
            println!(
                "{}",
                blue_cleanup::CleanupEngine::required_confirmation(&selected)
            );
        }
        CleanupCmd::Performance => {
            let snapshot = blue_cleanup::performance_snapshot()?;
            println!(
                "memory: {} available / {} total; swap: {} free / {} total; {} processes",
                human_bytes(snapshot.memory_available_bytes),
                human_bytes(snapshot.memory_total_bytes),
                human_bytes(snapshot.swap_free_bytes),
                human_bytes(snapshot.swap_total_bytes),
                snapshot.process_count
            );
            for process in snapshot.top_memory {
                println!(
                    "{:>7}  {:>9}  {}",
                    process.pid,
                    human_bytes(process.rss_bytes),
                    process.name
                );
            }
        }
    }
    Ok(())
}

/// The one test that proves the wiring. Not a demo: it asserts and exits non-zero.
fn cmd_drill(ctx: &Ctx) -> Result<()> {
    let engine = ctx.engine()?;
    let dir = ctx.cfg.state_dir().join("drill");
    std::fs::create_dir_all(&dir)?;
    let victim = dir.join("eicar-test-file.txt");
    std::fs::write(&victim, EICAR)?;

    let out = engine.scan_path(&victim)?;
    if out.tier < Tier::Corroborated {
        bail!(
            "drill FAILED: EICAR only reached {}; the pipeline is not detecting",
            out.tier.label()
        );
    }
    println!("[1/5] detected as {}", out.tier.label());

    if victim.exists() {
        bail!("drill FAILED: file still present after a quarantining verdict");
    }
    println!("[2/5] moved out of {}", victim.display());

    let qid = out
        .quarantined
        .context("drill FAILED: verdict allowed quarantine but nothing was quarantined")?;
    let listed = ctx.quarantine.list(false)?;
    if !listed.iter().any(|q| q.id == qid) {
        bail!("drill FAILED: quarantine record {qid} missing");
    }
    println!("[3/5] recorded as quarantine item {qid}");

    let back = ctx.quarantine.restore(qid)?;
    let restored = std::fs::read(&back)?;
    if restored != EICAR {
        bail!("drill FAILED: restored bytes differ from the original");
    }
    println!("[4/5] restored byte-identical to {}", back.display());

    // Clean up our own harmless test artifact. This is the only delete in the
    // suite, it is confined to the drill, and it only ever touches EICAR.
    std::fs::remove_file(&back)?; // allowed-delete: drill artifact only
    println!("[5/5] cleaned up test artifact");
    println!("drill PASSED");
    Ok(())
}

fn cmd_verify(ctx: &Ctx) -> Result<()> {
    println!("state dir : {}", ctx.cfg.state_dir().display());
    println!("database  : {}", ctx.cfg.db_path().display());
    let mut ok = true;

    match ctx.db.recent_events(1) {
        Ok(_) => println!("database  : OK"),
        Err(e) => {
            println!("database  : FAIL ({e:#})");
            ok = false;
        }
    }

    match ctx.engine() {
        Ok(engine) => {
            match engine.degraded() {
                Some(r) => println!("clamav    : DEGRADED ({r})"),
                None => println!("clamav    : OK"),
            }
            println!("rules     : OK ({} files)", count_rules(&ctx.cfg)?);
        }
        Err(e) => {
            println!("engine    : FAIL ({e:#})");
            ok = false;
        }
    }

    let lists = blue_core::config::expand_tilde(&ctx.cfg.feeds.lists_dir);
    if lists.exists() {
        let mut b = blue_dns::Blocklist::new();
        let n = b.load_dir(&lists)?;
        println!("dns lists : OK ({n} entries)");
    } else {
        println!("dns lists : none at {}", lists.display());
    }

    match blue_reputation::ReputationEngine::new(
        ctx.db.clone(),
        blue_reputation::ReputationConfig::from_config(&ctx.cfg),
    ) {
        Ok(engine) => {
            let status = engine.status();
            println!(
                "hash IOCs : OK ({} hashes, {} sources)",
                status.local_hashes, status.local_sources
            );
        }
        Err(error) => {
            println!("hash IOCs : DEGRADED ({error:#})");
            ok = false;
        }
    }

    println!(
        "network   : {}",
        if ctx.db.get_meta("net:remote-baseline")?.is_some() {
            "baseline present"
        } else {
            "no baseline (run `blue network`)"
        }
    );

    for upstream in &ctx.cfg.dns.upstreams {
        if let Err(error) = upstream.parse::<blue_dns::DnsUpstream>() {
            println!("dns config : FAIL ({upstream}: {error})");
            ok = false;
        }
    }

    if ok {
        println!("verify OK");
        Ok(())
    } else {
        bail!("verify found problems")
    }
}

fn count_rules(cfg: &Config) -> Result<usize> {
    let mut n = 0;
    for d in &cfg.scan.yara.rule_dirs {
        let dir = blue_core::config::expand_tilde(d);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            n += rd
                .flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|x| x == "yar" || x == "yara")
                        .unwrap_or(false)
                })
                .count();
        }
    }
    Ok(n)
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            collect_files(&entry.path(), out)?;
        }
    }
    Ok(())
}

fn short_hash(h: &str) -> &str {
    h.get(..12).unwrap_or(h)
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn init_tracing(level: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod firewall_cli_tests {
    use super::*;

    #[test]
    fn applying_requires_a_confirmation_argument() {
        assert!(Cli::try_parse_from(["blue", "firewall", "apply", "--profile", "public"]).is_err());
    }

    #[test]
    fn confirmation_is_exact_and_profiles_are_bounded() {
        assert!(require_firewall_confirmation("APPLY FIREWALL", "APPLY FIREWALL").is_ok());
        assert!(require_firewall_confirmation("apply firewall", "APPLY FIREWALL").is_err());
        assert!(parse_firewall_profile("public").is_ok());
        assert!(parse_firewall_profile("private").is_ok());
        assert!(parse_firewall_profile("public; flush ruleset").is_err());
    }
}
