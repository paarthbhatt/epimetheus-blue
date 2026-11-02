//! Chromium Native Messaging bridge for the Epimetheus Blue browser extension.
//!
//! Standard output is reserved exclusively for framed protocol messages. This
//! crate deliberately does not initialize a logger or print diagnostics.

use anyhow::{bail, Context, Result};
use blue_core::{Config, Db};
use blue_dns::Blocklist;
use serde_json::{json, Map, Value};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;

/// Chromium Native Messaging payload limit used for requests and responses.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Serve Native Messaging requests on this process's standard input/output.
///
/// Callers must not configure a logger that writes to stdout: Chromium expects
/// every stdout byte to belong to the framing protocol.
pub fn run(config: &Config, db: Arc<Db>) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve(config, db, stdin.lock(), stdout.lock())
}

/// Serve framed requests from any reader and write framed responses.
///
/// Keeping the transport generic makes framing and request handling testable
/// without replacing process-global stdin/stdout. The blocklist is loaded once
/// here and reused for every request handled by this host process.
pub fn serve<R: Read, W: Write>(
    config: &Config,
    db: Arc<Db>,
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    let mut blocklist = BlocklistCache::default();

    loop {
        let Some(length) = read_length(&mut reader)? else {
            return Ok(());
        };
        if length > MAX_MESSAGE_SIZE {
            bail!("native request is {length} bytes; maximum is {MAX_MESSAGE_SIZE} bytes");
        }

        let mut payload = vec![0_u8; length];
        reader
            .read_exact(&mut payload)
            .context("reading native request payload")?;

        let response = match serde_json::from_slice::<Value>(&payload) {
            Ok(request) => handle_request(request, config, &db, &mut blocklist),
            Err(error) => error_response(Value::Null, format!("invalid JSON request: {error}")),
        };
        write_response(&mut writer, response)?;
    }
}

fn read_length<R: Read>(reader: &mut R) -> Result<Option<usize>> {
    let mut header = [0_u8; 4];
    let mut offset = 0;

    while offset < header.len() {
        match reader.read(&mut header[offset..]) {
            Ok(0) if offset == 0 => return Ok(None),
            Ok(0) => bail!("truncated native request length prefix"),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("reading native request length prefix"),
        }
    }

    Ok(Some(u32::from_le_bytes(header) as usize))
}

fn write_response<W: Write>(writer: &mut W, response: Value) -> Result<()> {
    let id = response.get("id").cloned().unwrap_or(Value::Null);
    let mut payload = serde_json::to_vec(&response).context("serializing native response")?;

    if payload.len() > MAX_MESSAGE_SIZE {
        payload = serde_json::to_vec(&error_response(
            id,
            format!("native response exceeds {MAX_MESSAGE_SIZE} byte limit"),
        ))
        .context("serializing oversized-response error")?;
    }
    if payload.len() > MAX_MESSAGE_SIZE {
        bail!("native response and its error envelope both exceed the size limit");
    }

    let length = u32::try_from(payload.len()).context("native response length overflow")?;
    writer
        .write_all(&length.to_le_bytes())
        .context("writing native response length prefix")?;
    writer
        .write_all(&payload)
        .context("writing native response payload")?;
    writer.flush().context("flushing native response")?;
    Ok(())
}

fn handle_request(
    request: Value,
    config: &Config,
    db: &Db,
    blocklist: &mut BlocklistCache,
) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    match dispatch(&request, config, db, blocklist) {
        Ok(payload) => success_response(id, payload),
        Err(error) => error_response(id, format!("{error:#}")),
    }
}

fn dispatch(
    request: &Value,
    config: &Config,
    db: &Db,
    blocklist: &mut BlocklistCache,
) -> Result<Value> {
    let object = request
        .as_object()
        .context("request must be a JSON object")?;
    let message_type = object
        .get("type")
        .and_then(Value::as_str)
        .context("request.type must be a string")?;

    match message_type {
        "status" => Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "connected": true,
            "kill_switch": db.kill_switch(),
            "counts": db.counts().context("reading database counts")?,
            "active_feeds": active_feed_names(config)?,
        })),
        "check_domains" => check_domains(object, blocklist.get(config)?),
        "recent_findings" => recent_findings(object, db),
        other => bail!("unsupported request type {other:?}"),
    }
}

fn check_domains(object: &Map<String, Value>, blocklist: &Blocklist) -> Result<Value> {
    let domains = object
        .get("domains")
        .and_then(Value::as_array)
        .context("check_domains.domains must be an array")?;
    if domains.len() > 500 {
        bail!("check_domains accepts at most 500 domains");
    }

    let mut results = Map::new();
    for value in domains {
        let raw = value
            .as_str()
            .context("every check_domains entry must be a string")?;
        let domain = normalize_hostname(raw)?;
        let list = blocklist.is_blocked(&domain);
        let mut verdict = Map::new();
        verdict.insert("blocked".into(), Value::Bool(list.is_some()));
        if let Some(name) = list {
            verdict.insert("list".into(), Value::String(name.to_owned()));
        }
        results.insert(domain, Value::Object(verdict));
    }

    Ok(json!({ "domains": results }))
}

fn recent_findings(object: &Map<String, Value>, db: &Db) -> Result<Value> {
    let requested = object
        .get("limit")
        .context("recent_findings.limit is required")?;
    let limit = if let Some(value) = requested.as_i64() {
        value.clamp(1, 100) as usize
    } else if let Some(value) = requested.as_u64() {
        value.clamp(1, 100) as usize
    } else {
        bail!("recent_findings.limit must be an integer");
    };
    let findings = db
        .list_findings(limit, true)
        .context("reading recent findings")?;
    Ok(json!({ "findings": findings }))
}

fn success_response(id: Value, payload: Value) -> Value {
    let mut response = Map::new();
    response.insert("id".into(), id);
    response.insert("ok".into(), Value::Bool(true));
    if let Value::Object(fields) = payload {
        response.extend(fields);
    }
    Value::Object(response)
}

fn error_response(id: Value, error: impl Into<String>) -> Value {
    json!({
        "id": id,
        "ok": false,
        "error": error.into(),
    })
}

fn load_blocklist(config: &Config) -> Result<Blocklist> {
    let directory = blue_core::config::expand_tilde(&config.feeds.lists_dir);
    let mut blocklist = Blocklist::new();
    if directory.exists() {
        blocklist
            .load_dir(&directory)
            .with_context(|| format!("loading feed lists from {}", directory.display()))?;
    }
    Ok(blocklist)
}

/// Lazy so status/findings requests do not parse a large feed unnecessarily;
/// both a successful load and a load error are cached for this process.
#[derive(Default)]
struct BlocklistCache {
    loaded: Option<std::result::Result<Blocklist, String>>,
}

impl BlocklistCache {
    fn get(&mut self, config: &Config) -> Result<&Blocklist> {
        if self.loaded.is_none() {
            self.loaded = Some(load_blocklist(config).map_err(|error| format!("{error:#}")));
        }
        match self.loaded.as_ref().expect("blocklist cache initialized") {
            Ok(blocklist) => Ok(blocklist),
            Err(error) => bail!("{error}"),
        }
    }
}

fn active_feed_names(config: &Config) -> Result<Vec<String>> {
    let directory = blue_core::config::expand_tilde(&config.feeds.lists_dir);
    if !directory.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in std::fs::read_dir(&directory)
        .with_context(|| format!("reading feed directory {}", directory.display()))?
    {
        let path = entry
            .with_context(|| format!("reading feed directory {}", directory.display()))?
            .path();
        if path.is_file() && is_feed_file(&path) {
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .with_context(|| format!("non-UTF-8 feed filename {}", path.display()))?;
            names.push(name.to_owned());
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn is_feed_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("txt") || extension.eq_ignore_ascii_case("list")
        })
}

fn normalize_hostname(raw: &str) -> Result<String> {
    if raw.is_empty() || raw != raw.trim() {
        bail!("invalid hostname {raw:?}");
    }
    let hostname = raw.strip_suffix('.').unwrap_or(raw);
    if hostname.is_empty() || hostname.len() > 253 || !hostname.is_ascii() {
        bail!("invalid hostname {raw:?}");
    }

    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid hostname {raw:?}");
        }
    }
    Ok(hostname.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blue_core::Tier;
    use std::io::Cursor;

    fn config_for(directory: &Path) -> Config {
        let mut config = Config::default();
        config.feeds.lists_dir = directory.to_string_lossy().into_owned();
        config
    }

    fn framed(value: Value) -> Vec<u8> {
        let payload = serde_json::to_vec(&value).unwrap();
        let mut bytes = Vec::with_capacity(payload.len() + 4);
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn responses(bytes: &[u8]) -> Vec<Value> {
        let mut reader = Cursor::new(bytes);
        let mut output = Vec::new();
        while let Some(length) = read_length(&mut reader).unwrap() {
            let mut payload = vec![0_u8; length];
            reader.read_exact(&mut payload).unwrap();
            output.push(serde_json::from_slice(&payload).unwrap());
        }
        output
    }

    #[test]
    fn serves_multiple_frames_and_keeps_bad_requests_in_protocol() {
        let directory = tempfile::TempDir::new().unwrap();
        let config = config_for(directory.path());
        let db = Arc::new(Db::open_memory().unwrap());
        let mut input = framed(json!({"id": 1, "type": "status"}));
        input.extend(framed(json!({"id": "bad", "type": "write_files"})));
        input.extend(framed(
            json!({"id": 3, "type": "recent_findings", "limit": 5}),
        ));
        let mut output = Vec::new();

        serve(&config, db, Cursor::new(input), &mut output).unwrap();

        let decoded = responses(&output);
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0]["id"], 1);
        assert_eq!(decoded[0]["ok"], true);
        assert_eq!(decoded[1]["id"], "bad");
        assert_eq!(decoded[1]["ok"], false);
        assert!(decoded[1]["error"]
            .as_str()
            .unwrap()
            .contains("unsupported request type"));
        assert_eq!(decoded[2]["findings"], json!([]));
    }

    #[test]
    fn rejects_truncated_and_oversized_frames() {
        let directory = tempfile::TempDir::new().unwrap();
        let config = config_for(directory.path());

        let error = serve(
            &config,
            Arc::new(Db::open_memory().unwrap()),
            Cursor::new(vec![1, 2]),
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("truncated"));

        let mut truncated_payload = 8_u32.to_le_bytes().to_vec();
        truncated_payload.extend_from_slice(b"{}");
        assert!(serve(
            &config,
            Arc::new(Db::open_memory().unwrap()),
            Cursor::new(truncated_payload),
            Vec::new(),
        )
        .is_err());

        let oversized = ((MAX_MESSAGE_SIZE + 1) as u32).to_le_bytes();
        let error = serve(
            &config,
            Arc::new(Db::open_memory().unwrap()),
            Cursor::new(oversized),
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("maximum"));
    }

    #[test]
    fn status_reports_database_counts_and_active_feeds() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::write(directory.path().join("ads.txt"), "ads.example.com\n").unwrap();
        std::fs::write(directory.path().join("malware.list"), "evil.example\n").unwrap();
        std::fs::write(directory.path().join("notes.md"), "ignored.example\n").unwrap();
        let config = config_for(directory.path());
        let db = Arc::new(Db::open_memory().unwrap());
        db.record_artifact("/tmp/sample", "abc", 3, 1, 2).unwrap();
        db.add_finding("integrity", Tier::Candidate, "/tmp/sample", "changed", 3)
            .unwrap();
        db.set_kill_switch(true).unwrap();
        let mut output = Vec::new();

        serve(
            &config,
            db,
            Cursor::new(framed(json!({"id": "status-1", "type": "status"}))),
            &mut output,
        )
        .unwrap();

        let status = responses(&output).pop().unwrap();
        assert_eq!(status["id"], "status-1");
        assert_eq!(status["connected"], true);
        assert_eq!(status["kill_switch"], true);
        assert_eq!(status["counts"]["artifacts"], 1);
        assert_eq!(status["counts"]["findings"], 1);
        assert_eq!(status["active_feeds"], json!(["ads", "malware"]));
    }

    #[test]
    fn domain_checks_use_dns_suffix_semantics_and_attribution() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::write(directory.path().join("ads.txt"), "ads.example.com\n").unwrap();
        let config = config_for(directory.path());
        let request = json!({
            "id": 7,
            "type": "check_domains",
            "domains": ["ADS.Example.COM", "x.ads.example.com", "notads.example.com"]
        });
        let mut output = Vec::new();

        serve(
            &config,
            Arc::new(Db::open_memory().unwrap()),
            Cursor::new(framed(request)),
            &mut output,
        )
        .unwrap();

        let response = responses(&output).pop().unwrap();
        assert_eq!(response["domains"]["ads.example.com"]["blocked"], true);
        assert_eq!(response["domains"]["ads.example.com"]["list"], "ads");
        assert_eq!(response["domains"]["x.ads.example.com"]["blocked"], true);
        assert_eq!(
            response["domains"]["notads.example.com"],
            json!({"blocked": false})
        );
    }

    #[test]
    fn invalid_domain_returns_an_error_and_next_frame_is_processed() {
        let directory = tempfile::TempDir::new().unwrap();
        let config = config_for(directory.path());
        let mut input = framed(json!({
            "id": 1,
            "type": "check_domains",
            "domains": ["https://example.com/path"]
        }));
        input.extend(framed(json!({"id": 2, "type": "status"})));
        let mut output = Vec::new();

        serve(
            &config,
            Arc::new(Db::open_memory().unwrap()),
            Cursor::new(input),
            &mut output,
        )
        .unwrap();

        let decoded = responses(&output);
        assert_eq!(decoded[0]["ok"], false);
        assert_eq!(decoded[1]["id"], 2);
        assert_eq!(decoded[1]["ok"], true);
    }

    #[test]
    fn recent_findings_limit_is_clamped() {
        let directory = tempfile::TempDir::new().unwrap();
        let config = config_for(directory.path());
        let db = Arc::new(Db::open_memory().unwrap());
        for index in 0..3 {
            db.add_finding(
                "integrity",
                Tier::Observed,
                &format!("subject-{index}"),
                "changed",
                index,
            )
            .unwrap();
        }
        let mut input = framed(json!({
            "id": "low",
            "type": "recent_findings",
            "limit": 0
        }));
        input.extend(framed(json!({
            "id": "high",
            "type": "recent_findings",
            "limit": 1000
        })));
        let mut output = Vec::new();

        serve(&config, db, Cursor::new(input), &mut output).unwrap();

        let decoded = responses(&output);
        assert_eq!(decoded[0]["findings"].as_array().unwrap().len(), 1);
        assert_eq!(decoded[1]["findings"].as_array().unwrap().len(), 3);
    }
}
