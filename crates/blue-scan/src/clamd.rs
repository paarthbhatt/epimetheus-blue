//! clamd client over its Unix socket.
//!
//! Uses the documented INSTREAM command: `zINSTREAM\0`, then length-prefixed
//! chunks, then a zero length. No `clamscan` process per file.

use blue_core::{Confidence, Detector, DetectorResult};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const PING_TIMEOUT: Duration = Duration::from_secs(2);
const CHUNK_SIZE: usize = 64 * 1024;

fn connect(socket: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Read a NUL-terminated clamd reply.
fn read_reply(stream: &mut UnixStream) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.contains(&0) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(String::from_utf8_lossy(&bytes)
        .trim_matches('\0')
        .trim()
        .to_string())
}

/// `true` only when clamd answers `PONG`.
pub fn clamd_ping(socket: &Path) -> bool {
    let reply = connect(socket, PING_TIMEOUT).and_then(|mut stream| {
        stream.write_all(b"zPING\0")?;
        stream.flush()?;
        read_reply(&mut stream)
    });
    matches!(reply, Ok(text) if text == "PONG")
}

/// Scan one file with clamd INSTREAM.
///
/// `None` means clean *or* clamd unavailable; the caller already knows whether
/// the socket is configured. Transport errors are logged at debug level because
/// a missing clamd is a degraded mode, not a scan failure.
pub fn clamd_scan(socket: &Path, path: &Path, timeout: Duration) -> Option<DetectorResult> {
    match scan_inner(socket, path, timeout) {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!(
                socket = %socket.display(),
                path = %path.display(),
                error = %e,
                "clamd scan unavailable"
            );
            None
        }
    }
}

fn scan_inner(
    socket: &Path,
    path: &Path,
    timeout: Duration,
) -> std::io::Result<Option<DetectorResult>> {
    let mut file = std::fs::File::open(path)?;
    let mut stream = connect(socket, timeout)?;

    stream.write_all(b"zINSTREAM\0")?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let len = u32::try_from(n)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk too large"))?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(&buf[..n])?;
    }
    stream.write_all(&0u32.to_be_bytes())?;
    stream.flush()?;

    let reply = read_reply(&mut stream)?;
    Ok(parse_reply(&reply))
}

fn parse_reply(reply: &str) -> Option<DetectorResult> {
    if reply.eq_ignore_ascii_case("stream: OK") {
        return None;
    }
    if let Some(name) = reply
        .strip_prefix("stream: ")
        .and_then(|rest| rest.strip_suffix(" FOUND"))
    {
        let name = name.trim();
        if !name.is_empty() {
            return Some(
                DetectorResult::new(Detector::ClamAv, name, Confidence::High)
                    .with_detail("clamd INSTREAM"),
            );
        }
    }
    tracing::warn!(reply = %reply, "unexpected clamd reply");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_reply_is_none() {
        assert!(parse_reply("stream: OK").is_none());
    }

    #[test]
    fn found_reply_names_the_signature() {
        let hit = parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND").expect("finding");
        assert_eq!(hit.detector, Detector::ClamAv);
        assert_eq!(hit.signature.as_deref(), Some("Win.Test.EICAR_HDB-1"));
    }

    #[test]
    fn error_reply_is_none() {
        assert!(parse_reply("INSTREAM size limit exceeded. ERROR").is_none());
    }

    #[test]
    fn missing_socket_is_not_a_panic() {
        assert!(!clamd_ping(Path::new("/definitely/not/a/clamd.sock")));
    }
}
