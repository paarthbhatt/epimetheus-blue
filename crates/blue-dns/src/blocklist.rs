//! Suffix-based domain blocklist with per-list attribution.
//!
//! # Data structure
//!
//! Domains are stored **label-reversed** in a flat hash map:
//!
//! ```text
//! ads.example.com  ->  "com.example.ads"
//! ```
//!
//! A query `x.ads.example.com` is reversed the same way (`com.example.ads.x`)
//! and then probed at every label boundary, dropping the rightmost label each
//! time:
//!
//! ```text
//! com.example.ads.x   (x.ads.example.com)
//! com.example.ads     (ads.example.com)     <- hit
//! com.example         (example.com)
//! com                 (com)
//! ```
//!
//! Because both the stored keys and the probes are complete label sequences,
//! matching is exact-suffix: no substring, prefix, or partial-label matches are
//! possible. `ads.example.com` matches `x.ads.example.com` but never
//! `example.com` or `notads.example.com`.
//!
//! Reversing also means the walk narrows the key in place (`&str` slices), so a
//! lookup allocates only the one reversed query string and never any per-candidate
//! keys.
//!
//! The map value is an index into `names`, which gives first-list-wins
//! attribution without storing a list name per domain.
//!
//! Allowlisting uses the same reversed form in a separate set. It is consulted
//! before the block map, so an allow entry always wins regardless of list order.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    /// Reversed domain -> index into `names`.
    blocked: HashMap<Box<str>, usize>,
    /// List names, indexed by the map values above.
    names: Vec<Box<str>>,
    /// Reversed domains that are explicitly allowed.
    allowed: HashSet<Box<str>>,
}

impl Blocklist {
    pub fn new() -> Blocklist {
        Blocklist::default()
    }

    /// Parse `text` as a hosts file or a bare-domain list and add its entries
    /// under `name`.
    ///
    /// Returns the number of domains actually added. A domain already known
    /// from an earlier list is left attributed to that earlier list: first list
    /// wins.
    pub fn add_list(&mut self, name: &str, text: &str) -> usize {
        let index = match self.names.iter().position(|n| &**n == name) {
            Some(i) => i,
            None => {
                self.names.push(name.into());
                self.names.len() - 1
            }
        };

        let mut added = 0;
        for line in text.lines() {
            for domain in parse_line(line) {
                let key = reverse_labels(&domain).into_boxed_str();
                if let std::collections::hash_map::Entry::Vacant(slot) = self.blocked.entry(key) {
                    slot.insert(index);
                    added += 1;
                }
            }
        }
        added
    }

    /// Allow a domain: it and every subdomain of it will bypass every blocklist.
    ///
    /// Accepts the same syntax as [`Blocklist::add_list`] (`*.example.com`,
    /// `||example.com^`, a hosts line).
    pub fn allow(&mut self, pattern: &str) {
        for domain in parse_line(pattern) {
            self.allowed
                .insert(reverse_labels(&domain).into_boxed_str());
        }
    }

    /// Return the name of the list that blocks `qname`, if any.
    pub fn is_blocked(&self, qname: &str) -> Option<&str> {
        let rev = reverse_query(qname);
        if rev.is_empty() {
            return None;
        }

        // An allow entry anywhere on the suffix chain wins, even over a more
        // specific block entry.
        let mut probe = rev.as_str();
        loop {
            if self.allowed.contains(probe) {
                return None;
            }
            match probe.rfind('.') {
                Some(i) => probe = &probe[..i],
                None => break,
            }
        }

        let mut probe = rev.as_str();
        loop {
            if let Some(&index) = self.blocked.get(probe) {
                return self.names.get(index).map(|n| &**n);
            }
            let i = probe.rfind('.')?;
            probe = &probe[..i];
        }
    }

    /// Number of distinct blocked domains. Allowlist entries are not counted.
    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }

    /// Load every `*.txt` and `*.list` in `dir`, using the file stem as the list
    /// name. Files are read in sorted order so attribution is deterministic.
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("reading blocklist dir {}", dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("reading blocklist dir {}", dir.display()))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            if matches!(ext.as_deref(), Some("txt") | Some("list")) {
                files.push(path);
            }
        }
        files.sort();

        let mut added = 0;
        for path in files {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_owned)
                .with_context(|| format!("non-UTF-8 list filename {}", path.display()))?;
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading blocklist {}", path.display()))?;
            added += self.add_list(&name, &text);
        }
        Ok(added)
    }
}

/// Reverse the labels of a normalized domain: `a.b.c` -> `c.b.a`.
fn reverse_labels(domain: &str) -> String {
    let mut out = String::with_capacity(domain.len());
    for (i, label) in domain.rsplit('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(label);
    }
    out
}

/// Normalize a queried name into the same reversed form the map is keyed by.
fn reverse_query(qname: &str) -> String {
    let name = qname.trim();
    let name = name.strip_suffix('.').unwrap_or(name);
    let mut out = String::with_capacity(name.len());
    for (i, label) in name.rsplit('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        for c in label.chars() {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// Extract every domain on one input line.
///
/// Handles hosts-file lines (`0.0.0.0 a.example b.example`), bare domains,
/// `*.example.com`, and Adblock-style `||example.com^`. Comments (`#`, `!`) and
/// Adblock exception/cosmetic rules are dropped.
fn parse_line(line: &str) -> Vec<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return Vec::new();
    }
    // Exception rules: the allowlist is explicit, these are not block entries.
    if line.starts_with("@@") {
        return Vec::new();
    }
    // Cosmetic filters are not hostnames.
    if line.contains("##") || line.contains("#@#") || line.contains("#?#") {
        return Vec::new();
    }
    let line = match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    };

    let tokens: Vec<&str> = line.split_whitespace().collect();
    let rest = match tokens.first() {
        Some(first) if is_hosts_prefix(first) => &tokens[1..],
        _ => &tokens[..],
    };

    rest.iter()
        .filter_map(|token| normalize_domain(token))
        .collect()
}

/// Is this the address column of a hosts-file line?
fn is_hosts_prefix(token: &str) -> bool {
    token == "0" || token.parse::<IpAddr>().is_ok()
}

/// Reduce one token to a lowercase, validated domain name.
fn normalize_domain(raw: &str) -> Option<String> {
    let token = raw.trim();
    if token.is_empty() {
        return None;
    }

    // Adblock anchors: `||domain^`, `|domain|`.
    let token = token
        .strip_prefix("||")
        .or_else(|| token.strip_prefix('|'))
        .unwrap_or(token);

    // Rule modifiers, paths and option separators end the domain part.
    let end = token.find(['^', '$', '/', '|', '=']).unwrap_or(token.len());
    let token = token[..end].trim();

    // Optional wildcard or leading dot, then the trailing root dot.
    let token = token
        .strip_prefix("*.")
        .or_else(|| token.strip_prefix('.'))
        .unwrap_or(token);
    let token = token.trim_end_matches('.');

    if token.is_empty() || token.len() > 253 || token.contains('*') {
        return None;
    }

    let domain = token.to_ascii_lowercase();
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    Some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &str) -> Blocklist {
        let mut bl = Blocklist::new();
        bl.add_list("test", entries);
        bl
    }

    #[test]
    fn suffix_semantics_and_boundaries() {
        let bl = list("ads.example.com\n");
        assert_eq!(bl.is_blocked("ads.example.com"), Some("test"));
        assert_eq!(bl.is_blocked("x.ads.example.com"), Some("test"));
        assert_eq!(bl.is_blocked("a.b.ads.example.com"), Some("test"));
        assert_eq!(bl.is_blocked("ADS.Example.COM."), Some("test"));

        // Not blocked: parents and lookalikes.
        assert_eq!(bl.is_blocked("example.com"), None);
        assert_eq!(bl.is_blocked("notads.example.com"), None);
        assert_eq!(bl.is_blocked("ads.example.com.evil.net"), None);
    }

    #[test]
    fn blocking_a_parent_covers_children() {
        let bl = list("example.com");
        assert_eq!(bl.is_blocked("x.example.com"), Some("test"));
        assert_eq!(bl.is_blocked("example.com"), Some("test"));
        assert_eq!(bl.is_blocked("notexample.com"), None);
    }

    #[test]
    fn allowlist_wins_with_exact_and_suffix_semantics() {
        let mut bl = list("ads.example.com\ntracker.net");
        bl.allow("safe.ads.example.com");
        assert_eq!(bl.is_blocked("safe.ads.example.com"), None);
        assert_eq!(bl.is_blocked("x.safe.ads.example.com"), None);
        assert_eq!(bl.is_blocked("other.ads.example.com"), Some("test"));

        // Allowing a parent overrides a blocked child.
        bl.allow("tracker.net");
        assert_eq!(bl.is_blocked("tracker.net"), None);
        assert_eq!(bl.is_blocked("x.tracker.net"), None);
    }

    #[test]
    fn parses_hosts_format() {
        let bl = list(
            "# comment\n\
             127.0.0.1 localhost.localdomain localhost\n\
             0.0.0.0 ads.example.com tracker.net # inline\n\
             \n\
             ::1 v6.example.com\n",
        );
        assert_eq!(bl.len(), 5);
        assert_eq!(bl.is_blocked("x.ads.example.com"), Some("test"));
        assert_eq!(bl.is_blocked("sub.tracker.net"), Some("test"));
        assert_eq!(bl.is_blocked("v6.example.com"), Some("test"));
        assert_eq!(bl.is_blocked("localhost"), Some("test"));
        assert_eq!(bl.is_blocked("localhost.localdomain"), Some("test"));
    }

    #[test]
    fn parses_adblock_anchors() {
        let bl = list(
            "! adblock comment\n\
             ||ads.example.com^\n\
             ||tracker.net^$third-party\n\
             |plain.example.org|\n\
             *.wild.example.io\n\
             @@||safe.example.com^\n\
             example.com##.ad-banner\n",
        );
        assert_eq!(bl.len(), 4);
        assert_eq!(bl.is_blocked("img.ads.example.com"), Some("test"));
        assert_eq!(bl.is_blocked("tracker.net"), Some("test"));
        assert_eq!(bl.is_blocked("plain.example.org"), Some("test"));
        assert_eq!(bl.is_blocked("x.wild.example.io"), Some("test"));
        assert_eq!(bl.is_blocked("safe.example.com"), None);
        assert_eq!(bl.is_blocked("example.com"), None);
    }

    #[test]
    fn first_list_wins_attribution() {
        let mut bl = Blocklist::new();
        assert_eq!(bl.add_list("first", "ads.example.com\nshared.net\n"), 2);
        assert_eq!(bl.add_list("second", "ads.example.com\nother.org\n"), 1);
        assert_eq!(bl.is_blocked("x.ads.example.com"), Some("first"));
        assert_eq!(bl.is_blocked("shared.net"), Some("first"));
        assert_eq!(bl.is_blocked("other.org"), Some("second"));
        assert_eq!(bl.len(), 3);
    }

    #[test]
    fn load_dir_uses_file_stems_in_sorted_order() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("ads.txt"), "ads.example.com\n").unwrap();
        std::fs::write(dir.path().join("malware.list"), "evil.example.net\n").unwrap();
        std::fs::write(dir.path().join("ignore.md"), "not-a-list.example\n").unwrap();

        let mut bl = Blocklist::new();
        let added = bl.load_dir(dir.path()).unwrap();
        assert_eq!(added, 2);
        assert_eq!(bl.is_blocked("x.ads.example.com"), Some("ads"));
        assert_eq!(bl.is_blocked("evil.example.net"), Some("malware"));
        assert_eq!(bl.is_blocked("not-a-list.example"), None);
    }

    #[test]
    fn rejects_garbage_entries() {
        let bl = list(
            "http://not-a-domain/path\n\
             not_a_domain_without_dot_only\n\
             -\n\
             a..b.example.com\n\
             a*b.example.com\n",
        );
        // `not_a_domain_without_dot_only` is a syntactically valid single label.
        assert_eq!(bl.len(), 1);
        assert_eq!(bl.is_blocked("not_a_domain_without_dot_only"), Some("test"));
    }
}
