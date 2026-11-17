//! # Redaction (spec v0.2 §4.4)
//!
//! Runs before bytes are persisted or sent to a subscriber. Sources: exact values
//! known to the broker/scrubber, a versioned token-pattern set, and policy patterns.
//! A redacted span becomes `[redacted:<kind>]`; only count and kind are kept.
//! Best effort: encoded secrets can slip through.

use std::collections::BTreeMap;

pub const PATTERN_SET_VERSION: u32 = 1;

/// (kind, prefix, minimum total token length)
const TOKEN_PATTERNS: &[(&str, &str, usize)] = &[
    ("github-token", "ghp_", 20),
    ("github-token", "gho_", 20),
    ("github-token", "github_pat_", 30),
    ("aws-access-key", "AKIA", 20),
    ("slack-token", "xoxb-", 15),
    ("slack-token", "xoxp-", 15),
    ("api-key", "sk-", 20),
    ("google-api-key", "AIza", 30),
];

#[derive(Debug, Default, Clone)]
pub struct Redactor {
    exact: Vec<String>,
    custom_prefixes: Vec<(String, String, usize)>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RedactionReport {
    /// kind -> count (never the value or a hash of it)
    pub counts: BTreeMap<String, u64>,
}

impl RedactionReport {
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an exact secret value (credential broker / env scrubber).
    pub fn add_exact(&mut self, value: &str) {
        if value.len() >= 4 {
            self.exact.push(value.to_string());
        }
    }

    /// Policy-defined pattern: token starting with `prefix`, at least `min_len` long.
    pub fn add_pattern(&mut self, kind: &str, prefix: &str, min_len: usize) {
        self.custom_prefixes.push((kind.into(), prefix.into(), min_len));
    }

    pub fn redact(&self, input: &str) -> (String, RedactionReport) {
        let mut report = RedactionReport::default();
        let mut text = input.to_string();

        // Exact values first (longest first so superstrings win).
        let mut exact = self.exact.clone();
        exact.sort_by_key(|v| std::cmp::Reverse(v.len()));
        for v in &exact {
            let n = text.matches(v.as_str()).count();
            if n > 0 {
                text = text.replace(v.as_str(), "[redacted:secret]");
                *report.counts.entry("secret".into()).or_default() += n as u64;
            }
        }

        // Token patterns, scanning word-ish tokens.
        let mut out = String::with_capacity(text.len());
        let mut tok = String::new();
        let flush = |tok: &mut String, out: &mut String, report: &mut RedactionReport| {
            if tok.is_empty() {
                return;
            }
            let mut replaced = false;
            let all = TOKEN_PATTERNS
                .iter()
                .map(|(k, p, m)| (k.to_string(), p.to_string(), *m))
                .chain(self.custom_prefixes.iter().cloned());
            for (kind, prefix, min) in all {
                if tok.starts_with(&prefix) && tok.len() >= min {
                    out.push_str(&format!("[redacted:{}]", kind));
                    *report.counts.entry(kind).or_default() += 1;
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                out.push_str(tok);
            }
            tok.clear();
        };
        for ch in text.chars() {
            if ch.is_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                tok.push(ch);
            } else {
                flush(&mut tok, &mut out, &mut report);
                out.push(ch);
            }
        }
        flush(&mut tok, &mut out, &mut report);
        (out, report)
    }

    /// Redact raw output bytes (lossy on invalid UTF-8 only when a hit occurs).
    pub fn redact_bytes(&self, bytes: &[u8]) -> (Vec<u8>, RedactionReport) {
        match std::str::from_utf8(bytes) {
            Ok(s) => {
                let (o, r) = self.redact(s);
                (o.into_bytes(), r)
            }
            Err(_) => {
                let s = String::from_utf8_lossy(bytes);
                let (o, r) = self.redact(&s);
                if r.total() == 0 {
                    (bytes.to_vec(), r)
                } else {
                    (o.into_bytes(), r)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_value_redacted_without_trace() {
        let mut r = Redactor::new();
        r.add_exact("hunter2-super");
        let (o, rep) = r.redact("pass=hunter2-super done");
        assert_eq!(o, "pass=[redacted:secret] done");
        assert!(!o.contains("hunter2"));
        assert_eq!(rep.counts["secret"], 1);
    }

    #[test]
    fn token_patterns_redacted() {
        let r = Redactor::new();
        let (o, rep) = r.redact("token ghp_abcdefghijklmnopqrstuvwxyz0123 and AKIAABCDEFGHIJKLMNOP");
        assert!(o.contains("[redacted:github-token]"));
        assert!(o.contains("[redacted:aws-access-key]"));
        assert_eq!(rep.total(), 2);
    }

    #[test]
    fn policy_pattern_and_clean_text() {
        let mut r = Redactor::new();
        r.add_pattern("corp", "corp_", 8);
        let (o, _) = r.redact("corp_12345678 plain text ghp_short");
        assert_eq!(o, "[redacted:corp] plain text ghp_short");
    }
}
