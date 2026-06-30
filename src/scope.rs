//! Proxy scope filtering for Cogitator.
//!
//! A `Scope` is an ordered list of regex rules, each either an "include" or
//! an "exclude" rule. `Scope::in_scope` decides whether a given URL should be
//! recorded/analyzed by the proxy, or silently auto-forwarded:
//!
//!   * If the URL matches **any** exclude rule → out of scope.
//!   * Else, if there are **no** include rules at all → in scope (an empty
//!     include list means "everything not explicitly excluded is in scope").
//!   * Else, the URL must match **at least one** include rule to be in scope.
//!
//! Rules are persisted as newline-delimited JSON (one `{"pattern":...,
//! "include":...}` object per line) via `load_from_file` / `save_to_file`.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

/// On-disk representation of a single rule (NDJSON line). `Regex` itself
/// isn't `Serialize`/`Deserialize`, so this mirrors `ScopeRule` using the
/// raw pattern string instead of the compiled `Regex`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScopeRuleRecord {
    pattern: String,
    include: bool,
}

/// A single compiled scope rule.
pub struct ScopeRule {
    pub pattern: Regex,
    pub include: bool,
}

/// Ordered collection of scope rules. See module docs for matching semantics.
pub struct Scope(pub Vec<ScopeRule>);

impl Scope {
    pub fn new() -> Self {
        Scope(Vec::new())
    }

    /// Add an include rule. `pattern` must be a valid regex.
    pub fn add_include(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let compiled = Regex::new(pattern)?;
        self.0.push(ScopeRule { pattern: compiled, include: true });
        Ok(())
    }

    /// Add an exclude rule. `pattern` must be a valid regex.
    pub fn add_exclude(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let compiled = Regex::new(pattern)?;
        self.0.push(ScopeRule { pattern: compiled, include: false });
        Ok(())
    }

    /// Remove every rule.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// `true` if no rules are configured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `(pattern_str, include)` for every configured rule, in insertion
    /// order — for the TUI's `Scope-List` command.
    pub fn list(&self) -> Vec<(String, bool)> {
        self.0
            .iter()
            .map(|r| (r.pattern.as_str().to_string(), r.include))
            .collect()
    }

    /// Decide whether `url` is in scope.
    ///
    /// Returns `true` iff `url` matches at least one include rule AND zero
    /// exclude rules. An empty include list is treated as "all in scope"
    /// (subject still to exclude rules).
    pub fn in_scope(&self, url: &str) -> bool {
        let mut has_include_rule = false;
        let mut matched_include = false;

        for rule in &self.0 {
            if rule.include {
                has_include_rule = true;
                if rule.pattern.is_match(url) {
                    matched_include = true;
                }
            } else if rule.pattern.is_match(url) {
                // Any exclude match disqualifies the URL outright.
                return false;
            }
        }

        if !has_include_rule {
            true
        } else {
            matched_include
        }
    }

    /// Load rules from a newline-delimited JSON file, replacing any rules
    /// currently held. Blank lines are skipped.
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut loaded = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record: ScopeRuleRecord = serde_json::from_str(line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let compiled = Regex::new(&record.pattern)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            loaded.push(ScopeRule { pattern: compiled, include: record.include });
        }

        self.0 = loaded;
        Ok(())
    }

    /// Save current rules as newline-delimited JSON, overwriting `path`.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = File::create(path)?;
        for rule in &self.0 {
            let record = ScopeRuleRecord {
                pattern: rule.pattern.as_str().to_string(),
                include: rule.include,
            };
            let line = serde_json::to_string(&record)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            writeln!(file, "{}", line)?;
        }
        Ok(())
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_is_all_in_scope() {
        let scope = Scope::new();
        assert!(scope.in_scope("http://example.com/anything"));
    }

    #[test]
    fn include_rule_restricts_to_matches() {
        let mut scope = Scope::new();
        scope.add_include(r"example\.com").unwrap();
        assert!(scope.in_scope("http://example.com/path"));
        assert!(!scope.in_scope("http://other.org/path"));
    }

    #[test]
    fn exclude_rule_overrides_include() {
        let mut scope = Scope::new();
        scope.add_include(r"example\.com").unwrap();
        scope.add_exclude(r"example\.com/private").unwrap();
        assert!(scope.in_scope("http://example.com/path"));
        assert!(!scope.in_scope("http://example.com/private/data"));
    }

    #[test]
    fn exclude_only_excludes_matches_rest_in_scope() {
        let mut scope = Scope::new();
        scope.add_exclude(r"ads\.").unwrap();
        assert!(scope.in_scope("http://example.com/path"));
        assert!(!scope.in_scope("http://ads.example.com/track"));
    }

    #[test]
    fn invalid_regex_returns_err() {
        let mut scope = Scope::new();
        assert!(scope.add_include("(unclosed").is_err());
    }

    #[test]
    fn clear_removes_all_rules() {
        let mut scope = Scope::new();
        scope.add_include(r"example\.com").unwrap();
        scope.clear();
        assert!(scope.is_empty());
        assert!(scope.in_scope("http://anything.tld/"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut scope = Scope::new();
        scope.add_include(r"example\.com").unwrap();
        scope.add_exclude(r"example\.com/private").unwrap();

        let tmp = std::env::temp_dir().join(format!(
            "cogitator_scope_test_{}.ndjson",
            std::process::id()
        ));
        scope.save_to_file(&tmp).unwrap();

        let mut loaded = Scope::new();
        loaded.load_from_file(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(loaded.list().len(), 2);
        assert!(loaded.in_scope("http://example.com/path"));
        assert!(!loaded.in_scope("http://example.com/private/data"));
    }

    #[test]
    fn list_reports_pattern_and_include_flag() {
        let mut scope = Scope::new();
        scope.add_include(r"foo").unwrap();
        scope.add_exclude(r"bar").unwrap();
        let listed = scope.list();
        assert_eq!(listed, vec![("foo".to_string(), true), ("bar".to_string(), false)]);
    }
}