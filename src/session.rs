//! Session management: cookie jar + custom-header profiles for Repeater and
//! Intruder.
//!
//! # Overview
//!
//! [`CookieJar`] is a thread-safe, domain-keyed store of `Cookie:` header
//! strings.  Cookies are learned automatically from `Set-Cookie` response
//! headers and injected into outgoing `reqwest::RequestBuilder`s before
//! they are sent.
//!
//! A [`SessionProfile`] is a named snapshot of the jar plus any extra
//! request headers (e.g. a `Bearer` token in `Authorization:`).  Profiles
//! are persisted only in memory for the lifetime of the process — there is
//! no disk serialisation yet.
//!
//! # TUI commands (handled in `main.rs`)
//!
//! | Command | Effect |
//! |---------|--------|
//! | `Session-Save <name>` | Snapshot the current [`CookieJar`] into a named profile |
//! | `Session-Load <name>` | Restore a saved profile into the live jar |
//! | `Session-List`        | Show the names of all saved profiles |

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use reqwest::header::HeaderMap;
use reqwest::RequestBuilder;

// ─── SessionProfile ───────────────────────────────────────────────────────────

/// A named, immutable snapshot of session state that can be loaded into
/// [`CookieJar`] or passed directly to [`RepeaterEngine::send`] /
/// [`IntruderConfig`].
///
/// `custom_headers` is the primary hook for tokens that live outside the
/// cookie mechanism (e.g. `Authorization: Bearer <token>`).
#[derive(Debug, Clone, Default)]
pub struct SessionProfile {
    /// Human-readable label used by `Session-Save` / `Session-Load`.
    pub name: String,
    /// domain → cookie string (e.g. `"session=abc; csrf=xyz"`).
    pub cookies: HashMap<String, String>,
    /// Extra request headers injected verbatim before every send
    /// (e.g. `("Authorization", "Bearer eyJ…")`).
    pub custom_headers: Vec<(String, String)>,
}

// ─── CookieJar ────────────────────────────────────────────────────────────────

/// Thread-safe, domain-keyed cookie store.
///
/// Cloning a [`CookieJar`] is cheap — all clones share the same inner map
/// via `Arc<Mutex<…>>`.
#[derive(Clone, Default)]
pub struct CookieJar(Arc<Mutex<HashMap<String, String>>>);

impl CookieJar {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    // ── Cookie ingestion ──────────────────────────────────────────────────

    /// Parse `Set-Cookie` headers from `headers` and merge them into the
    /// per-`domain` cookie string.
    ///
    /// Each `Set-Cookie` value is expected to look like:
    /// ```text
    /// name=value; Path=/; HttpOnly; Secure
    /// ```
    /// Only the `name=value` pair (the first `;`-delimited token) is
    /// stored; attributes such as `Path`, `Secure`, and `HttpOnly` are
    /// acknowledged but not persisted — Cogitator is a MITM proxy tool,
    /// not a user-agent, so path/secure enforcement would just get in the
    /// way of manual request replay.
    ///
    /// Cookies with the same name arriving in later responses overwrite
    /// the previous value for that domain (last-writer-wins within a
    /// single response as well as across responses).
    pub fn update_from_response(&self, domain: &str, headers: &HeaderMap) {
        let new_cookies: Vec<String> = headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|raw| {
                // First token before `;` is `name=value`.
                raw.split(';').next().map(|kv| kv.trim().to_string())
            })
            .filter(|kv| !kv.is_empty())
            .collect();

        if new_cookies.is_empty() {
            return;
        }

        let mut jar = self.0.lock().unwrap();
        let entry = jar.entry(domain.to_string()).or_default();

        // Merge: split the existing cookie string into a `name → value`
        // map, overwrite/insert the new pairs, then rejoin.
        let mut existing: HashMap<String, String> = parse_cookie_pairs(entry);

        for kv in &new_cookies {
            if let Some((name, value)) = kv.split_once('=') {
                existing.insert(name.trim().to_string(), value.trim().to_string());
            } else {
                // A bare name with no `=` is unusual but valid (value = "").
                existing.insert(kv.trim().to_string(), String::new());
            }
        }

        *entry = serialise_cookie_map(&existing);
    }

    // ── Cookie injection ──────────────────────────────────────────────────

    /// Inject the stored cookie string for `domain` into `builder`, returning
    /// the (possibly-modified) builder.  If no cookies are stored for the
    /// domain the builder is returned unchanged.
    pub fn inject_into_request(&self, domain: &str, builder: RequestBuilder) -> RequestBuilder {
        let jar = self.0.lock().unwrap();
        if let Some(cookie_str) = jar.get(domain) {
            if !cookie_str.is_empty() {
                return builder.header("Cookie", cookie_str);
            }
        }
        builder
    }

    // ── Snapshot ──────────────────────────────────────────────────────────

    /// Return a [`SessionProfile`] whose `cookies` map is a clone of the
    /// current jar state.  `custom_headers` is empty — callers that hold
    /// extra headers (e.g. `Authorization: Bearer …`) must fill that field
    /// themselves after calling `snapshot`.
    pub fn snapshot(&self) -> SessionProfile {
        let jar = self.0.lock().unwrap();
        SessionProfile {
            name: String::new(), // filled by the caller (`Session-Save <name>`)
            cookies: jar.clone(),
            custom_headers: Vec::new(),
        }
    }

    /// Restore a saved [`SessionProfile`] into this jar, replacing every
    /// currently-stored cookie for every domain mentioned in the profile.
    /// Domains that are in the jar but *not* in the profile are left
    /// untouched (restore is additive/overwriting, not a full replacement).
    pub fn restore_from_profile(&self, profile: &SessionProfile) {
        let mut jar = self.0.lock().unwrap();
        for (domain, cookie_str) in &profile.cookies {
            jar.insert(domain.clone(), cookie_str.clone());
        }
    }

    /// Expose the raw inner map for display purposes (e.g. `Session-List`).
    pub fn snapshot_raw(&self) -> HashMap<String, String> {
        self.0.lock().unwrap().clone()
    }
}

// ─── ProfileStore ─────────────────────────────────────────────────────────────

/// In-memory registry of named [`SessionProfile`]s.
///
/// All operations are cheap to clone — the inner store is shared via
/// `Arc<Mutex<…>>`.
#[derive(Clone, Default)]
pub struct ProfileStore(Arc<Mutex<HashMap<String, SessionProfile>>>);

impl ProfileStore {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    /// Save `profile` under `profile.name`, overwriting any previous entry
    /// with the same name.
    pub fn save(&self, profile: SessionProfile) {
        self.0.lock().unwrap().insert(profile.name.clone(), profile);
    }

    /// Look up a saved profile by name.
    pub fn load(&self, name: &str) -> Option<SessionProfile> {
        self.0.lock().unwrap().get(name).cloned()
    }

    /// Return the names of every saved profile, sorted alphabetically.
    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.0.lock().unwrap().keys().cloned().collect();
        names.sort();
        names
    }
}

// ─── Profile application helpers (used by Repeater + Intruder) ───────────────

/// Inject the cookies and custom headers from an optional [`SessionProfile`]
/// into `builder`.
///
/// Call this immediately before `.send()` in both the Repeater and Intruder
/// hot paths:
///
/// ```rust,ignore
/// let builder = apply_profile(client.request(method, &url), domain, profile);
/// let resp = builder.send().await?;
/// ```
pub fn apply_profile(
    builder: RequestBuilder,
    domain: &str,
    profile: Option<&SessionProfile>,
) -> RequestBuilder {
    let Some(p) = profile else { return builder };

    // 1. Inject per-domain cookie string.
    let mut b = if let Some(cookie_str) = p.cookies.get(domain) {
        if !cookie_str.is_empty() {
            builder.header("Cookie", cookie_str)
        } else {
            builder
        }
    } else {
        builder
    };

    // 2. Append every custom header (e.g. `Authorization: Bearer …`).
    for (name, value) in &p.custom_headers {
        b = b.header(name.as_str(), value.as_str());
    }

    b
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Split a `Cookie:` header string (`"a=1; b=2"`) into a
/// `name → value` map.
fn parse_cookie_pairs(cookie_str: &str) -> HashMap<String, String> {
    cookie_str
        .split(';')
        .map(|pair| pair.trim())
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            if let Some((k, v)) = pair.split_once('=') {
                (k.trim().to_string(), v.trim().to_string())
            } else {
                (pair.to_string(), String::new())
            }
        })
        .collect()
}

/// Serialise a `name → value` map back to a `Cookie:` header string.
fn serialise_cookie_map(map: &HashMap<String, String>) -> String {
    map.iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k.clone()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn set_cookie_headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for v in values {
            map.append(
                HeaderName::from_static("set-cookie"),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    // ── CookieJar ─────────────────────────────────────────────────────────

    #[test]
    fn update_stores_name_value_pair() {
        let jar = CookieJar::new();
        let headers = set_cookie_headers(&["session=abc; Path=/; HttpOnly"]);
        jar.update_from_response("example.com", &headers);
        let raw = jar.snapshot_raw();
        assert!(raw["example.com"].contains("session=abc"));
    }

    #[test]
    fn update_merges_multiple_set_cookie_headers() {
        let jar = CookieJar::new();
        let headers = set_cookie_headers(&["a=1", "b=2"]);
        jar.update_from_response("example.com", &headers);
        let raw = jar.snapshot_raw();
        let s = &raw["example.com"];
        assert!(s.contains("a=1"), "missing a=1 in {s}");
        assert!(s.contains("b=2"), "missing b=2 in {s}");
    }

    #[test]
    fn update_overwrites_same_name() {
        let jar = CookieJar::new();
        jar.update_from_response("example.com", &set_cookie_headers(&["tok=old"]));
        jar.update_from_response("example.com", &set_cookie_headers(&["tok=new"]));
        let raw = jar.snapshot_raw();
        assert!(raw["example.com"].contains("tok=new"));
        assert!(!raw["example.com"].contains("tok=old"));
    }

    #[test]
    fn update_ignores_empty_set_cookie() {
        let jar = CookieJar::new();
        jar.update_from_response("example.com", &HeaderMap::new());
        assert!(jar.snapshot_raw().is_empty());
    }

    #[test]
    fn snapshot_and_restore() {
        let jar = CookieJar::new();
        jar.update_from_response("a.com", &set_cookie_headers(&["x=1"]));
        let mut profile = jar.snapshot();
        profile.name = "p1".into();
        profile.custom_headers.push(("Authorization".into(), "Bearer tok".into()));

        let jar2 = CookieJar::new();
        jar2.restore_from_profile(&profile);
        let raw = jar2.snapshot_raw();
        assert!(raw["a.com"].contains("x=1"));
    }

    // ── ProfileStore ──────────────────────────────────────────────────────

    #[test]
    fn save_and_load_profile() {
        let store = ProfileStore::new();
        let profile = SessionProfile {
            name: "test".into(),
            cookies: [("x.com".to_string(), "tok=abc".to_string())].into(),
            custom_headers: vec![("X-Foo".into(), "bar".into())],
        };
        store.save(profile.clone());
        let loaded = store.load("test").expect("profile not found");
        assert_eq!(loaded.cookies["x.com"], "tok=abc");
        assert_eq!(loaded.custom_headers[0], ("X-Foo".into(), "bar".into()));
    }

    #[test]
    fn list_returns_sorted_names() {
        let store = ProfileStore::new();
        for name in &["beta", "alpha", "gamma"] {
            store.save(SessionProfile { name: name.to_string(), ..Default::default() });
        }
        assert_eq!(store.list(), vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn load_missing_returns_none() {
        let store = ProfileStore::new();
        assert!(store.load("nope").is_none());
    }

    // ── apply_profile ─────────────────────────────────────────────────────

    #[test]
    fn apply_profile_none_is_noop() {
        // Just verify it compiles and doesn't panic — we can't easily
        // inspect a `RequestBuilder`'s headers without sending it.
        let client = reqwest::Client::new();
        let builder = client.get("http://example.com");
        let _ = apply_profile(builder, "example.com", None);
    }

    // ── Internals ─────────────────────────────────────────────────────────

    #[test]
    fn parse_cookie_pairs_roundtrip() {
        let input = "a=1; b=2; c=3";
        let map = parse_cookie_pairs(input);
        assert_eq!(map["a"], "1");
        assert_eq!(map["b"], "2");
        assert_eq!(map["c"], "3");
    }

    #[test]
    fn serialise_then_parse_roundtrip() {
        let mut map = HashMap::new();
        map.insert("session".to_string(), "xyz".to_string());
        map.insert("csrf".to_string(), "tok".to_string());
        let s = serialise_cookie_map(&map);
        let back = parse_cookie_pairs(&s);
        assert_eq!(back["session"], "xyz");
        assert_eq!(back["csrf"], "tok");
    }
}
