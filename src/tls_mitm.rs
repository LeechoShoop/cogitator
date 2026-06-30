//! TLS man-in-the-middle support for Proxy Guard's CONNECT handling.
//!
//! ## Overview
//!
//! When the proxy receives `CONNECT host:443`, the tunnel is opaque TLS and
//! we can't run any analysis on it. To inspect it we terminate TLS
//! ourselves:
//!
//! 1. A local root CA (`cogitator_ca.pem` / `cogitator_ca.key`) is generated
//!    once and reused across runs.
//! 2. For every distinct `host` the client CONNECTs to, we mint a leaf
//!    certificate for that hostname, signed by our CA, and build a
//!    [`tokio_rustls::TlsAcceptor`] around it.
//! 3. The proxy performs the TLS handshake with the client using that
//!    acceptor. As long as the client trusts `cogitator_ca.pem` (installed
//!    manually into the OS/browser trust store — this module does not do
//!    that automatically), the handshake succeeds and the plaintext
//!    request/response becomes visible to the rest of Cogitator.
//!
//! This is the same trust model Burp Suite / mitmproxy use for HTTPS
//! interception, and carries the same caveat: **only point this at traffic
//! you're authorized to inspect.** Installing the generated CA into a trust
//! store you don't control is on the operator, not this code.
//!
//! ## Leaf cert caching
//!
//! The same `host` is typically CONNECTed to many times in a session
//! (HTTP/1.1 reconnects, multiple resources, redirects). [`CertCache`]
//! memoizes the rustls-ready [`TlsAcceptor`] per hostname so repeated
//! CONNECTs are cheap.

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::logger;

const CA_CERT_PATH: &str = "cogitator_ca.pem";
const CA_KEY_PATH: &str = "cogitator_ca.key";

/// Validity window for generated leaf certificates.
const LEAF_VALID_DAYS: i64 = 365;
/// CA validity — long-lived since the same CA is reused across runs and the
/// person installs it once into their trust store.
const CA_VALID_DAYS: i64 = 10 * 365;

/// Errors that can occur while bootstrapping the CA or minting leaf certs.
#[derive(Debug)]
pub enum TlsMitmError {
    Io(std::io::Error),
    Rcgen(rcgen::Error),
    Rustls(rustls::Error),
    /// `host` could not be encoded as a valid DNS SAN (rare — e.g. contains
    /// characters outside the IA5String charset).
    InvalidHostname(String),
    /// `forward_to_origin` was given a `host` that isn't a valid DNS name or
    /// IP literal for [`ServerName`] (origin-connection equivalent of
    /// `InvalidHostname`, kept separate since the two paths fail at
    /// different layers — SAN encoding vs. rustls's own name type).
    InvalidServerName(String),
    /// The hyper HTTP/1.1 or HTTP/2 client connection to the origin failed
    /// (handshake, send, or body streaming) — which protocol was in play
    /// is recorded separately via `NegotiatedProtocol`, not in this variant.
    Hyper(hyper::Error),
}

impl std::fmt::Display for TlsMitmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMitmError::Io(e) => write!(f, "I/O error: {e}"),
            TlsMitmError::Rcgen(e) => write!(f, "certificate generation error: {e}"),
            TlsMitmError::Rustls(e) => write!(f, "TLS config error: {e}"),
            TlsMitmError::InvalidHostname(h) => write!(f, "invalid hostname for cert SAN: {h}"),
            TlsMitmError::InvalidServerName(h) => write!(f, "invalid hostname for origin TLS SNI: {h}"),
            TlsMitmError::Hyper(e) => write!(f, "origin HTTP connection error: {e}"),
        }
    }
}
impl std::error::Error for TlsMitmError {}
impl From<std::io::Error> for TlsMitmError {
    fn from(e: std::io::Error) -> Self { TlsMitmError::Io(e) }
}
impl From<rcgen::Error> for TlsMitmError {
    fn from(e: rcgen::Error) -> Self { TlsMitmError::Rcgen(e) }
}
impl From<rustls::Error> for TlsMitmError {
    fn from(e: rustls::Error) -> Self { TlsMitmError::Rustls(e) }
}
impl From<hyper::Error> for TlsMitmError {
    fn from(e: hyper::Error) -> Self { TlsMitmError::Hyper(e) }
}

// ─── Root CA ──────────────────────────────────────────────────────────────

/// The local root CA used to sign every generated leaf certificate.
struct LocalCa {
    cert: rcgen::Certificate,
    key: KeyPair,
    /// `true` if this CA was minted by this call (no usable cert/key found
    /// on disk); `false` if it was loaded from an existing pair. Surfaced
    /// via [`CertCache::ca_was_freshly_generated`] purely for the startup
    /// log line in `main` — checking the filesystem *after* construction
    /// would always say "exists" since `generate_and_persist_at` has
    /// already written the files by then.
    freshly_generated: bool,
}

impl LocalCa {
    /// Load the CA from `cert_path` / `key_path` if both exist and parse
    /// cleanly; otherwise generate a fresh CA and persist it there.
    fn load_or_generate_at(cert_path: &Path, key_path: &Path) -> Result<Self, TlsMitmError> {
        if cert_path.exists() && key_path.exists() {
            match Self::load_from(cert_path, key_path) {
                Ok(ca) => {
                    logger::log_event(&format!(
                        "TLS MITM: loaded existing local CA from {}",
                        cert_path.display()
                    ));
                    return Ok(ca);
                }
                Err(e) => {
                    logger::warn(&format!(
                        "TLS MITM: failed to load existing CA ({e}), regenerating"
                    ));
                }
            }
        }
        Self::generate_and_persist_at(cert_path, key_path)
    }

    fn load_from(cert_path: &Path, key_path: &Path) -> Result<Self, TlsMitmError> {
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;

        let key = KeyPair::from_pem_and_sign_algo(&key_pem, &PKCS_ECDSA_P256_SHA256)?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let cert = params.self_signed(&key)?;

        Ok(Self { cert, key, freshly_generated: false })
    }

    fn generate_and_persist_at(cert_path: &Path, key_path: &Path) -> Result<Self, TlsMitmError> {
        let key = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::minutes(1);
        params.not_after = now + TimeDuration::days(CA_VALID_DAYS);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Cogitator Local MITM CA");
        dn.push(DnType::OrganizationName, "Cogitator");
        params.distinguished_name = dn;

        let cert = params.self_signed(&key)?;

        fs::write(cert_path, cert.pem())?;
        fs::write(key_path, key.serialize_pem())?;

        logger::log_event(&format!(
            "TLS MITM: generated new local CA at {} / {}. \
             Import {} into your client's trust store to intercept TLS without warnings.",
            cert_path.display(),
            key_path.display(),
            cert_path.display(),
        ));

        Ok(Self { cert, key, freshly_generated: true })
    }

    fn cert_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }
}

// ─── Per-host leaf certificate generation ────────────────────────────────────

/// Generate a fresh leaf certificate for `host`, signed by `ca`, and wrap it
/// (plus the CA cert, for chain completeness) into a rustls [`ServerConfig`].
fn build_server_config(host: &str, ca: &LocalCa) -> Result<ServerConfig, TlsMitmError> {
    let leaf_key = KeyPair::generate()?;

    let mut params = CertificateParams::default();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - TimeDuration::minutes(1);
    params.not_after = now + TimeDuration::days(LEAF_VALID_DAYS);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // SANs: if `host` parses as an IP literal, use SanType::IpAddress;
    // otherwise treat it as a DNS name. CONNECT targets are almost always
    // hostnames, but handle raw IPs defensively (e.g. CONNECT 1.2.3.4:443).
    let san = match IpAddr::from_str(host) {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => {
            let dns_name = Ia5String::try_from(host)
                .map_err(|_| TlsMitmError::InvalidHostname(host.to_string()))?;
            SanType::DnsName(dns_name)
        }
    };
    params.subject_alt_names = vec![san];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);
    params.distinguished_name = dn;

    // Sign the leaf with the CA's certificate + key — this is the
    // documented rcgen 0.13 pattern for "issue a cert from an existing CA".
    let leaf_cert = params.signed_by(&leaf_key, &ca.cert, &ca.key)?;

    let leaf_der: CertificateDer<'static> = leaf_cert.der().clone();
    let chain = vec![leaf_der, ca.cert_der()];

    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key_der)?;

    // Advertise both h2 and http/1.1 to the client during the inbound TLS
    // handshake. Order matters: rustls (as a server) picks the first entry
    // here that the client also offers, so h2 is preferred when the client
    // supports it. `hyper_util::server::conn::auto::Builder` (used by
    // `proxy_guard::handle_connect`) inspects the connection preface itself
    // to decide h1 vs h2, but it can only ever see h2 bytes if ALPN above
    // actually let the client negotiate h2 in the first place — without
    // this, every MITM'd connection was silently pinned to http/1.1
    // regardless of what the real client supports.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

// ─── Public cache + entry point ──────────────────────────────────────────────

/// Caches one [`TlsAcceptor`] per hostname so repeated `CONNECT host:443`
/// calls in the same process don't re-mint a certificate every time.
///
/// ## Why `Arc<TlsAcceptor>` and not `rcgen::CertifiedKey`
///
/// rcgen 0.13 (pinned in `Cargo.toml`) dropped the `CertifiedKey` struct
/// that existed in older rcgen 0.10/0.11 APIs (`{ cert, key_pair }`).  In
/// 0.13, [`CertificateParams::signed_by`] returns a bare [`rcgen::Certificate`]
/// and the [`KeyPair`] is generated/held separately — there's no single
/// struct to cache them under that name.
///
/// More importantly, caching the *rustls-ready* [`TlsAcceptor`] is strictly
/// better here: it's the exact value [`make_mitm_acceptor`] needs to hand
/// back, with the leaf cert + CA chain + private key already baked into a
/// [`rustls::ServerConfig`]. Caching the raw cert/key pair instead would
/// just mean re-deriving the `ServerConfig` (and re-wrapping it in a new
/// `TlsAcceptor`) on every cache hit — strictly more work for the same
/// "don't regenerate per connection" guarantee. So the cache below already
/// satisfies that requirement; this comment exists so a future pass doesn't
/// "fix" it back into the slower shape.
pub struct CertCache {
    ca: LocalCa,
    acceptors: Mutex<HashMap<String, Arc<TlsAcceptor>>>,
}

impl CertCache {
    /// Load (or generate + persist) the local CA from the well-known paths
    /// `cogitator_ca.pem` / `cogitator_ca.key` in the working directory.
    ///
    /// Call this exactly once at startup and share the result (e.g. via
    /// `Arc`) with every proxy connection task.
    pub fn new() -> Result<Self, TlsMitmError> {
        let ca = LocalCa::load_or_generate_at(Path::new(CA_CERT_PATH), Path::new(CA_KEY_PATH))?;
        Ok(Self {
            ca,
            acceptors: Mutex::new(HashMap::new()),
        })
    }

    /// `true` if the CA cert/key pair had to be generated fresh when this
    /// `CertCache` was constructed (no existing/loadable `cogitator_ca.pem`
    /// + `.key` on disk); `false` if an existing pair was loaded.
    ///
    /// Purely informational — used by `main` for the startup log line
    /// ("loaded existing CA" vs "generated new CA"). [`CertCache::new`]
    /// already does the generate-if-missing work internally regardless of
    /// how this returns.
    pub fn ca_was_freshly_generated(&self) -> bool {
        self.ca.freshly_generated
    }

    /// Path to the CA certificate, for surfacing to the user (e.g. "import
    /// this file into your browser/OS trust store").
    pub fn ca_cert_path(&self) -> &'static str {
        CA_CERT_PATH
    }

    /// Write the CA certificate (PEM, public cert only — never the private
    /// key) out to `dest_dir/cogitator_ca.pem`, returning the full
    /// destination path on success.
    ///
    /// Used by the TUI `Export-CA` command so the operator gets a copy of
    /// the CA cert sitting in a convenient, known location to feed into a
    /// browser/OS trust-store import dialog.
    ///
    /// Serializes directly from the in-memory [`LocalCa`] rather than
    /// re-reading `cogitator_ca.pem` off disk — this is the same PEM bytes
    /// either way (this *is* what `generate_and_persist_at` / `load_from`
    /// wrote/read), but it keeps this method correct even if the on-disk
    /// file were ever moved or deleted out from under a running process,
    /// and avoids depending on the current working directory.
    pub fn export_ca_to(&self, dest_dir: &Path) -> Result<std::path::PathBuf, TlsMitmError> {
        let dest_path = dest_dir.join(CA_CERT_PATH);
        fs::write(&dest_path, self.ca.cert.pem())?;
        Ok(dest_path)
    }

    /// Get or create a [`TlsAcceptor`] configured with a leaf certificate
    /// for `host`, signed by the local CA.
    ///
    /// `host` may include a trailing `:port` (as CONNECT targets usually
    /// do, e.g. `"example.com:443"`) — it is stripped before generating the
    /// certificate SAN and before the cache lookup, so `"example.com:443"`
    /// and `"example.com:8443"` share one cached acceptor.
    pub fn make_mitm_acceptor(&self, host: &str) -> Result<Arc<TlsAcceptor>, TlsMitmError> {
        let bare_host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);

        {
            let cache = self.acceptors.lock().unwrap();
            if let Some(acceptor) = cache.get(bare_host) {
                return Ok(acceptor.clone());
            }
        }

        let config = build_server_config(bare_host, &self.ca)?;
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(config)));

        let mut cache = self.acceptors.lock().unwrap();
        // Another task may have raced us to build the same host's acceptor;
        // prefer whichever landed first in the map.
        let acceptor = cache
            .entry(bare_host.to_string())
            .or_insert(acceptor)
            .clone();

        Ok(acceptor)
    }
}

// ─── Forwarding decrypted requests to the real origin ───────────────────────
//
// Once `handle_connect` has terminated TLS with the client (see above) and
// the plaintext request has been pulled out for analysis, that request still
// needs to actually reach the real origin server — otherwise the client gets
// no response and every MITM'd site appears broken. `forward_to_origin`
// re-establishes TLS *outbound* (this time as the client) to `host`, replays
// the request, and streams the origin's response back so the caller can
// return it to the original client unchanged.

/// Process-wide outbound `ClientConfig`, built once from the Mozilla root
/// store shipped in `webpki-roots`.
///
/// This is deliberately separate from anything in [`CertCache`]: the inbound
/// side (`ServerConfig`, one per intercepted host) authenticates *us* to the
/// client using our own locally-minted CA, while this config authenticates
/// the *real origin* to us using the public WebPKI hierarchy. Sharing one
/// `OnceLock`-backed `Arc` across every `forward_to_origin` call avoids
/// rebuilding the root store (a non-trivial parse) on every single proxied
/// request.
static ORIGIN_CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

/// `pub(crate)` (rather than private) so `ws_interceptor::dial_origin` can
/// build its own `TlsConnector` for the outbound `wss://` leg using the same
/// WebPKI root store + verification behaviour as `forward_to_origin` — there
/// is exactly one outbound trust policy for "the real origin", and it should
/// stay that way regardless of which module is dialing out.
pub(crate) fn origin_client_config() -> Arc<ClientConfig> {
    ORIGIN_CLIENT_CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();

            // Same ALPN offer as the inbound (client-facing) side: let the
            // real origin pick h2 if it supports it. Whatever the origin
            // negotiates here is independent of what the *client* (other
            // side of the MITM) negotiated with us — `forward_to_origin`
            // reads this back off the handshake to decide which hyper
            // client (h1 vs h2) to speak on the upstream leg.
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Arc::new(config)
        })
        .clone()
}

/// Which HTTP version ended up live on a given TLS leg, per ALPN.
///
/// Falls back to `Http1` if the peer didn't negotiate ALPN at all (common
/// for older/non-browser origins) — `with_single_cert`/rustls leaves
/// `alpn_protocol()` as `None` in that case, and plain HTTP/1.1 is always a
/// safe default since every origin that speaks h2 also speaks h1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedProtocol {
    Http1,
    Http2,
}

impl NegotiatedProtocol {
    fn from_alpn(alpn: Option<&[u8]>) -> Self {
        match alpn {
            Some(proto) if proto == b"h2" => NegotiatedProtocol::Http2,
            _ => NegotiatedProtocol::Http1,
        }
    }
}

/// Rewrite `req` so it's safe to put on the wire to a real origin server
/// over plain HTTP/1.1.
///
/// Two adjustments are needed depending on how the request arrived:
///
/// * **Plain (non-tunneled) proxy requests** carry an absolute-form URI
///   (`http://example.com/path`, per RFC 7230 §5.3.2 — that's how a client
///   addresses a forward proxy). Real origin servers expect origin-form
///   (`/path`) with the host carried separately in the `Host` header, so we
///   rewrite the URI down to just path+query here. Requests arriving inside
///   a decrypted CONNECT tunnel are already origin-form (the client talks
///   to what it thinks is the origin directly), so this is a no-op for them.
/// * **`Host` header**: guaranteed present and correct for `host:port`
///   either way — absolute-form requests technically already encode the
///   host in the URI, but some clients still expect to see it echoed in the
///   header too, and tunneled requests already carry whatever `Host` the
///   client set, which should match `host` (the original CONNECT target)
///   and is left alone if so.
fn normalize_for_origin(req: Request<Incoming>, host: &str, port: u16) -> Request<Incoming> {
    let (mut parts, body) = req.into_parts();

    if parts.uri.scheme().is_some() {
        // Absolute-form: rebuild as origin-form, keeping only path+query.
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        if let Ok(new_uri) = path_and_query.parse() {
            parts.uri = new_uri;
        }
    }

    let needs_host_header = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.is_empty())
        .unwrap_or(true);

    if needs_host_header {
        let host_value = if port == 443 || port == 80 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        if let Ok(value) = hyper::header::HeaderValue::from_str(&host_value) {
            parts.headers.insert(hyper::header::HOST, value);
        }
    }

    Request::from_parts(parts, body)
}

/// Outcome of [`forward_to_origin`]: the response to hand back to the
/// client, plus what actually happened on the upstream leg so the caller
/// (`proxy_guard::record_exchange`) can log it into `RequestRecord`.
pub struct OriginForward {
    pub response: Response<Full<Bytes>>,
    /// Which protocol was actually spoken to the real origin — independent
    /// of whatever the *client* negotiated with us on the inbound leg, see
    /// [`NegotiatedProtocol`].
    pub protocol: NegotiatedProtocol,
    /// `Some(1)` when `protocol` is `Http2`, `None` for `Http1`. See the
    /// doc comment on the h2 branch in `forward_to_origin` for why this is
    /// always `1` rather than a real wire-level `h2::StreamId`.
    pub stream_id: Option<u64>,
}

/// Open a TLS connection to the real origin for `host`, forward `req` over
/// it, and return the origin's response with its body fully buffered into a
/// [`Full<Bytes>`] so it can be handed straight back to the client.
///
/// `host` is the bare hostname (or IP literal) the client originally
/// CONNECTed to — i.e. [`CertCache::make_mitm_acceptor`]'s `host` argument
/// with any `:port` already stripped is *not* required here; this function
/// accepts either `"example.com"` (defaults to port 443) or
/// `"example.com:8443"` and parses the port itself, since the real origin
/// may not be listening on 443.
///
/// This performs real WebPKI certificate verification via
/// [`rustls::client::WebPkiServerVerifier`] (the verifier `ClientConfig`
/// builds internally from the root store passed to it) — unlike the
/// client-facing side of the MITM, there is no reason to weaken trust here:
/// we want to know immediately if the real origin's certificate doesn't
/// check out, the same as any normal TLS client would.
pub async fn forward_to_origin(
    host: &str,
    req: Request<Incoming>,
) -> Result<OriginForward, TlsMitmError> {
    let (bare_host, port) = match host.rsplit_once(':') {
        // Only treat the suffix as a port if it actually parses as one —
        // guards against bare IPv6 literals like "::1" being split on the
        // wrong colon. CONNECT targets always carry an explicit port, but
        // this function is also reachable with the un-suffixed hostname
        // resolved via the Host header, so default to 443 in that case.
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => (host, 443),
        },
        None => (host, 443),
    };

    logger::debug(&format!(
        "TLS MITM: forwarding request to real origin {}:{}", bare_host, port
    ));

    // ── 1. TCP connect ────────────────────────────────────────────────────
    let tcp = TcpStream::connect((bare_host, port)).await?;

    // ── 2. TLS handshake as the client, verifying the origin's real cert ───
    let server_name = ServerName::try_from(bare_host.to_string())
        .map_err(|_| TlsMitmError::InvalidServerName(bare_host.to_string()))?;

    let connector = TlsConnector::from(origin_client_config());
    let tls_stream = connector.connect(server_name, tcp).await?;

    // ALPN result is only available *after* the handshake completes, and
    // only on the rustls-level connection (`.get_ref().1`) — `TokioIo`
    // doesn't expose it, so this must be read before wrapping the stream.
    let protocol = NegotiatedProtocol::from_alpn(tls_stream.get_ref().1.alpn_protocol());

    let io = TokioIo::new(tls_stream);
    let req = normalize_for_origin(req, bare_host, port);

    let (origin_resp, stream_id) = match protocol {
        NegotiatedProtocol::Http1 => {
            // Plain http1 client — covers both "origin only speaks h1" and
            // "origin speaks h2 but for some reason ALPN settled on h1"
            // (e.g. a non-conformant origin). This is also the path taken
            // when the *inbound* client only speaks h1: the two legs are
            // negotiated completely independently (see `OriginForward`
            // doc comment), so an h1 client can still be transparently
            // served by an h2-speaking origin without either side knowing
            // the other leg's version — that translation is exactly this
            // independent per-leg ALPN negotiation, nothing more is needed.
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    logger::debug(&format!("TLS MITM: origin connection task ended: {e}"));
                }
            });

            (sender.send_request(req).await?, None)
        }
        NegotiatedProtocol::Http2 => {
            // h2 client. `hyper::client::conn::http2::handshake` needs an
            // executor to drive the connection's background tasks (stream
            // multiplexing, flow control, etc.) — `TokioExecutor` mirrors
            // what `proxy_guard` already uses for the client-facing
            // `hyper_util::server::conn::auto::Builder`.
            let (mut sender, conn) =
                hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                    .handshake(io)
                    .await?;

            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    logger::debug(&format!("TLS MITM: origin h2 connection task ended: {e}"));
                }
            });

            // `forward_to_origin` opens a fresh connection per call (no
            // pooling/reuse — see the body-buffering note below for why
            // that's an acceptable tradeoff for an inspection proxy), so
            // there is exactly one h2 stream on this connection and it is
            // always the first client-initiated id per the h2 spec's
            // odd-numbered sequence. hyper's `client::conn::http2` API
            // does not surface the underlying `h2::StreamId` directly, so
            // `1` here is reported on that basis rather than read off the
            // wire.
            (sender.send_request(req).await?, Some(1))
        }
    };

    // ── Buffer the response body and hand back an owned Response ───────────
    //
    // The caller (proxy_guard::handle_proxy_request) needs a
    // `Response<Full<Bytes>>` to match the rest of the proxy's response
    // type — Incoming can't outlive this function since it's tied to the
    // connection task we just spawned, so we collect it fully here. This
    // means forward_to_origin does not stream large responses
    // incrementally; that's an acceptable tradeoff for an inspection proxy
    // (which is already buffering for analysis elsewhere) but would need
    // revisiting if Cogitator ever proxies large file downloads.
    let (parts, body) = origin_resp.into_parts();
    let collected = body.collect().await?;
    let bytes = collected.to_bytes();

    Ok(OriginForward {
        response: Response::from_parts(parts, Full::new(bytes)),
        protocol,
        stream_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a CA in a per-test temp file pair so tests never touch the
    /// real cogitator_ca.pem / .key used by the running app, and never
    /// collide with each other when run in parallel.
    fn test_ca() -> LocalCa {
        let unique = format!(
            "{}_{:?}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            std::thread::current().id()
        );
        let cert_path = std::env::temp_dir().join(format!("cogitator_test_ca_{unique}.pem"));
        let key_path = std::env::temp_dir().join(format!("cogitator_test_ca_{unique}.key"));
        let ca = LocalCa::generate_and_persist_at(&cert_path, &key_path)
            .expect("test CA generation should succeed");
        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
        ca
    }

    #[test]
    fn leaf_cert_signed_by_ca_for_dns_host() {
        let ca = test_ca();
        let config = build_server_config("example.com", &ca);
        assert!(config.is_ok(), "expected DNS-name leaf cert to build: {:?}", config.err());
    }

    #[test]
    fn leaf_cert_signed_by_ca_for_ip_host() {
        let ca = test_ca();
        let config = build_server_config("127.0.0.1", &ca);
        assert!(config.is_ok(), "expected IP-literal leaf cert to build: {:?}", config.err());
    }

    #[test]
    fn leaf_cert_for_subdomain() {
        let ca = test_ca();
        let config = build_server_config("api.example.com", &ca);
        assert!(config.is_ok(), "expected subdomain leaf cert to build: {:?}", config.err());
    }

    #[test]
    fn cache_reuses_acceptor_for_same_host_different_port() {
        let ca = test_ca();
        let cache = CertCache { ca, acceptors: Mutex::new(HashMap::new()) };

        let a1 = cache.make_mitm_acceptor("example.com:443").unwrap();
        let a2 = cache.make_mitm_acceptor("example.com:8443").unwrap();
        assert!(
            Arc::ptr_eq(&a1, &a2),
            "same hostname should reuse cached acceptor regardless of port"
        );
    }

    #[test]
    fn cache_distinguishes_different_hosts() {
        let ca = test_ca();
        let cache = CertCache { ca, acceptors: Mutex::new(HashMap::new()) };

        let a1 = cache.make_mitm_acceptor("a.example.com").unwrap();
        let a2 = cache.make_mitm_acceptor("b.example.com").unwrap();
        assert!(!Arc::ptr_eq(&a1, &a2), "different hostnames must get distinct acceptors");
    }

    #[test]
    fn host_without_port_works() {
        let ca = test_ca();
        let cache = CertCache { ca, acceptors: Mutex::new(HashMap::new()) };
        assert!(cache.make_mitm_acceptor("example.com").is_ok());
    }

    #[test]
    fn fresh_generation_is_flagged() {
        let unique = format!(
            "{}_{:?}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            std::thread::current().id()
        );
        let cert_path = std::env::temp_dir().join(format!("cogitator_flag_test_{unique}.pem"));
        let key_path = std::env::temp_dir().join(format!("cogitator_flag_test_{unique}.key"));

        // Neither file exists yet -> must generate, flag should be true.
        let ca = LocalCa::load_or_generate_at(&cert_path, &key_path)
            .expect("first load_or_generate_at should generate a fresh CA");
        assert!(ca.freshly_generated, "no prior files on disk -> should be freshly generated");

        // Files now exist on disk -> loading again should flip the flag false.
        let ca2 = LocalCa::load_or_generate_at(&cert_path, &key_path)
            .expect("second load_or_generate_at should load the persisted CA");
        assert!(!ca2.freshly_generated, "files now exist on disk -> should be loaded, not generated");

        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
    }

    #[test]
    fn export_ca_to_writes_cert_into_dest_dir() {
        let ca = test_ca();
        let cache = CertCache { ca, acceptors: Mutex::new(HashMap::new()) };

        let dest_dir = std::env::temp_dir().join(format!(
            "cogitator_export_test_{}_{:?}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&dest_dir).expect("failed to create temp dest dir");

        let result = cache.export_ca_to(&dest_dir);
        let dest_path = result.expect("export_ca_to should succeed");
        assert_eq!(dest_path, dest_dir.join(CA_CERT_PATH));

        let written = fs::read_to_string(&dest_path).expect("exported file should be readable");
        assert!(written.contains("BEGIN CERTIFICATE"), "exported file should contain a PEM cert block");

        let _ = fs::remove_dir_all(&dest_dir);
    }
}