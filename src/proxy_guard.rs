use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use crate::history::{History, RequestRecord};
use crate::interceptor::InterceptorEngine;
use crate::logger;
use crate::scope::Scope;
use crate::tls_mitm::{self, CertCache};
use crate::web_analyzer::SiteAnalyzer;
use crate::ws_interceptor;

/// Hard cap on how much of a request/response body gets retained in
/// `History`. Bodies larger than this are stored truncated and tagged
/// `"truncated"` — this is an inspection log, not a replay buffer, so there
/// is no value in holding multi-megabyte bodies in memory indefinitely.
const MAX_HISTORY_BODY_BYTES: usize = 1024 * 1024; // 1 MB

/// Monotonic id generator for `RequestRecord`s pushed from the proxy path.
/// Separate from `InterceptorEngine::request_counter` since the plain proxy
/// path (this module) does not go through the intercept queue.
static HISTORY_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Resolve the domain a request is "about", for analysis + report naming.
///
/// * Plain (non-tunneled) proxy requests carry an absolute-form URI, so
///   `req.uri().host()` is populated directly.
/// * Requests arriving **inside** a decrypted CONNECT tunnel have a
///   relative URI (just `/path`) — the host isn't in the URI at all, so we
///   fall back to the `Host` header, and finally to `tunnel_host` (the
///   original `CONNECT host:port` target captured when the tunnel was
///   opened) if even that's missing.
fn resolve_target_host(req: &Request<Incoming>, tunnel_host: Option<&str>) -> String {
    if let Some(host) = req.uri().host() {
        return host.to_string();
    }
    if let Some(host_header) = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        // Host header may include ":port" — strip it for the bare domain.
        let bare = host_header.split(':').next().unwrap_or(host_header);
        if !bare.is_empty() {
            return bare.to_string();
        }
    }
    tunnel_host.unwrap_or("unknown-target").to_string()
}

/// Handle a single proxied (plaintext) request: analyse the target domain,
/// write a report, then forward the request to the real origin server and
/// return its response to the client (see [`tls_mitm::forward_to_origin`]).
///
/// `analyzer` is the shared [`SiteAnalyzer`] constructed in `main`.  Using
/// the trait rather than raw clients lets tests substitute a stub
/// implementation without spinning up a real HTTP stack.
///
/// `tunnel_host` is `Some("host:port")` when this request arrived inside a
/// decrypted CONNECT tunnel (see [`resolve_target_host`]); it is `None` for
/// ordinary plain-HTTP proxy requests, where the URI is already absolute.
/// It doubles as the forwarding target: it carries the real port the client
/// asked to reach, which `host` (used only for report naming) does not.
async fn handle_proxy_request(
    req: Request<Incoming>,
    analyzer: Arc<dyn SiteAnalyzer>,
    tunnel_host: Option<String>,
    history: Arc<History>,
    scope: Arc<Mutex<Scope>>,
    interceptor_engine: Arc<InterceptorEngine>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let uri    = req.uri().to_string();
    let host   = resolve_target_host(&req, tunnel_host.as_deref());
    let path   = req.uri().path().to_string();

    // Scope check — built from host + path so patterns can match either
    // (e.g. `example\.com` or `/admin`). Out-of-scope requests are
    // auto-forwarded with no analysis, no report, and no History entry.
    let scope_url = format!("{}{}", host, path);
    let in_scope = scope.lock().unwrap().in_scope(&scope_url);

    if !in_scope {
        // `host` is not used after this early return, so move it instead of cloning.
        let origin_target = tunnel_host.unwrap_or(host);
        return match tls_mitm::forward_to_origin(&origin_target, req).await {
            Ok(fwd) => Ok(fwd.response),
            Err(e) => {
                logger::debug(&format!(
                    "Proxy Guard: out-of-scope request failed to forward to origin {}: {}",
                    origin_target, e
                ));
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!(
                        "Cogitator Proxy Guard: failed to reach origin {}: {}",
                        origin_target, e
                    ))))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
            }
        };
    }

    // WebSocket upgrade: `Upgrade: websocket` + `Connection: Upgrade` means
    // this is not an ordinary request/response exchange — hyper's
    // request/response model stops applying the moment the 101 response is
    // flushed, so hand off to `ws_interceptor` entirely instead of falling
    // through to the analysis/forwarding path below. `tunnel_host.is_some()`
    // means this request arrived inside a decrypted CONNECT tunnel, i.e. the
    // original scheme was `wss://` — the outbound leg to the real origin
    // needs its own TLS handshake too in that case.
    if ws_interceptor::is_websocket_upgrade(req.headers()) {
        let use_tls = tunnel_host.is_some();
        // `intercept_websocket` needs both the stripped `host` (for logging/history)
        // and the full `origin_target` (with port, for the outbound connection).
        // When tunnel_host is Some they differ, so we must clone host here rather
        // than moving it into origin_target and losing it for the host argument.
        let origin_target = tunnel_host.unwrap_or_else(|| host.clone());
        return ws_interceptor::intercept_websocket(
            req,
            host,
            origin_target,
            use_tls,
            history,
            interceptor_engine,
        )
            .await;
    }

    // Capture request headers before `req` is consumed by forwarding —
    // `Incoming`'s body can't outlive that call, so the request body is not
    // captured here (mirrors the same tradeoff already made in
    // `interceptor::freeze_request`).
    let request_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or("<non-utf8>").to_string(),
            )
        })
        .collect();

    logger::log_event(&format!("Proxy Guard Intercepted: {} {} (host: {})", method, uri, host));

    let analysis_result = analyzer.analyze(&host).await;
    let report = analyzer.format(&analysis_result);

    let safe_domain = host.replace(':', "_");
    let filename    = format!("{}_proxy_report.txt", safe_domain);

    if let Err(e) = std::fs::write(&filename, report) {
        logger::log_event(&format!("Failed to write proxy report to {}: {}", filename, e));
    } else {
        logger::log_event(&format!("Proxy Guard report saved to {}", filename));
    }

    // `forward_to_origin` needs a "host[:port]" target for the *outbound*
    // connection. Inside a decrypted CONNECT tunnel, `tunnel_host` already
    // carries the real port (e.g. "example.com:443") — that's the one to
    // use, since `host` above has had any port stripped for report naming.
    // For plain (non-tunneled) proxying there is no CONNECT target, so fall
    // back to the bare host; `forward_to_origin` defaults that to port 80,
    // which matches an ordinary unencrypted HTTP proxy request.
    // `host` must survive to be passed into `record_exchange` below (L184),
    // so we cannot move it into `origin_target` when `tunnel_host` is None.
    let origin_target = tunnel_host.unwrap_or_else(|| host.clone());

    let started_at = Instant::now();

    match tls_mitm::forward_to_origin(&origin_target, req).await {
        Ok(fwd) => {
            record_exchange(
                &history,
                method,
                host,
                path,
                request_headers,
                &fwd.response,
                started_at.elapsed(),
                fwd.stream_id,
            )
                .await;
            Ok(fwd.response)
        }
        Err(e) => {
            logger::log_event(&format!(
                "Proxy Guard: failed to forward request to origin {}: {}", origin_target, e
            ));
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!(
                    "Cogitator Proxy Guard: failed to reach origin {}: {}",
                    origin_target, e
                ))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
        }
    }
}

/// Build a `RequestRecord` for a completed exchange and push it into
/// `history`.
///
/// The response body is re-collected here (cheap: `Full<Bytes>` wraps an
/// already-buffered `Bytes`, so `BodyExt::collect` does no I/O) and capped at
/// [`MAX_HISTORY_BODY_BYTES`] — anything beyond that is dropped and the
/// record is tagged `"truncated"` so the cap is visible in the TUI/history
/// view rather than silently losing data.
async fn record_exchange(
    history: &History,
    method: String,
    host: String,
    path: String,
    request_headers: Vec<(String, String)>,
    resp: &Response<Full<Bytes>>,
    elapsed: std::time::Duration,
    stream_id: Option<u64>,
) {
    let status = resp.status().as_u16();
    let response_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or("<non-utf8>").to_string(),
            )
        })
        .collect();

    // Clone the body so the original response (returned to the client
    // unchanged) is left untouched — `Full<Bytes>` clones cheaply since
    // `Bytes` is itself a cheap, ref-counted view.
    let collected = match resp.body().clone().collect().await {
        Ok(c) => c,
        Err(_) => {
            // `Full<Bytes>`'s `Error` type is `Infallible` in practice, but
            // handle it defensively rather than unwrapping.
            let id = HISTORY_REQUEST_ID.fetch_add(1, Ordering::SeqCst);
            history.push(RequestRecord {
                id,
                timestamp: Instant::now(),
                method,
                host,
                path,
                headers: request_headers,
                body: Vec::new(),
                response_status: Some(status),
                response_headers,
                response_body: None,
                response_time_ms: Some(elapsed.as_millis()),
                tags: vec!["body-read-error".to_string()],
                stream_id,
            });
            return;
        }
    };
    let full_bytes = collected.to_bytes();

    let truncated = full_bytes.len() > MAX_HISTORY_BODY_BYTES;
    let stored_body = if truncated {
        full_bytes[..MAX_HISTORY_BODY_BYTES].to_vec()
    } else {
        full_bytes.to_vec()
    };

    let mut tags = Vec::new();
    if truncated {
        tags.push("truncated".to_string());
    }

    let id = HISTORY_REQUEST_ID.fetch_add(1, Ordering::SeqCst);
    history.push(RequestRecord {
        id,
        timestamp: Instant::now(),
        method,
        host,
        path,
        headers: request_headers,
        // Request body is not captured — see the comment in
        // `handle_proxy_request` for why.
        body: Vec::new(),
        response_status: Some(status),
        response_headers,
        response_body: Some(stored_body),
        response_time_ms: Some(elapsed.as_millis()),
        tags,
        stream_id,
    });
}

/// Top-level per-request dispatcher: routes `CONNECT` requests into the TLS
/// MITM path and everything else into the ordinary plaintext analysis path.
async fn route_request(
    req: Request<Incoming>,
    analyzer: Arc<dyn SiteAnalyzer>,
    cert_cache: Arc<CertCache>,
    history: Arc<History>,
    scope: Arc<Mutex<Scope>>,
    interceptor_engine: Arc<InterceptorEngine>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::CONNECT {
        handle_connect(req, analyzer, cert_cache, history, scope, interceptor_engine).await
    } else {
        handle_proxy_request(req, analyzer, None, history, scope, interceptor_engine).await
    }
}

/// Handle `CONNECT host:443` by establishing a tunnel, then transparently
/// terminating TLS inside it so the plaintext request/response can be
/// analysed like any other proxied traffic.
///
/// Flow:
/// 1. Reply `200 Connection Established` immediately — this is what tells
///    the client's TLS stack "go ahead and start the handshake now".
/// 2. Take ownership of the now-tunnel-only connection via
///    [`hyper::upgrade::on`].
/// 3. Perform a server-side TLS handshake over that raw stream using a
///    per-domain certificate from [`CertCache`] (see `tls_mitm.rs`).
/// 4. Serve HTTP/1.1 (or h2) inside the now-decrypted stream, feeding each
///    inner request back through [`handle_proxy_request`] for analysis.
///
/// Steps 2-4 happen in a spawned task, since `hyper::upgrade::on`'s future
/// only resolves *after* the 200 response has actually been flushed to the
/// client — we can't await it before returning that response.
async fn handle_connect(
    req: Request<Incoming>,
    analyzer: Arc<dyn SiteAnalyzer>,
    cert_cache: Arc<CertCache>,
    history: Arc<History>,
    scope: Arc<Mutex<Scope>>,
    interceptor_engine: Arc<InterceptorEngine>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // CONNECT's request-target is authority-form: "host:port" (no scheme,
    // no path). `req.uri().authority()` is the correct accessor for that.
    // Use `tunnel_host` directly for both the log below and the spawned task.
    // Separating `target` and `tunnel_host` with a clone served no purpose.
    let tunnel_host = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    logger::log_event(&format!("Proxy Guard CONNECT received for {}", tunnel_host));

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(upgraded) => upgraded,
            Err(e) => {
                logger::log_event(&format!(
                    "Proxy Guard CONNECT upgrade failed for {}: {}", tunnel_host, e
                ));
                return;
            }
        };
        let client_io = TokioIo::new(upgraded);

        let acceptor = match cert_cache.make_mitm_acceptor(&tunnel_host) {
            Ok(acceptor) => acceptor,
            Err(e) => {
                logger::log_event(&format!(
                    "Proxy Guard TLS MITM: failed to build certificate for {}: {}",
                    tunnel_host, e
                ));
                return;
            }
        };

        let tls_stream = match acceptor.accept(client_io).await {
            Ok(stream) => stream,
            Err(e) => {
                // Very common if the client doesn't trust cogitator_ca.pem —
                // not an application bug, so log at debug rather than error.
                logger::debug(&format!(
                    "Proxy Guard TLS MITM handshake failed for {} (client may not trust the local CA): {}",
                    tunnel_host, e
                ));
                return;
            }
        };

        logger::log_event(&format!("Proxy Guard TLS MITM established for {}", tunnel_host));

        let tls_io = TokioIo::new(tls_stream);
        let inner_analyzer = analyzer.clone();
        let inner_host = tunnel_host.clone();
        let inner_history = history.clone();
        let inner_scope = scope.clone();
        let inner_engine = interceptor_engine.clone();

        if let Err(err) = Builder::new(TokioExecutor::new())
            .serve_connection(
                tls_io,
                hyper::service::service_fn(move |inner_req| {
                    handle_proxy_request(
                        inner_req,
                        inner_analyzer.clone(),
                        Some(inner_host.clone()),
                        inner_history.clone(),
                        inner_scope.clone(),
                        inner_engine.clone(),
                    )
                }),
            )
            .await
        {
            logger::log_event(&format!(
                "Proxy Guard MITM connection error for {}: {:?}", tunnel_host, err
            ));
        }
    });

    // Must be returned (and flushed) before hyper::upgrade::on resolves in
    // the spawned task above — that's what signals the client to start its
    // TLS handshake.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
}

/// Start the proxy server.
///
/// `analyzer` is the shared [`SiteAnalyzer`] forwarded to every plaintext
/// [`handle_proxy_request`] call (both for ordinary HTTP proxying and for
/// requests decrypted out of a CONNECT/TLS MITM tunnel).
///
/// `cert_cache` is the shared [`CertCache`] (local CA + per-domain
/// certificate cache, see `tls_mitm.rs`) used to terminate TLS for
/// `CONNECT` requests. Construct it once in `main` with
/// [`CertCache::new`] and pass the same `Arc` to every call of this
/// function across the process's lifetime, so the leaf-certificate cache
/// is actually shared rather than rebuilt per connection.
///
/// `history` is the shared [`History`] store. Every completed exchange
/// (plain proxy or decrypted-tunnel) is recorded into it once the origin's
/// response is in hand — see `record_exchange`.
///
/// # Shutdown
///
/// The server shuts down cleanly when **any** of the following occur:
///
/// * The caller cancels `shutdown` (TUI `exit` / `Esc`).
/// * `Ctrl-C` / `SIGINT` is received (signal handler inside this task).
///
/// In both cases:
/// 1. The accept loop exits immediately (no new connections accepted).
/// 2. `status_flag` is set to `false` so the TUI header reverts to `[OFFLINE]`.
/// 3. A shutdown event is logged.
/// 4. In-flight connection tasks (including MITM tunnels spawned by
///    [`handle_connect`]) are left to finish naturally — they own their own
///    `tokio::spawn` handle and are not forcibly aborted.
pub async fn start_proxy(
    addr: &str,
    status_flag: Arc<AtomicBool>,
    shutdown: CancellationToken,
    analyzer: Arc<dyn SiteAnalyzer>,
    cert_cache: Arc<CertCache>,
    history: Arc<History>,
    scope: Arc<Mutex<Scope>>,
    interceptor_engine: Arc<InterceptorEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;

    status_flag.store(true, Ordering::SeqCst);
    logger::log_event(&format!("Proxy Guard successfully initialized on {}", addr));
    logger::log_event(&format!(
        "Proxy Guard TLS MITM CA ready at {} — import it into your client's trust store \
         to intercept HTTPS (CONNECT) traffic without certificate warnings.",
        cert_cache.ca_cert_path()
    ));

    // Internal token so the Ctrl-C handler can also cancel in-flight work.
    // We clone `shutdown` so both paths (TUI exit + signal) converge on the
    // same token the caller holds.
    let signal_shutdown = shutdown.clone();

    // Spawn a lightweight task that waits for Ctrl-C and cancels the token.
    // If the caller already cancelled before Ctrl-C fires, this task exits
    // immediately on the next poll without issuing a duplicate cancel.
    tokio::spawn(async move {
        tokio::select! {
            _ = signal_shutdown.cancelled() => {
                // TUI already requested shutdown — nothing extra to do.
            }
            _ = async {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sigint  = signal(SignalKind::interrupt()).unwrap();
                    let mut sigterm = signal(SignalKind::terminate()).unwrap();
                    tokio::select! {
                        _ = sigint.recv()  => {},
                        _ = sigterm.recv() => {},
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await.ok();
                }
            } => {
                logger::log_event("Proxy Guard received OS signal — shutting down");
                signal_shutdown.cancel();
            }
        }
    });

    // ── Accept loop ───────────────────────────────────────────────────────────
    loop {
        tokio::select! {
            // Prioritise the cancellation signal so a queued accept does not
            // delay shutdown.
            biased;

            _ = shutdown.cancelled() => {
                logger::log_event("Proxy Guard accept loop stopping (shutdown requested)");
                status_flag.store(false, Ordering::SeqCst);
                break;
            }

            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer_addr)) => {
                        logger::debug(&format!("Proxy Guard accepted connection from {}", peer_addr));
                        let io = TokioIo::new(stream);
                        let conn_analyzer = analyzer.clone();
                        let conn_cert_cache = cert_cache.clone();
                        let conn_history = history.clone();
                        let conn_scope = scope.clone();
                        let conn_engine = interceptor_engine.clone();
                        tokio::spawn(async move {
                            // `serve_connection_with_upgrades` is required so
                            // hyper::upgrade::on (used by handle_connect for
                            // CONNECT requests) actually gets handed ownership
                            // of the underlying stream once the 200 response
                            // has been flushed.
                            if let Err(err) = Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(io, hyper::service::service_fn(move |req| {
                                    route_request(req, conn_analyzer.clone(), conn_cert_cache.clone(), conn_history.clone(), conn_scope.clone(), conn_engine.clone())
                                }))
                                .await
                            {
                                logger::log_event(&format!("Proxy Guard connection error: {:?}", err));
                            }
                        });
                    }
                    Err(e) => {
                        // Transient accept errors (e.g. EMFILE) — log and
                        // continue rather than crashing the whole server.
                        logger::log_event(&format!("Proxy Guard accept error (continuing): {}", e));
                    }
                }
            }
        }
    }

    logger::log_event("Proxy Guard shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HOST;

    fn empty_request(uri: &str, host_header: Option<&str>) -> Request<()> {
        let mut builder = Request::builder().uri(uri);
        if let Some(h) = host_header {
            builder = builder.header(HOST, h);
        }
        builder.body(()).unwrap()
    }

    // resolve_target_host takes Request<Incoming> in production, but the
    // logic only touches .uri() and .headers(), so we exercise it through a
    // tiny local re-implementation here to avoid needing a live Incoming
    // body for unit tests. This mirrors resolve_target_host exactly.
    fn resolve_for_test(req: &Request<()>, tunnel_host: Option<&str>) -> String {
        if let Some(host) = req.uri().host() {
            return host.to_string();
        }
        if let Some(host_header) = req.headers().get(HOST).and_then(|v| v.to_str().ok()) {
            let bare = host_header.split(':').next().unwrap_or(host_header);
            if !bare.is_empty() {
                return bare.to_string();
            }
        }
        tunnel_host.unwrap_or("unknown-target").to_string()
    }

    #[test]
    fn absolute_uri_uses_uri_host() {
        let req = empty_request("http://example.com/path", None);
        assert_eq!(resolve_for_test(&req, Some("ignored.example:443")), "example.com");
    }

    #[test]
    fn relative_uri_falls_back_to_host_header() {
        let req = empty_request("/path", Some("example.com:443"));
        assert_eq!(resolve_for_test(&req, None), "example.com");
    }

    #[test]
    fn relative_uri_no_host_header_falls_back_to_tunnel_host() {
        let req = empty_request("/path", None);
        assert_eq!(resolve_for_test(&req, Some("example.com:443")), "example.com");
    }

    #[test]
    fn nothing_available_falls_back_to_unknown() {
        let req = empty_request("/path", None);
        assert_eq!(resolve_for_test(&req, None), "unknown-target");
    }

    #[test]
    fn host_header_with_port_is_stripped() {
        let req = empty_request("/path", Some("api.example.com:8443"));
        assert_eq!(resolve_for_test(&req, None), "api.example.com");
    }
}