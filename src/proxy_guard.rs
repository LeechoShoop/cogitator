use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use crate::logger;
use crate::web_analyzer::SiteAnalyzer;

/// Handle a single proxied request: analyse the target domain and write a report.
///
/// `analyzer` is the shared [`SiteAnalyzer`] constructed in `main`.  Using the
/// trait rather than raw clients lets tests substitute a stub implementation
/// without spinning up a real HTTP stack.
async fn handle_proxy_request(
    req: Request<Incoming>,
    analyzer: Arc<dyn SiteAnalyzer>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let uri    = req.uri().to_string();
    let host   = req.uri().host().unwrap_or("unknown-target").to_string();

    logger::log_event(&format!("Proxy Guard Intercepted: {} {}", method, uri));

    let analysis_result = analyzer.analyze(&host).await;
    let report = analyzer.format(&analysis_result);

    let safe_domain = host.replace(':', "_");
    let filename    = format!("{}_proxy_report.txt", safe_domain);

    if let Err(e) = std::fs::write(&filename, report) {
        logger::log_event(&format!("Failed to write proxy report to {}: {}", filename, e));
    } else {
        logger::log_event(&format!("Proxy Guard report saved to {}", filename));
    }

    Ok(Response::new(Full::new(Bytes::from(
        format!("Cogitator Proxy Guard analyzed: {}", host)
    ))))
}

/// Start the proxy server.
///
/// `analyzer` is the shared [`SiteAnalyzer`] forwarded to every
/// [`handle_proxy_request`] call.  Pass a [`crate::web_analyzer::DefaultSiteAnalyzer`]
/// in production or a stub in tests.
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
/// 4. In-flight connection tasks are left to finish naturally — they own their
///    own `tokio::spawn` handle and are not forcibly aborted.
pub async fn start_proxy(
    addr: &str,
    status_flag: Arc<AtomicBool>,
    shutdown: CancellationToken,
    analyzer: Arc<dyn SiteAnalyzer>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;

    status_flag.store(true, Ordering::SeqCst);
    logger::log_event(&format!("Proxy Guard successfully initialized on {}", addr));

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
                        tokio::spawn(async move {
                            if let Err(err) = Builder::new(TokioExecutor::new())
                                .serve_connection(io, hyper::service::service_fn(move |req| {
                                    handle_proxy_request(req, conn_analyzer.clone())
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