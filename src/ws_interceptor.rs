//! WebSocket interception for Proxy Guard.
//!
//! `proxy_guard::handle_proxy_request` detects a WebSocket upgrade request
//! (`Upgrade: websocket` + a `Connection` header whose tokens include
//! `upgrade`) via [`is_websocket_upgrade`] and hands it off to
//! [`intercept_websocket`] instead of the ordinary HTTP forwarding path —
//! once a connection upgrades, hyper's request/response model no longer
//! applies, so control of the raw socket has to be taken over for the
//! lifetime of the connection.
//!
//! ## Flow
//!
//! 1. Compute `Sec-WebSocket-Accept` from the client's `Sec-WebSocket-Key`
//!    and return a `101 Switching Protocols` response immediately.
//! 2. Once that response is flushed, `hyper::upgrade::on` resolves with the
//!    raw client connection (this mirrors `proxy_guard::handle_connect`'s
//!    CONNECT-tunnel pattern — same API, just triggered by `Upgrade:` on an
//!    ordinary request instead of the `CONNECT` method).
//! 3. Independently, dial the real origin (TLS if this WS request arrived
//!    inside a CONNECT/TLS-MITM tunnel — i.e. `wss://` — plain TCP
//!    otherwise) and perform our *own* WS handshake with it, reusing the
//!    client's `Sec-WebSocket-Key` (the origin only needs *a* valid 16-byte
//!    base64 key — there's no requirement that it differ from what the
//!    client sent).
//! 4. Pump frames bidirectionally. Every frame is logged into `History` and,
//!    if `InterceptorEngine::ws_intercept_enabled()` is set, parked for an
//!    operator Forward/Drop/Replace decision before being relayed.
//!
//! ## History representation
//!
//! `RequestRecord` has no WebSocket-specific fields, so frames are recorded
//! using the existing shape, tagged `"websocket"`:
//!   * `method` — opcode name ("Text", "Binary", "Ping", "Pong", "Close", …)
//!   * `path`   — direction ("client→server" / "server→client")
//!   * `body`   — payload preview, capped at `config::WS_PAYLOAD_PREVIEW_BYTES`
//!   * `host`   — the WS target host
//! This keeps `History`/`HistoryFilter` untouched — `InterceptorView`'s 'w'
//! toggle (see `styletui.rs`) just filters on `has_tag: Some("websocket")`.

use crate::config;
use crate::history::{History, RequestRecord};
use crate::interceptor::{InterceptorEngine, WsFrameAction};
use crate::logger;
use crate::tls_mitm;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::convert::Infallible;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Monotonic id generator for WS frame `RequestRecord`s. Separate from
/// `proxy_guard::HISTORY_REQUEST_ID` / `InterceptorEngine::request_counter`
/// since this module pushes straight into `History` without going through
/// either of those call paths.
static WS_HISTORY_ID: AtomicU64 = AtomicU64::new(1);

// ─── Upgrade detection ────────────────────────────────────────────────────────

/// `true` if `headers` carry a WebSocket upgrade request: `Upgrade:
/// websocket` (case-insensitive) plus a `Connection` header whose
/// comma-separated tokens include `upgrade` (also case-insensitive, since
/// `Connection: keep-alive, Upgrade` is common in the wild).
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade_ok = headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    let connection_ok = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("upgrade")))
        .unwrap_or(false);

    upgrade_ok && connection_ok
}

// ─── Minimal SHA-1 + base64 ───────────────────────────────────────────────────
//
// Only used to derive `Sec-WebSocket-Accept` per RFC 6455 §1.3 — a protocol
// handshake step, not a security boundary — so a small self-contained
// implementation avoids pulling in a new crate dependency just for this.

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A827999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62C1D6u32)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = (b0 as u32) << 16 | (b1 as u32) << 8 | b2 as u32;
        out.push(B64_TABLE[(n >> 18 & 0x3F) as usize] as char);
        out.push(B64_TABLE[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { B64_TABLE[(n >> 6 & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_TABLE[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}

/// RFC 6455 §1.3: `Sec-WebSocket-Accept` = base64(SHA1(key + GUID)).
fn compute_accept_key(client_key: &str) -> String {
    let mut buf = client_key.as_bytes().to_vec();
    buf.extend_from_slice(WS_GUID.as_bytes());
    base64_encode(&sha1(&buf))
}

/// Cheap, non-cryptographic mask key generator. RFC 6455 only requires the
/// client-to-server mask be unpredictable enough to defeat naive
/// proxy-cache poisoning — not cryptographically secure — so time-based
/// entropy is sufficient here.
fn random_mask_key() -> [u8; 4] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    nanos.to_le_bytes()
}

// ─── Raw RFC 6455 frame I/O ───────────────────────────────────────────────────

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        OP_CONTINUATION => "Continuation",
        OP_TEXT => "Text",
        OP_BINARY => "Binary",
        OP_CLOSE => "Close",
        OP_PING => "Ping",
        OP_PONG => "Pong",
        _ => "Unknown",
    }
}

struct WsFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// Read one frame off `stream`, unmasking the payload in place if the frame
/// arrived masked (client→server frames always are, per RFC 6455;
/// server→client frames never are — this just handles whichever shows up).
async fn read_frame<S: AsyncReadExt + Unpin>(stream: &mut S) -> io::Result<WsFrame> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;

    let fin = head[0] & 0x80 != 0;
    let opcode = head[0] & 0x0F;
    let masked = head[1] & 0x80 != 0;
    let mut len = (head[1] & 0x7F) as u64;

    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }

    let mask_key = if masked {
        let mut k = [0u8; 4];
        stream.read_exact(&mut k).await?;
        Some(k)
    } else {
        None
    };

    let mut payload = vec![0u8; len as usize];
    if !payload.is_empty() {
        stream.read_exact(&mut payload).await?;
    }

    if let Some(key) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }

    Ok(WsFrame { fin, opcode, payload })
}

/// Write one frame to `stream`. `mask` must be `true` when writing toward
/// the real origin (the proxy is acting as the WS *client* on that side —
/// RFC 6455 mandates clients always mask) and `false` when writing toward
/// the browser/client (the proxy acts as the WS *server* there). Getting
/// this backwards causes some peers to reject the frame outright.
async fn write_frame<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    fin: bool,
    opcode: u8,
    payload: &[u8],
    mask: bool,
) -> io::Result<()> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push((if fin { 0x80 } else { 0x00 }) | opcode);

    let len = payload.len();
    let mask_bit = if mask { 0x80 } else { 0x00 };
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if mask {
        let key = random_mask_key();
        out.extend_from_slice(&key);
        let mut masked = payload.to_vec();
        for (i, b) in masked.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
        out.extend_from_slice(&masked);
    } else {
        out.extend_from_slice(payload);
    }

    stream.write_all(&out).await?;
    stream.flush().await
}

// ─── Origin connection (plain TCP or TLS, depending on ws:// vs wss://) ──────

/// Either side of a duplex stream to the origin, boxed behind the standard
/// async traits so `pump_direction` doesn't need to be generic over which
/// variant was dialed.
type BoxedRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

/// Dial the real origin for `host` (bare hostname or `"host:port"`) and
/// return its read/write halves. Mirrors
/// `tls_mitm::forward_to_origin`'s connection setup, but kept separate here
/// since that function buffers a full HTTP response rather than handing
/// back a live duplex stream — not reusable for an upgrade.
async fn dial_origin(host: &str, use_tls: bool) -> io::Result<(BoxedRead, BoxedWrite)> {
    let (bare_host, port) = match host.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => (host, if use_tls { 443 } else { 80 }),
        },
        None => (host, if use_tls { 443 } else { 80 }),
    };

    let tcp = TcpStream::connect((bare_host, port)).await?;

    if use_tls {
        let server_name = ServerName::try_from(bare_host.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid origin hostname for TLS SNI"))?;
        let connector = TlsConnector::from(tls_mitm::origin_client_config());
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("origin TLS handshake failed: {e}")))?;
        let (r, w) = tokio::io::split(tls_stream);
        Ok((Box::new(r), Box::new(w)))
    } else {
        let (r, w) = tokio::io::split(tcp);
        Ok((Box::new(r), Box::new(w)))
    }
}

/// Send the WS upgrade request to the origin and read its response,
/// returning once the `101 Switching Protocols` line has been consumed (so
/// whatever's left in the stream is pure WS frames).
async fn perform_origin_handshake(
    writer: &mut BoxedWrite,
    reader: &mut BoxedRead,
    bare_host: &str,
    path: &str,
    client_key: &str,
) -> io::Result<()> {
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {bare_host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {client_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read the origin's response headers byte-by-byte until the terminating
    // blank line. A WS handshake response is small (a handful of headers),
    // so this isn't worth pulling in a buffered reader for.
    let mut header_bytes = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).await?;
        header_bytes.push(byte[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_bytes.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "origin handshake response too large"));
        }
    }

    let header_text = String::from_utf8_lossy(&header_bytes);
    let status_line = header_text.lines().next().unwrap_or("");
    if !status_line.contains("101") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("origin rejected WebSocket upgrade: {status_line}"),
        ));
    }

    Ok(())
}

// ─── Frame pump ───────────────────────────────────────────────────────────────

/// Drain frames from `src`, log + (optionally) freeze each one, then write
/// the resulting frame to `dst`. Runs until `src` closes, errors, or a Close
/// frame is forwarded.
async fn pump_direction<R, W>(
    mut src: R,
    mut dst: W,
    direction: &'static str,
    dst_masks: bool,
    host: String,
    history: Arc<History>,
    engine: Arc<InterceptorEngine>,
) where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    loop {
        let frame = match read_frame(&mut src).await {
            Ok(f) => f,
            Err(e) => {
                logger::debug(&format!("WS Interceptor: {direction} stream ended for {host}: {e}"));
                return;
            }
        };

        let is_close = frame.opcode == OP_CLOSE;
        let opcode_str = opcode_name(frame.opcode).to_string();
        let preview_len = frame.payload.len().min(config::WS_PAYLOAD_PREVIEW_BYTES);
        let preview = frame.payload[..preview_len].to_vec();

        // ── Log into History (always — this is the inspection record) ───
        let id = WS_HISTORY_ID.fetch_add(1, Ordering::SeqCst);
        history.push(RequestRecord {
            id,
            timestamp: Instant::now(),
            method: opcode_str.clone(),
            host: host.clone(),
            path: direction.to_string(),
            headers: Vec::new(),
            body: preview.clone(),
            response_status: None,
            response_headers: Vec::new(),
            response_body: None,
            response_time_ms: None,
            tags: vec!["websocket".to_string()],
            stream_id: None,
        });

        // ── Operator review (Frozen mode), only when explicitly enabled ──
        let outgoing_payload = if engine.ws_intercept_enabled() {
            let rx = engine.freeze_ws_frame(direction, opcode_str, preview);
            match rx.await {
                Ok(WsFrameAction::Forward) => Some(frame.payload),
                Ok(WsFrameAction::Drop) => None,
                Ok(WsFrameAction::Replace(bytes)) => Some(bytes),
                // Sender dropped without a decision (e.g. TUI exited) —
                // fail safe by forwarding the original frame rather than
                // silently eating it.
                Err(_) => Some(frame.payload),
            }
        } else {
            Some(frame.payload)
        };

        if let Some(payload) = outgoing_payload {
            if let Err(e) = write_frame(&mut dst, frame.fin, frame.opcode, &payload, dst_masks).await {
                logger::debug(&format!("WS Interceptor: failed to relay {direction} frame for {host}: {e}"));
                return;
            }
        }

        if is_close {
            return;
        }
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Handle a WebSocket upgrade request: hijack the client connection, dial
/// the real origin and upgrade it too, then proxy frames bidirectionally
/// until either side closes.
///
/// `host` is used for `History`/logging only. `origin_target` is the
/// `"host[:port]"` to actually dial — same shape `tls_mitm::forward_to_origin`
/// expects. `use_tls` is `true` when this request arrived inside a
/// CONNECT/TLS-MITM tunnel (i.e. the original scheme was `wss://`).
pub async fn intercept_websocket(
    req: Request<Incoming>,
    host: String,
    origin_target: String,
    use_tls: bool,
    history: Arc<History>,
    engine: Arc<InterceptorEngine>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let client_key = match req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
    {
        Some(k) => k,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Cogitator: missing Sec-WebSocket-Key on upgrade request")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
        }
    };

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let bare_host = origin_target.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| origin_target.clone());

    let accept_key = compute_accept_key(&client_key);

    logger::log_event(&format!(
        "Proxy Guard: WebSocket upgrade detected for {} {} (origin {})",
        host, path, origin_target
    ));

    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::UPGRADE, HeaderValue::from_static("websocket"))
        .header(hyper::header::CONNECTION, HeaderValue::from_static("Upgrade"))
        .header(
            "sec-websocket-accept",
            HeaderValue::from_str(&accept_key).unwrap_or_else(|_| HeaderValue::from_static("")),
        )
        .body(Full::new(Bytes::new()));

    let response = match response {
        Ok(r) => r,
        Err(_) => return Ok(Response::new(Full::new(Bytes::new()))),
    };

    tokio::spawn(async move {
        let client_upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                logger::log_event(&format!("WS Interceptor: client upgrade failed for {}: {}", host, e));
                return;
            }
        };
        let (client_read, client_write) = tokio::io::split(TokioIo::new(client_upgraded));

        let (mut origin_read, mut origin_write) = match dial_origin(&origin_target, use_tls).await {
            Ok(streams) => streams,
            Err(e) => {
                logger::log_event(&format!(
                    "WS Interceptor: failed to dial origin {} for {}: {}", origin_target, host, e
                ));
                return;
            }
        };

        if let Err(e) =
            perform_origin_handshake(&mut origin_write, &mut origin_read, &bare_host, &path, &client_key).await
        {
            logger::log_event(&format!("WS Interceptor: origin handshake failed for {}: {}", host, e));
            return;
        }

        logger::log_event(&format!("WS Interceptor: tunnel established for {} ({})", host, origin_target));

        let history_c2s = history.clone();
        let history_s2c = history.clone();
        let engine_c2s = engine.clone();
        let engine_s2c = engine.clone();
        let host_c2s = host.clone();
        let host_s2c = host.clone();

        // client→server frames are read unmasked (read_frame already
        // strips the client's mask) and must be re-masked when written to
        // the real origin (the proxy is the WS client on that side).
        let client_to_server = pump_direction(
            client_read,
            origin_write,
            "client→server",
            /* dst_masks */ true,
            host_c2s,
            history_c2s,
            engine_c2s,
        );
        // server→client frames arrive unmasked from the origin and must
        // stay unmasked toward the browser (the proxy is the WS server on
        // that side).
        let server_to_client = pump_direction(
            origin_read,
            client_write,
            "server→client",
            /* dst_masks */ false,
            host_s2c,
            history_s2c,
            engine_s2c,
        );

        tokio::join!(client_to_server, server_to_client);
        logger::log_event(&format!("WS Interceptor: tunnel closed for {}", host));
    });

    Ok(response)
}

// Silence "unused" warnings for the read/write half type aliases — kept for
// documentation purposes even though `dial_origin`'s trait-object return
// type makes them unnecessary at the call site; retained for readers
// looking for the split-stream type names used elsewhere in this module.
#[allow(dead_code)]
type _UnusedReadHalf = ReadHalf<TcpStream>;
#[allow(dead_code)]
type _UnusedWriteHalf = WriteHalf<TcpStream>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc6455_example() {
        // RFC 6455 §1.3 worked example.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(compute_accept_key(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn detects_upgrade_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(hyper::header::CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn rejects_missing_connection_token() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(hyper::header::CONNECTION, HeaderValue::from_static("keep-alive"));
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn rejects_non_websocket_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::UPGRADE, HeaderValue::from_static("h2c"));
        headers.insert(hyper::header::CONNECTION, HeaderValue::from_static("Upgrade"));
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn opcode_names_map_correctly() {
        assert_eq!(opcode_name(OP_TEXT), "Text");
        assert_eq!(opcode_name(OP_BINARY), "Binary");
        assert_eq!(opcode_name(OP_CLOSE), "Close");
        assert_eq!(opcode_name(OP_PING), "Ping");
        assert_eq!(opcode_name(OP_PONG), "Pong");
        assert_eq!(opcode_name(0x3), "Unknown");
    }

    #[tokio::test]
    async fn write_then_read_frame_roundtrips_masked() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, true, OP_TEXT, b"hello", true).await.unwrap();
        let frame = read_frame(&mut b).await.unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, OP_TEXT);
        assert_eq!(frame.payload, b"hello");
    }

    #[tokio::test]
    async fn write_then_read_frame_roundtrips_unmasked() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, true, OP_BINARY, b"\x00\x01\x02", false).await.unwrap();
        let frame = read_frame(&mut b).await.unwrap();
        assert_eq!(frame.opcode, OP_BINARY);
        assert_eq!(frame.payload, vec![0u8, 1, 2]);
    }

    #[tokio::test]
    async fn extended_16bit_length_roundtrips() {
        let (mut a, mut b) = tokio::io::duplex(70_000);
        let payload = vec![0xABu8; 1000];
        write_frame(&mut a, true, OP_BINARY, &payload, true).await.unwrap();
        let frame = read_frame(&mut b).await.unwrap();
        assert_eq!(frame.payload, payload);
    }
}