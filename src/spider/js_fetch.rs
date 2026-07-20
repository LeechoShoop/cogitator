//! Headless-browser fetch helper for the Spider JS execution path.
//!
//! A single [`Browser`] instance is reused across the whole crawl (see
//! [`launch_browser`]). Each page fetch opens a new tab, waits up to 5 s
//! for the network to go idle, captures the rendered HTML via
//! [`Page::content`], then closes the tab.
//!
//! On any error (browser not found, tab crash, timeout) [`fetch_js`] returns
//! `None`; the caller in `mod.rs` then falls back to a plain `reqwest` GET.

use std::sync::Arc;
use std::time::Duration;

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::Page;
use futures::StreamExt; // required for Handler::next() — futures is a direct dep

use crate::logger;

// ─── Browser lifecycle ────────────────────────────────────────────────────────

/// Launch a headless Chromium browser and return the handle.
///
/// Also spawns the mandatory CDP handler task on the current Tokio runtime.
/// The caller should store the returned `Browser` in an `Arc` and share it
/// across all worker tasks; the handler task exits automatically when the last
/// `Arc<Browser>` clone is dropped.
///
/// Returns an error if Chrome/Chromium is not found on `PATH` or fails to
/// start; the orchestrator falls back to the static reqwest path in that case.
pub(super) async fn launch_browser() -> Result<Browser, Box<dyn std::error::Error + Send + Sync>> {
    let config = BrowserConfig::builder()
        .arg("--headless=new")
        .arg("--no-sandbox")
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .build()
        .map_err(|e| format!("chromiumoxide: BrowserConfig error: {e}"))?;

    let (browser, mut handler) = Browser::launch(config).await?;

    // The handler *must* be polled to keep the CDP connection alive.
    tokio::spawn(async move {
        while let Some(event) = handler.next().await {
            if event.is_err() {
                break;
            }
        }
    });

    Ok(browser)
}

// ─── Per-URL fetch ────────────────────────────────────────────────────────────

/// Navigate `url` in a fresh browser tab, wait for network idle (≤ 5 s), and
/// return the rendered HTML.
///
/// Returns `None` on any failure so the caller can fall back to a static
/// `reqwest` fetch without interrupting the crawl.
pub(super) async fn fetch_js(
    browser: &Arc<Browser>,
    url: &str,
    user_agent: &str,
) -> Option<String> {
    let page = match new_page(browser, url, user_agent).await {
        Ok(p) => p,
        Err(e) => {
            logger::warn(&format!(
                "spider[js]: failed to open tab for {url}: {e} — falling back to static fetch"
            ));
            return None;
        }
    };

    // Wait up to 5 s for network idle; a timeout is not fatal — we still try
    // to capture whatever content has rendered so far.
    let wait_result = tokio::time::timeout(
        Duration::from_secs(5),
        page.wait_for_navigation(),
    )
    .await;

    match wait_result {
        Err(_elapsed) => {
            logger::warn(&format!(
                "spider[js]: network-idle timeout for {url}, capturing partial content"
            ));
        }
        Ok(Err(e)) => {
            logger::warn(&format!(
                "spider[js]: navigation wait error for {url}: {e}, capturing partial content"
            ));
        }
        Ok(Ok(_)) => {}
    }

    let html = match page.content().await {
        Ok(h) => h,
        Err(e) => {
            logger::warn(&format!(
                "spider[js]: failed to get content for {url}: {e} — falling back to static fetch"
            ));
            close_page(page, url).await;
            return None;
        }
    };

    close_page(page, url).await;
    Some(html)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async fn new_page(
    browser: &Arc<Browser>,
    url: &str,
    user_agent: &str,
) -> Result<Page, chromiumoxide::error::CdpError> {
    // Open a new tab, set UA, then navigate.
    let page = browser.new_page("about:blank").await?;
    page.set_user_agent(user_agent).await?;
    page.goto(url).await?;
    Ok(page)
}

async fn close_page(page: Page, url: &str) {
    if let Err(e) = page.close().await {
        logger::debug(&format!("spider[js]: failed to close tab for {url}: {e}"));
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: launch a real browser, navigate to `about:blank`, confirm
    /// `page.content()` returns valid HTML.
    ///
    /// Gated behind both `--features js-spider` (so CI without Chrome skips
    /// it) and `#[ignore]` (so `cargo test` does not block on it by default).
    ///
    /// Run with:
    ///   cargo test --features js-spider spider::js_fetch -- --ignored
    #[cfg(feature = "js-spider")]
    #[ignore]
    #[tokio::test]
    async fn browser_renders_about_blank() {
        let browser = launch_browser()
            .await
            .expect("Chrome/Chromium must be on PATH to run this test");
        let browser = Arc::new(browser);

        let page = browser
            .new_page("about:blank")
            .await
            .expect("should open a new tab");

        let html = page.content().await.expect("should return HTML");
        assert!(
            html.to_lowercase().contains("<html"),
            "expected an HTML document, got: {html:?}"
        );

        let _ = page.close().await;
    }
}
