use reqwest::Client;
use serde::Serialize;

#[derive(Serialize)]
pub struct RedirectHop {
    pub url: String,
    pub status: String,
}

/// Follow redirects manually to build a hop chain.
///
/// A `HashSet` of visited URLs is maintained so that a cycle (A->B->A) is
/// detected before the next request is issued, rather than burning all
/// remaining hops or looping forever.
pub async fn collect_redirects(client: &Client, start_url: &str, max_hops: usize) -> Vec<RedirectHop> {
    let mut chain = Vec::new();
    let mut current = start_url.to_string();
    let mut visited = std::collections::HashSet::new();

    for _ in 0..max_hops {
        // Cycle guard: if we have already visited this URL, stop immediately.
        if !visited.insert(current.clone()) {
            chain.push(RedirectHop {
                url: current,
                status: "Loop detected".to_string(),
            });
            break;
        }

        match client.get(&current).send().await {
            Ok(resp) => {
                let status = resp.status();
                chain.push(RedirectHop { url: current.clone(), status: status.to_string() });

                if status.is_redirection() {
                    if let Some(loc) = resp.headers().get("location")
                        .and_then(|v| v.to_str().ok())
                    {
                        // Handle relative redirects
                        if loc.starts_with("http://") || loc.starts_with("https://") {
                            current = loc.to_string();
                        } else {
                            let base = current.trim_end_matches('/');
                            current = format!("{}/{}", base, loc.trim_start_matches('/'));
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    chain
}
