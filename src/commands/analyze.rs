//! Analyze-Site, Analyze-Site-Json, Analyze-Email, Export-CA handlers.

use crate::{dns_guard, web_analyzer};
use super::CommandContext;

// ── Analyze-Site-Json ─────────────────────────────────────────────────────────

pub fn analyze_site_json(ctx: &mut CommandContext<'_>, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() == 1 {
        let result = ctx.rt.block_on(web_analyzer::analyze_site(parts[0], ctx.no_follow, ctx.follow));
        *ctx.popup_text = web_analyzer::export_to_json(&result);

        let filename = format!("{}_report.json", parts[0].replace(':', "_"));
        match web_analyzer::save_to_file(&result, &filename) {
            Ok(_) => *ctx.output_buffer = format!("✅ JSON saved to {}", filename),
            Err(e) => *ctx.output_buffer = format!("❌ Save failed: {}", e),
        }
        *ctx.popup_scroll = 0;
        *ctx.show_popup = true;
    } else {
        *ctx.output_buffer = "Usage: Analyze-Site-Json <domain>".to_string();
    }
}

// ── Analyze-Email ─────────────────────────────────────────────────────────────

pub fn analyze_email(ctx: &mut CommandContext<'_>, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() == 1 {
        let domain = parts[0];
        let records = dns_guard::audit_email_security(domain);
        let mut text = format!("┌─[ EMAIL SECURITY: {} ]─────────────────────\n", domain);
        text.push_str(&format!("│  SPF:   {}\n", records.spf.as_deref().unwrap_or("❌ Not found")));
        text.push_str(&format!("│  DMARC: {}\n", records.dmarc.as_deref().unwrap_or("❌ Not found")));
        text.push_str(&format!(
            "│  DKIM:  {}\n",
            if records.dkim_selector_found { "✅ Found (common selector)" } else { "⚠️  Not detected" }
        ));
        text.push_str(&format!("│  {}\n", records.summary));
        text.push_str("└────────────────────────────────────────────\n");
        *ctx.popup_text = text;
        *ctx.popup_scroll = 0;
        *ctx.show_popup = true;
        *ctx.output_buffer = format!("✅ Email security checked: {}", domain);
    } else {
        *ctx.output_buffer = "Usage: Analyze-Email <domain>".to_string();
    }
}

// ── Analyze-Site ──────────────────────────────────────────────────────────────

pub fn analyze_site(ctx: &mut CommandContext<'_>, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() == 1 {
        let result = ctx.rt.block_on(web_analyzer::analyze_site(parts[0], ctx.no_follow, ctx.follow));
        *ctx.popup_text = web_analyzer::format_analysis(&result);
        *ctx.popup_scroll = 0;
        *ctx.show_popup = true;
        *ctx.output_buffer = format!("✅ Scan complete: {}", parts[0]);
    } else {
        *ctx.output_buffer = "Usage: Analyze-Site <domain>".to_string();
    }
}

// ── Export-CA ─────────────────────────────────────────────────────────────────

pub fn export_ca(ctx: &mut CommandContext<'_>) {
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    match ctx.cert_cache.export_ca_to(&cwd) {
        Ok(dest_path) => {
            let mut text = String::from(
                "┌─[ EXPORT CA: cogitator_ca.pem ]──────────────\n",
            );
            text.push_str(&format!("│  Copied to: {}\n", dest_path.display()));
            text.push_str("│\n");
            text.push_str("│  CHROME / EDGE (chromium-based):\n");
            text.push_str("│    Settings → Privacy and security → Security →\n");
            text.push_str("│    Manage certificates → Authorities tab → Import.\n");
            text.push_str("│    Select the file above, check \"Trust this\n");
            text.push_str("│    certificate for identifying websites\", confirm.\n");
            text.push_str("│\n");
            text.push_str("│  FIREFOX:\n");
            text.push_str("│    Settings → Privacy & Security → Certificates →\n");
            text.push_str("│    View Certificates → Authorities tab → Import.\n");
            text.push_str("│    Select the file above, check \"Trust this CA to\n");
            text.push_str("│    identify websites\", confirm.\n");
            text.push_str("│\n");
            text.push_str("│  OS TRUST STORE:\n");
            text.push_str("│    Windows: double-click the .pem → Install\n");
            text.push_str("│      Certificate → Local Machine → place in\n");
            text.push_str("│      \"Trusted Root Certification Authorities\".\n");
            text.push_str("│    macOS: open in Keychain Access → System keychain\n");
            text.push_str("│      → set \"Always Trust\" for this certificate.\n");
            text.push_str("│    Linux (Debian/Ubuntu): copy to\n");
            text.push_str("│      /usr/local/share/ca-certificates/ as a .crt\n");
            text.push_str("│      file, then run `sudo update-ca-certificates`.\n");
            text.push_str("│\n");
            text.push_str("│  ⚠ This CA can decrypt any TLS traffic from a\n");
            text.push_str("│    client that trusts it. Only install it on\n");
            text.push_str("│    machines/browsers you control and intend to\n");
            text.push_str("│    MITM-inspect with Cogitator.\n");
            text.push_str("└────────────────────────────────────────────\n");
            *ctx.popup_text = text;
            *ctx.popup_scroll = 0;
            *ctx.show_popup = true;
            *ctx.output_buffer = format!("✅ CA exported to {}", dest_path.display());
        }
        Err(e) => {
            *ctx.output_buffer = format!(
                "❌ Export-CA failed: {} (has the proxy generated {} yet?)",
                e,
                ctx.cert_cache.ca_cert_path()
            );
        }
    }
}
