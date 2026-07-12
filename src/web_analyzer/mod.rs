pub mod types;
pub mod redirects;
pub mod cors;
pub mod http_methods;
pub mod clickjacking;
pub mod fingerprint;
pub mod scoring;
pub mod formatter;
pub mod analyzer;
pub(crate) mod utils;

pub use types::{SCHEMA_VERSION, WebAnalysisResult, export_to_json, save_to_file};
pub use clickjacking::ClickjackingAudit;
pub use cors::CorsAudit;
pub use fingerprint::PassiveTechFingerprint;
pub use http_methods::HttpMethodAudit;
pub use redirects::RedirectHop;
pub use formatter::format_analysis;
pub use analyzer::{analyze_site, build_clients, DefaultSiteAnalyzer, SiteAnalyzer};
