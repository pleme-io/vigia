// Parse the saguão 4-part hostname back into (app, cluster, location)
// so vigia can extract the requested service from the X-Original-URL
// header that nginx forwards.

use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTarget {
    pub app: String,
    pub cluster: String,
    pub location: String,
}

#[derive(Debug, Error)]
pub enum HostnameError {
    #[error("missing host in URL")]
    MissingHost,
    #[error("not a 4-part saguão hostname: {0}")]
    NotFourPart(String),
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
}

/// Parse `<app>.<cluster>.<location>.quero.cloud` (or any
/// 4-part-then-tld shape) into its components.
///
/// The TLD is allowed to be more than two labels (e.g., `co.uk`),
/// so we treat everything from `<app>` through the cluster/location
/// as the prefix and the rest as the TLD.
///
/// Logic: split on `.`, take the first three labels as
/// (app, cluster, location). The remainder is the TLD; it must have
/// at least 2 labels (e.g., `quero.cloud`).
pub fn parse(host: &str) -> Result<ServiceTarget, HostnameError> {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 5 {
        return Err(HostnameError::NotFourPart(host.into()));
    }
    Ok(ServiceTarget {
        app: labels[0].into(),
        cluster: labels[1].into(),
        location: labels[2].into(),
    })
}

/// Extract the host from a URL string and parse it.
pub fn parse_url(url: &str) -> Result<ServiceTarget, HostnameError> {
    let parsed = Url::parse(url).map_err(|e| HostnameError::InvalidUrl(e.to_string()))?;
    let host = parsed.host_str().ok_or(HostnameError::MissingHost)?;
    parse(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_4_part() {
        let t = parse("vault.rio.bristol.quero.cloud").unwrap();
        assert_eq!(t.app, "vault");
        assert_eq!(t.cluster, "rio");
        assert_eq!(t.location, "bristol");
    }

    #[test]
    fn parses_url_form() {
        let t = parse_url("https://photos.mar.parnamirim.quero.cloud/album/1").unwrap();
        assert_eq!(t.app, "photos");
        assert_eq!(t.cluster, "mar");
        assert_eq!(t.location, "parnamirim");
    }

    #[test]
    fn rejects_3_part() {
        let r = parse("vault.quero.cloud");
        assert!(r.is_err());
    }

    #[test]
    fn rejects_2_part() {
        let r = parse("quero.cloud");
        assert!(r.is_err());
    }

    #[test]
    fn handles_subpaths_in_url() {
        // Subpath shouldn't affect parsing.
        let t = parse_url("https://chat.rio.bristol.quero.cloud/api/v1/messages").unwrap();
        assert_eq!(t.app, "chat");
    }
}
