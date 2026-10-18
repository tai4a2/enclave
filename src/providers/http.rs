//! Shared HTTP client construction honouring the `[network]` settings.
//!
//! Two hardening features are applied here, once, for every provider:
//!
//! * **Proxy / Tor** — an explicit `proxy` URL (e.g. `socks5h://127.0.0.1:9050`)
//!   or `tor = true` routes all provider traffic through a local Tor SOCKS
//!   proxy. `socks5h` resolves DNS remotely so the origin is not leaked.
//! * **TLS certificate pinning** — when `tls_pin` is set (SHA-256 of the
//!   provider's leaf certificate DER, hex) the TLS handshake succeeds only if
//!   the server presents exactly that certificate.
use std::sync::OnceLock;

use crate::config::NetworkSettings;

static NETWORK: OnceLock<NetworkSettings> = OnceLock::new();

/// Store the process-wide network settings (called once at startup).
pub fn set_network(cfg: NetworkSettings) {
    let _ = NETWORK.set(cfg);
}

fn configured() -> Option<&'static NetworkSettings> {
    NETWORK.get()
}

/// Resolve the effective proxy URL: an explicit `proxy` wins, then `tor`
/// implies the local Tor SOCKS proxy.
pub fn proxy_url(cfg: &NetworkSettings) -> Option<String> {
    if let Some(p) = cfg.proxy.as_ref().filter(|p| !p.trim().is_empty()) {
        return Some(p.clone());
    }
    if cfg.tor {
        return Some("socks5h://127.0.0.1:9050".to_string());
    }
    None
}

/// Parse a hex (optionally `:`-separated) SHA-256 pin into 32 bytes.
pub fn parse_pin(s: &str) -> Option<[u8; 32]> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    } else {
        None
    }
}

/// Build a provider HTTP client applying proxy/Tor/pinning from `[network]`.
pub fn client() -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if let Some(cfg) = configured() {
        if let Some(url) = proxy_url(cfg) {
            if let Ok(proxy) = reqwest::Proxy::all(&url) {
                builder = builder.proxy(proxy);
            }
        }
        if let Some(pin) = cfg.tls_pin.as_deref().filter(|p| !p.trim().is_empty()) {
            if let Some(tls) = pinned_tls_config(pin) {
                builder = builder.use_preconfigured_tls(tls);
            }
        }
    }
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// Build a rustls `ClientConfig` that verifies the certificate chain normally
/// and then requires the leaf certificate to match the pinned SHA-256.
fn pinned_tls_config(pin: &str) -> Option<rustls::ClientConfig> {
    use std::sync::Arc;

    let pin = parse_pin(pin)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .ok()?;
    let verifier = Arc::new(PinningVerifier { inner, pin });

    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
        .into()
}

/// A certificate verifier that runs normal WebPKI validation and additionally
/// requires the leaf certificate to match a pinned SHA-256 fingerprint.
#[derive(Debug)]
struct PinningVerifier {
    inner: std::sync::Arc<rustls::client::WebPkiServerVerifier>,
    pin: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let ok = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.pin {
            Ok(ok)
        } else {
            Err(rustls::Error::General(
                "TLS certificate pin mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_proxy_wins_over_tor() {
        let cfg = NetworkSettings {
            proxy: Some("socks5h://127.0.0.1:9000".into()),
            tor: true,
            tls_pin: None,
        };
        assert_eq!(proxy_url(&cfg).as_deref(), Some("socks5h://127.0.0.1:9000"));
    }

    #[test]
    fn tor_implies_the_default_socks_proxy() {
        let cfg = NetworkSettings {
            tor: true,
            ..Default::default()
        };
        assert_eq!(proxy_url(&cfg).as_deref(), Some("socks5h://127.0.0.1:9050"));
    }

    #[test]
    fn no_proxy_by_default() {
        assert!(proxy_url(&NetworkSettings::default()).is_none());
    }

    #[test]
    fn parse_pin_accepts_hex_and_colons() {
        let hex64 = "ab".repeat(32);
        assert!(parse_pin(&hex64).is_some());
        let colon = hex64
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap().to_string())
            .collect::<Vec<_>>()
            .join(":");
        assert!(parse_pin(&colon).is_some());
        assert!(parse_pin("deadbeef").is_none());
        assert!(parse_pin("zz".repeat(32).as_str()).is_none());
    }

    #[test]
    fn client_builds() {
        let _ = client();
    }
}
