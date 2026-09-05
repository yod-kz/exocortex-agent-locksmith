//! Per-tool reqwest client pool (T1.3 / INF-25 / Q-27).
//!
//! M0 built a fresh `reqwest::Client` per request, which defeats keep-alive
//! and TLS session reuse. The pool caches one `Arc<Client>` per tool name
//! and rebuilds only when the tool's client-affecting fields change
//! (timeouts, egress, etc.) — detected via a fingerprint stored alongside
//! the cached client.
//!
//! Hot reload of the YAML config (M2 / T2.20) doesn't yet exist; once it
//! does, the pool naturally tracks config changes through fingerprint
//! comparison on each lookup, and `cleanup_removed` purges entries for
//! tools that no longer appear in the active config.

use reqwest::Client;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::{AppConfig, EgressMode, ToolConfig, ToolTimeouts};

/// Stable fingerprint of the tool fields that affect `Client` construction.
/// Two tool configs with the same fingerprint produce equivalent clients;
/// any change forces a rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolFingerprint {
    request_seconds: u64,
    idle_seconds: u64,
    egress: EgressMode,
    egress_proxy_url: Option<String>,
    follow_redirects: bool,
}

impl ToolFingerprint {
    fn of(tool: &ToolConfig, config: &AppConfig) -> Self {
        let mut fingerprint = Self::of_parts(&tool.name, tool.timeouts, tool.egress, config);
        fingerprint.follow_redirects &= tool.request_allowlist.is_none();
        fingerprint
    }

    fn of_parts(
        name: &str,
        timeouts: ToolTimeouts,
        egress: EgressMode,
        config: &AppConfig,
    ) -> Self {
        Self {
            request_seconds: timeouts.request_seconds,
            idle_seconds: timeouts.idle_seconds,
            egress,
            // A redirect would escape the request's exact method/path authorization.
            // Catalog-backed targets inherit any restriction configured by name.
            follow_redirects: !config
                .tools
                .iter()
                .any(|tool| tool.name == name && tool.request_allowlist.is_some()),
            // Egress proxy is shared across tools but only matters when
            // the tool is `proxied`. Including it in the fingerprint means
            // changes to the global proxy URL evict every proxied tool's
            // client (which is the right behavior).
            egress_proxy_url: if matches!(egress, EgressMode::Proxied) {
                config.egress_proxy.clone()
            } else {
                None
            },
        }
    }
}

#[derive(Default)]
pub struct ClientPool {
    entries: RwLock<HashMap<String, (Arc<Client>, ToolFingerprint)>>,
}

impl ClientPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an `Arc<Client>` for `tool`, building (or rebuilding) only if no
    /// cached client matches the tool's current fingerprint.
    pub fn get_or_build(&self, tool: &ToolConfig, config: &AppConfig) -> Arc<Client> {
        let fingerprint = ToolFingerprint::of(tool, config);

        // Fast path: matching cached entry.
        {
            let entries = self
                .entries
                .read()
                .expect("client_pool entries lock poisoned");
            if let Some((client, cached_fp)) = entries.get(&tool.name)
                && cached_fp == &fingerprint
            {
                return Arc::clone(client);
            }
        }

        // Slow path: build a new client and insert. Re-check under the
        // write lock in case another caller raced us to build the same
        // tool's client; a redundant build is fine but redundant insert
        // would replace a possibly-valid entry — checking handles that.
        let mut entries = self
            .entries
            .write()
            .expect("client_pool entries lock poisoned");
        if let Some((client, cached_fp)) = entries.get(&tool.name)
            && cached_fp == &fingerprint
        {
            return Arc::clone(client);
        }
        let client = Arc::new(build_client_for(
            tool.timeouts,
            tool.egress,
            config,
            fingerprint.follow_redirects,
        ));
        entries.insert(tool.name.clone(), (Arc::clone(&client), fingerprint));
        client
    }

    /// Phase E.6 — variant keyed by fields rather than a `ToolConfig`.
    /// Used by the proxy hot path when the target came from the
    /// registrations catalog (no `ToolConfig` available). Same caching
    /// semantics, same fingerprint shape, so registration-sourced and
    /// config-sourced clients share the cache by name when they share
    /// timeouts and egress.
    pub fn get_or_build_for(
        &self,
        name: &str,
        timeouts: ToolTimeouts,
        egress: EgressMode,
        config: &AppConfig,
    ) -> Arc<Client> {
        let fingerprint = ToolFingerprint::of_parts(name, timeouts, egress, config);

        {
            let entries = self
                .entries
                .read()
                .expect("client_pool entries lock poisoned");
            if let Some((client, cached_fp)) = entries.get(name)
                && cached_fp == &fingerprint
            {
                return Arc::clone(client);
            }
        }

        let mut entries = self
            .entries
            .write()
            .expect("client_pool entries lock poisoned");
        if let Some((client, cached_fp)) = entries.get(name)
            && cached_fp == &fingerprint
        {
            return Arc::clone(client);
        }
        let client = Arc::new(build_client_for(
            timeouts,
            egress,
            config,
            fingerprint.follow_redirects,
        ));
        entries.insert(name.to_string(), (Arc::clone(&client), fingerprint));
        client
    }

    /// Remove cache entries for tool names not in `keep`. Called by M2's
    /// hot-reload mechanism after a successful config swap to drop clients
    /// whose tool was removed from configuration.
    pub fn cleanup_removed(&self, keep: &[&str]) {
        let mut entries = self
            .entries
            .write()
            .expect("client_pool entries lock poisoned");
        entries.retain(|name, _| keep.iter().any(|k| *k == name));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .read()
            .expect("client_pool entries lock poisoned")
            .len()
    }
}

fn build_client_for(
    timeouts: ToolTimeouts,
    egress: EgressMode,
    config: &AppConfig,
    follow_redirects: bool,
) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeouts.request_seconds))
        .read_timeout(Duration::from_secs(timeouts.idle_seconds));
    if !follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    // Extra upstream-CA trust (e.g. an internal CA in front of an HTTPS
    // upstream). reqwest's rustls+webpki roots ignore the system store,
    // so private CAs must be named explicitly; this only ADDS roots.
    if let Some(tls) = &config.tls
        && let Some(ca_path) = &tls.upstream_ca_bundle
    {
        builder = add_ca_bundle(builder, ca_path);
    }

    if matches!(egress, EgressMode::Proxied)
        && let Some(proxy_url) = &config.egress_proxy
        && let Ok(proxy) = reqwest::Proxy::all(proxy_url)
    {
        builder = builder.proxy(proxy);
    }

    builder.build().unwrap_or_else(|_| {
        // A degraded client must retain the restriction. Client::new() would
        // silently restore automatic redirects and bypass the request allowlist.
        Client::builder()
            .redirect(if follow_redirects {
                reqwest::redirect::Policy::default()
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()
            .expect("build fallback HTTP client")
    })
}

/// Add each PEM certificate in `ca_path` to the client's root store.
/// Failures degrade to built-in-roots-only with a warning (never a hard
/// error and never accept-invalid-certs — a missing CA file must not
/// silently disable verification).
fn add_ca_bundle(
    mut builder: reqwest::ClientBuilder,
    ca_path: &std::path::Path,
) -> reqwest::ClientBuilder {
    let pem = match std::fs::read(ca_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                path = %ca_path.display(), error = %e,
                "tls.upstream_ca_bundle unreadable; using built-in roots only",
            );
            return builder;
        }
    };
    let mut added = 0usize;
    for block in split_pem_certificates(&pem) {
        match reqwest::Certificate::from_pem(&block) {
            Ok(cert) => {
                builder = builder.add_root_certificate(cert);
                added += 1;
            }
            Err(e) => tracing::warn!(error = %e, "skipping malformed cert in upstream_ca_bundle"),
        }
    }
    if added == 0 {
        tracing::warn!(path = %ca_path.display(), "no usable certs in upstream_ca_bundle");
    } else {
        tracing::info!(path = %ca_path.display(), count = added, "added upstream CA root(s)");
    }
    builder
}

/// Split a PEM file into individual `BEGIN/END CERTIFICATE` blocks so each
/// can be handed to `reqwest::Certificate::from_pem` (which takes one cert).
fn split_pem_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;
    for line in text.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            current.clear();
        }
        if in_cert {
            current.push_str(line);
            current.push('\n');
        }
        if line.contains("END CERTIFICATE") {
            in_cert = false;
            certs.push(current.as_bytes().to_vec());
        }
    }
    certs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ToolConfig, ToolTimeouts};

    fn tool(name: &str, request_seconds: u64) -> ToolConfig {
        ToolConfig {
            name: name.to_string(),
            description: String::new(),
            upstream: "http://x".to_string(),
            egress: EgressMode::Direct,
            credential_handles: Vec::new(),
            request_allowlist: None,
            auth: None,
            timeouts: ToolTimeouts {
                request_seconds,
                idle_seconds: 60,
            },
            body_limit_bytes: 1024,
            response: None,
        }
    }

    fn empty_config() -> AppConfig {
        crate::config::parse_config_str(
            r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
        )
        .unwrap()
    }

    #[test]
    fn returns_same_arc_for_unchanged_tool() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let t = tool("github", 30);
        let a = pool.get_or_build(&t, &cfg);
        let b = pool.get_or_build(&t, &cfg);
        assert!(
            Arc::ptr_eq(&a, &b),
            "second lookup should return the cached Arc"
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rebuilds_when_fingerprint_changes() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let a = pool.get_or_build(&tool("github", 30), &cfg);
        let b = pool.get_or_build(&tool("github", 60), &cfg);
        assert!(
            !Arc::ptr_eq(&a, &b),
            "different fingerprint must produce a new client"
        );
        assert_eq!(pool.len(), 1, "still one entry; old replaced");
    }

    #[test]
    fn independent_entries_per_tool() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let github = pool.get_or_build(&tool("github", 30), &cfg);
        let anthropic = pool.get_or_build(&tool("anthropic", 30), &cfg);
        assert!(!Arc::ptr_eq(&github, &anthropic));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn cleanup_removed_drops_unlisted_entries() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let _g = pool.get_or_build(&tool("github", 30), &cfg);
        let _a = pool.get_or_build(&tool("anthropic", 30), &cfg);
        assert_eq!(pool.len(), 2);
        pool.cleanup_removed(&["anthropic"]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn split_pem_certificates_handles_bundle_and_junk() {
        // Two cert blocks separated by junk + leading/trailing noise.
        let pem = b"# comment\n\
            -----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n\
            some junk between\n\
            -----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\ntrailing\n";
        let blocks = split_pem_certificates(pem);
        assert_eq!(blocks.len(), 2, "two cert blocks");
        let first = String::from_utf8_lossy(&blocks[0]);
        assert!(first.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(first.trim_end().ends_with("-----END CERTIFICATE-----"));
        assert!(first.contains("AAAA") && first.contains("BBBB"));
        assert!(!first.contains("junk"));
        assert!(String::from_utf8_lossy(&blocks[1]).contains("CCCC"));
    }

    #[test]
    fn split_pem_certificates_empty_on_no_certs() {
        assert!(split_pem_certificates(b"no certs here\n").is_empty());
    }

    #[test]
    fn unreadable_ca_bundle_degrades_to_builtin_roots() {
        // A missing CA file must NOT hard-fail or disable verification —
        // build still yields a usable client (built-in roots only).
        let builder = add_ca_bundle(
            Client::builder(),
            std::path::Path::new("/nonexistent/ca.pem"),
        );
        assert!(builder.build().is_ok());
    }
}
