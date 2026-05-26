use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::deprecation::{DeprecationDisposition, DeprecationRegistry, default_registry};
use crate::secret::SecretRef;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub listen: ListenConfig,
    pub inbound_auth: Option<InboundAuthConfig>,
    pub egress_proxy: Option<String>,
    pub kamiwaza: Option<KamiwazaConfig>,
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    #[serde(default)]
    pub tools: Vec<ToolConfig>,
    /// Path to the operator credentials YAML file (M2). Required iff
    /// `listen.admin_socket` is set; main.rs validates the pairing at
    /// startup. Cleartext operator tokens are NOT here — only argon2 hashes
    /// and metadata.
    pub operator_credentials_path: Option<PathBuf>,
    /// SQLite database location (M2). Required iff `listen.admin_socket`
    /// is set; main.rs validates the pairing at startup.
    pub database: Option<DatabaseConfig>,
    /// Audit subsystem tuning (M3). Optional — daemon applies defaults
    /// (90-day retention, hourly sweep) when absent.
    pub audit: Option<AuditConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Days of audit history to retain. Rows older than `now -
    /// retention_days` are deleted by the sweeper. Default 90 (Q-26 C).
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,
    /// Sweep cadence in seconds. Default 3600 (hourly).
    #[serde(default = "default_audit_sweep_interval_seconds")]
    pub sweep_interval_seconds: u64,
    /// Optional JSONL mirror — when set, every successful SQL audit
    /// insert is also appended to this path (PRD §14.1 #6).
    #[serde(default)]
    pub jsonl_path: Option<PathBuf>,
    /// Cap on a single rotated JSONL file's size in bytes. Default
    /// 100 MiB. Only consulted when `jsonl_path` is set.
    #[serde(default = "default_jsonl_max_bytes")]
    pub jsonl_max_bytes: u64,
    /// Number of rotated JSONL files to keep. Default 14.
    #[serde(default = "default_jsonl_keep_files")]
    pub jsonl_keep_files: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention_days: default_audit_retention_days(),
            sweep_interval_seconds: default_audit_sweep_interval_seconds(),
            jsonl_path: None,
            jsonl_max_bytes: default_jsonl_max_bytes(),
            jsonl_keep_files: default_jsonl_keep_files(),
        }
    }
}

fn default_audit_retention_days() -> u32 {
    90
}

fn default_audit_sweep_interval_seconds() -> u64 {
    3600
}

fn default_jsonl_max_bytes() -> u64 {
    100 * 1024 * 1024
}

fn default_jsonl_keep_files() -> usize {
    14
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    #[serde(default = "default_drain_window")]
    pub drain_window_seconds: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_window_seconds: default_drain_window(),
        }
    }
}

fn default_drain_window() -> u64 {
    crate::shutdown::DEFAULT_DRAIN_WINDOW_SECS
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Optional admin Unix-domain-socket listener (M2). When present the
    /// daemon binds the admin router (C-2) at this path with mode 0660.
    /// Absent ⇒ M0/M1 backward-compat behavior (TCP listener only).
    pub admin_socket: Option<AdminSocketConfig>,
    /// Optional admin HTTPS listener (M4 / C-3, SPEC §4.2.5). When present
    /// AND `enabled: true`, the daemon binds a TLS-terminated TCP listener
    /// that serves the same admin router as `admin_socket` (C-2). The
    /// fields under this block are listener-shape (R-N5 carve-out): a
    /// change to host/port/cert_path/key_path requires a daemon restart.
    pub admin_https: Option<AdminHttpsConfig>,
    /// Agent-listener authentication mode (M6 / T6.6). Default `bearer`
    /// preserves M0..M5 behavior. `mtls` requires a valid client cert
    /// AND no bearer header. `both` tries mTLS first; on missing-cert
    /// falls back to bearer. See `docs/v2/runbooks/m6-mtls-migration.md`
    /// for the rolling-migration recipe.
    #[serde(default)]
    pub auth_mode: AuthMode,
    /// mTLS configuration for the agent listener (M6). Required when
    /// `auth_mode` is `mtls` or `both`; ignored otherwise.
    pub mtls: Option<MtlsConfig>,
    /// Optional bootstrap-only listener (M6 / T6.8 / C-4). Off by
    /// default. When enabled, exposes a TLS-terminated TCP endpoint
    /// that accepts only `POST /admin/agent/register` for onboarding
    /// agents in mtls-only deployments.
    pub bootstrap_only: Option<BootstrapOnlyConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BootstrapOnlyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_bootstrap_host")]
    pub host: String,
    #[serde(default = "default_bootstrap_port")]
    pub port: u16,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

fn default_bootstrap_host() -> String {
    "127.0.0.1".to_string()
}

fn default_bootstrap_port() -> u16 {
    9202
}

/// Agent-listener authentication mode (T6.6).
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Bearer token in `Authorization: Bearer ...`. M0..M5 default.
    #[default]
    Bearer,
    /// Client cert presented at TLS handshake; bearer header is rejected.
    Mtls,
    /// Both supported. Listener tries mTLS first; if no client cert is
    /// presented, falls back to bearer.
    Both,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MtlsConfig {
    /// PEM CA bundle. Every client leaf cert must chain back to one of
    /// these. Required when `auth_mode` is `mtls` or `both`.
    pub ca_bundle_path: PathBuf,
    /// PEM server certificate the agent listener presents at the TLS
    /// handshake. Required when `auth_mode` is `mtls` or `both`. Daemon
    /// fail-fasts if missing or unreadable (same contract as
    /// `admin_https.cert_path` per T4.2).
    #[serde(default)]
    pub server_cert_path: Option<PathBuf>,
    /// PEM (PKCS#8 or RSA) private key matching `server_cert_path`.
    #[serde(default)]
    pub server_key_path: Option<PathBuf>,
    /// Optional CRL URL (T6.3). When set the daemon refreshes the CRL
    /// in the background at `crl_refresh_interval_seconds`.
    #[serde(default)]
    pub crl_url: Option<String>,
    #[serde(default = "default_crl_refresh_interval_seconds")]
    pub crl_refresh_interval_seconds: u64,
    /// Optional emergency blocklist file (T6.4). One hex serial per line.
    #[serde(default)]
    pub blocklist_path: Option<PathBuf>,
    #[serde(default = "default_blocklist_reload_interval_seconds")]
    pub blocklist_reload_interval_seconds: u64,
}

fn default_crl_refresh_interval_seconds() -> u64 {
    3600
}

fn default_blocklist_reload_interval_seconds() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSocketConfig {
    pub path: PathBuf,
}

/// Admin HTTPS listener configuration (C-3, T4.3).
///
/// Off-by-default. The daemon only attempts to bind when `enabled` is
/// true; in that case `cert_path` and `key_path` must point at a valid
/// PEM cert chain and PKCS#8 private key respectively. PEM loading is
/// performed at startup so misconfiguration is fail-fast (T4.2).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminHttpsConfig {
    /// When false (default), the listener is not bound regardless of
    /// other fields. Lets operators leave the block in their config
    /// during onboarding without accidentally exposing the admin
    /// surface.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_https_host")]
    pub host: String,
    #[serde(default = "default_admin_https_port")]
    pub port: u16,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Operator-side authentication mode for the admin HTTPS listener
    /// (#83 / T6.7 wire-side closure). Default `bearer` preserves M4
    /// behavior. `mtls` requires an operator client cert at the TLS
    /// handshake and rejects the bearer header. `both` accepts either.
    #[serde(default)]
    pub auth_mode: AuthMode,
    /// Required when `auth_mode` is `mtls` or `both`. Names the CA
    /// bundle that operator client certs must chain back to.
    pub mtls: Option<AdminHttpsMtlsConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminHttpsMtlsConfig {
    /// PEM CA bundle for operator client certs. Mirrors the agent-side
    /// `listen.mtls.ca_bundle_path` shape.
    pub ca_bundle_path: PathBuf,
}

fn default_admin_https_host() -> String {
    "127.0.0.1".to_string()
}

fn default_admin_https_port() -> u16 {
    9201
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    9200
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundAuthConfig {
    pub mode: String,
    pub token: Option<SecretString>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Per-tool egress routing (R-F13). Replaces M0's `cloud: bool`.
/// `direct`: route the upstream call without proxy intermediation
/// (LAN-bound services typically). `proxied`: route through the configured
/// `egress_proxy` HTTP CONNECT proxy (typically Pipelock for internet-bound
/// traffic, D-16).
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    /// Preserves M0 default (`cloud: false` ⇒ no proxy).
    #[default]
    Direct,
    Proxied,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConfig {
    pub name: String,
    pub description: String,
    pub upstream: String,
    #[serde(default)]
    pub egress: EgressMode,
    pub auth: Option<ToolAuthConfig>,
    #[serde(default)]
    pub timeouts: ToolTimeouts,
    #[serde(default = "default_body_limit")]
    pub body_limit_bytes: u64,
    /// Per-tool response controls (M7 / T7.1). Optional. When absent
    /// the proxy passes the response through unmodified (M0..M6
    /// behavior).
    #[serde(default)]
    pub response: Option<ResponseControlsConfig>,
}

/// Per-tool response controls. All fields optional; absent fields
/// disable that specific control.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ResponseControlsConfig {
    /// Maximum total bytes accepted from the upstream. Applies to both
    /// non-streaming and streaming responses. Streaming bodies that
    /// exceed the cap emit a truncation marker and close the stream;
    /// non-streaming responses return 502 with `response_size_exceeded`.
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
    /// Whitelist of acceptable upstream Content-Type values. The check
    /// compares the part before any `;` (so `application/json;
    /// charset=utf-8` matches `application/json`). Absent ⇒ no
    /// content-type filtering.
    #[serde(default)]
    pub content_type_allowlist: Option<Vec<String>>,
    /// Regex patterns applied to non-streaming response bodies.
    /// Streaming bypasses redaction (R-N6 first-byte latency budget
    /// doesn't tolerate per-chunk regex). Use M3 / D-18 for streaming
    /// inspection (LlamaFirewall, etc.).
    #[serde(default)]
    pub redaction_patterns: Vec<RedactionPatternConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RedactionPatternConfig {
    /// Stable identifier; appears in `response_redaction` audit rows.
    /// Operators choose a meaningful name (e.g. "openai_key") so audit
    /// queries can filter by pattern source.
    pub id: String,
    pub regex: String,
    /// Replacement text. Defaults to `[REDACTED:<id>]`.
    #[serde(default)]
    pub replacement: Option<String>,
}

/// Per-tool timeout configuration (R-F12).
/// `request_seconds` is the total request timeout (headers + body completion).
/// `idle_seconds` is the per-read inactivity timeout — useful for streaming
/// upstreams where the total duration is unbounded but inactivity should
/// terminate the connection.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolTimeouts {
    #[serde(default = "default_request_seconds")]
    pub request_seconds: u64,
    #[serde(default = "default_idle_seconds")]
    pub idle_seconds: u64,
}

impl Default for ToolTimeouts {
    fn default() -> Self {
        Self {
            request_seconds: default_request_seconds(),
            idle_seconds: default_idle_seconds(),
        }
    }
}

fn default_request_seconds() -> u64 {
    30
}

fn default_idle_seconds() -> u64 {
    60
}

fn default_body_limit() -> u64 {
    10 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAuthConfig {
    pub header: String,
    /// Credential reference (M5). Accepts both the legacy plain-string
    /// form (`value: "Bearer ${TOKEN}"`) and the typed forms (`value:
    /// { from_env: { var: ... } }`, `from_file_sealed`, etc.). See
    /// `crate::secret::SecretRef` for the deserialization contract.
    pub value: SecretRef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KamiwazaConfig {
    #[serde(default)]
    pub enabled: bool,
    pub api_url: Option<String>,
    #[serde(default)]
    pub api_url_candidates: Vec<String>,
    pub api_token: Option<SecretString>,
    #[serde(default = "default_kamiwaza_tool_prefix")]
    pub tool_prefix: String,
    #[serde(default = "default_kamiwaza_include_types")]
    pub include_types: Vec<String>,
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    #[serde(default)]
    pub cloud: bool,
    #[serde(default = "default_kamiwaza_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub delegation: KamiwazaDelegationConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KamiwazaDelegationConfig {
    /// Attach a signed agent-delegation JWT on Kamiwaza MCP tool calls
    /// when an authenticated `AgentIdentity` is present.
    #[serde(default)]
    pub enabled: bool,
    /// When true, reject tool invocations that cannot carry a signed
    /// agent identity. Discovery remains available without identity.
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub signing_secret: Option<SecretString>,
    #[serde(default = "default_kamiwaza_delegation_header")]
    pub header: String,
    #[serde(default = "default_kamiwaza_delegation_issuer")]
    pub issuer: String,
    #[serde(default = "default_kamiwaza_delegation_audience")]
    pub audience: String,
    #[serde(default = "default_kamiwaza_delegation_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for KamiwazaDelegationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            signing_secret: None,
            header: default_kamiwaza_delegation_header(),
            issuer: default_kamiwaza_delegation_issuer(),
            audience: default_kamiwaza_delegation_audience(),
            ttl_seconds: default_kamiwaza_delegation_ttl_seconds(),
        }
    }
}

fn default_kamiwaza_tool_prefix() -> String {
    "kamiwaza".to_string()
}

fn default_kamiwaza_include_types() -> Vec<String> {
    vec!["tool".to_string()]
}

fn default_true() -> bool {
    true
}

fn default_kamiwaza_timeout_seconds() -> u64 {
    30
}

fn default_kamiwaza_delegation_header() -> String {
    "x-kamiwaza-agent-delegation".to_string()
}

fn default_kamiwaza_delegation_issuer() -> String {
    "agent-locksmith".to_string()
}

fn default_kamiwaza_delegation_audience() -> String {
    "kamiwaza-tools".to_string()
}

fn default_kamiwaza_delegation_ttl_seconds() -> u64 {
    60
}

impl AppConfig {
    /// Return tools that are *structurally* active — auth is None, or
    /// auth.value carries something that looks present. Used for
    /// listings and config audits where we don't have access to the
    /// runtime resolved-credentials map. The runtime authority is
    /// `active_tools_against`.
    pub fn active_tools(&self) -> Vec<&ToolConfig> {
        self.tools
            .iter()
            .filter(|t| match &t.auth {
                Some(auth) => auth.value.looks_present(),
                None => true,
            })
            .collect()
    }

    /// Return tools that are active given a resolved-credentials map.
    /// Tools with declared auth must have a non-empty entry in
    /// `resolved`. Tools without auth declarations are always active.
    pub fn active_tools_against<'a>(
        &'a self,
        resolved: &std::collections::HashMap<String, SecretString>,
    ) -> Vec<&'a ToolConfig> {
        self.tools
            .iter()
            .filter(|t| match &t.auth {
                Some(_) => resolved.contains_key(&t.name),
                None => true,
            })
            .collect()
    }
}

/// Expand `${VAR_NAME}` patterns in a string using environment variables.
/// Missing variables expand to empty string.
///
/// NOTE (INF-23): textual pre-parse expansion is fragile when env values
/// contain YAML-significant characters (`:`, leading whitespace, `null`,
/// `true`, `false`, etc.). M2 introduces typed `SecretRef` parsing as the
/// recommended replacement. v2 keeps this behavior for backward compat
/// with M0 deployments.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = env::var(var_name).unwrap_or_default();
            result = format!(
                "{}{}{}",
                &result[..start],
                value,
                &result[start + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

/// Parse YAML text into `AppConfig` after env-var expansion and
/// deprecation interception.
///
/// The pipeline:
/// 1. Expand `${VAR}` patterns in the raw YAML text.
/// 2. Parse to an untyped `serde_yaml::Value` tree.
/// 3. Apply the deprecation registry (T1.5/T1.6/INF-24): rename / remove
///    legacy fields with a one-shot warning per field.
/// 4. Deserialize into typed `AppConfig` with `deny_unknown_fields`. Any
///    remaining unknown field is rejected with a structured error.
pub fn parse_config_str(raw: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let expanded = expand_env_vars(raw);
    let registry = default_registry();
    parse_with_registry(&expanded, &registry)
}

fn parse_with_registry(
    yaml: &str,
    registry: &DeprecationRegistry,
) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    apply_deprecations(&mut value, registry);
    let config: AppConfig = serde_yaml::from_value(value)?;
    validate_response_controls(&config)?;
    Ok(config)
}

/// Compile every `redaction_patterns[].regex` and reject duplicate
/// pattern ids per tool. Catches misconfig at startup so the proxy
/// hot path can pull pre-compiled regexes off `ResponseControls` (the
/// runtime mirror) without ever hitting a parse path.
fn validate_response_controls(cfg: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    for tool in &cfg.tools {
        let Some(rc) = &tool.response else { continue };
        let mut seen = std::collections::HashSet::new();
        for pattern in &rc.redaction_patterns {
            if !seen.insert(pattern.id.as_str()) {
                return Err(format!(
                    "tool `{}`: duplicate redaction_patterns id `{}`",
                    tool.name, pattern.id
                )
                .into());
            }
            regex::Regex::new(&pattern.regex).map_err(|e| -> Box<dyn std::error::Error> {
                format!(
                    "tool `{}`: redaction pattern `{}` regex compile failed: {e}",
                    tool.name, pattern.id
                )
                .into()
            })?;
        }
    }
    Ok(())
}

/// Walk the parsed YAML tree and apply registered deprecation rules
/// in-place. Each registered field encountered emits at most one warning
/// per registry lifetime via `registry.notice(path)`.
fn apply_deprecations(value: &mut serde_yaml::Value, registry: &DeprecationRegistry) {
    let serde_yaml::Value::Mapping(top) = value else {
        return;
    };

    // Top-level: telemetry (removed)
    let telemetry_key = serde_yaml::Value::String("telemetry".to_string());
    if top.contains_key(&telemetry_key) {
        emit_deprecation(registry, "telemetry");
        top.remove(&telemetry_key);
    }

    // tools[]: cloud → egress, timeout_seconds → timeouts.request_seconds.
    let tools_key = serde_yaml::Value::String("tools".to_string());
    if let Some(serde_yaml::Value::Sequence(tools)) = top.get_mut(&tools_key) {
        for tool in tools {
            let serde_yaml::Value::Mapping(tool_map) = tool else {
                continue;
            };
            translate_cloud(tool_map, registry);
            translate_timeout_seconds(tool_map, registry);
        }
    }
}

fn translate_cloud(tool_map: &mut serde_yaml::Mapping, registry: &DeprecationRegistry) {
    let cloud_key = serde_yaml::Value::String("cloud".to_string());
    let egress_key = serde_yaml::Value::String("egress".to_string());
    if let Some(cloud_val) = tool_map.remove(&cloud_key) {
        emit_deprecation(registry, "tools[].cloud");
        // Explicit `egress` wins if both are present.
        if !tool_map.contains_key(&egress_key) {
            let new_egress = match cloud_val {
                serde_yaml::Value::Bool(true) => "proxied",
                serde_yaml::Value::Bool(false) => "direct",
                _ => "direct",
            };
            tool_map.insert(
                egress_key,
                serde_yaml::Value::String(new_egress.to_string()),
            );
        }
    }
}

fn translate_timeout_seconds(tool_map: &mut serde_yaml::Mapping, registry: &DeprecationRegistry) {
    let legacy_key = serde_yaml::Value::String("timeout_seconds".to_string());
    let timeouts_key = serde_yaml::Value::String("timeouts".to_string());
    let request_seconds_key = serde_yaml::Value::String("request_seconds".to_string());
    let Some(legacy_val) = tool_map.remove(&legacy_key) else {
        return;
    };
    emit_deprecation(registry, "tools[].timeout_seconds");
    // Explicit `timeouts.request_seconds` wins if already set; do nothing
    // beyond the warning + drop in that case.
    if let Some(serde_yaml::Value::Mapping(existing_timeouts)) = tool_map.get(&timeouts_key)
        && existing_timeouts.contains_key(&request_seconds_key)
    {
        return;
    }
    // Insert `timeouts.request_seconds: <legacy_val>`, preserving any
    // partial timeouts mapping the operator may have provided.
    let timeouts_entry = tool_map
        .entry(timeouts_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    if let serde_yaml::Value::Mapping(existing) = timeouts_entry {
        existing.insert(request_seconds_key, legacy_val);
    }
}

fn emit_deprecation(registry: &DeprecationRegistry, field_path: &str) {
    if !registry.notice(field_path) {
        return;
    }
    let entry = match registry.lookup(field_path) {
        Some(e) => e,
        None => return,
    };
    match &entry.disposition {
        DeprecationDisposition::Renamed { new_name } => warn!(
            field = field_path,
            replacement = *new_name,
            since_version = entry.since_version,
            removal_target = entry.removal_target.unwrap_or(""),
            "configuration field renamed; replace with the documented field"
        ),
        DeprecationDisposition::Deprecated => warn!(
            field = field_path,
            since_version = entry.since_version,
            removal_target = entry.removal_target.unwrap_or(""),
            "configuration field deprecated; please migrate"
        ),
        DeprecationDisposition::Removed => warn!(
            field = field_path,
            since_version = entry.since_version,
            "configuration field removed; value is ignored"
        ),
    }
}

/// Load config from YAML file. Convenience wrapper over `parse_config_str`
/// that reads the file from disk.
pub fn load_config(path: &Path) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    parse_config_str(&raw)
}
