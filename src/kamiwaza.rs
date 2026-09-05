use axum::{
    Json,
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::Client;
use reqwest::header::{HeaderName as ReqwestHeaderName, HeaderValue as ReqwestHeaderValue};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::{Value, json};
use std::env;
use std::fmt;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;

use crate::auth_v2::AgentIdentity;
use crate::config::{AppConfig, KamiwazaConfig, KamiwazaDelegationConfig};

const MCP_PROTOCOL_VERSION: &str = "2025-03-26";
const DEFAULT_API_URL_CANDIDATES: &[&str] = &[
    "https://localhost/api",
    "https://host.docker.internal/api",
    "https://traefik/api",
];
const KAMIWAZA_DELEGATION_SECRET_ENV: &str = "KAMIWAZA_DELEGATION_SIGNING_SECRET";
type HmacSha256 = Hmac<sha2::Sha256>;

#[derive(Debug, Clone)]
pub struct KamiwazaTool {
    pub slug: String,
    pub extension_name: String,
    pub mcp_url: String,
    pub tool_name: String,
    pub description: Option<String>,
    pub input_schema: Option<Value>,
}

#[derive(Debug)]
pub enum KamiwazaError {
    Disabled,
    MissingToken,
    MissingDelegationSigningSecret,
    MissingAgentIdentity,
    Request(String),
    Protocol(String),
}

impl fmt::Display for KamiwazaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "Kamiwaza provider is disabled"),
            Self::MissingToken => write!(f, "Kamiwaza provider has no API token configured"),
            Self::MissingDelegationSigningSecret => write!(
                f,
                "Kamiwaza delegated identity is enabled but no signing secret is configured"
            ),
            Self::MissingAgentIdentity => write!(
                f,
                "Kamiwaza delegated identity is required but no authenticated agent identity is available"
            ),
            Self::Request(message) => write!(f, "Kamiwaza request failed: {message}"),
            Self::Protocol(message) => write!(f, "Kamiwaza MCP protocol error: {message}"),
        }
    }
}

impl std::error::Error for KamiwazaError {}

#[derive(Debug, Deserialize)]
struct ExtensionResponse {
    name: String,
    #[serde(rename = "type")]
    extension_type: Option<String>,
    phase: Option<String>,
    #[serde(default)]
    services: Vec<ExtensionServiceStatus>,
    endpoints: Option<ExtensionEndpoints>,
}

#[derive(Debug, Deserialize)]
struct ExtensionServiceStatus {
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    available_replicas: u64,
}

#[derive(Debug, Deserialize)]
struct ExtensionEndpoints {
    external: Option<String>,
    internal: Option<String>,
}

fn trim_nonempty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn api_token(kamiwaza: &KamiwazaConfig) -> Option<String> {
    if let Some(token) = &kamiwaza.api_token
        && let Some(value) = trim_nonempty(token.expose_secret())
    {
        return Some(value);
    }
    env::var("KAMIWAZA_API_KEY")
        .ok()
        .and_then(|value| trim_nonempty(&value))
}

fn delegation_signing_secret(delegation: &KamiwazaDelegationConfig) -> Option<String> {
    if let Some(secret) = &delegation.signing_secret
        && let Some(value) = trim_nonempty(secret.expose_secret())
    {
        return Some(value);
    }
    env::var(KAMIWAZA_DELEGATION_SECRET_ENV)
        .ok()
        .and_then(|value| trim_nonempty(&value))
}

#[derive(Debug, Clone)]
struct DelegationHeader {
    name: ReqwestHeaderName,
    value: ReqwestHeaderValue,
}

fn build_delegation_header(
    kamiwaza: &KamiwazaConfig,
    identity: Option<&AgentIdentity>,
    tool: &KamiwazaTool,
) -> Result<Option<DelegationHeader>, KamiwazaError> {
    let delegation = &kamiwaza.delegation;
    let secret = delegation_signing_secret(delegation);
    let delegation_requested = delegation.enabled || delegation.required || secret.is_some();
    if !delegation_requested {
        return Ok(None);
    }
    let Some(identity) = identity else {
        if delegation.required {
            return Err(KamiwazaError::MissingAgentIdentity);
        }
        return Ok(None);
    };
    let Some(secret) = secret else {
        return Err(KamiwazaError::MissingDelegationSigningSecret);
    };
    let jwt = build_delegation_jwt(delegation, identity, tool, &secret)?;
    let header_name = ReqwestHeaderName::from_bytes(delegation.header.as_bytes())
        .map_err(|error| KamiwazaError::Protocol(format!("invalid delegation header: {error}")))?;
    let header_value = ReqwestHeaderValue::from_str(&format!("Bearer {jwt}")).map_err(|error| {
        KamiwazaError::Protocol(format!("invalid delegation header value: {error}"))
    })?;
    Ok(Some(DelegationHeader {
        name: header_name,
        value: header_value,
    }))
}

fn build_delegation_jwt(
    delegation: &KamiwazaDelegationConfig,
    identity: &AgentIdentity,
    tool: &KamiwazaTool,
    secret: &str,
) -> Result<String, KamiwazaError> {
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let expires_at = issued_at.saturating_add(delegation.ttl_seconds);
    let header = json!({
        "alg": "HS256",
        "typ": "JWT",
    });
    let claims = json!({
        "iss": delegation.issuer.as_str(),
        "aud": delegation.audience.as_str(),
        "sub": identity.public_id.as_str(),
        "agent_id": identity.id,
        "agent_name": identity.name.as_str(),
        "iat": issued_at,
        "exp": expires_at,
        "scope": "kamiwaza.tool.invoke",
        "tool": tool.slug.as_str(),
        "extension": tool.extension_name.as_str(),
        "mcp_tool": tool.tool_name.as_str(),
    });
    let signing_input = format!("{}.{}", jwt_segment(&header)?, jwt_segment(&claims)?);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| KamiwazaError::Protocol(error.to_string()))?;
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{signing_input}.{signature}"))
}

fn jwt_segment(value: &Value) -> Result<String, KamiwazaError> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|error| KamiwazaError::Protocol(error.to_string()))
}

fn api_url_candidates(kamiwaza: &KamiwazaConfig) -> Vec<String> {
    if let Some(api_url) = &kamiwaza.api_url
        && let Some(value) = trim_nonempty(api_url)
    {
        return vec![value];
    }
    for name in [
        "KAMIWAZA_API_URL",
        "KAMIWAZA_API_URI",
        "KAMIWAZA_BASE_URL",
        "KAMIWAZA_BASE_URI",
    ] {
        if let Ok(value) = env::var(name)
            && let Some(value) = trim_nonempty(&value)
        {
            return vec![value];
        }
    }
    let configured: Vec<String> = kamiwaza
        .api_url_candidates
        .iter()
        .filter_map(|value| trim_nonempty(value))
        .collect();
    if !configured.is_empty() {
        return configured;
    }
    DEFAULT_API_URL_CANDIDATES
        .iter()
        .map(|value| value.to_string())
        .collect()
}

fn build_client(config: &AppConfig, kamiwaza: &KamiwazaConfig) -> Result<Client, KamiwazaError> {
    let mut builder = Client::builder().timeout(Duration::from_secs(kamiwaza.timeout_seconds));
    if !kamiwaza.verify_tls {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if kamiwaza.cloud
        && let Some(proxy_url) = &config.egress_proxy
        && let Ok(proxy) = reqwest::Proxy::all(proxy_url)
    {
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|error| KamiwazaError::Request(error.to_string()))
}

fn sanitize_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_separator = false;
    for ch in value.chars().flat_map(|ch| ch.to_lowercase()) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_was_separator = false;
            continue;
        }
        if !last_was_separator && !out.is_empty() {
            out.push('_');
            last_was_separator = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() { "x".to_string() } else { out }
}

fn tool_slug(prefix: &str, extension_name: &str, tool_name: &str) -> String {
    format!(
        "{}_{}_{}",
        sanitize_component(prefix),
        sanitize_component(extension_name),
        sanitize_component(tool_name)
    )
}

fn extension_is_allowed(kamiwaza: &KamiwazaConfig, extension: &ExtensionResponse) -> bool {
    if !matches!(extension.phase.as_deref(), Some("Running")) {
        return false;
    }
    if !kamiwaza.include_types.is_empty() {
        let extension_type = extension.extension_type.as_deref().unwrap_or("");
        if !kamiwaza
            .include_types
            .iter()
            .any(|expected| expected.eq_ignore_ascii_case(extension_type))
        {
            return false;
        }
    }
    if !extension.services.is_empty()
        && !extension
            .services
            .iter()
            .any(|service| service.ready || service.available_replicas > 0)
    {
        return false;
    }
    if !kamiwaza.extension_names.is_empty()
        && !kamiwaza
            .extension_names
            .iter()
            .any(|pattern| extension_name_matches(pattern, &extension.name))
    {
        return false;
    }
    true
}

/// Case-insensitive glob match where `*` matches any run of characters.
fn extension_name_matches(pattern: &str, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let segments: Vec<&str> = pattern.split('*').collect();
    if segments.len() == 1 {
        return name == pattern.to_ascii_lowercase();
    }
    let lowered: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
    let mut cursor = 0usize;
    for (index, segment) in lowered.iter().enumerate() {
        if segment.is_empty() {
            continue;
        }
        if index == 0 {
            if !name[cursor..].starts_with(segment.as_str()) {
                return false;
            }
            cursor += segment.len();
            continue;
        }
        match name[cursor..].find(segment.as_str()) {
            Some(found) => cursor += found + segment.len(),
            None => return false,
        }
    }
    // A pattern without a trailing `*` must consume to the end.
    if !pattern.ends_with('*')
        && let Some(last) = lowered.last()
        && !last.is_empty()
        && !name.ends_with(last.as_str())
    {
        return false;
    }
    true
}

fn mcp_url_for_extension(extension: &ExtensionResponse) -> Option<String> {
    let endpoint = extension
        .endpoints
        .as_ref()
        .and_then(|endpoints| endpoints.external.as_ref().or(endpoints.internal.as_ref()))?;
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        None
    } else {
        // No trailing slash: the Kamiwaza ingress 307-redirects `/mcp/` to a
        // prefix-stripped plain-http URL, which breaks tool discovery.
        Some(format!("{endpoint}/mcp"))
    }
}

async fn fetch_extensions(
    client: &Client,
    candidates: &[String],
    token: &str,
) -> Result<Vec<ExtensionResponse>, KamiwazaError> {
    let mut last_error = None;
    for candidate in candidates {
        let url = format!("{}/extensions", candidate.trim_end_matches('/'));
        match client.get(&url).bearer_auth(token).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    last_error = Some(format!("{} returned {}", url, resp.status()));
                    continue;
                }
                return resp
                    .json::<Vec<ExtensionResponse>>()
                    .await
                    .map_err(|error| KamiwazaError::Request(error.to_string()));
            }
            Err(error) => {
                last_error = Some(format!("{}: {}", url, error));
            }
        }
    }
    Err(KamiwazaError::Request(last_error.unwrap_or_else(|| {
        "no Kamiwaza API URL candidates configured".to_string()
    })))
}

async fn send_mcp_json(
    client: &Client,
    mcp_url: &str,
    token: &str,
    session_id: Option<&str>,
    delegation: Option<&DelegationHeader>,
    payload: &Value,
) -> Result<(Option<String>, Value), KamiwazaError> {
    let mut request = client
        .post(mcp_url)
        .bearer_auth(token)
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(payload);
    if let Some(session_id) = session_id {
        request = request.header("mcp-session-id", session_id);
    }
    if let Some(delegation) = delegation {
        request = request.header(delegation.name.clone(), delegation.value.clone());
    }
    let response = request
        .send()
        .await
        .map_err(|error| KamiwazaError::Request(error.to_string()))?;
    if response.status() == StatusCode::ACCEPTED {
        return Ok((
            header_value(response.headers(), "mcp-session-id"),
            Value::Null,
        ));
    }
    if !response.status().is_success() {
        return Err(KamiwazaError::Request(format!(
            "MCP endpoint returned {}",
            response.status()
        )));
    }
    let session_id = header_value(response.headers(), "mcp-session-id");
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let text = response
        .text()
        .await
        .map_err(|error| KamiwazaError::Request(error.to_string()))?;
    let payload = parse_mcp_response_body(&content_type, &text)?;
    Ok((session_id, payload))
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(trim_nonempty)
}

fn parse_mcp_response_body(content_type: &str, text: &str) -> Result<Value, KamiwazaError> {
    if content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
    {
        let mut data = String::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(rest.trim_start());
            } else if line.trim().is_empty() && !data.is_empty() {
                break;
            }
        }
        if data.is_empty() {
            return Err(KamiwazaError::Protocol(
                "empty streamable HTTP response".to_string(),
            ));
        }
        serde_json::from_str(&data).map_err(|error| KamiwazaError::Protocol(error.to_string()))
    } else {
        serde_json::from_str(text).map_err(|error| KamiwazaError::Protocol(error.to_string()))
    }
}

async fn close_mcp_session(
    client: &Client,
    mcp_url: &str,
    token: &str,
    session_id: Option<&str>,
    delegation: Option<&DelegationHeader>,
) {
    if let Some(session_id) = session_id {
        let mut request = client
            .delete(mcp_url)
            .bearer_auth(token)
            .header("mcp-session-id", session_id);
        if let Some(delegation) = delegation {
            request = request.header(delegation.name.clone(), delegation.value.clone());
        }
        let _ = request.send().await;
    }
}

async fn initialize_session(
    client: &Client,
    mcp_url: &str,
    token: &str,
    delegation: Option<&DelegationHeader>,
) -> Result<Option<String>, KamiwazaError> {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "agent-locksmith",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    });
    let (session_id, payload) =
        send_mcp_json(client, mcp_url, token, None, delegation, &initialize).await?;
    if payload.get("error").is_some() {
        return Err(KamiwazaError::Protocol(
            "initialize returned error".to_string(),
        ));
    }
    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    });
    let _ = send_mcp_json(
        client,
        mcp_url,
        token,
        session_id.as_deref(),
        delegation,
        &initialized,
    )
    .await?;
    Ok(session_id)
}

async fn list_mcp_tools(
    client: &Client,
    mcp_url: &str,
    token: &str,
) -> Result<Vec<Value>, KamiwazaError> {
    let session_id = initialize_session(client, mcp_url, token, None).await?;
    let list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    });
    let result = send_mcp_json(client, mcp_url, token, session_id.as_deref(), None, &list).await;
    close_mcp_session(client, mcp_url, token, session_id.as_deref(), None).await;
    let payload = result?.1;
    if let Some(error) = payload.get("error") {
        return Err(KamiwazaError::Protocol(format!(
            "tools/list returned error: {}",
            error
        )));
    }
    let tools = payload
        .get("result")
        .and_then(|value| value.get("tools"))
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(tools)
}

struct CachedCatalog {
    expires_at: Instant,
    tools: Vec<KamiwazaTool>,
}

static CATALOG_CACHE: OnceLock<AsyncMutex<Option<CachedCatalog>>> = OnceLock::new();

/// Discovery is several slow MCP round-trips per extension; the `/tools`
/// listing and every proxy call would otherwise re-run it. Serve a cached
/// catalog within its TTL and only re-discover (single-flight, behind the
/// mutex) once it expires.
pub async fn discover_tools(config: &AppConfig) -> Result<Vec<KamiwazaTool>, KamiwazaError> {
    let Some(kamiwaza) = config.kamiwaza.as_ref() else {
        return Ok(Vec::new());
    };
    if !kamiwaza.enabled {
        return Ok(Vec::new());
    }
    let ttl = Duration::from_secs(kamiwaza.catalog_ttl_seconds.max(1));
    let cache = CATALOG_CACHE.get_or_init(|| AsyncMutex::new(None));
    let mut guard = cache.lock().await;
    if let Some(entry) = guard.as_ref()
        && entry.expires_at > Instant::now()
    {
        return Ok(entry.tools.clone());
    }
    let tools = discover_tools_uncached(config).await?;
    *guard = Some(CachedCatalog {
        expires_at: Instant::now() + ttl,
        tools: tools.clone(),
    });
    Ok(tools)
}

/// Drop any cached catalog so the next discovery re-probes immediately.
pub async fn invalidate_catalog_cache() {
    if let Some(cache) = CATALOG_CACHE.get() {
        *cache.lock().await = None;
    }
}

async fn discover_tools_uncached(config: &AppConfig) -> Result<Vec<KamiwazaTool>, KamiwazaError> {
    let Some(kamiwaza) = config.kamiwaza.as_ref() else {
        return Ok(Vec::new());
    };
    if !kamiwaza.enabled {
        return Ok(Vec::new());
    }
    let token = api_token(kamiwaza).ok_or(KamiwazaError::MissingToken)?;
    let client = build_client(config, kamiwaza)?;
    let extensions = fetch_extensions(&client, &api_url_candidates(kamiwaza), &token).await?;

    // Each extension costs several slow serial MCP round-trips; a shared
    // cluster can host dozens, so probe them concurrently with a bounded
    // fan-out instead of walking them one at a time.
    let targets: Vec<(ExtensionResponse, String)> = extensions
        .into_iter()
        .filter(|extension| extension_is_allowed(kamiwaza, extension))
        .filter_map(|extension| mcp_url_for_extension(&extension).map(|url| (extension, url)))
        .collect();
    let concurrency = kamiwaza.discovery_concurrency.max(1);
    let prefix = kamiwaza.tool_prefix.clone();

    let mut discovered =
        futures_util::stream::iter(targets.into_iter().map(|(extension, mcp_url)| {
            let client = &client;
            let token = &token;
            let prefix = &prefix;
            async move {
                let tools = match list_mcp_tools(client, &mcp_url, token).await {
                    Ok(tools) => tools,
                    Err(error) => {
                        tracing::warn!(
                            extension = %extension.name,
                            error = %error,
                            "failed to discover Kamiwaza MCP tools"
                        );
                        return Vec::new();
                    }
                };
                let mut out = Vec::new();
                for tool in tools {
                    let Some(tool_name) = tool
                        .get("name")
                        .and_then(|value| value.as_str())
                        .and_then(trim_nonempty)
                    else {
                        continue;
                    };
                    out.push(KamiwazaTool {
                        slug: tool_slug(prefix, &extension.name, &tool_name),
                        extension_name: extension.name.clone(),
                        mcp_url: mcp_url.clone(),
                        tool_name,
                        description: tool
                            .get("description")
                            .and_then(|value| value.as_str())
                            .and_then(trim_nonempty),
                        input_schema: tool.get("inputSchema").cloned(),
                    });
                }
                out
            }
        }))
        .buffer_unordered(concurrency)
        .collect::<Vec<Vec<KamiwazaTool>>>()
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    discovered.sort_by(|left, right| left.slug.cmp(&right.slug));
    Ok(discovered)
}

pub fn is_configured(config: &AppConfig) -> bool {
    config
        .kamiwaza
        .as_ref()
        .is_some_and(|kamiwaza| kamiwaza.enabled)
}

pub async fn invoke_tool(
    config: &AppConfig,
    discovered: &KamiwazaTool,
    identity: Option<&AgentIdentity>,
    arguments: Value,
) -> Result<Value, KamiwazaError> {
    let kamiwaza = config.kamiwaza.as_ref().ok_or(KamiwazaError::Disabled)?;
    let token = api_token(kamiwaza).ok_or(KamiwazaError::MissingToken)?;
    let client = build_client(config, kamiwaza)?;
    let delegation = build_delegation_header(kamiwaza, identity, discovered)?;
    let session_id =
        initialize_session(&client, &discovered.mcp_url, &token, delegation.as_ref()).await?;
    let call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": discovered.tool_name,
            "arguments": arguments,
        },
    });
    let result = send_mcp_json(
        &client,
        &discovered.mcp_url,
        &token,
        session_id.as_deref(),
        delegation.as_ref(),
        &call,
    )
    .await;
    // Each MCP round-trip through the platform ingress is slow (seconds), so
    // the best-effort session close is detached and not awaited on the call's
    // critical path; the result is already in hand.
    if let Some(session_id) = session_id {
        let client = client.clone();
        let mcp_url = discovered.mcp_url.clone();
        let token = token.clone();
        let delegation = delegation.clone();
        tokio::spawn(async move {
            close_mcp_session(
                &client,
                &mcp_url,
                &token,
                Some(&session_id),
                delegation.as_ref(),
            )
            .await;
        });
    }
    let payload = result?.1;
    if let Some(error) = payload.get("error") {
        return Err(KamiwazaError::Protocol(format!(
            "tools/call returned error: {}",
            error
        )));
    }
    Ok(payload.get("result").cloned().unwrap_or(Value::Null))
}

fn json_error(status: StatusCode, message: impl Into<String>, error_type: &str) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "message": message.into(),
                "type": error_type,
            }
        })),
    )
        .into_response()
}

fn response_json(value: Value) -> Response {
    let mut response = Response::new(Body::from(value.to_string()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

fn query_arguments(query: Option<&str>) -> Value {
    let mut args = serde_json::Map::new();
    if let Some(query) = query {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut parts = pair.splitn(2, '=');
            let Some(key) = parts.next().and_then(trim_nonempty) else {
                continue;
            };
            let value = parts.next().unwrap_or_default();
            args.insert(key, Value::String(value.to_string()));
        }
    }
    Value::Object(args)
}

fn parse_arguments(
    method: &Method,
    query: Option<&str>,
    body: Bytes,
) -> Result<Value, Box<Response>> {
    if body.is_empty() {
        return Ok(query_arguments(query));
    }
    if method != Method::POST && method != Method::PUT && method != Method::PATCH {
        return Err(Box::new(json_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Kamiwaza MCP tool calls with a request body require POST, PUT, or PATCH",
            "method_not_allowed",
        )));
    }
    let value: Value = serde_json::from_slice(&body).map_err(|_| {
        Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "Kamiwaza MCP tool arguments must be a JSON object",
            "bad_request",
        ))
    })?;
    if value.as_object().is_none() {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "Kamiwaza MCP tool arguments must be a JSON object",
            "bad_request",
        )));
    }
    Ok(value)
}

pub async fn handle_proxy_call(
    config: &AppConfig,
    tool_name: &str,
    req: axum::extract::Request<Body>,
) -> Option<Response> {
    if !is_configured(config) {
        return None;
    }
    let discovered = match discover_tools(config).await {
        Ok(tools) => tools,
        Err(error) => {
            return Some(json_error(
                StatusCode::BAD_GATEWAY,
                format!("Kamiwaza discovery failed: {error}"),
                "upstream_error",
            ));
        }
    };
    let tool = discovered.into_iter().find(|tool| tool.slug == tool_name)?;
    let identity = req.extensions().get::<AgentIdentity>().cloned();
    let method = req.method().clone();
    let query = req.uri().query().map(|value| value.to_string());
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return Some(json_error(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
                "bad_request",
            ));
        }
    };
    let arguments = match parse_arguments(&method, query.as_deref(), body) {
        Ok(arguments) => arguments,
        Err(response) => return Some(*response),
    };
    match invoke_tool(config, &tool, identity.as_ref(), arguments).await {
        Ok(result) => Some(response_json(result)),
        Err(error) => Some(json_error(
            StatusCode::BAD_GATEWAY,
            format!("Kamiwaza MCP call failed: {error}"),
            "upstream_error",
        )),
    }
}

pub fn catalog_entry(tool: &KamiwazaTool) -> Value {
    let mut entry = json!({
        "name": tool.slug,
        "type": "mcp",
        "path": format!("/api/{}", tool.slug),
        "description": tool.description.clone().unwrap_or_else(|| {
            format!(
                "Kamiwaza MCP tool {} from extension {}",
                tool.tool_name, tool.extension_name
            )
        }),
        "extension": tool.extension_name,
        "mcpTool": tool.tool_name,
    });
    if let Some(input_schema) = &tool.input_schema {
        entry["inputSchema"] = input_schema.clone();
    }
    entry
}

pub fn filtered_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut response_headers = HeaderMap::new();
    for (name, value) in headers {
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            response_headers.insert(name.clone(), v);
        }
    }
    response_headers
}

#[cfg(test)]
mod extension_name_match_tests {
    use super::extension_name_matches;

    #[test]
    fn exact_name_matches_only_itself() {
        assert!(extension_name_matches(
            "tool-serperdev-kz1",
            "tool-serperdev-kz1"
        ));
        assert!(!extension_name_matches(
            "tool-serperdev-kz1",
            "tool-serperdev-oc2"
        ));
    }

    #[test]
    fn trailing_suffix_wildcard_scopes_to_one_runtime() {
        assert!(extension_name_matches(
            "*-agentzero",
            "tool-serperdev-agentzero"
        ));
        assert!(extension_name_matches(
            "*-agentzero",
            "tool-untrusted-content-agentzero"
        ));
        assert!(!extension_name_matches("*-agentzero", "tool-serperdev-kz1"));
        assert!(!extension_name_matches(
            "*-agentzero",
            "tool-serperdev-agentzero-2"
        ));
    }

    #[test]
    fn leading_and_interior_wildcards() {
        assert!(extension_name_matches(
            "tool-serperdev-*",
            "tool-serperdev-kz1"
        ));
        assert!(extension_name_matches("tool-*-kz1", "tool-serperdev-kz1"));
        assert!(!extension_name_matches(
            "tool-serperdev-*",
            "tool-telegram-kz1"
        ));
    }

    #[test]
    fn case_insensitive() {
        assert!(extension_name_matches(
            "*-AgentZero",
            "tool-serperdev-agentzero"
        ));
    }
}
