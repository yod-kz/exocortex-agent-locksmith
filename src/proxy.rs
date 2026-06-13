use axum::{
    Json,
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

use crate::app::AppState;
use crate::config::{EgressMode, ToolConfig, ToolTimeouts};
use crate::registrations::{AuthSpec, Registration};
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use crate::response_controls::{ApplyOutcome, ResponseControls, SizeCappedStream};

/// Per-request context snapshot. Built once at the top of `proxy_handler`
/// and threaded through every audit-emitting helper so each call site
/// shares one consistent set of identity / timing / metadata fields.
/// Replaces the pre-M9 pattern of cloning these strings 3-5 times per
/// request inline.
struct RequestCtx {
    tool_name: String,
    request_path: String,
    /// `Method::as_str()` snapshot — kept as `String` so it survives
    /// being moved into audit events without re-borrowing the request.
    method: String,
    /// `"bearer"` or `"mtls"`, derived from `AuthenticatedAs` in
    /// request extensions.
    auth_method: &'static str,
    /// Stamped only when the bearer or mTLS path resolved an
    /// `AgentIdentity` into request extensions (M0/M1 deployments
    /// without admin substrate leave this `None`).
    agent_public_id: Option<String>,
    /// Phase G4 — human-readable agent name from `AgentIdentity.name`.
    /// Used as the `originator` header value on codex hot-path
    /// requests when the agent didn't supply their own.
    agent_name: Option<String>,
    started: Instant,
    /// Phase G3 — populated when `codex_body::fixup` modified the
    /// request body destined for codex `/responses`. `None` when no
    /// fixup happened (most calls); flows into `details.codex_body_fixup`
    /// on the `proxy_request` audit row when set.
    codex_body_fixup: Option<serde_json::Value>,
}

impl RequestCtx {
    /// Snapshot the request metadata. Reads `AuthenticatedAs` and
    /// `AgentIdentity` from request extensions (stamped by the
    /// `auth::auth_middleware`).
    fn snapshot(req: &Request<Body>, tool_name: String) -> Self {
        let started = Instant::now();
        let request_path = req.uri().path().to_string();
        let method = req.method().as_str().to_string();
        let auth_method = match req.extensions().get::<crate::auth::AuthenticatedAs>() {
            Some(crate::auth::AuthenticatedAs::Mtls) => "mtls",
            _ => "bearer",
        };
        let identity = req.extensions().get::<crate::auth_v2::AgentIdentity>();
        let agent_public_id = identity.map(|id| id.public_id.clone());
        let agent_name = identity.map(|id| id.name.clone());
        Self {
            tool_name,
            request_path,
            method,
            auth_method,
            agent_public_id,
            agent_name,
            started,
            codex_body_fixup: None,
        }
    }

    fn latency_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// An `AuditEvent` with the per-request metadata fields populated.
    /// Caller fills in `event_class`, `event`, `status`, `decision`,
    /// `details`, and `upstream_host`.
    fn audit_event_base(&self) -> AuditEvent {
        AuditEvent {
            ts_ms: now_ms(),
            tool: Some(self.tool_name.clone()),
            method: Some(self.method.clone()),
            path: Some(self.request_path.clone()),
            latency_ms: Some(self.latency_ms()),
            auth_method: Some(self.auth_method.to_string()),
            agent_public_id: self.agent_public_id.clone(),
            ..AuditEvent::default()
        }
    }
}

/// Phase E.6 — unified proxy target shape. Built from either an
/// in-memory `Registration` (catalog path) or a `ToolConfig`
/// (config.tools fallback). Owns its data so the hot path doesn't
/// hold borrows into the catalog `ArcSwap` snapshot or the config
/// snapshot across the upstream request.
struct ProxyTarget {
    name: String,
    upstream: String,
    body_limit_bytes: u64,
    timeouts: ToolTimeouts,
    egress: EgressMode,
    auth: ProxyAuth,
    /// Phase G — audit attribution for the credential applied:
    /// `"registration_default"` (no override active) or
    /// `"agent_override"` (per-agent override applied).
    auth_source: &'static str,
    /// Phase G — for OAuth requests, the session label resolved at
    /// proxy time. `Some("default")` for the common shared-OAuth case;
    /// `Some("hermes")` etc. when the agent has an OAuth override
    /// pointing at a non-default label. `None` for non-OAuth requests.
    oauth_session_label: Option<String>,
}

/// What the proxy needs to know about auth at injection time. Each
/// variant carries the audit label so `proxy_request` rows can record
/// the `auth_mode` used (see TS-151).
#[derive(Debug, Clone)]
enum ProxyAuth {
    /// `AuthSpec::None` — operator-stated authless. Strip incoming
    /// auth-shaped headers, inject nothing.
    None,
    /// Inject `header: value` where `value` comes from `override_value`
    /// if present (Phase G per-agent override path) else from
    /// `resolved_creds[name]` (registration-default path).
    /// `audit_mode` distinguishes registration-sourced ("header") from
    /// config-sourced ("config") for the audit row.
    Header {
        header: String,
        audit_mode: &'static str,
        /// Phase G per-agent override (`None` for registration-default).
        override_value: Option<secrecy::SecretString>,
    },
    /// Inject `Authorization: Bearer value` where `value` comes from
    /// `override_value` if present (Phase G per-agent override path)
    /// else from `resolved_creds[name]` (registration-default path).
    /// Catalog-only — config.tools' Authorization shape goes through
    /// `Header { header: "Authorization", ... }` because the legacy
    /// resolver may have already prefixed the value.
    Bearer {
        /// Phase G per-agent override (`None` for registration-default).
        override_value: Option<secrecy::SecretString>,
    },
    /// OAuth (PKCE or device-code). Access token resolved from the
    /// `oauth_sessions` cache before this struct is constructed, so
    /// `build_upstream_request` can inject without async work. The
    /// `oauth_session_id` is included in audit details for forensics
    /// (ADR-0005 D4).
    ///
    /// `access_token=None` indicates a session in degraded state or
    /// missing entirely — `build_upstream_request` skips injection
    /// (the response will surface as 401 from upstream, but the
    /// 503 envelope from `proxy_handler` should already have caught
    /// this). The variant exists so audit rows still record OAuth
    /// auth_mode + session id.
    Oauth {
        /// `"oauth_pkce"` or `"oauth_device_code"` per ADR-0005 D4.
        audit_mode: &'static str,
        oauth_session_id: String,
        access_token: Option<secrecy::SecretString>,
        /// Phase G2 — provider-side account identifier extracted from
        /// the access-token JWT (`https://api.openai.com/auth.chatgpt_account_id`).
        /// Injected as `ChatGPT-Account-ID` on codex hot-path requests
        /// when the upstream URL matches the codex pattern. `None` for
        /// non-JWT access tokens; the proxy then skips the header,
        /// which is the correct outcome for non-codex providers.
        account_id: Option<String>,
    },
}

impl ProxyAuth {
    fn audit_mode(&self) -> &'static str {
        match self {
            ProxyAuth::None => "none",
            ProxyAuth::Header { audit_mode, .. } => audit_mode,
            ProxyAuth::Bearer { .. } => "bearer",
            ProxyAuth::Oauth { audit_mode, .. } => audit_mode,
        }
    }

    /// OAuth session id for audit details, when applicable.
    fn oauth_session_id(&self) -> Option<&str> {
        match self {
            ProxyAuth::Oauth {
                oauth_session_id, ..
            } => Some(oauth_session_id.as_str()),
            _ => None,
        }
    }

    /// Header name (lowercased) that should be stripped from the
    /// agent's incoming request to prevent override of the configured
    /// credential. `None` means no specific stripping beyond the
    /// always-stripped `authorization` / `x-api-key` / `host`.
    fn strip_header_lower(&self) -> Option<String> {
        match self {
            ProxyAuth::None => None,
            ProxyAuth::Header { header, .. } => Some(header.to_lowercase()),
            ProxyAuth::Bearer { .. } => None, // "authorization" is always stripped
            ProxyAuth::Oauth { .. } => None,  // F.5 will inject Authorization; always stripped
        }
    }
}

impl ProxyTarget {
    /// Build from a Phase E `Registration`. Translates `AuthSpec` →
    /// `ProxyAuth` so the build-upstream-request path is uniform across
    /// catalog and legacy sources.
    fn from_registration(r: &Registration) -> Self {
        // OAuth ProxyAuth carries token material; this constructor
        // can only fill the static-credential variants. OAuth
        // registrations are built via [`from_registration_oauth`]
        // after the proxy_handler resolves the access token.
        let auth = match &r.auth {
            AuthSpec::None => ProxyAuth::None,
            AuthSpec::Header { header, .. } => ProxyAuth::Header {
                header: header.clone(),
                audit_mode: "header",
                override_value: None,
            },
            AuthSpec::Bearer { .. } => ProxyAuth::Bearer {
                override_value: None,
            },
            AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. } => {
                // Caller must use from_registration_oauth instead;
                // this path indicates a programming error. We return
                // a placeholder Oauth variant with empty session_id
                // so the audit row still records the right
                // auth_mode if anyone calls this incorrectly.
                let audit_mode = match &r.auth {
                    AuthSpec::OauthPkce { .. } => "oauth_pkce",
                    AuthSpec::OauthDeviceCode { .. } => "oauth_device_code",
                    _ => unreachable!(),
                };
                ProxyAuth::Oauth {
                    audit_mode,
                    oauth_session_id: String::new(),
                    access_token: None,
                    account_id: None,
                }
            }
        };
        Self {
            name: r.name.clone(),
            upstream: r.upstream.clone(),
            body_limit_bytes: r.body_limit_bytes,
            timeouts: r.timeouts,
            egress: r.egress,
            auth,
            auth_source: "registration_default",
            oauth_session_label: None,
        }
    }

    /// Build from a legacy `ToolConfig`. Preserves the pre-Phase-E
    /// behavior: tools with `auth: { header, value: ... }` inject
    /// `header: <resolved>` (the resolved value may already include
    /// "Bearer " when the operator wrote a legacy "Bearer ${VAR}"
    /// string); tools with no `auth:` block inject nothing.
    fn from_tool_config(t: &ToolConfig) -> Self {
        let auth = match &t.auth {
            None => ProxyAuth::None,
            Some(a) => ProxyAuth::Header {
                header: a.header.clone(),
                audit_mode: "config",
                override_value: None,
            },
        };
        Self {
            name: t.name.clone(),
            upstream: t.upstream.clone(),
            body_limit_bytes: t.body_limit_bytes,
            timeouts: t.timeouts,
            egress: t.egress,
            auth,
            auth_source: "registration_default",
            oauth_session_label: None,
        }
    }
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path((tool_name, path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    let mut ctx = RequestCtx::snapshot(&req, tool_name);

    // M9 ACL gate. When the request carries an AgentIdentity (per-agent
    // bearer or mTLS), enforce the agent's tool_allowlist /
    // tool_denylist before reaching the tool resolver. Identity-less
    // requests reach this code only in M0/M1 deployments without admin
    // substrate (preserved for back-compat).
    if let Some(identity) = req.extensions().get::<crate::auth_v2::AgentIdentity>()
        && let Err(reason) = identity.allows_tool(&ctx.tool_name)
    {
        return record_authz_denied(&state.audit, &ctx, reason).await;
    }

    // Phase E.6: catalog lookup first; legacy `config.tools` fallback
    // for M0/M1 / M9 test paths that haven't wired registrations.
    let target = resolve_target(&state, &ctx.tool_name);
    let mut target = match target {
        Some(t) => t,
        None => return record_tool_not_found(&state.audit, &ctx).await,
    };

    // Phase G: per-agent credential override. When an override row
    // exists for (agent_id, registration), swap in the override's
    // AuthSpec BEFORE OAuth resolution / static-credential injection.
    // Default behavior (no override) leaves target unchanged.
    apply_agent_credential_override(&state, &mut target, req.extensions()).await;

    // Phase F.5: for OAuth registrations, materialize the access token
    // before building the upstream request. Returns a 503 envelope if
    // the session is missing, degraded, or the sealing key isn't
    // configured — operator fixes via re-bootstrap.
    if matches!(target.auth, ProxyAuth::Oauth { .. }) {
        // Phase G: session_label was set during apply_agent_credential_override
        // (defaults to DEFAULT_SESSION_LABEL when no override is in effect).
        let session_label = target
            .oauth_session_label
            .clone()
            .unwrap_or_else(|| crate::oauth::session::DEFAULT_SESSION_LABEL.to_string());
        match resolve_oauth_token(&state, &target, &session_label).await {
            Ok(updated_auth) => target.auth = updated_auth,
            Err(envelope) => {
                record_oauth_unavailable(&state.audit, &ctx, envelope.audit_cause).await;
                return envelope.response;
            }
        }
    }

    let config = state.config.load();
    let upstream_host = url_host(&target.upstream);
    let upstream_url = format!("{}/{}", target.upstream.trim_end_matches('/'), path);
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match read_request_body(req, target.body_limit_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return record_body_read_error(&state.audit, &ctx, upstream_host).await;
        }
    };

    // Phase G3 — codex Responses API body fixup. Only when both
    // predicates match (upstream is chatgpt.com codex AND request
    // path is /responses). Skips on empty body (passthrough) and on
    // non-JSON bodies (passthrough). Returns 413 only on the >1MB
    // size cap. The summary is stashed on `ctx` so audit_details
    // can emit `details.codex_body_fixup` when fixup happened.
    let body_bytes = if is_chatgpt_codex_upstream(&target.upstream)
        && request_path_ends_with_responses(&ctx.request_path)
    {
        match crate::codex_body::fixup(&body_bytes) {
            Ok((new_body, summary)) => {
                if !summary.is_noop() {
                    ctx.codex_body_fixup = Some(serde_json::json!({
                        "fields_added": summary.fields_added,
                        "fields_overridden": summary.fields_overridden,
                        "fields_removed": summary.fields_removed,
                    }));
                }
                Bytes::from(new_body)
            }
            Err(crate::codex_body::CodexBodyError::TooLarge) => {
                return record_codex_body_too_large(&state.audit, &ctx, upstream_host).await;
            }
        }
    } else {
        body_bytes
    };

    let upstream_req = build_upstream_request(
        &state,
        &config,
        &target,
        method,
        &upstream_url,
        headers,
        body_bytes,
        ctx.agent_name.as_deref(),
    );

    match upstream_req.send().await {
        Ok(resp) => {
            handle_upstream_response(state.clone(), &ctx, &target, upstream_host, resp).await
        }
        Err(e) => record_upstream_error(&state.audit, &ctx, &target, upstream_host, e).await,
    }
}

/// Phase E.6 lookup: try the in-memory catalog (registrations) first,
/// fall back to `config.tools`. Returns `None` only when the name is
/// in neither source — which is when `record_tool_not_found` should
/// fire.
fn resolve_target(state: &AppState, name: &str) -> Option<ProxyTarget> {
    // Catalog path. `lookup_active` already filters out `disabled=true`
    // rows so admin-disabled seed entries return None and proxy_handler
    // surfaces 404.
    let catalog = state.catalog.load();
    if let Some(r) = catalog.lookup_active(name) {
        return Some(ProxyTarget::from_registration(r));
    }
    drop(catalog);
    // Legacy fallback. `active_tools()` includes every tool whose
    // upstream is configured; credential-resolved filtering happens
    // implicitly via `resolved_creds.get(name)` at injection time.
    let config = state.config.load();
    config
        .active_tools()
        .into_iter()
        .find(|t| t.name == name)
        .map(ProxyTarget::from_tool_config)
}

/// Read the request body up to the tool's `body_limit_bytes`. On error
/// returns `()` — the caller emits the audit row with `RequestCtx`
/// fields it already has.
async fn read_request_body(req: Request<Body>, body_limit: u64) -> Result<Bytes, ()> {
    let limit = usize::try_from(body_limit).unwrap_or(usize::MAX);
    axum::body::to_bytes(req.into_body(), limit)
        .await
        .map_err(|_| ())
}

/// Forward request headers (with auth-related headers stripped) plus
/// the configured credential, and attach the body if present. Phase
/// E.6: source-agnostic — driven by `ProxyTarget` (built from either
/// a `Registration` or a legacy `ToolConfig`).
/// Phase G2 — does the upstream point at codex's ChatGPT-plan
/// Responses backend? The trigger is the path fragment
/// `/backend-api/codex` — distinct from the bare `/backend-api`
/// surface (chat plugins, etc.). The substring match is intentionally
/// loose: it works against the canonical `chatgpt.com` host, the
/// `chatgpt-staging.com` host, AND test/proxy hosts that mirror the
/// path shape, so tests can drive the injection through wiremock
/// without monkey-patching DNS.
///
/// False positives are extremely narrow — no other proxied provider
/// uses `/backend-api/codex` in its URL, and an operator who
/// deliberately routes elsewhere through that path would already be
/// off the supported configuration map.
fn is_chatgpt_codex_upstream(upstream: &str) -> bool {
    upstream.to_ascii_lowercase().contains("/backend-api/codex")
}

/// Phase G3 — does this request path target the codex Responses
/// endpoint? Tighter than [`is_chatgpt_codex_upstream`] (which is
/// upstream-URL-based): only `/responses` requests get body fixup.
/// Other codex endpoints (sessions, model info, etc.) pass through
/// untouched even when the upstream registration is codex.
///
/// Case-insensitive suffix match on `/responses` (the leading slash
/// guarantees we don't false-positive on paths like `/myresponses`).
/// `request_path` is the URI path with query string stripped, so we
/// don't need to handle `?stream=true` etc.
fn request_path_ends_with_responses(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with("/responses")
}

// Phase G4 added the `agent_name` parameter (used as the codex
// `originator` fallback). build_upstream_request was already at the
// clippy threshold; allow rather than refactor mid-phase. Future work
// could collapse the per-call params into a struct.
#[allow(clippy::too_many_arguments)]
fn build_upstream_request(
    state: &AppState,
    config: &crate::config::AppConfig,
    target: &ProxyTarget,
    method: axum::http::Method,
    upstream_url: &str,
    headers: HeaderMap,
    body_bytes: Bytes,
    // Phase G4 — used as the codex `originator` header value when the
    // agent didn't supply one. `None` for M0/M1 paths without
    // `AgentIdentity`; falls back to a static `"locksmith-proxy"` then.
    agent_name: Option<&str>,
) -> reqwest::RequestBuilder {
    let client =
        state
            .client_pool
            .get_or_build_for(&target.name, target.timeouts, target.egress, config);
    let mut upstream_req = client.request(method, upstream_url);

    // Forward headers, stripping auth-related ones so the agent can't
    // override the configured credential. `host`/`authorization`/
    // `x-api-key` are always stripped (defense in depth — even when
    // `auth: none` we don't want the agent injecting their own bearer
    // and reaching the upstream as the proxy's principal). The
    // target's own auth header is also stripped when distinct.
    //
    // `content-length` and `transfer-encoding` are also stripped:
    // reqwest computes both itself based on the body we attach via
    // `.body(...)`, and Phase G3 may rewrite the body to a different
    // size. Forwarding the agent's stale Content-Length to upstream
    // causes silent body truncation/mismatch (Phase G3 hit this with
    // codex `/responses` returning 400 when the injected default
    // `instructions` made the body larger than the original
    // Content-Length advertised).
    let extra_strip = target.auth.strip_header_lower();
    let codex_upstream = is_chatgpt_codex_upstream(&target.upstream);
    // Phase G4 — for codex requests, snapshot whether the agent supplied
    // their own `originator` header before stripping; controls whether
    // we inject our default below.
    let agent_sent_originator = codex_upstream
        && headers
            .iter()
            .any(|(name, _)| name.as_str().eq_ignore_ascii_case("originator"));
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_lowercase();
        if lower == "host"
            || lower == "authorization"
            || lower == "x-api-key"
            || lower == "content-length"
            || lower == "transfer-encoding"
            // Phase G4 — for codex, force `OpenAI-Beta: responses=experimental`.
            // Strip the agent's value (if any) here; we re-inject below.
            || (codex_upstream && lower == "openai-beta")
            || extra_strip.as_deref() == Some(&lower)
        {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }

    // Inject configured credentials. Reads from the resolved-creds
    // snapshot (M5 / T5.1) — daemon resolves SecretRefs and
    // registration env vars once at startup, the proxy never touches
    // raw values on the hot path. AuthSpec::None deliberately skips
    // injection (Phase E.6 / TS-150).
    match &target.auth {
        ProxyAuth::None => {}
        ProxyAuth::Header {
            header,
            override_value,
            ..
        } => {
            // Phase G: per-agent override takes precedence; falls back
            // to the registration-default `resolved_creds[name]` when
            // None.
            if let Some(value) = override_value {
                upstream_req =
                    upstream_req.header(header, secrecy::ExposeSecret::expose_secret(value));
            } else {
                let resolved = state.resolved_creds.load();
                if let Some(value) = resolved.get(&target.name) {
                    upstream_req =
                        upstream_req.header(header, secrecy::ExposeSecret::expose_secret(value));
                }
                // Auth declared but no credential resolved → degraded
                // mode. Forward without injection; upstream typically
                // returns 401 and the response pipeline records the
                // proxy-side audit row.
            }
        }
        ProxyAuth::Bearer { override_value } => {
            if let Some(value) = override_value {
                let header_value =
                    format!("Bearer {}", secrecy::ExposeSecret::expose_secret(value));
                upstream_req = upstream_req.header("Authorization", header_value);
            } else {
                let resolved = state.resolved_creds.load();
                if let Some(value) = resolved.get(&target.name) {
                    let header_value =
                        format!("Bearer {}", secrecy::ExposeSecret::expose_secret(value));
                    upstream_req = upstream_req.header("Authorization", header_value);
                }
            }
        }
        ProxyAuth::Oauth {
            access_token,
            account_id,
            ..
        } => {
            if let Some(token) = access_token {
                let header_value =
                    format!("Bearer {}", secrecy::ExposeSecret::expose_secret(token));
                upstream_req = upstream_req.header("Authorization", header_value);
            }
            // No access token → proxy_handler should have already
            // returned 503 via record_oauth_unavailable. Reaching
            // this branch with `None` indicates a degraded session
            // we couldn't refresh; forwarding without injection lets
            // the upstream surface its own 401 (informational; the
            // proxy already audited the failure).

            // Phase G2 — inject `ChatGPT-Account-ID` for codex's
            // chatgpt.com/backend-api/codex endpoint. Both hermes and
            // openclaw extract this from the JWT themselves when they
            // own the access token; under locksmith they only see
            // their per-agent bearer, so locksmith must inject. The
            // upstream-URL pattern is the trigger — `account_id` is
            // populated only for JWTs that carry the OpenAI claim, so
            // a non-codex provider with a JWT-shaped access token
            // (rare) won't get the header injected unless it also
            // routes to a chatgpt.com upstream.
            if let Some(acct) = account_id
                && is_chatgpt_codex_upstream(&target.upstream)
            {
                upstream_req = upstream_req.header("ChatGPT-Account-ID", acct.as_str());
            }
        }
    }

    // Phase G4 — codex required headers, applied to every codex
    // request regardless of auth shape (paranoia: only `oauth_*`
    // configurations make sense for codex today, but the predicate
    // is upstream-URL-based so a hypothetical future static-key codex
    // route still gets the headers).
    //
    // - `OpenAI-Beta: responses=experimental` is mandatory; codex
    //   rejects requests without it. We strip the agent's value
    //   (above) and force ours so a confused agent can't downgrade.
    //
    // - `originator: <agent-name>` lets codex distinguish requesters.
    //   We preserve the agent's value if they sent one (it might be
    //   meaningful to their own observability) and inject the agent
    //   name otherwise. Falls back to `"locksmith-proxy"` for paths
    //   without an `AgentIdentity` (M0/M1 deployments).
    if codex_upstream {
        upstream_req = upstream_req.header("OpenAI-Beta", "responses=experimental");
        if !agent_sent_originator {
            let originator = agent_name.unwrap_or("locksmith-proxy");
            upstream_req = upstream_req.header("originator", originator);
        }
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes);
    }
    upstream_req
}

/// Top-level dispatch for the upstream's response: snapshot headers,
/// apply M7 response-controls (size cap / content-type allowlist /
/// redaction), emit the success audit row, and stream the body to the
/// agent. Any Stage-specific deny path emits its own audit row before
/// returning.
async fn handle_upstream_response(
    state: Arc<AppState>,
    ctx: &RequestCtx,
    target: &ProxyTarget,
    upstream_host: Option<String>,
    resp: reqwest::Response,
) -> Response {
    let upstream_status = resp.status().as_u16();
    let status = StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
    // Snapshot upstream Content-Type before consuming the response —
    // needed for response-controls dispatch and for the response we
    // hand to the agent.
    let upstream_content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let response_headers = forward_response_headers(resp.headers());

    // M7 / T7.2-T7.4: per-tool response controls.
    let rc = state.response_controls.get(&ctx.tool_name).cloned();
    if let Some(rc) = rc.as_ref() {
        // Content-type allowlist (T7.2 streaming pre-check).
        if !rc.streaming_content_type_allowed(upstream_content_type.as_deref()) {
            return record_response_content_type_disallowed(
                &state.audit,
                ctx,
                upstream_host,
                upstream_content_type,
            )
            .await;
        }
        // Tool has redaction patterns ⇒ buffer + apply non-streaming.
        // Tools that need streaming + redaction compose with D-18
        // in-process scanners (LlamaFirewall) — see m7-response-controls
        // runbook.
        if rc_should_buffer(rc) {
            return apply_buffered_response_controls(
                rc,
                &state.audit,
                ctx,
                target,
                upstream_host,
                upstream_status,
                upstream_content_type,
                response_headers,
                resp,
            )
            .await;
        }
    }

    record_proxy_request_success(
        &state.audit,
        ctx,
        target,
        upstream_host.clone(),
        upstream_status,
    )
    .await;

    // Stream the upstream body to the agent rather than buffering
    // (R-N6: ≤100ms first-byte added latency). T1.2 closes T1.1.
    // Wrap with the M7 size-cap adapter when configured.
    let body = match rc.as_ref().and_then(|c| c.streaming_size_cap()) {
        Some(cap) => {
            let on_truncate = build_streaming_truncate_callback(
                state.audit.clone(),
                ctx,
                upstream_host,
                upstream_status,
                cap,
            );
            let wrapped = SizeCappedStream::new(resp.bytes_stream(), Some(cap), on_truncate);
            Body::from_stream(wrapped)
        }
        None => Body::from_stream(resp.bytes_stream()),
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
}

/// Strip hop-by-hop headers (the body is rebuilt as an axum stream
/// downstream, so axum/hyper sets these afresh).
fn forward_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "upgrade"
                | "te"
                | "trailer"
        ) {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            out.insert(name.clone(), v);
        }
    }
    out
}

/// Build the `on_truncate` callback for `SizeCappedStream`. Spawned as
/// a tokio task on truncation so the audit write doesn't stall the
/// stream backpressure (INF-26). Captured fields are owned snapshots
/// of the request context.
fn build_streaming_truncate_callback(
    audit: Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_status: u16,
    cap: u64,
) -> impl FnMut(u64) + Send + 'static {
    let tool = ctx.tool_name.clone();
    let method = ctx.method.clone();
    let path = ctx.request_path.clone();
    let auth_method = ctx.auth_method;
    let agent_public_id = ctx.agent_public_id.clone();
    move |observed: u64| {
        let event = AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Proxy,
            event: "response_size_exceeded".to_string(),
            tool: Some(tool.clone()),
            upstream_host: upstream_host.clone(),
            method: Some(method.clone()),
            path: Some(path.clone()),
            status: Some(upstream_status),
            decision: Decision::Denied,
            auth_method: Some(auth_method.to_string()),
            agent_public_id: agent_public_id.clone(),
            details: Some(json!({
                "observed_bytes": observed,
                "cap_bytes": cap,
                "flow": "streaming",
            })),
            ..AuditEvent::default()
        };
        if let Some(repo) = audit.clone() {
            tokio::spawn(async move {
                if let Err(e) = repo.record(&event).await {
                    tracing::warn!(error = %e, "response_size_exceeded audit write failed");
                }
            });
        }
    }
}

// ─── Audit-emitting helpers (one per response shape) ──────────────────
//
// Each helper centralises the "emit an audit row + return the wire
// response" pattern for a specific deny / error shape, so the
// orchestrator (`proxy_handler` / `handle_upstream_response`) reads as
// pure flow control.

/// M9 / B1: emit a `security/authz_denied` audit row and return the
/// generic 403 wire response with the §4.7.9 envelope. `reason` is
/// `"in_denylist"` or `"not_in_allowlist"` per `AgentIdentity::allows_tool`.
async fn record_authz_denied(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    reason: &'static str,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Security;
    event.event = "authz_denied".to_string();
    event.status = Some(403);
    event.decision = Decision::Denied;
    event.details = Some(json!({ "reason": reason }));
    audit_record(audit, event).await;
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "message": "tool access denied",
                "type": "authz_error",
                "code": "tool_not_allowed",
            }
        })),
    )
        .into_response()
}

/// Emit a `proxy/tool_not_found` audit row + 404 wire response when
/// the requested tool name does not match any active tool.
async fn record_tool_not_found(audit: &Option<AuditRepository>, ctx: &RequestCtx) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "tool_not_found".to_string();
    event.status = Some(404);
    event.decision = Decision::Denied;
    audit_record(audit, event).await;
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "message": format!("Unknown tool: {}", ctx.tool_name),
                "type": "not_found",
            }
        })),
    )
        .into_response()
}

/// Emit a `proxy/request_body_read_error` audit row + 400 wire response
/// when reading the agent's request body fails (typically the
/// per-tool body-size cap was exceeded).
async fn record_body_read_error(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "request_body_read_error".to_string();
    event.status = Some(400);
    event.decision = Decision::Error;
    event.upstream_host = upstream_host;
    audit_record(audit, event).await;
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": {"message": "Failed to read request body", "type": "bad_request"}})),
    )
        .into_response()
}

/// Phase G3 — emit a `proxy/codex_body_too_large` audit row + 413
/// wire response when the codex Responses request body exceeds the
/// 1 MiB cap. Tighter than the per-tool `body_limit_bytes`: this is
/// the size at which locksmith refuses to inspect the body for
/// fixup, even if `body_limit_bytes` would allow more.
async fn record_codex_body_too_large(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "codex_body_too_large".to_string();
    event.status = Some(413);
    event.decision = Decision::Denied;
    event.upstream_host = upstream_host;
    audit_record(audit, event).await;
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({
            "error": {
                "message": format!("Codex request body exceeds {} byte cap", crate::codex_body::MAX_BODY_BYTES),
                "type": "payload_too_large",
                "code": "codex_body_too_large",
            }
        })),
    )
        .into_response()
}

/// Emit a `proxy/response_content_type_disallowed` audit row + 502
/// wire response when the upstream's Content-Type isn't in the M7
/// allowlist.
async fn record_response_content_type_disallowed(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_content_type: Option<String>,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "response_content_type_disallowed".to_string();
    event.status = Some(502);
    event.decision = Decision::Denied;
    event.upstream_host = upstream_host;
    event.details = Some(json!({
        "observed_content_type": upstream_content_type,
    }));
    audit_record(audit, event).await;
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": {
                "message": "upstream content-type not allowed",
                "type": "response_content_type_disallowed",
            }
        })),
    )
        .into_response()
}

/// Emit the streaming-success `proxy/proxy_request` audit row.
async fn record_proxy_request_success(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    target: &ProxyTarget,
    upstream_host: Option<String>,
    upstream_status: u16,
) {
    let decision = if upstream_status >= 500 {
        Decision::Error
    } else {
        Decision::Allowed
    };
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "proxy_request".to_string();
    event.status = Some(upstream_status);
    event.decision = decision;
    event.upstream_host = upstream_host;
    // Phase E.6 / TS-151 — record the upstream auth shape used. "none"
    // for AuthSpec::None (operator-stated authless), "bearer" /
    // "header" for the Phase E catalog path, "config" for the legacy
    // ToolConfig path. Phase F.5 — OAuth requests additionally carry
    // `oauth_session_id` (ADR-0005 D4) for forensic correlation
    // across access-token refreshes within the same session.
    event.details = Some(audit_details(ctx, target));
    audit_record(audit, event).await;
}

/// Build audit `details` JSON with `auth_mode` always present,
/// `oauth_session_id` populated for OAuth requests, Phase G
/// fields (`auth_source`, `oauth_session_label`) tracking whether
/// the credential came from the registration default or a per-agent
/// override and which OAuth session label was used, and the Phase G3
/// `codex_body_fixup` field when locksmith modified the request body
/// for a codex `/responses` call.
fn audit_details(ctx: &RequestCtx, target: &ProxyTarget) -> serde_json::Value {
    let mut v = json!({
        "auth_mode": target.auth.audit_mode(),
        "auth_source": target.auth_source,
    });
    if let Some(sid) = target.auth.oauth_session_id() {
        v["oauth_session_id"] = json!(sid);
    }
    if let Some(label) = &target.oauth_session_label {
        v["oauth_session_label"] = json!(label);
    }
    if let Some(fixup) = &ctx.codex_body_fixup {
        v["codex_body_fixup"] = fixup.clone();
    }
    v
}

/// Emit a `proxy/timeout` or `proxy/upstream_error` audit row + the
/// matching 504 / 502 wire response when the upstream call fails.
async fn record_upstream_error(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    target: &ProxyTarget,
    upstream_host: Option<String>,
    e: reqwest::Error,
) -> Response {
    let (status, kind, message) = if e.is_timeout() {
        (StatusCode::GATEWAY_TIMEOUT, "timeout", "Upstream timeout")
    } else {
        (StatusCode::BAD_GATEWAY, "upstream_error", "Upstream error")
    };
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = kind.to_string();
    event.status = Some(status.as_u16());
    event.decision = Decision::Error;
    event.upstream_host = upstream_host;
    event.details = Some(audit_details(ctx, target));
    audit_record(audit, event).await;
    (
        status,
        Json(json!({"error": {"message": message, "type": kind}})),
    )
        .into_response()
}

/// True when this tool's response controls require buffering the
/// full body before responding (M7 / SPEC §6.2 T7.2). Streaming flows
/// skip this path; redaction explicitly bypasses streaming per SPEC
/// ("only total-size cap applies to streaming").
fn rc_should_buffer(rc: &ResponseControls) -> bool {
    rc.has_redaction_patterns()
}

/// M7 buffered response pipeline (size cap + content-type + redaction).
/// Reached only when `rc_should_buffer(rc)` is true (i.e. there are
/// redaction patterns to apply).
#[allow(clippy::too_many_arguments)]
async fn apply_buffered_response_controls(
    rc: &ResponseControls,
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    target: &ProxyTarget,
    upstream_host: Option<String>,
    upstream_status: u16,
    upstream_content_type: Option<String>,
    response_headers: HeaderMap,
    resp: reqwest::Response,
) -> Response {
    let body_bytes = match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => return record_upstream_body_read_error(audit, ctx, upstream_host, e).await,
    };
    match rc.apply_non_streaming(upstream_content_type.as_deref(), body_bytes) {
        ApplyOutcome::SizeExceeded { observed, cap } => {
            record_response_size_exceeded_buffered(audit, ctx, upstream_host, observed, cap).await
        }
        ApplyOutcome::ContentTypeDisallowed { observed } => {
            record_response_content_type_disallowed(audit, ctx, upstream_host, Some(observed)).await
        }
        ApplyOutcome::Allowed { body, redactions } => {
            for rec in &redactions {
                record_response_redaction(audit, ctx, upstream_host.clone(), upstream_status, rec)
                    .await;
            }
            record_proxy_request_success(audit, ctx, target, upstream_host, upstream_status).await;
            let status_code =
                StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status_code;
            *response.headers_mut() = response_headers;
            response
        }
    }
}

async fn record_upstream_body_read_error(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    e: reqwest::Error,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "upstream_body_read_error".to_string();
    event.status = Some(502);
    event.decision = Decision::Error;
    event.upstream_host = upstream_host;
    event.details = Some(json!({"error": e.to_string()}));
    audit_record(audit, event).await;
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": {"message": "upstream body read failed", "type": "upstream_error"}})),
    )
        .into_response()
}

async fn record_response_size_exceeded_buffered(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    observed: usize,
    cap: u64,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "response_size_exceeded".to_string();
    event.status = Some(502);
    event.decision = Decision::Denied;
    event.upstream_host = upstream_host;
    event.details = Some(json!({
        "observed_bytes": observed,
        "cap_bytes": cap,
        "flow": "non_streaming",
    }));
    audit_record(audit, event).await;
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": {"message": "response too large", "type": "response_size_exceeded"}
        })),
    )
        .into_response()
}

async fn record_response_redaction(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_status: u16,
    rec: &crate::response_controls::RedactionRecord,
) {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "response_redaction".to_string();
    event.status = Some(upstream_status);
    event.decision = Decision::Allowed;
    event.upstream_host = upstream_host;
    event.details = Some(json!({
        "pattern_id": rec.pattern_id,
        "matches": rec.matches,
        "match_hash": rec.match_hash,
    }));
    audit_record(audit, event).await;
}

/// Best-effort audit write. Errors are logged and swallowed — audit
/// must never block proxy traffic (INF-26).
async fn audit_record(audit: &Option<AuditRepository>, event: AuditEvent) {
    let Some(repo) = audit else {
        return;
    };
    if let Err(e) = repo.record(&event).await {
        tracing::warn!(error = %e, event = %event.event, "audit write failed");
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn url_host(url: &str) -> Option<String> {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = stripped.split(['/', ':']).next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

// ─── Phase G: per-agent credential override ──────────────────────────────

/// Apply the per-agent credential override (if any) onto `target`,
/// updating `target.auth`, `target.auth_source`, and (for OAuth)
/// `target.oauth_session_label`. No-op when:
///   - the agent_creds repo isn't wired (M0/M1 / pre-Phase-G test path),
///   - no `AgentIdentity` is in extensions (unauthenticated request),
///   - no override row exists for (agent_id, registration).
///
/// Override `auth_spec` shapes:
///   - `AuthSpec::None` → `ProxyAuth::None`
///   - `AuthSpec::Header { header, env_var }` → reads `env_var` directly
///     and stashes the value in `ProxyAuth::Header.override_value`.
///     Bypasses `resolved_creds` because per-agent overrides don't
///     participate in the startup-resolved creds map.
///   - `AuthSpec::Bearer { env_var }` → same as Header but for the
///     `Authorization: Bearer ...` injection path.
///   - `AuthSpec::OauthPkce` / `OauthDeviceCode` → records the
///     `session_label` so `resolve_oauth_token` reads from a non-default
///     label (or "default" when the override doesn't specify a label).
async fn apply_agent_credential_override(
    state: &AppState,
    target: &mut ProxyTarget,
    extensions: &axum::http::Extensions,
) {
    let Some(agent_creds) = state.agent_creds.as_ref() else {
        return; // No repo wired: keep registration default.
    };
    let Some(identity) = extensions.get::<crate::auth_v2::AgentIdentity>() else {
        return; // No AgentIdentity (M0 shared-bearer path).
    };
    let override_row = match agent_creds.get(identity.id, &target.name).await {
        Ok(Some(row)) => row,
        Ok(None) => return, // No override: keep registration default.
        Err(e) => {
            tracing::warn!(
                agent_id = identity.id,
                tool = %target.name,
                error = %e,
                "agent_credential_overrides lookup failed; falling back to registration default",
            );
            return;
        }
    };

    target.auth_source = "agent_override";

    match override_row.auth_spec {
        AuthSpec::None => {
            target.auth = ProxyAuth::None;
        }
        AuthSpec::Header { header, env_var } => {
            let value = std::env::var(&env_var)
                .ok()
                .map(secrecy::SecretString::from);
            if value.is_none() {
                tracing::warn!(
                    agent_id = identity.id,
                    tool = %target.name,
                    env_var = %env_var,
                    "agent_override env var not set; forwarding without injection (will likely 401)",
                );
            }
            target.auth = ProxyAuth::Header {
                header,
                audit_mode: "header",
                override_value: value,
            };
        }
        AuthSpec::Bearer { env_var } => {
            let value = std::env::var(&env_var)
                .ok()
                .map(secrecy::SecretString::from);
            if value.is_none() {
                tracing::warn!(
                    agent_id = identity.id,
                    tool = %target.name,
                    env_var = %env_var,
                    "agent_override env var not set; forwarding without injection (will likely 401)",
                );
            }
            target.auth = ProxyAuth::Bearer {
                override_value: value,
            };
        }
        AuthSpec::OauthPkce { session_label, .. }
        | AuthSpec::OauthDeviceCode { session_label, .. } => {
            // Don't replace target.auth for OAuth — the registration's
            // ProxyAuth::Oauth placeholder is correct (resolve_oauth_token
            // will fill in audit_mode + access token). We only need to
            // tell that resolver which label to use.
            let label = session_label
                .unwrap_or_else(|| crate::oauth::session::DEFAULT_SESSION_LABEL.to_string());
            target.oauth_session_label = Some(label);
        }
    }
}

// ─── Phase F.5: OAuth resolution helpers ─────────────────────────────────

/// Wrapped error returned by [`resolve_oauth_token`] when the session
/// can't be materialized. Carries both the wire response and the
/// audit cause string for the failure-mode audit row.
struct OauthUnavailable {
    response: Response,
    audit_cause: &'static str,
}

/// Phase F.5 — materialize the OAuth access token for `target`.
///
/// Walks the lifecycle decisions from ADR-0005 D6:
/// - Sealing key unset (operator hasn't set `LOCKSMITH_OAUTH_SEALING_KEY`)
///   → 503 `oauth_sealing_key_unset`.
/// - Session row missing (operator hasn't run `locksmith oauth bootstrap`)
///   → 503 `oauth_session_missing`.
/// - Session degraded (refresh previously failed) → 503
///   `oauth_refresh_failed`.
/// - Access token absent or expiring within 60s → trigger inline
///   refresh under the per-session lock; surface the new token.
/// - Refresh failed inline → mark degraded + 503 `oauth_refresh_failed`.
async fn resolve_oauth_token(
    state: &AppState,
    target: &ProxyTarget,
    session_label: &str,
) -> Result<ProxyAuth, OauthUnavailable> {
    let Some(rt) = &state.oauth else {
        return Err(OauthUnavailable {
            response: oauth_unavailable_envelope(
                StatusCode::SERVICE_UNAVAILABLE,
                "oauth_sealing_key_unset",
                "OAuth registration requires LOCKSMITH_OAUTH_SEALING_KEY at daemon startup",
            ),
            audit_cause: "sealing_key_unset",
        });
    };
    let audit_mode = match &target.auth {
        ProxyAuth::Oauth { audit_mode, .. } => *audit_mode,
        _ => "oauth_unknown", // shouldn't happen; caller guards on Oauth variant
    };

    let lock = rt.locks.get(&target.name, session_label).await;
    let _guard = lock.lock().await;

    let session = match rt
        .sessions
        .get(&rt.sealing_key, &target.name, session_label)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(OauthUnavailable {
                response: oauth_unavailable_envelope(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "oauth_session_missing",
                    "OAuth session not bootstrapped for this registration",
                ),
                audit_cause: "session_missing",
            });
        }
        Err(e) => {
            tracing::warn!(name = %target.name, error = %e, "oauth session read failed");
            return Err(OauthUnavailable {
                response: oauth_unavailable_envelope(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "oauth_session_read_failed",
                    "OAuth session unavailable (sealing failure)",
                ),
                audit_cause: "session_read_failed",
            });
        }
    };

    if session.degraded {
        return Err(OauthUnavailable {
            response: oauth_unavailable_envelope(
                StatusCode::SERVICE_UNAVAILABLE,
                "oauth_refresh_failed",
                "OAuth session degraded — operator must re-bootstrap",
            ),
            audit_cause: "degraded",
        });
    }

    let now = now_secs();
    let needs_refresh = match (&session.access_token, session.access_token_expires_at) {
        (None, _) => true,
        (Some(_), Some(exp)) if exp <= now + 60 => true,
        _ => false,
    };

    let active_session = if needs_refresh {
        let cat = state.catalog.load();
        match crate::oauth::refresh::refresh_session(
            &rt.sessions,
            &cat,
            &rt.sealing_key,
            &rt.refresh_client,
            &session,
        )
        .await
        {
            Ok(updated) => updated,
            Err(e) => {
                let _ = rt.sessions.mark_degraded(&target.name, session_label).await;
                tracing::warn!(
                    name = %target.name,
                    cause = e.audit_cause(),
                    error = %e,
                    "oauth refresh failed inline; marking session degraded"
                );
                return Err(OauthUnavailable {
                    response: oauth_unavailable_envelope(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "oauth_refresh_failed",
                        "OAuth refresh failed — operator must re-bootstrap",
                    ),
                    audit_cause: e.audit_cause(),
                });
            }
        }
    } else {
        session
    };

    let oauth_session_id = active_session.audit_session_id();
    let access_token = active_session.access_token;
    let account_id = active_session.account_id;

    Ok(ProxyAuth::Oauth {
        audit_mode,
        oauth_session_id,
        access_token,
        account_id,
    })
}

/// Render the §4.7.9 envelope for OAuth-side unavailability. Three
/// codes per ADR-0005 D6 + sibling cases above.
fn oauth_unavailable_envelope(status: StatusCode, code: &'static str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "type": "auth_error",
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response()
}

/// Audit the OAuth-side failure that caused proxy_handler to short-
/// circuit before reaching the upstream. Distinct from
/// `record_upstream_error` because no upstream contact happened.
async fn record_oauth_unavailable(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    audit_cause: &'static str,
) {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "oauth_unavailable".to_string();
    event.status = Some(503);
    event.decision = Decision::Error;
    event.details = Some(json!({"oauth_cause": audit_cause}));
    audit_record(audit, event).await;
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod codex_upstream_tests {
    use super::is_chatgpt_codex_upstream;

    #[test]
    fn matches_canonical_codex_upstream() {
        assert!(is_chatgpt_codex_upstream(
            "https://chatgpt.com/backend-api/codex"
        ));
        assert!(is_chatgpt_codex_upstream(
            "https://chatgpt.com/backend-api/codex/responses"
        ));
        assert!(is_chatgpt_codex_upstream(
            "HTTPS://CHATGPT.COM/backend-api/codex"
        )); // case-insensitive
    }

    #[test]
    fn matches_staging_and_test_hosts() {
        assert!(is_chatgpt_codex_upstream(
            "https://chatgpt-staging.com/backend-api/codex"
        ));
        // Test wiremock mirroring the path shape — used by integration
        // tests so they don't need real DNS for chatgpt.com.
        assert!(is_chatgpt_codex_upstream(
            "http://127.0.0.1:43287/backend-api/codex"
        ));
    }

    #[test]
    fn rejects_non_codex_upstreams() {
        assert!(!is_chatgpt_codex_upstream("https://api.openai.com"));
        assert!(!is_chatgpt_codex_upstream("https://api.anthropic.com"));
        // Bare backend-api without /codex is the *other* codex
        // surface (chat plugins / etc.) — distinct from the Responses
        // endpoint that needs the account_id header.
        assert!(!is_chatgpt_codex_upstream(
            "https://chatgpt.com/backend-api"
        ));
        assert!(!is_chatgpt_codex_upstream(
            "https://chatgpt.com/backend-api/dev"
        ));
        assert!(!is_chatgpt_codex_upstream("http://localhost:9200"));
        assert!(!is_chatgpt_codex_upstream(""));
    }
}

#[cfg(test)]
mod request_path_responses_tests {
    use super::request_path_ends_with_responses;

    #[test]
    fn matches_canonical_responses_path() {
        assert!(request_path_ends_with_responses("/responses"));
        assert!(request_path_ends_with_responses("/api/codex/responses"));
        assert!(request_path_ends_with_responses("/backend-api/codex/responses"));
    }

    #[test]
    fn case_insensitive() {
        assert!(request_path_ends_with_responses("/RESPONSES"));
        assert!(request_path_ends_with_responses("/api/codex/Responses"));
    }

    #[test]
    fn rejects_non_responses_paths() {
        assert!(!request_path_ends_with_responses("/api/codex/sessions"));
        assert!(!request_path_ends_with_responses("/api/codex"));
        assert!(!request_path_ends_with_responses("/responses-debug"));
        assert!(!request_path_ends_with_responses("/myresponses"));
        assert!(!request_path_ends_with_responses("/responses/"));
        assert!(!request_path_ends_with_responses(""));
    }
}
