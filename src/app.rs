use arc_swap::ArcSwap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, extract::State, middleware, routing};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::auth_v2::AgentAuthenticator;
use crate::client_pool::ClientPool;
use crate::config::AppConfig;
use crate::mtls::MtlsAuthenticator;
use crate::proxy;
use crate::repo::AuditRepository;
use crate::response_controls::ResponseControls;
use crate::secret::{ResolvedCreds, resolve_tool_creds_sync_env_only};
use std::collections::HashMap;

pub struct AppState {
    pub config: Arc<ArcSwap<AppConfig>>,
    pub started_at: Instant,
    pub client_pool: ClientPool,
    /// Audit sink (T3.1). `None` for M0/M1 deployments without admin
    /// substrate; the proxy hot path then skips audit writes entirely
    /// rather than fail.
    pub audit: Option<AuditRepository>,
    /// Resolved credential map (M5 / T5.1). Populated at startup by
    /// the daemon (`secret::resolve_tool_creds`) or by the eager
    /// sync helper used in test paths
    /// (`secret::resolve_tool_creds_sync_env_only`). The proxy hot
    /// path reads from this map; tools whose credentials are absent
    /// are inactive (degraded per INF-4).
    pub resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    /// Per-tool response controls (M7 / T7.2 / T7.3). Compiled once
    /// at AppState build; the proxy hot path looks up tool name and
    /// applies size-cap / content-type / redaction. Tools without a
    /// `response:` block are absent from the map and the proxy
    /// streams unchanged (M0..M6 behavior).
    pub response_controls: Arc<HashMap<String, ResponseControls>>,
    /// mTLS authenticator for the agent listener (post-v2 / #67). Only
    /// populated when the daemon is configured for `auth_mode: mtls`
    /// or `auth_mode: both`; absent under bearer-only deployments.
    /// Agent-auth middleware consults this when a peer cert is present
    /// in the request extensions.
    pub mtls_authenticator: Option<Arc<MtlsAuthenticator>>,
    /// Per-agent authenticator for the bearer path (M9 / B1). Named to
    /// match the existing `UdsState.agent_auth` field — the same `Arc`
    /// is shared across both consumers so admin self-service ops and
    /// the proxy hot path use one authenticator and one audit fanout.
    /// Populated by the daemon when the admin substrate is active (both
    /// `listen.admin_socket` and `database.path` configured); absent
    /// under M0/M1 deployments without the substrate. When present,
    /// `auth_middleware` uses it on every request; when absent, the M0
    /// shared-bearer fallback preserves pre-v2 behavior.
    pub agent_auth: Option<Arc<dyn AgentAuthenticator>>,
    /// Phase E.3 — registrations repo for the public discovery
    /// endpoints `/tools` and `/models`. Same Arc as
    /// `UdsState.registrations` (shared across admin + discovery).
    /// `None` for M0/M1 deployments without admin substrate; the
    /// discovery handlers then fall back to the YAML-loaded
    /// `config.tools` so existing M9 tests stay green.
    pub registrations: Option<Arc<crate::registrations::RegistrationRepository>>,
    /// Phase E.6 — in-memory `Catalog` mirror of the registrations
    /// table. Empty when registrations isn't wired (M0/M1 / M9 test
    /// path). The proxy hot path looks up by name; the discovery
    /// handlers can iterate by kind without round-tripping the DB.
    /// Refreshed by admin handlers after upsert/delete/enable so
    /// runtime state matches the DB without a daemon restart.
    pub catalog: Arc<ArcSwap<crate::registrations::Catalog>>,
    /// Phase F.5 — OAuth runtime state. `None` when
    /// `LOCKSMITH_OAUTH_SEALING_KEY` is unset — OAuth registrations in
    /// the catalog then surface `503 oauth_sealing_key_unset` from
    /// proxy hot path. `Some` enables proxy-side access-token
    /// injection + on-401 refresh + audit `oauth_session_id`.
    pub oauth: Option<OauthRuntime>,
    /// Phase G — per-agent credential overrides. `None` for M0/M1
    /// deployments without admin substrate. `Some` enables the
    /// proxy hot path's override-then-default credential resolution.
    /// An empty repository (no rows) is functionally equivalent to
    /// `None` — every lookup is `Ok(None)` and the registration's
    /// default `auth_spec` always wins.
    pub agent_creds: Option<crate::repo::AgentCredentialRepository>,
}

/// Bundle of OAuth runtime state shared between the proxy hot path
/// (this module) and the admin endpoints (`UdsState.oauth`). The
/// daemon constructs one of these and shares the same Arc-backed
/// fields with both consumers.
#[derive(Clone)]
pub struct OauthRuntime {
    pub sessions: crate::oauth::OauthSessionRepository,
    pub sealing_key: crate::oauth::SealingKey,
    pub locks: crate::oauth::refresh::RefreshLockMap,
    /// Shared HTTP client for token-endpoint refresh exchanges.
    /// Built once at daemon startup so we don't allocate a fresh
    /// reqwest::Client for every refresh.
    pub refresh_client: reqwest::Client,
}

fn compile_response_controls(cfg: &AppConfig) -> HashMap<String, ResponseControls> {
    let mut out = HashMap::new();
    for tool in &cfg.tools {
        let Some(rc_cfg) = &tool.response else {
            continue;
        };
        // parse_config_str validated the regex compile earlier; this
        // unwrap is structurally safe.
        match ResponseControls::compile(rc_cfg) {
            Ok(rc) => {
                out.insert(tool.name.clone(), rc);
            }
            Err(e) => {
                tracing::error!(
                    tool = %tool.name,
                    error = %e,
                    "response_controls compile failed at AppState build (config validation should have caught this)"
                );
            }
        }
    }
    out
}

pub fn build_app(config: AppConfig) -> Router {
    build_app_with_shared_config(Arc::new(ArcSwap::from_pointee(config)))
}

/// Build the agent router using a shared config snapshot. M2's daemon
/// runtime calls this so the agent listener and the AdminService observe
/// the same `ArcSwap<AppConfig>` (single source of truth for hot reload).
pub fn build_app_with_shared_config(config: Arc<ArcSwap<AppConfig>>) -> Router {
    build_app_with_audit(config, None)
}

/// Build the agent router with an optional audit sink. M3 calls this so
/// the proxy hot path emits one audit row per request. Eager-resolves
/// `tool.auth.value` SecretRefs synchronously (env + legacy paths only) —
/// daemon callers that need sealed/Vault/AWS go through
/// `build_app_with_audit_and_creds`.
pub fn build_app_with_audit(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
) -> Router {
    let snapshot = config.load();
    let resolved = resolve_tool_creds_sync_env_only(&snapshot);
    drop(snapshot);
    build_app_with_audit_and_creds(config, audit, Arc::new(ArcSwap::from_pointee(resolved)))
}

/// Full-power constructor used by the daemon: caller supplies an
/// already-resolved credentials map (typically built via the async
/// `secret::resolve_tool_creds` so sealed/Vault/AWS paths work).
pub fn build_app_with_audit_and_creds(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
) -> Router {
    build_app_full(config, audit, resolved_creds, None, None)
}

/// Full-power constructor (post-v2 / #67 + M9): supplies all M0..M7
/// state plus the optional MtlsAuthenticator (#67) and the optional
/// BearerAuthenticator (M9). Used by the daemon. M0/M1 deployments
/// without admin substrate pass `None` for `agent_auth`,
/// which preserves the M0 shared-bearer middleware path; deployments
/// with admin substrate enabled pass `Some(...)` so `auth_middleware`
/// enforces per-agent bearer authentication on every request.
pub fn build_app_full(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    mtls_authenticator: Option<Arc<MtlsAuthenticator>>,
    agent_auth: Option<Arc<dyn AgentAuthenticator>>,
) -> Router {
    build_app_full_with_registrations(
        config,
        audit,
        resolved_creds,
        mtls_authenticator,
        agent_auth,
        None,
    )
}

/// Phase E.3 entrypoint — extends `build_app_full` with the
/// registrations repo so `/tools` and `/models` discovery endpoints
/// read from the registrations table when wired. `None` preserves the
/// M9 / pre-Phase-E behavior (discovery falls back to `config.tools`).
///
/// Phase E.6 added an in-memory `Catalog` cache; this entry point
/// constructs an empty one so existing callers keep their signature.
/// Daemon and integration tests that need a populated catalog use
/// [`build_app_full_with_catalog`].
pub fn build_app_full_with_registrations(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    mtls_authenticator: Option<Arc<MtlsAuthenticator>>,
    agent_auth: Option<Arc<dyn AgentAuthenticator>>,
    registrations: Option<Arc<crate::registrations::RegistrationRepository>>,
) -> Router {
    let catalog = Arc::new(ArcSwap::from_pointee(
        crate::registrations::Catalog::default(),
    ));
    build_app_full_with_catalog(
        config,
        audit,
        resolved_creds,
        mtls_authenticator,
        agent_auth,
        registrations,
        catalog,
    )
}

/// Phase E.6 entrypoint — extends [`build_app_full_with_registrations`]
/// with a pre-built `ArcSwap<Catalog>`. The daemon path calls this
/// after the seed loader and legacy bootstrap have populated the
/// registrations table; it loads the catalog from the repo, resolves
/// AuthSpec env vars into `resolved_creds`, and passes both in.
///
/// Phase F.5 added an optional `OauthRuntime` for OAuth proxy
/// dispatch — this entry point passes `None`. The daemon-bound entry
/// point [`build_app_full_with_oauth`] takes the runtime and wires
/// it into AppState.
#[allow(clippy::too_many_arguments)]
pub fn build_app_full_with_catalog(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    mtls_authenticator: Option<Arc<MtlsAuthenticator>>,
    agent_auth: Option<Arc<dyn AgentAuthenticator>>,
    registrations: Option<Arc<crate::registrations::RegistrationRepository>>,
    catalog: Arc<ArcSwap<crate::registrations::Catalog>>,
) -> Router {
    build_app_full_with_oauth(
        config,
        audit,
        resolved_creds,
        mtls_authenticator,
        agent_auth,
        registrations,
        catalog,
        None,
    )
}

/// Phase F.5 entrypoint — same as [`build_app_full_with_catalog`] but
/// also takes an optional `OauthRuntime`. Daemon path uses this when
/// `LOCKSMITH_OAUTH_SEALING_KEY` is set.
///
/// Phase G entrypoint forwards to [`build_app_full_with_phase_g`] with
/// no agent_creds — preserves the existing 8-arg signature for callers
/// (and there are many) that don't yet wire per-agent overrides.
#[allow(clippy::too_many_arguments)]
pub fn build_app_full_with_oauth(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    mtls_authenticator: Option<Arc<MtlsAuthenticator>>,
    agent_auth: Option<Arc<dyn AgentAuthenticator>>,
    registrations: Option<Arc<crate::registrations::RegistrationRepository>>,
    catalog: Arc<ArcSwap<crate::registrations::Catalog>>,
    oauth: Option<OauthRuntime>,
) -> Router {
    build_app_full_with_phase_g(
        config,
        audit,
        resolved_creds,
        mtls_authenticator,
        agent_auth,
        registrations,
        catalog,
        oauth,
        None,
    )
}

/// Phase G entrypoint — same as [`build_app_full_with_oauth`] but also
/// takes an optional `AgentCredentialRepository`. Daemon path uses
/// this once the admin substrate is wired so per-agent credential
/// overrides are honored on the proxy hot path.
#[allow(clippy::too_many_arguments)]
pub fn build_app_full_with_phase_g(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    mtls_authenticator: Option<Arc<MtlsAuthenticator>>,
    agent_auth: Option<Arc<dyn AgentAuthenticator>>,
    registrations: Option<Arc<crate::registrations::RegistrationRepository>>,
    catalog: Arc<ArcSwap<crate::registrations::Catalog>>,
    oauth: Option<OauthRuntime>,
    agent_creds: Option<crate::repo::AgentCredentialRepository>,
) -> Router {
    let snapshot = config.load();
    let response_controls = Arc::new(compile_response_controls(&snapshot));
    drop(snapshot);
    let state = Arc::new(AppState {
        config,
        started_at: Instant::now(),
        client_pool: ClientPool::new(),
        audit,
        resolved_creds,
        response_controls,
        mtls_authenticator,
        agent_auth,
        registrations,
        catalog,
        oauth,
        agent_creds,
    });

    Router::new()
        // k8s-style health endpoints (INF-3 / Q-18). Unauthenticated by
        // design — orchestrators should not need credentials to probe the
        // process. /health is preserved as an alias to /livez for
        // backward compatibility with M0 deployments.
        .route("/livez", routing::get(livez_handler))
        .route("/health", routing::get(livez_handler))
        .route("/readyz", routing::get(readyz_handler))
        .route("/version", routing::get(version_handler))
        // Agent skill (M9 / B1 follow-up). One auth-OPTIONAL route:
        // - No `Authorization` header → generic form (no tool/model
        //   leak). The auth middleware lets the request through
        //   unauthenticated for /skill specifically.
        // - Valid `Authorization: Bearer lk_...` → personalized form
        //   (the agent's resolved tool catalog, ACL, audit-debug
        //   recipes). The auth middleware runs the full bearer path,
        //   stamps `AgentIdentity` into request extensions, and the
        //   handler dispatches to the personalized renderer.
        // - Invalid bearer → 401 (no silent downgrade — preserves the
        //   §4.7.9 envelope contract).
        .route("/skill", routing::get(skill_handler))
        .route("/tools", routing::get(tools_handler))
        .route("/models", routing::get(models_handler))
        .route(
            "/api/{tool_name}/{*path}",
            routing::any(proxy::proxy_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Liveness: process is up. Returns 200 unless the process is so broken it
/// cannot serve a fixed response. INF-3.
async fn livez_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "live",
        "uptime_seconds": state.started_at.elapsed().as_secs(),
    }))
}

/// Readiness: process is ready to serve traffic. Returns 200 only when all
/// tools that declare an `auth` block have a resolved credential
/// (non-empty value). Tools without auth declarations are always ready.
/// In M2, this also checks DB reachability.
///
/// "Required backend" semantics (per INF-3 / Q-18 / A-4): in M1, all tools
/// are considered required. M2 introduces per-tool `on_secret_failure:
/// degraded` to opt out of the readiness check.
async fn readyz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.load();
    let resolved = state.resolved_creds.load();
    let unconfigured: Vec<&str> = config
        .tools
        .iter()
        .filter(|t| match &t.auth {
            Some(_) => !resolved.contains_key(&t.name),
            None => false,
        })
        .map(|t| t.name.as_str())
        .collect();

    if !unconfigured.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "reason": "tool_credentials_unresolved",
                "tools": unconfigured,
            })),
        )
            .into_response();
    }

    Json(json!({
        "status": "ready",
        "uptime_seconds": state.started_at.elapsed().as_secs(),
    }))
    .into_response()
}

/// Build metadata. Unauthenticated; useful for incident response and
/// debugging. INF-3.
async fn version_handler() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
    }))
}

/// `/skill` — auth-optional. Dispatches to the personalized form when
/// `AgentIdentity` is in request extensions (the auth middleware
/// stamped it after validating a bearer); otherwise renders the
/// generic form (no operational leak). Cache headers vary by form:
/// generic is `public, max-age=86400` (embedded at build time, same
/// per binary); personalized is `private, no-cache, no-store`
/// (operators can change an agent's ACL at any time and the body
/// embeds per-agent detail).
async fn skill_handler(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let identity = req
        .extensions()
        .get::<crate::auth_v2::AgentIdentity>()
        .cloned();
    match identity {
        Some(ref id) => {
            // Source of truth: same path /tools uses (catalog_listing
            // over the registrations table when wired, fallback to
            // legacy config.tools when not). Pre-Phase-E this returned
            // legacy ToolConfig entries via config.active_tools_against;
            // post-Phase-E that always returned empty for catalog
            // deployments because tools live in the registrations table.
            let listing =
                catalog_listing(&state, Some(id), crate::registrations::Kind::Tool).await;
            let available: Vec<(String, String)> = listing
                .into_iter()
                .filter_map(|v| {
                    let name = v.get("name")?.as_str()?.to_string();
                    let description = v
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some((name, description))
                })
                .collect();
            skill_response(
                crate::skill::render_authenticated(id, &available),
                "private, no-cache, no-store",
            )
        }
        None => skill_response(
            crate::skill::render_unauthenticated(),
            "public, max-age=86400",
        ),
    }
}

/// Common response shape for both `/skill` handlers: markdown body,
/// `text/markdown; charset=utf-8` content type, caller-supplied
/// `Cache-Control` (unauth → public/cacheable; auth → private/no-cache).
fn skill_response(body: String, cache_control: &'static str) -> Response {
    use axum::http::HeaderValue;
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    resp
}

async fn tools_handler(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Json<Value> {
    let identity = req.extensions().get::<crate::auth_v2::AgentIdentity>();
    let tools = catalog_listing(&state, identity, crate::registrations::Kind::Tool).await;
    Json(json!({ "tools": tools }))
}

async fn models_handler(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Json<Value> {
    let identity = req.extensions().get::<crate::auth_v2::AgentIdentity>();
    let models = catalog_listing(&state, identity, crate::registrations::Kind::Model).await;
    Json(json!({ "models": models }))
}

/// Render a public discovery listing (used by `/tools` and `/models`).
///
/// When the registrations repo is wired (Phase E.3+), reads from the
/// registrations table — kind-discriminated, ACL-filtered, drops
/// `disabled=true` rows. When the repo is `None` (M0/M1 / M9 test
/// path without admin substrate), falls back to the YAML-loaded
/// `config.tools` for `/tools` and returns an empty array for
/// `/models` (pre-Phase-E deployments had no model concept).
async fn catalog_listing(
    state: &Arc<AppState>,
    identity: Option<&crate::auth_v2::AgentIdentity>,
    kind: crate::registrations::Kind,
) -> Vec<Value> {
    if let Some(repo) = state.registrations.as_ref() {
        match crate::registrations::api::list_public(repo.as_ref(), kind, identity).await {
            Ok(items) => return items,
            Err(e) => {
                tracing::error!(error = ?e, "registrations list_public failed; returning empty");
                return Vec::new();
            }
        }
    }

    // Fallback: pre-Phase-E behavior. Only honors `kind=tool` (config has
    // no model concept). `kind=model` returns empty. ACL filter still
    // applies via AgentIdentity::allows_tool.
    if !matches!(kind, crate::registrations::Kind::Tool) {
        return Vec::new();
    }
    let config = state.config.load();
    let resolved = state.resolved_creds.load();
    config
        .active_tools_against(&resolved)
        .iter()
        .filter(|t| identity.is_none_or(|id| id.allows_tool(&t.name).is_ok()))
        .map(|t| {
            json!({
                "name": t.name,
                "type": "api",
                "path": format!("/api/{}", t.name),
                "description": t.description,
            })
        })
        .collect()
}
