use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;

use crate::agent_listener::PeerCertDer;
use crate::app::AppState;
use crate::auth_v2::{AuthError, auth_error_response};
use crate::config::AuthMode;

/// Recorded on the request extension to tell downstream code (proxy
/// audit emit) which transport authenticated this request. Drives the
/// `auth_method` audit column (T6.10).
#[derive(Clone, Debug)]
pub enum AuthenticatedAs {
    /// M0/M1 shared bearer or M2 per-agent bearer.
    Bearer,
    /// M6 client certificate.
    Mtls,
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Skip auth for unauthenticated probes / metadata endpoints (INF-3).
    // /health is preserved as an alias to /livez for backward compat with
    // M0 deployments.
    let path = req.uri().path();
    if matches!(path, "/livez" | "/readyz" | "/version" | "/health") {
        return next.run(req).await;
    }

    // Credential transport routes authenticate with per-tool fake bearer
    // handles instead of the normal agent bearer. This avoids colliding with
    // SDKs such as Slack that must use `Authorization: Bearer <token>` for
    // their own upstream auth material.
    if path == "/transport" || path.starts_with("/transport/") {
        return next.run(req).await;
    }

    // /skill is auth-OPTIONAL (M9 / B1 follow-up). With no
    // `Authorization` header the request passes through unauthenticated
    // and the handler renders the generic (no-leak) form. With a header
    // present we run the full auth path so a successful bearer stamps
    // `AgentIdentity` (handler renders personalized) and a failure
    // returns 401 (don't silently downgrade — that would let an
    // attacker probe valid token formats by checking content variation).
    if path == "/skill" && !req.headers().contains_key("authorization") {
        return next.run(req).await;
    }

    let auth_mode = state.config.load().listen.auth_mode;

    // mTLS branches (post-v2 / #67). Under `Mtls` we require a peer
    // cert; under `Both` we try mTLS first and fall back to bearer.
    // All error responses route through `auth_error_response` so the
    // wire envelope matches §4.7.9 (status + `code` field) for both
    // bearer and mTLS paths uniformly (M9).
    if matches!(auth_mode, AuthMode::Mtls | AuthMode::Both) {
        let peer = req.extensions().get::<PeerCertDer>().cloned();
        let has_cert = peer.as_ref().is_some_and(|p| p.0.is_some());
        if has_cert {
            let cert = peer.unwrap().0.unwrap();
            let Some(authn) = state.mtls_authenticator.clone() else {
                tracing::error!(
                    "auth_mode={:?} but no mtls_authenticator wired in AppState",
                    auth_mode
                );
                return auth_error_response(&AuthError::MtlsMisconfigured);
            };
            return match authn.authenticate_cert(&cert).await {
                Ok(identity) => {
                    req.extensions_mut().insert(AuthenticatedAs::Mtls);
                    req.extensions_mut().insert(identity);
                    next.run(req).await
                }
                Err(e) => auth_error_response(&e),
            };
        }
        if matches!(auth_mode, AuthMode::Mtls) {
            // Strict mode requires a client cert. Render through the
            // §4.7.9 envelope using `MissingCredential` (no presented
            // cert is the equivalent of a missing bearer header).
            return auth_error_response(&AuthError::MissingCredential);
        }
        // Both: fall through to bearer path.
    }

    // M9 / B1: per-agent bearer authentication when the admin substrate
    // is enabled (BearerAuthenticator wired by daemon.rs). On success
    // we stamp `AuthenticatedAs::Bearer` AND the resolved `AgentIdentity`
    // into request extensions so `proxy::proxy_handler` can enforce
    // tool ACL and emit `agent_public_id` audit rows.
    if let Some(authn) = state.agent_auth.as_ref() {
        return run_bearer_branch(authn.as_ref(), req, next).await;
    }

    // M0/M1 shared-bearer fallback. Preserves pre-v2 behavior for
    // deployments that haven't enabled the admin substrate
    // (`listen.admin_socket` + `database.path`). When the admin
    // substrate IS enabled, the branch above handles the request and
    // this fallback is unreachable.
    let config = state.config.load();
    let auth_config = match &config.inbound_auth {
        Some(auth) if auth.mode == "bearer" => auth,
        _ => {
            req.extensions_mut().insert(AuthenticatedAs::Bearer);
            return next.run(req).await;
        }
    };
    let expected_token = match &auth_config.token {
        Some(t) => t,
        None => {
            req.extensions_mut().insert(AuthenticatedAs::Bearer);
            return next.run(req).await;
        }
    };
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    let provided_token = auth_header.and_then(|h| h.strip_prefix("Bearer "));
    match provided_token {
        Some(token) if token == expected_token.expose_secret() => {
            req.extensions_mut().insert(AuthenticatedAs::Bearer);
            next.run(req).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": "Unauthorized", "type": "auth_error"}})),
        )
            .into_response(),
    }
}

/// Per-agent bearer branch (M9). Always routes through the authenticator
/// — including missing or unparseable headers — so the authenticator owns
/// audit emission for every failure mode (missing/malformed/unknown/
/// expired/wrong-secret). The empty string fallback maps non-ASCII or
/// absent `Authorization` headers onto the same `missing_credential`
/// audit path as a fully-absent header, so probe traffic stays visible
/// in the security log regardless of how the client malformed the request.
async fn run_bearer_branch(
    authn: &dyn crate::auth_v2::AgentAuthenticator,
    mut req: Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    match authn.authenticate_bearer(&header).await {
        Ok(identity) => {
            req.extensions_mut().insert(AuthenticatedAs::Bearer);
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        Err(e) => auth_error_response(&e),
    }
}
