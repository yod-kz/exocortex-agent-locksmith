# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Working branch

`develop` is the default working branch — currently at **v2.7.1**
(catalog substrate + per-agent ACL + mTLS + OAuth credential variant
+ per-agent credential overrides + OAuth session labels + complete
codex transparent integration through Phase G2/G3/G4/G5). `main` tracks
releases (promoted from `develop` at release time; currently at v2.7.1).
Cut feature branches from `develop`.

Recent phase shipments on develop:

- **Phase G** (v2.1.0): per-agent credential overrides + OAuth
  session labels. `agent_credential_overrides(agent_id, registration)`
  table; `oauth_sessions` PK extended with `session_label`.
- **Phase G2** (v2.2.0): codex `ChatGPT-Account-ID` header
  injection. Locksmith decodes the access-token JWT at OAuth
  bootstrap/refresh, extracts `chatgpt_account_id`, stores it on the
  session row, and injects the header on `/backend-api/codex/*`
  upstream calls. Migration 0006 adds `oauth_sessions.account_id`.
- **Phase G3** (v2.3.0): codex Responses API body fixup. When the
  upstream is codex AND the path ends with `/responses`, locksmith
  inspects the request body and injects/overrides three required
  fields: `store: false`, `stream: true`, `instructions: <default>`.
  1 MiB body cap (413 over). Audit captures
  `details.codex_body_fixup` when fixup happened.
- **Phase G4** (v2.4.0): codex required-header injection
  (`OpenAI-Beta: responses=experimental` + `originator: <agent>`).
  Forces `OpenAI-Beta`; preserves agent-supplied `originator` else
  injects `AgentIdentity.name` (fallback `locksmith-proxy` for
  identityless paths). After G4, agents can call codex through
  locksmith with only `Authorization` + minimal body — locksmith
  owns every codex-specific wire piece.
  See `docs/user/concepts/oauth-flow.md` for the end-to-end flow.
- **Phase G5** (v2.5.2): codex `max_output_tokens` strip. The codex
  Responses backend rejects `max_output_tokens`; `codex_body::fixup`
  now removes it alongside the G3 store/stream/instructions fixups.
- **v2.5.0 / v2.5.1**: Phase H operator guide (1Password setup) +
  personalized `/skill` catalog-read fix (WEM-334).
- **Phase I** (v2.6.0, pairs with layer8-proxy v1.6.0): codex
  seed-upstream `/backend-api/codex` suffix fix (catalog 2.2.0, #90)
  so seed-default deployments trigger the G2–G5 codex behaviors. Agent
  endpoints reach hermes agents through locksmith as ordinary
  `kind=model` registrations (no taxonomy change — agents-stack
  ADR-0007); the ingress itself is config-only. Design:
  `agents-stack/docs/spec/v0.4.0-agent-connectivity.md`.
- **Upstream CA trust** (v2.7.0): optional `tls.upstream_ca_bundle`
  config adds a private/internal CA to reqwest's roots so locksmith can
  verify HTTPS upstreams behind an internal CA. Enables the Kamiwaza MCP
  passthrough (layer8-proxy `examples/site/scripts/kamiwaza-mcp-registrar.py`).
  Adds roots only; never disables verification.
- **Query-string forwarding** (v2.7.1): `proxy_handler` re-attaches the
  inbound query string (`req.uri().query()`) to the upstream URL — axum's
  `{*path}` capture excludes it, so query-driven GETs (ComfyUI
  `/view?filename=...`, paginated/filtered REST APIs) reached the upstream
  stripped and 404'd. Regression test `test_proxy_forwards_query_string`.

The authoritative stack-level docs live at `agents-stack/docs/`:

- `agents-stack/docs/spec/v0.2.0.md` — formal as-built design (Phase E + F + G + G2 + G3 + G4).
- `agents-stack/docs/prd/v0.2.0.md` — user-facing requirements.
- `agents-stack/docs/adrs/0004-kind-taxonomy.md` — kind enum decision.
- `agents-stack/docs/adrs/0005-oauth-credentials.md` — OAuth design (Phase F + G2 + G3 + G4 addenda).

In-repo per-component engineering docs are at `docs/v2/SPEC.md` (with
`SPEC.state.md` for "what's actually in code") + `docs/v2/HANDOFF.md`
(cold-start handoff for contributors). User docs are at `docs/user/`
(concepts, agent-integration recipes).

**Ignore the top-level `SPEC.md`.** It's the deprecated M0-era "Secure Agent Proxy (SAP)" document — the project was renamed to agent-locksmith and v2 explicitly removed the `/llm/*`, `/mcp/*`, `/a2a/*` namespaces and the wire-level scanner sidecar described there. It's kept only for archaeology and carries a deprecation banner at the top.

## Common commands

```bash
# Build (release)
cargo build --release           # binaries: target/release/{locksmithd,locksmith}

# Tests + lint (CI runs all three; clippy is -D warnings)
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Single test binary / single test
cargo test --test admin_https_mtls_e2e_test
cargo test --test proxy_test -- streaming_passthrough  # name filter
cargo test path::to::module::test_name                 # for unit tests in src/

# Audit-write benchmark (criterion)
cargo bench --bench audit_write_bench

# Run daemon against the example config (tools degrade unless env vars are set)
GITHUB_TOKEN=... ANTHROPIC_API_KEY=... TAVILY_API_KEY=... \
  target/release/locksmithd --config config.example.yaml

# Operator CLI — UDS by default, HTTPS via --admin-url / LOCKSMITH_ADMIN_URL
target/release/locksmith agent list
LOCKSMITH_ADMIN_URL=https://host:9201 LOCKSMITH_CA_BUNDLE=ca.crt \
  target/release/locksmith agent list
```

SQLite migrations under `migrations/` are embedded and applied on daemon startup via `migrations::open_and_migrate`; there is no external migration tool to run.

## Two-binary layout

`Cargo.toml` declares two binaries from one crate:

- **`locksmithd`** (`src/main.rs`) — the daemon. Loads YAML config, wires telemetry + shutdown coordinator, calls `daemon::run`.
- **`locksmith`** (`src/cli/main.rs`) — operator + agent self-service CLI. Talks to the daemon over the admin UDS or admin HTTPS. Subcommands: `agent`, `bootstrap`, `bootstrap-operator` (offline; mints operator credential), `tool` / `model` / `infra` (catalog management — Phase E.4), `oauth` (Phase F.4), `audit`, `export`, `mtls`, `status`, `rotate`. Exit codes are SPEC §4.7.2 (0/1/2/3/4/5).

Library code (everything in `src/lib.rs`) is shared between both binaries and the integration tests in `tests/` (~70 test binaries, ~340 tests at v2.0.0).

## Runtime architecture

`daemon::run` (in `src/daemon.rs`) is the single composition root. Everything below is wired from there:

1. **Shared config** — `Arc<ArcSwap<AppConfig>>`. The agent router and the AdminService both observe the same snapshot, so hot reload (T1.5) is unified across surfaces. The `deny_unknown_fields` schema is in `src/config.rs`.
2. **Credential resolution** — two paths converge into one `ResolvedCreds` map:
   - **`config.tools` legacy path**: `secret::SecretResolver` resolves each `tool.auth.value: SecretRef` at startup. Backends in `src/secret/`: `EnvBackend` (incl. legacy `${VAR}` strings), `FileSealedBackend` (systemd-creds-decrypted files; rejects group/world-readable), Vault + AWS stubs.
   - **Phase E registrations path**: after seed_loader + legacy_bootstrap populate the registrations table, `secret::resolve_registration_creds_sync_env_only` walks `AuthSpec::Header` / `AuthSpec::Bearer` entries and resolves their env vars into the same map. OAuth registrations skip this path (their tokens live in the `oauth_sessions` cache).

   Tools whose secrets fail to resolve are inactive (degraded per INF-4) but the daemon still boots.
3. **Admin substrate** (built only when `listen.admin_socket` is set) — opens the SQLite pool (`migrations::open_and_migrate`), constructs `AgentRepository`, `BootstrapTokenRepository`, `AuditRepository`, `RegistrationRepository` (Phase E), `OauthSessionRepository` (Phase F, when `LOCKSMITH_OAUTH_SEALING_KEY` is set), the `BearerAuthenticator` (for agents), the `OperatorAuthenticator` (loaded from `operator_credentials_path`), and the `AdminService`. Runs the seed loader (Phase E.7) and the `legacy_bootstrap` shim (config.tools → registrations migration). The audit repository is **shared** with the agent listener so proxy and admin writes hit the same SQLite pool and JSONL mirror.
4. **Audit retention sweeper** — bounded `DELETE WHERE ts < cutoff` on a tokio interval; co-terminates with the shutdown signal.
5. **Agent listener** — switches on `listen.auth_mode`:
   - `Bearer`: plain TCP + axum.
   - `Mtls` / `Both`: TLS-terminated TCP via `agent_listener::bind_and_serve_mtls`. The handshake verifies client certs against `listen.mtls.ca_bundle_path`; the resolved peer cert is stamped into request extensions for `auth::auth_middleware` to consume. `MtlsAuthenticator` (in `src/mtls/`) maps cert identity (CN → SAN_DNS → SAN_URI) to an agent row, applies CRL + local blocklist, and emits `auth_method=mtls` audit rows.
6. **Admin UDS listener** — at `listen.admin_socket.path`. AdminService handlers live in `src/admin/service.rs`; the UDS shim is `src/admin/uds.rs`.
7. **Admin HTTPS listener** (M4, off by default) — same `UdsState` / handlers, different transport. Supports `Bearer`, `Mtls`, or `Both` independently of the agent listener. Operator client certs map to operators via `OperatorRecord.cert_identity`.
8. **Bootstrap-only listener** (M6 / C-4) — separate single-endpoint TLS listener for agent enrollment that doesn't require operator credentials.
9. **OAuth refresh task** (Phase F, when `LOCKSMITH_OAUTH_SEALING_KEY` is set) — `tokio` task scanning `oauth_sessions` for tokens nearing expiry; refreshes via `oauth::refresh::run`. Per-session `Mutex<()>` (`RefreshLockMap`) prevents racing with on-demand proxy refresh.

Both listeners share one `ShutdownCoordinator` with a configurable drain window (`shutdown.drain_window_seconds`, default 30s).

## Agent request flow (the proxy hot path)

Router is built by `app::build_app_full_with_oauth` in `src/app.rs`:

```
/livez, /health, /readyz, /version             unauthenticated
/skill                                         auth-optional (personalised when bearer present)
/tools                                         agent-authenticated; kind=tool, ACL-filtered
/models                                        agent-authenticated; kind=model, ACL-filtered
/api/{tool_name}/{*path}                       agent-authenticated; bearer or mtls
                                               → proxy::proxy_handler
```

(`kind=infra` registrations have no agent-facing surface — operator-only via `/admin/operator/infra/*`.)

`proxy::proxy_handler` (`src/proxy.rs`):

1. Reads `auth_method` + `agent_public_id` from request extensions stamped by `auth::auth_middleware`. `AgentIdentity` carries `id: i64` (Phase G — used for the agent-credential override lookup).
2. **M9 ACL gate**: when `AgentIdentity` is in extensions, calls `identity.allows_tool(name)`. Failure → 403 `tool_not_allowed` + `authz_denied` audit row (M9 / B1).
3. **Phase E.6 target resolution**: `state.catalog.lookup_active(name)` (registrations table, in-memory cache). Falls back to `config.active_tools()` for M0/M1 / pre-Phase-E test paths. `ProxyTarget::from_registration` or `from_tool_config`.
4. **Phase G per-agent override**: `apply_agent_credential_override` looks up `agent_credential_overrides[agent_id, name]`. If present, swaps in the override's AuthSpec (header/bearer reads env var directly; OAuth records the `session_label` for downstream resolution). `target.auth_source` flips to `agent_override`.
5. **Phase F.5 OAuth resolution**: when `target.auth` is `ProxyAuth::Oauth`, calls `resolve_oauth_token` with `target.oauth_session_label` (defaults to `DEFAULT_SESSION_LABEL`) to materialize the access token from `oauth_sessions(name, label)` (with inline refresh on expiry). Failures map to 503 envelope codes (`oauth_session_missing`, `oauth_refresh_failed`, `oauth_sealing_key_unset`).
6. Strips agent-sent `Authorization` and `x-api-key` headers, plus the target's auth header (defense against agent override). Always strips even when `auth: none`.
7. Injects credentials per `ProxyAuth` variant: `None` skips; `Header { override_value, .. }` and `Bearer { override_value }` use the override value when set, else fall back to `resolved_creds[name]`; `Oauth` injects access token from the OAuth cache.
7a. **Phase G2 codex header injection**: when `ProxyAuth::Oauth.account_id` is `Some(_)` and `is_chatgpt_codex_upstream(target.upstream)` matches (`/backend-api/codex` substring, case-insensitive), adds `ChatGPT-Account-ID: <account_id>`. Silent skip otherwise. The account_id was extracted from the access-token JWT at bootstrap/refresh by `oauth::jwt::extract_chatgpt_account_id` and stored in `oauth_sessions.account_id`.
7b. **Phase G3 codex body fixup**: when `is_chatgpt_codex_upstream(target.upstream)` AND `request_path_ends_with_responses(ctx.request_path)` both match, calls `codex_body::fixup` on the request body. Injects `store: false`, `stream: true`, `instructions: <default>` if missing; overrides `store`/`stream` if set wrong; preserves user-supplied `instructions`. 1 MiB body cap (413 over via `record_codex_body_too_large`). Non-JSON bodies pass through. `RequestCtx.codex_body_fixup` records what changed; surfaces in audit `details.codex_body_fixup` when non-noop.
7c. **Phase G4 codex required headers**: when `is_chatgpt_codex_upstream(target.upstream)` matches (any path, not just `/responses`), forces `OpenAI-Beta: responses=experimental` (agent's value stripped during forward loop). Injects `originator: <agent-name>` from `AgentIdentity.name` if the agent didn't supply their own; falls back to `"locksmith-proxy"` for identityless paths. Preserves agent-supplied `originator`.
8. Routes through `egress_proxy` (CONNECT proxy / Pipelock) when `target.egress: proxied`; otherwise direct.
9. Applies `ResponseControls` (M7) when the tool has a `response:` block: `max_size_bytes` (with streaming truncation marker via `SizeCappedStream`), `content_type_allowlist`, `redaction_patterns` (regex; cleartext is **never** logged — audit stores `pattern_id`, match count, and SHA-256 hash).
10. Emits one `AuditEvent` per request. Phase F adds `details.oauth_session_id`; Phase G adds `details.auth_source` (`registration_default` | `agent_override`) and `details.oauth_session_label`. `details.auth_mode` covers `none` / `header` / `bearer` / `oauth_pkce` / `oauth_device_code` / `config` / `config_absent`. Audit query results LEFT JOIN `agents` to surface `agent_name` alongside `agent_public_id` (G.0).

`/readyz` is the source-of-truth liveness check for orchestrators: it returns 503 if any tool with an `auth` block has no resolved credential. `/livez` is liveness only. `/health` is an M0 alias for `/livez`.

## Module map

```
src/
  main.rs                  locksmithd entry
  lib.rs                   public module surface
  daemon.rs                composition root (read this first)
  app.rs                   axum router + AppState
  proxy.rs                 hot path: header strip, credential inject, egress, response controls
  auth.rs                  agent-auth middleware (bearer + mtls dispatch, stamps extensions)
  auth_v2/                 BearerAuthenticator (agents) + OperatorAuthenticator (operators)
  mtls/                    MtlsValidator (webpki) + CrlStore + Blocklist + MtlsAuthenticator
  admin/                   AdminService (handlers) + uds + https + bootstrap_listener + uds_client
  agent_listener.rs        TLS-terminated TCP serve loop for auth_mode=mtls/both
  repo/                    AgentRepository, BootstrapTokenRepository, AuditRepository (sqlx)
  audit_sink.rs            JsonlSink (size-rotating mirror)
  secret/                  SecretRef + SecretResolver + Env / FileSealed / Vault / AWS backends
  response_controls.rs     M7: size cap, content-type allowlist, regex redaction
  config.rs                deny_unknown_fields YAML schema (ListenConfig, ToolConfig, AuditConfig, …)
  migrations.rs            embeds migrations/*.sql; open_and_migrate(path) → SqlitePool
  client_pool.rs           reqwest client cache keyed by egress mode + timeouts
  cli/                     locksmith CLI: client.rs (UDS/HTTPS), commands/{agent,audit,bootstrap,bootstrap_operator,export,infra,model,mtls,oauth,registration,self_svc,tool}.rs
  registrations/           Phase E: kind enum, AuthSpec, validators, RegistrationRepository, Catalog cache, seed_loader, legacy_bootstrap, admin api
  oauth/                   Phase F + G + G2: SealingKey (AES-GCM), OauthSessionRepository (label-aware + account_id), refresh task + RefreshLockMap, jwt.rs (chatgpt_account_id extraction), admin handlers
  codex_body.rs            Phase G3: pure-functional fixup() for codex /responses request bodies — inject store:false / stream:true / instructions, 1 MiB cap
  repo/agent_creds.rs      Phase G: AgentCredentialRepository — per-agent credential overrides keyed on (agent_id, registration)
  shutdown.rs              ShutdownCoordinator + drain window
  telemetry.rs             tracing-subscriber JSON setup
  deprecation.rs           one-shot warnings for legacy config shapes
tests/                     integration tests, one binary per file
benches/audit_write_bench  criterion bench — validates A-2 / INF-26 audit throughput
migrations/                SQLite schema (embedded into the binary)
seed/catalog.yaml          Phase E.7: bundled default registrations (16 entries at v2.1.0)
dist/systemd/              hardened unit template (NoNewPrivileges, ProtectSystem=strict, …)
dist/examples/             smallstep mTLS + sealed-secrets worked examples
docs/user/                 User docs (concepts, agent-integration recipes)
docs/v2/                   SPEC, PRD, HANDOFF, threat-model, runbooks (engineering)
```

## Conventions worth knowing

- **Secrets discipline.** Anything secret rides in `secrecy::SecretString` (zeroized on drop). It must never appear in log fields, error messages, HTTP responses, audit rows, or test fixtures committed to the repo. The redaction subsystem hashes cleartext into audit, never the cleartext itself.
- **`deny_unknown_fields`** is on every config struct. Adding a field means a schema change — bump tests in `tests/config_*` and the example config alongside.
- **Hot-reload carve-out.** Listener-shape config (admin_https paths, mTLS cert paths, bind ports) requires a daemon restart by design; tools/audit/retention/response_controls are reload-safe via the shared `ArcSwap<AppConfig>`. T2.20 (extending hot reload to remaining non-listener fields) is on the post-v2 backlog.
- **Auth surfaces are independent.** Agent listener (`listen.auth_mode`) and admin HTTPS (`listen.admin_https.auth_mode`) each pick `bearer | mtls | both` separately. The UDS admin listener uses operator bearer tokens only (peer-uid gate is the OS).
- **Audit is one schema, two sinks.** Every event goes through `AuditRepository::record`, which writes to SQLite and optionally appends to a size-rotating JSONL mirror. New event types extend `EventClass` / `event` strings — keep them stable; runbooks and CLI queries grep against them.
- **Cloud routing.** Tools mark `egress: proxied` (preferred) or legacy `cloud: true` to route through `egress_proxy` (typically Pipelock). LAN tools use `egress: direct` and bypass the CONNECT proxy.
- **Comments.** Existing source comments often cite SPEC tasks (`T6.5`, `INF-3`, `D-10`, `R-N6`, etc.) — those tags map to `docs/v2/SPEC.md` / `PRD.md`. Preserve that vocabulary when adding new code so future archaeology stays cheap.

## Stack-root context

The parent `agents-stack/AGENTS.md` and `agents-stack/CLAUDE.md` apply at the meta-repo level (cross-repo orchestration, `stack.py`). Implementation work belongs in this sub-repo; this CLAUDE.md takes precedence over the stack root for everything inside `agent-locksmith/`.
