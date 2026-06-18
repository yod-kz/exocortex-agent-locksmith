# agent-locksmith

A Rust credential proxy that sits between AI agents and external services.
Agents never see provider API keys — locksmith injects credentials, enforces
per-agent ACLs, audits every request, and routes outbound traffic through a
configurable egress chain.

The keystone component of the [layer8-proxy][layer8] stack.

[layer8]: https://github.com/SentientSwarm/layer8-proxy

**Current version: v2.7.1** ([release notes](https://github.com/SentientSwarm/agent-locksmith/releases/tag/v2.7.1))

## What it does

- **Agent sends:** `POST /api/anthropic/v1/messages` with the agent's per-agent
  bearer token (no provider API key).
- **Locksmith validates:** the bearer is registered + the agent's ACL allows
  `anthropic`.
- **Locksmith forwards:** `POST https://api.anthropic.com/v1/messages` with
  `x-api-key: <real provider key>` injected from sealed-at-rest creds.
- **Locksmith audits:** one row per request — agent identity, tool, status,
  latency, auth_mode.

The agent discovers available tools via `GET /tools` (kind=tool) and
`GET /models` (kind=model). Discovery is per-agent ACL-filtered. Internal
middleware (`kind=infra`) is operator-only.

## Highlights (v2.7.1)

- **Kind-discriminated registrations (Phase E)** — `model` / `tool` / `infra`
  taxonomy. Agents reason about LLMs vs service tools differently;
  operator-only middleware (lf-scan today) lives in its own kind.
- **Per-agent bearer + ACL** — each agent registration carries an
  `allowlist` / `denylist`. The proxy hot path enforces it before reaching
  upstream.
- **mTLS feature flag** — listener `auth_mode: bearer | mtls | both`.
  Admin HTTPS path gets the same treatment.
- **OAuth credential variant (Phase F)** — `AuthSpec::OauthPkce` and
  `AuthSpec::OauthDeviceCode` for codex / copilot / anthropic-oauth /
  google-gemini-cli / qwen-cli. Refresh tokens sealed at rest with
  AES-GCM (`LOCKSMITH_OAUTH_SEALING_KEY`); access tokens auto-refresh.
- **Per-agent credential overrides + OAuth labels (Phase G)** —
  `agent_credential_overrides(agent_id, registration) → AuthSpec`
  swaps the default credential on a per-agent basis. OAuth sessions
  gain a `session_label` dimension so one registration can hold N
  sessions (one per ChatGPT account, GitHub account, etc.). Default
  behavior unchanged when no overrides are set.
- **codex `ChatGPT-Account-ID` injection (Phase G2)** — locksmith
  decodes the access-token JWT at OAuth bootstrap/refresh, extracts
  `chatgpt_account_id`, and injects the required
  `ChatGPT-Account-ID` header on `/backend-api/codex/*` upstream
  calls. Agents proxied through locksmith get full ChatGPT plan auth
  (Responses API) without needing to be JWT-aware OAuth clients
  themselves. See [`docs/user/concepts/oauth-flow.md`](docs/user/concepts/oauth-flow.md).
- **codex Responses API body fixup (Phase G3)** — on requests where
  the upstream is codex AND the path is `/responses`, locksmith
  inspects the JSON body and injects/overrides the three codex-
  required fields: `store: false`, `stream: true`, `instructions:
  <default>` (preserves user-supplied `instructions`). Agents that
  send a generic `openai-responses` body shape get a working codex
  call without needing codex-specific code paths. 1 MiB body cap.
  Audit captures `details.codex_body_fixup` when fixup happened.
- **codex required-header injection (Phase G4)** — locksmith
  injects `OpenAI-Beta: responses=experimental` (forced) and
  `originator: <agent-name>` (preserves agent-supplied value
  otherwise) on every `/backend-api/codex/*` upstream call. Combined
  with G2 (ChatGPT-Account-ID) and G3 (body fields), agents can call
  codex with only `Authorization: Bearer lk_…` + minimal body —
  locksmith owns every codex-specific wire piece.
- **Seed catalog** — 16 default providers baked into the image
  (anthropic, openai, openrouter, ai-gateway, ollama, lmstudio, tavily,
  github, duckduckgo, wikipedia, lf-scan + 5 OAuth providers). Operators
  provide `.env` credentials and override site-specific fields via the
  admin API.
- **Admin substrate** — UDS (default) and optional HTTPS for cross-host
  operations. Agent registration, tool/model PUT, audit query, OAuth
  bootstrap, per-agent credential overrides.
- **Audit** — every proxy request + admin write emits one structured
  audit row; SQLite + optional JSONL mirror. Phase G adds
  `agent_name` (LEFT JOIN), `auth_source` (registration vs override),
  and `oauth_session_label` to every `proxy_request` row.
- **Memory-safe secrets** — credentials in `secrecy::SecretString`
  (zeroized on drop); never logged, never in HTTP responses.
- **Upstream CA trust (v2.7.0)** — optional `tls.upstream_ca_bundle`
  adds a private/internal CA to the client root store so locksmith can
  verify HTTPS upstreams behind an internal CA (e.g. a Kamiwaza MCP
  endpoint). Adds roots only; verification is never disabled.
- **Query-string forwarding (v2.7.1)** — the proxy now re-attaches the
  inbound query string to the upstream URL. Query-driven GETs (e.g.
  ComfyUI `/view?filename=...`, paginated/filtered REST APIs) previously
  reached the upstream stripped and 404'd.

## Two-binary layout

```
locksmithd   the daemon (src/main.rs)
locksmith    operator + agent self-service CLI (src/cli/main.rs)
```

CLI subcommands: `agent` (operator), `tool` / `model` / `infra` (operator —
catalog management), `oauth` (operator — OAuth session bootstrap), `audit`,
`bootstrap` (token mint), `mtls`, `status` / `rotate` (agent self-service).

## Quick start

### Build

```bash
cargo build --release
# binaries: target/release/{locksmithd,locksmith}
```

### Configure

```yaml
# /etc/locksmith/config.yaml
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: bearer       # bearer | mtls | both
  admin_socket:
    path: "/var/run/locksmith/admin.sock"

operator_credentials_path: "/etc/locksmith/operators.yaml"

database:
  path: "/var/lib/locksmith/locksmith.db"

audit:
  retention_days: 90
  sweep_interval_seconds: 3600

# Optional egress chokepoint (typically Pipelock CONNECT proxy).
egress_proxy: "http://127.0.0.1:8888"
```

The seed catalog at `/etc/locksmith/seed/catalog.yaml` (baked into the
docker image) populates the registrations table on first boot. Operators
provide credentials via env vars (or the layer8-proxy-site sealed-creds
flow); no per-tool YAML required for the 16 default providers.

### Run (standalone)

```bash
# 1. Mint an operator credential. Writes operators.yaml to stdout
#    (with the argon2-hashed token) + prints the cleartext wire
#    token to stderr ONCE.
target/release/locksmith bootstrap-operator --name dev > operators.yaml
# Save the printed wire token. Conventionally:
#   export LOCKSMITH_OP_TOKEN=lkop_<public_id>.<secret>

# 2. Start the daemon. config.example.yaml in this repo is a working
#    minimal config; point operator_credentials_path at the
#    operators.yaml from step 1.
target/release/locksmithd --config config.example.yaml

# 3. Register an agent.
LOCKSMITH_OP_TOKEN=lkop_... \
  target/release/locksmith agent register \
    --name dev-agent --allowlist anthropic,openai,tavily
# The printed bearer (lk_...) goes in the agent's environment as
#   LOCKSMITH_AGENT_TOKEN=lk_...

# 4. Operator commands (catalog, audit, OAuth):
LOCKSMITH_OP_TOKEN=lkop_... target/release/locksmith model list
LOCKSMITH_OP_TOKEN=lkop_... target/release/locksmith audit query --since-ms $(($(date +%s) * 1000 - 3600000))

# 5. Agent self-service.
LOCKSMITH_AGENT_TOKEN=lk_... target/release/locksmith status
```

`bootstrap-operator` is offline — it doesn't talk to a daemon. The
operator credential it produces is what the daemon validates incoming
admin-API requests against. Re-running `bootstrap-operator` mints a
fresh token; the prior wire token stops working immediately.

### Run (production, layer8-proxy bundle)

For Docker Compose deploys with pipelock + lf-scan + sealed-creds
infrastructure, see [layer8-proxy][layer8]. The bundle includes
`./scripts/init-site.sh` to bootstrap a site repo from a public
template at `layer8-proxy/examples/site/`.

## Wire surface

### Public (per-agent-bearer authenticated; ACL-filtered)

```
GET  /livez                      unauthenticated; liveness probe
GET  /readyz                     unauthenticated; readiness (503 if any
                                 tool with auth has no resolved credential)
GET  /version                    unauthenticated
GET  /skill                      auth-optional; markdown personalised when
                                 a valid agent bearer is supplied
GET  /tools                      kind=tool catalog, ACL-filtered
GET  /models                     kind=model catalog, ACL-filtered
ANY  /api/{tool_name}/{*path}    proxy hot path
```

### Operator (operator-credential authenticated; UDS or HTTPS)

```
GET    /admin/operator/agents
POST   /admin/operator/agents                    register an agent
GET    /admin/operator/agents/{public_id}
PATCH  /admin/operator/agents/{public_id}        modify ACL
POST   /admin/operator/agents/{public_id}/revoke

GET    /admin/operator/{tools,models,infra}
GET    /admin/operator/{tools,models,infra}/{name}
PUT    /admin/operator/{tools,models,infra}/{name}
DELETE /admin/operator/{tools,models,infra}/{name}
POST   /admin/operator/{tools,models,infra}/{name}/enable

POST   /admin/operator/oauth/{name}/bootstrap    OAuth session (Phase F)
GET    /admin/operator/oauth/{name}              session status
DELETE /admin/operator/oauth/{name}              revoke

GET    /admin/operator/bootstrap_tokens
POST   /admin/operator/bootstrap_tokens
POST   /admin/operator/bootstrap_tokens/{public_id}/revoke

GET    /admin/operator/audit                     audit query
```

### Error envelope (§4.7.9)

Every error renders as:

```json
{ "error": { "type": "...", "code": "...", "message": "..." } }
```

Codes include `name_in_use`, `reserved_name`, `auth_required`,
`wrong_kind`, `model_auth_required`, `tool_not_allowed`,
`invalid_credential`, `oauth_session_missing`, `oauth_refresh_failed`,
`oauth_sealing_key_unset`, etc. The agent-facing surface follows
existence-leak avoidance (Q-8): admin errors never reveal whether a
name exists; per-agent errors are generic.

## Configuration reference

```yaml
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: bearer | mtls | both
  admin_socket:
    path: "/var/run/locksmith/admin.sock"
  admin_https:                # optional; v2.0.0+
    bind_address: "0.0.0.0:9201"
    auth_mode: bearer | mtls | both
    cert_path: "..."
    key_path: "..."
  mtls:                       # required when auth_mode != bearer
    ca_bundle_path: "..."
    server_cert_path: "..."
    server_key_path: "..."

operator_credentials_path: "/etc/locksmith/operators.yaml"

database:
  path: "/var/lib/locksmith/locksmith.db"

audit:
  retention_days: 90
  sweep_interval_seconds: 3600
  jsonl_path: "/var/log/locksmith/audit.jsonl"   # optional mirror
  jsonl_max_bytes: 104857600
  jsonl_keep_files: 7

egress_proxy: "http://127.0.0.1:8888"

logging:
  level: info

shutdown:
  drain_window_seconds: 30

# Pre-Phase-E `tools:` block is still accepted for backward compat;
# entries are migrated into the registrations table at first boot
# (legacy_bootstrap shim). Removed in v0.3. New deployments rely on
# the seed catalog + admin API instead.
tools: []
```

## Security model

- **Credential confinement**: provider API keys never leave locksmith.
  Agent processes literally don't hold them.
- **Per-agent identity**: every agent has its own bearer; revoke is
  per-agent.
- **ACL enforcement**: hot-path `tool_allowlist` / `tool_denylist`
  check before any upstream contact.
- **Audit trail**: every request → one structured row (SQLite + JSONL
  mirror). `auth_method` (bearer / mtls), `auth_mode` (none / header /
  bearer / oauth_*), `oauth_session_id` for forensic correlation.
- **Sealed creds at rest**: provider keys via `SecretRef::FromFileSealed`
  (systemd-creds / openssl-sealed); OAuth refresh tokens via AES-GCM
  with `LOCKSMITH_OAUTH_SEALING_KEY`.
- **Header stripping**: agent-sent `Authorization` / `x-api-key` are
  stripped before forwarding, defense-in-depth even when the
  registration is `auth: none`.
- **mTLS** (feature flag): client-cert authentication on the agent
  listener and admin HTTPS — independent settings.

## Deployment

```
       ┌──────────┐
agent ─┤  bearer  ├─► locksmith :9200 ──► pipelock :8888 ──► Internet
       └──────────┘         │
                            ├──► LAN services (direct egress)
                            └──► lf-scan :9100 (kind=infra middleware)
```

For the canonical deployment story:

- **Stack bundle**: [layer8-proxy][layer8] — Docker Compose composition.
- **Per-host site repo**: `layer8-proxy-site` (proxy operator) and
  `hermes-site` / `openclaw-site` (agent operator).
- **Stack docs**: `agents-stack/docs/{spec,prd,adrs,plans}/`.

## Documentation

- **Stack-level (cross-repo)**:
  - [`agents-stack/docs/spec/v0.2.0.md`][spec] — formal as-built design.
  - [`agents-stack/docs/prd/v0.2.0.md`][prd] — user-facing requirements.
  - [`agents-stack/docs/adrs/`][adrs] — cumulative decisions
    (kind taxonomy, OAuth, etc.).

- **User docs (locksmith-side)**:
  - [`docs/user/concepts/`](docs/user/concepts) — kind taxonomy, error
    envelope, agent identity + ACL, trust boundary, per-agent
    credentials + OAuth labels.
  - [`docs/user/agent-integration/`](docs/user/agent-integration) —
    wiring agents (hermes, openclaw) into a layer8-proxy deployment.
  - [`docs/user/cli-reference.md`](docs/user/cli-reference.md) —
    full `locksmith` CLI surface.

- **Engineering docs (per-component)**:
  - [`docs/v2/SPEC.md`](docs/v2/SPEC.md) — engineering spec with task
    references (T1.x, T2.x, …).
  - [`docs/v2/HANDOFF.md`](docs/v2/HANDOFF.md) — cold-start handoff for
    contributors.
  - [`docs/v2/runbooks/`](docs/v2/runbooks) — operational runbooks.

[spec]: https://github.com/SentientSwarm/agents-stack/blob/main/docs/spec/v0.2.0.md
[prd]: https://github.com/SentientSwarm/agents-stack/blob/main/docs/prd/v0.2.0.md
[adrs]: https://github.com/SentientSwarm/agents-stack/blob/main/docs/adrs/

## Development

```bash
# All gates (CI runs all three; clippy is -D warnings).
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Single test binary or single test.
cargo test --test admin_https_mtls_e2e_test
cargo test --test proxy_test -- streaming_passthrough

# Audit-write benchmark.
cargo bench --bench audit_write_bench

# Run daemon against the example config.
target/release/locksmithd --config config.example.yaml
```

SQLite migrations are embedded at compile time via `migrations/*.sql`
and applied by `migrations::open_and_migrate` on daemon startup. No
external migration tool to run.

## License

MIT — see [LICENSE](LICENSE).
