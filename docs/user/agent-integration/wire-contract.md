# Wire contract (agent-developer reference)

What an agent sees when calling locksmith. Use this as the spec for
wiring any agent (hermes, openclaw, or your own) through a layer8-proxy
deployment.

## Authentication

Every agent-facing endpoint (except `/livez`, `/readyz`, `/version`,
`/skill`) requires a bearer token in the `Authorization` header:

```
Authorization: Bearer lk_<22-char-public-id>.<43-char-secret>
```

The bearer is issued by the operator via `locksmith agent register`
(see [add-an-agent.md](https://github.com/SentientSwarm/layer8-proxy/blob/main/docs/user/add-an-agent.md)).
It identifies the agent and carries its ACL — the agent NEVER sends
provider API keys. Locksmith strips agent-supplied
`Authorization` / `x-api-key` / `host` headers before forwarding
upstream.

For mTLS-deployed agents (`auth_mode: mtls | both`), the bearer
is replaced by a client certificate; the cert's CN/SAN/URI maps to an
agent record.

## Endpoints

### `GET /livez` — liveness

```
HTTP 200 application/json
{"status": "live", "uptime_seconds": 3600}
```

Unauthenticated. Use as a Kubernetes liveness probe.

### `GET /readyz` — readiness

```
HTTP 200 application/json
{"status": "ready", "uptime_seconds": 3600}
```

Or, when any tool with auth has unresolved credentials:

```
HTTP 503 application/json
{"status": "not_ready", "reason": "tool_credentials_unresolved", "tools": ["foo", "bar"]}
```

Unauthenticated. Use as a Kubernetes readiness probe / orchestrator
gate.

### `GET /version` — build metadata

```
HTTP 200 application/json
{"name": "agent-locksmith", "version": "2.0.0"}
```

Unauthenticated.

### `GET /skill` — agent skill rendering

Auth-optional. With a valid agent bearer, returns a personalised
markdown blob describing the agent's catalog (its allowed tools,
ACL, audit-debug recipes). Without a bearer, returns a generic
form (no operational leak — same content for every requester).

```
HTTP 200 text/markdown; charset=utf-8
Cache-Control: private, no-cache, no-store        (personalised)
Cache-Control: public, max-age=86400              (generic)

# locksmith — agent: my-first-agent
You can call:
  - anthropic at /api/anthropic/...
  - openai    at /api/openai/...
  - tavily    at /api/tavily/...
...
```

The agentskills.io format. Useful for an LLM-based agent to bootstrap
its tool catalog at startup.

### `GET /tools` — kind=tool discovery

```
HTTP 200 application/json
Authorization: Bearer lk_...

{
  "tools": [
    {"name": "tavily", "type": "api", "path": "/api/tavily", "description": "Tavily search API"},
    {"name": "github", "type": "api", "path": "/api/github", "description": "GitHub REST API v3"}
  ]
}
```

Returns ONLY `kind=tool` registrations the calling agent's allowlist
permits. `kind=model` and `kind=infra` are filtered out (use `/models`
for models; infra is operator-only).

### `GET /models` — kind=model discovery

```
HTTP 200 application/json
Authorization: Bearer lk_...

{
  "models": [
    {"name": "anthropic", "type": "api", "path": "/api/anthropic", "description": "Anthropic Messages API"},
    {"name": "openai",    "type": "api", "path": "/api/openai",    "description": "OpenAI Responses + Chat Completions API"}
  ]
}
```

Same shape as `/tools`, but `kind=model` only.

### `ANY /api/{tool_name}/{*path}` — proxy hot path

The provider call. Locksmith:

1. Validates the bearer.
2. Checks the agent's ACL against `tool_name`.
3. Looks up the registration in the catalog.
4. Strips agent-supplied auth headers.
5. Injects the configured credential.
6. Forwards to the registration's `upstream + /{*path}`.
7. Streams the response back.
8. Audits.

#### Method + path passthrough

The HTTP method, request body, query string, and remaining path
segments after `tool_name` are forwarded as-is. So calling
`POST /api/anthropic/v1/messages` with a JSON body lands on
`POST <anthropic.upstream>/v1/messages` with the same body.

#### Headers

**Stripped from the agent's request** (defense-in-depth):

- `Authorization` (always — even when `auth: none`)
- `x-api-key` (always)
- `host`
- The target's own auth header (e.g., `x-api-key` for anthropic
  registrations, `Authorization` for bearer ones)

**Forwarded as-is**: any other header the agent sends (e.g.,
`anthropic-version`, `content-type`, custom application headers).

**Injected by locksmith**:

- For `AuthSpec::Header { header, env_var, force_replace }`: `<header>: <env-var-value>`
- For `AuthSpec::Bearer { env_var, force_replace }`: `Authorization: Bearer <env-var-value>`
- For OAuth: `Authorization: Bearer <access_token-from-cache>`
- For `AuthSpec::None`: nothing.

The agent never sees the injected credential. When `force_replace` is true and
the configured replacement credential is unavailable, Locksmith returns
`503 credential_unavailable` before contacting upstream.

#### Streaming

Locksmith streams the upstream response body chunk-by-chunk. SSE
streams (Anthropic, OpenAI completion streaming) work natively — no
buffering. R-N6 contract: ≤100ms first-byte added latency.

When response controls are configured (`max_size_bytes` /
`content_type_allowlist` / `redaction_patterns`), behavior depends
on the policy:

- `max_size_bytes` only → stream with size cap (truncates with
  marker if exceeded).
- `redaction_patterns` → buffer the whole response, apply regex,
  then return.
- `content_type_allowlist` → stream-time pre-check.

## Error envelope

All locksmith-side errors render as:

```json
{
  "error": {
    "type": "...",     // bad_request | not_found | conflict | auth_error | authz_error | upstream_error | timeout | response_size_exceeded | response_content_type_disallowed
    "code": "...",     // specific machine-readable code
    "message": "..."   // human-readable explanation
  }
}
```

Common codes:

| HTTP | type | code | When |
|---|---|---|---|
| 401 | `auth_error` | `invalid_credential` | Bearer doesn't match a registered agent. |
| 401 | `auth_error` | `missing_credential` | No `Authorization` header. |
| 403 | `authz_error` | `tool_not_allowed` | Agent's ACL doesn't permit this tool. |
| 404 | `not_found` | (no code) | Tool name not registered. |
| 400 | `bad_request` | (varies) | Malformed body / param. |
| 502 | `upstream_error` | (varies) | Upstream provider returned 5xx or unreachable. |
| 504 | `timeout` | `timeout` | Upstream took longer than configured timeout. |
| 503 | `auth_error` | `oauth_session_missing` | OAuth tool but no session bootstrapped. |
| 503 | `auth_error` | `oauth_refresh_failed` | OAuth session degraded; operator action required. |
| 503 | `auth_error` | `oauth_sealing_key_unset` | OAuth tool but daemon has no sealing key. |
| 502 | `upstream_error` | `response_content_type_disallowed` | M7 content-type allowlist rejected the response. |
| 502 | `upstream_error` | `response_size_exceeded` | M7 size cap exceeded. |

**Existence-leak avoidance (Q-8)**: agent-facing errors don't reveal
whether a name exists in the catalog. A request to `/api/nonexistent/...`
with a valid bearer returns 404 generic; without a bearer returns
401. The 404 doesn't differentiate "tool exists but ACL denies"
(that's 403) from "tool doesn't exist".

## Streaming contract details

For Anthropic / OpenAI / streaming completion-style:

- Upstream response `Content-Type: text/event-stream` flows through
  unchanged.
- Heartbeat / keepalive frames are forwarded as-is.
- Stream truncation (size cap exceeded) emits a marker frame:
  `data: {"locksmith":{"truncated":true,"observed_bytes":N,"cap_bytes":M}}\n\n`
  followed by `data: [DONE]\n\n`.

## Audit fields agents can correlate against

If your agent wants to correlate locksmith's audit rows back to its
own logs, the stable identifiers are:

- `agent_public_id` — your agent's stable public ID (the part before
  the `.` in your bearer).
- `tool` — the registration name in the URL.
- `path` — the suffix after `/api/{tool}/`.
- `oauth_session_id` (OAuth requests) — sha256-derived; stable across
  access-token refreshes within a session.

Locksmith does NOT pass through arbitrary correlation IDs — if you
need request-level correlation, your agent should set its own
identifying header (e.g., `x-request-id: ...`) which locksmith
forwards untouched.

## Worked example: Anthropic

```http
POST /api/anthropic/v1/messages HTTP/1.1
Host: layer8.lan:9200
Authorization: Bearer lk_yN2vR6jFKNYfIwNjFU2MSA.1TJlTmOgmswZYZx_aQHyjaNiugeJjudytNPFJgT9aqM
anthropic-version: 2023-06-01
Content-Type: application/json

{
  "model": "claude-haiku-4-5",
  "max_tokens": 100,
  "messages": [{"role": "user", "content": "Hello"}]
}
```

What locksmith forwards to Anthropic:

```http
POST /v1/messages HTTP/1.1
Host: api.anthropic.com
x-api-key: sk-ant-...                            ← injected from .env
anthropic-version: 2023-06-01                    ← passed through
Content-Type: application/json                   ← passed through

{ ... same body ... }
```

What flows back: Anthropic's response (status, headers, body),
streamed through locksmith with one audit row written.

## See also

- [`openclaw.md`](openclaw.md) — openclaw integration recipe.
- [`hermes.md`](hermes.md) — hermes integration recipe (planned).
- [`examples/`](examples/) — curl + Python + TypeScript snippets
  (planned).
- [`../concepts/error-envelope.md`](../concepts/error-envelope.md) —
  conceptual deep-dive on the envelope shape + Q-8.
- [`../concepts/agent-identity-and-acl.md`](../concepts/agent-identity-and-acl.md)
  — bearer token semantics + ACL evaluation.
