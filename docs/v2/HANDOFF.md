# Handoff — Agent Locksmith v2 Implementation

**Last updated:** 2026-05-03
**Default working branch:** `develop` (post-v1.0.0 enhancements merged: #67 mTLS bind + #68 audit bench) — **Tagged v1.1.0**
**Active feature branch:** `feature/m9-proxy-bearer-acl` (B1 closure — per-agent bearer + ACL on proxy hot path; tagged **v2.0.0** breaking on merge)

This document is the cold-start context for the next session. Read top to bottom before touching code.

---

## 1. Where we are

| Branch | State | What's there |
|--------|-------|--------------|
| `main` | **v2.6.0** | Tracks releases through v2.6.0 (M0..M7 + Phase E/F/G/G2-G5 + H + I). CI passes. |
| `develop` | **v1.1.0** | M0..M7 + post-v1.0.0 #67 (agent-listener mTLS bind path activated) + #68 (audit-write bench validated A-2 / INF-26). Tagged **v1.1.0**. |
| `feature/m9-proxy-bearer-acl` | **In review (v2.0.0)** | M9 / B1 closure. Per-agent bearer enforcement on the proxy hot path; tool ACL gate; uniform §4.7.9 error envelope; `inbound_auth.token` deprecation when admin substrate is enabled. **Breaking change** — merge tags v2.0.0. |
| `m3/audit-pipeline`, `m4/admin-https`, `m5/keys-at-rest`, `m6/mtls-agent-side`, `m7/response-controls` | Merged | Kept for archaeology. |

### What's merged into `develop`

- v2 PRD + design (SoftwareDesign workflow, all 7 phases).
- **M1** (T1.1–T1.13): inference-ready hardening.
- **M2** (T2.1–T2.10, T2.12–T2.16, T2.22–T2.27): agent identity + admin substrate + locksmith CLI.
- **M3** (T3.1–T3.6, T3.8, T3.11): governance audit log.
- **M4** (T4.1–T4.6): admin HTTPS listener for remote management.
- **M5** (T2.17, T2.19, T5.1–T5.5): keys-at-rest hardening with file-sealed credentials.
- **M6** (T6.1–T6.11): mTLS — validator, CRL fetcher, blocklist, authenticator, bootstrap-only listener, operator cert mapping, CLI mtls subcommands, smallstep example, 3 mTLS runbooks.
- **M7** (T7.1–T7.4): per-tool response controls — max_size_bytes, content_type_allowlist, regex redaction with cleartext-never-in-audit hashing.
- **post-v1.0.0**: #67 agent-listener mTLS bind path (activates M6 validator/authenticator on the wire); #68 audit-write bench (validates A-2 / INF-26 with ~33× headroom; T3.10 stays deferred).

### What's pending in `feature/m9-proxy-bearer-acl` (B1 closure → v2.0.0)

- **M9 / B1 carry-over closed.** The `BearerAuthenticator` constructed in M2 is now wired into the agent listener (`AppState.agent_auth`, sharing one Arc with `UdsState.agent_auth`), and `proxy_handler` enforces the per-agent `tool_allowlist` / `tool_denylist` recorded in the M2 admin DB. See SPEC §6.2 #M9.
- **Behavior flip when admin substrate is enabled.** `auth_mode: bearer` keeps its name but its semantics shift from "permissive when `inbound_auth.token` unset" to "per-agent bearer required." Operators upgrading from M0/M1 must register agents (`bootstrap-operator.py` + `register-agents.sh`) before requests will succeed. M0/M1 deployments without admin substrate are unchanged. See `docs/v2/runbooks/m9-proxy-bearer-acl.md`.
- **`inbound_auth.token` deprecation.** Carrying a shared bearer forward into a deployment with admin substrate enabled emits a one-shot startup warning; the shared bearer is silently ignored. Tracked via the existing `DeprecationRegistry` (`src/deprecation.rs`).
- **Wire shape.** New audit `event` string `authz_denied` (class `security`); new error envelope variant `tool_not_allowed` (403); 401 envelope canonicalised to §4.7.9 with `code` field across all `AuthError` variants.

### Test + lint state on `feature/m9-proxy-bearer-acl`

- `cargo test --tests`: **264 / 264 pass** across 49 test binaries (251 baseline + new `proxy_acl_test.rs` + new lib unit tests + updated `secret_proxy_integration_test.rs` + updated `audit_proxy_test.rs` + new `deprecation_test.rs` cases).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.

### Test + lint state at v1.1.0

- `cargo test --tests`: **251 / 251 pass** across 48 test binaries.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.

### M7 task progress (per SPEC §6.2)

| Task | Status | Notes |
|------|--------|-------|
| T7.1 — response config schema | ✅ | tools[].response: { max_size_bytes, content_type_allowlist, redaction_patterns }. Regex compile + duplicate-id rejection at parse time. 4 tests. |
| T7.2 — apply_non_streaming | ✅ | ResponseControls runtime; SizeExceeded / ContentTypeDisallowed / Allowed outcomes. 10 unit tests. |
| T7.3 — SizeCappedStream | ✅ | Zero-overhead passthrough when cap=None; truncation marker on overflow. 4 tests. |
| T7.4 — audit events | ✅ | response_size_exceeded / response_content_type_disallowed / response_redaction. SHA-256 hash; cleartext NEVER recorded. 4 size + 2 content-type + 2 redaction integration tests. |

### M6 task progress (per SPEC §6.2)

| Task | Status | Notes |
|------|--------|-------|
| T6.1 — deps | ✅ | x509-parser, pem, rustls-webpki, time (dev). |
| T6.2 GATE — MtlsValidator | ✅ | webpki chain + identity extraction (CN→SAN_DNS→SAN_URI). 8 tests. |
| T6.3 — CRL fetcher | ✅ | CrlStore + apply_pem + refresh_once. Stale-but-up. 4 tests. |
| T6.4 — local blocklist | ✅ | File-backed; mtime-driven reload. 3 tests. |
| T6.5 GATE — MtlsAuthenticator | ✅ | Implements `authenticate_cert(der)`; revoked agents filtered. 4 tests. |
| T6.6 — auth_mode | ✅ | Bearer/Mtls/Both config + 4 parse tests. **Bind-path wiring deferred to v0.7.x** (see §3 below). |
| T6.7 GATE — operator mTLS | ✅ | OperatorRecord.cert_identity + authenticate_cert_identity. 3 tests. |
| T6.8 — bootstrap-only listener | ✅ | C-4 single-endpoint TLS listener. 2 tests. |
| T6.9 — `locksmith mtls` CLI | ✅ | revoke / list-blocklist / crl-status. Subprocess test. |
| T6.10 — auth_method audit | ✅ | Auto-fill in AdminService.audit + proxy hot path. 2 tests. |
| T6.11 — smallstep example + 3 runbooks | ✅ | dist/examples/smallstep/ + onboarding/migration/revocation runbooks. |

### M5 task progress (per SPEC §6.2)

| Task | Status | Notes |
|------|--------|-------|
| T2.17 — typed SecretRef enum | ✅ | `src/secret/mod.rs`. Custom Deserialize accepts legacy plain-string + tagged maps (FromEnv / FromFileSealed / FromVault / FromAwsSecretsManager). 8 parse tests. |
| T2.19 — SecretBackend trait + EnvBackend | ✅ | Async trait + `BackendError` + `SecretResolver` dispatcher. EnvBackend handles LegacyString (with one-shot INF-24 deprecation warning) and FromEnv. 6 tests. |
| T5.1 — FileSealedBackend | ✅ | Reads systemd-creds-decrypted file; rejects group/world-readable; caches; zeroizes on Drop. 5 tests. |
| T5.2 — systemd hardened unit template | ✅ | `dist/systemd/locksmith.service.template` with NoNewPrivileges, ProtectSystem=strict, MemoryDenyWriteExecute, dedicated user, etc. |
| T5.3 — Vault + AWS stubs | ✅ | `src/secret/vault.rs` + `src/secret/aws.rs`. Constructible; `resolve()` → `NotImplemented`. 2 stub tests. |
| T5.4 — threat model | ✅ | `docs/v2/threat-model.md`. 11-row mitigations matrix mapping threats to milestones. |
| T5.5 — sealed-secrets worked example | ✅ | `dist/examples/sealed-secrets/{README.md,locksmith.service,config.yaml,seal-credential.sh}`. |
| M5 integration | ✅ | `tool.auth.value: SecretRef`. Daemon resolves at startup; proxy hot path reads from `resolved_creds` map. Degraded mode for failed tools (per INF-4 / Q-17). 2 daemon-driven integration tests. |
| M5 runbook | ✅ | `docs/v2/runbooks/m5-sealed-secrets.md`. |

### Verification gates closed

| Task | Status |
|------|--------|
| T2.4 schema | Closed in M2 |
| T2.9 AgentAuthenticator | Closed in M2 |
| T2.12 AdminService | Closed in M2 |
| T3.3 retention worker | Closed in M3 |

M4 + M5 + M7 had no verification gates (low-risk per SPEC §6.2). M6 closed three gates: T6.2 (MtlsValidator), T6.5 (MtlsAuthenticator), T6.7 (operator mTLS).

**All verification gates are closed.** v2 is feature-complete.

---

## 2. M7 acceptance demo

```yaml
# Bound an LLM stream at 5 MiB; reject HTML; redact known secret shapes.
tools:
  - name: openai
    upstream: "https://api.openai.com"
    response:
      max_size_bytes: 5242880
      content_type_allowlist: ["application/json", "text/event-stream"]
      redaction_patterns:
        - id: openai_key
          regex: 'sk-[A-Za-z0-9]{20,}'
        - id: aws_secret
          regex: 'AKIA[A-Z0-9]{16}'
```

Streaming SSE under 5 MB passes through unchanged (R-N6 first-byte ≤100ms preserved). Over the cap, the proxy emits `STREAM_TRUNCATION_MARKER` and an audit row. Tools with `redaction_patterns` set take the buffered path; matches replaced with `[REDACTED:<pattern_id>]`; audit records `pattern_id` + `matches` count + SHA-256 hash of cleartext (not the cleartext).

```bash
locksmith audit query --event response_redaction --format json | jq
locksmith audit query --event response_size_exceeded --since-ms <yesterday> --format json
```

Full operational guide: `docs/v2/runbooks/m7-response-controls.md`.

## 2.1 M6 acceptance demo (kept for reference)

Smallstep deployment per `dist/examples/smallstep/README.md`. Fast version:

```bash
# Provision agent CA bundle
sudo install -m 0644 -o locksmith -g locksmith \
    agents-ca.crt /etc/locksmith/agents-ca.crt

# Daemon config (auth_mode=both during migration; mtls once fleet rotates)
cat >> /etc/locksmith/config.yaml <<EOF
listen:
  auth_mode: both
  mtls:
    ca_bundle_path: "/etc/locksmith/agents-ca.crt"
    crl_url: "https://step-ca.example.com/crl"
    crl_refresh_interval_seconds: 600
    blocklist_path: "/etc/locksmith/blocklist"
  bootstrap_only:
    enabled: true
    host: "0.0.0.0"
    port: 9202
    cert_path: "/etc/locksmith/tls/bootstrap.crt"
    key_path: "/etc/locksmith/tls/bootstrap.key"
EOF
sudo systemctl restart locksmith

# Onboard an agent through the bootstrap-only listener (no operator creds needed)
TOKEN=$(locksmith bootstrap mint --single-use --format json | jq -r .token)
curl -X POST https://locksmith.example.com:9202/admin/agent/register \
    --cacert /etc/locksmith/agents-ca.crt \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg t "$TOKEN" '{bootstrap_token: $t, name: "agent-7"}')"

# Bind cert_identity (via the AgentRepository helper; CLI wrapper lands v0.7.x)
# UPDATE agents SET cert_identity = 'agent-7' WHERE public_id = '<public_id>';

# Emergency revoke a serial (effective within 30s — blocklist watcher)
sudo locksmith mtls revoke <SERIAL_HEX> \
    --blocklist-path /etc/locksmith/blocklist \
    --reason "incident 2026-04-30"

# Verify mtls auth_method appears in audit
locksmith audit query --event-class security --limit 5 --format json
```

Full operational guide: `docs/v2/runbooks/m6-mtls-onboarding.md`. Migration recipe: `docs/v2/runbooks/m6-mtls-migration.md`. Incident response: `docs/v2/runbooks/m6-mtls-revocation.md`.

## 2.1 M5 acceptance demo (kept for reference)

The M5 contract — *"operator can deploy with the file-sealed backend and have no upstream credential present in env vars or in any operator-readable config"* — is met. Full walk-through is in `dist/examples/sealed-secrets/README.md`.

```bash
# (1) Seal the credential — plaintext never touches disk.
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token /etc/locksmith/credentials/openai.enc

# (2) Install the hardened unit + sealed-secrets-aware config.
sudo install -m 0644 dist/examples/sealed-secrets/locksmith.service \
    /etc/systemd/system/locksmith.service
sudo install -m 0644 -o locksmith -g locksmith \
    dist/examples/sealed-secrets/config.yaml \
    /etc/locksmith/config.yaml
sudo systemctl daemon-reload && sudo systemctl enable --now locksmith

# (3) Verify resolution.
journalctl -u locksmith --since "1 min ago" | grep file-sealed
# Expect: "file-sealed credential resolved" with the path

# (4) Verify the threat boundary as an unprivileged user.
cat /run/credentials/locksmith/openai_token  # → permission denied
cat /etc/locksmith/credentials/openai.enc    # → encrypted bytes; useless without TPM/master key

# (5) Rotate.
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token /etc/locksmith/credentials/openai.enc
sudo systemctl restart locksmith
```

The previous milestone's M4 demo (admin HTTPS) is in `docs/v2/runbooks/m4-remote-management.md` §3.

## 2.1 M4 acceptance demo (kept for reference)

The M4 contract — *"identical results between CLI-via-UDS and CLI-via-HTTPS for every admin operation"* — is met. The full verification matrix is in `docs/v2/runbooks/m4-remote-management.md` §1.

```bash
# (1) Generate cert + key (smallstep / step-ca for prod; openssl for dev).
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout /etc/locksmith/tls/server.key \
    -out /etc/locksmith/tls/server.crt \
    -subj "/CN=locksmith.local" \
    -addext "subjectAltName=DNS:locksmith.local,IP:127.0.0.1"

# (2) Add admin_https block to the daemon config.
cat >> /etc/locksmith/config.yaml <<EOF
listen:
  admin_https:
    enabled: true
    host: "0.0.0.0"
    port: 9201
    cert_path: "/etc/locksmith/tls/server.crt"
    key_path: "/etc/locksmith/tls/server.key"
EOF
locksmithd --config /etc/locksmith/config.yaml &

# (3) Operator runs CLI remotely. UDS path no longer required.
export LOCKSMITH_ADMIN_URL="https://locksmith.example.com:9201"
export LOCKSMITH_CA_BUNDLE="/etc/ssl/certs/locksmith-ca.crt"   # private CA
export LOCKSMITH_OP_TOKEN="lkop_..."

locksmith agent list
locksmith agent register --name agent-frontend
locksmith audit query --event-class operator --limit 50

# (4) Bootstrap-token register works over HTTPS WITHOUT the operator
#     bearer (D-10): the agent host gets the bootstrap token and that's
#     the only credential it needs.
curl -X POST https://locksmith.example.com:9201/admin/agent/register \
    --cacert /etc/ssl/certs/locksmith-ca.crt \
    -H 'content-type: application/json' \
    -d '{"bootstrap_token":"lkbt_...","name":"agent-X"}'

# (5) UDS path still works. Identical JSON output for the same op.
locksmith --socket /var/run/locksmith/admin.sock agent list
```

---

## 3. v2 is feature-complete — what comes next is post-v2

All seven planned milestones are merged. v1.0.0 is tagged. The remaining work is post-v2 enhancement, not blocking the v2 contract.

### Milestone walk

| Milestone | Version | Status |
|-----------|---------|--------|
| ~~M4~~ | ~~v0.5.0~~ | ~~Admin HTTPS~~ ✅ Closed |
| ~~M5~~ | ~~v0.6.0~~ | ~~Keys-at-rest~~ ✅ Closed |
| ~~M6~~ | ~~v0.7.0~~ | ~~mTLS (validator/CRL/blocklist/authenticator/bootstrap-only listener/operator cert)~~ ✅ Closed |
| ~~M7~~ | ~~v1.0.0~~ | ~~Response controls~~ ✅ Closed |

### Post-v1.0.0 enhancement track (priority-ordered)

Two HIGH-priority items closed in v1.1.0 (#67 mTLS bind path + #68 audit bench). Remaining tracks below.

| Track | Priority | Estimated session count | Notes |
|-------|----------|-------------------------|-------|
| ~~v0.7.x agent-listener mTLS bind~~ | ~~High~~ | ~~1~~ | ✅ Closed in v1.1.0 (#67). |
| ~~T3.9 audit-write bench~~ | ~~High~~ | ~~1~~ | ✅ Closed in v1.1.0 (#68); INF-26 trigger not tripped. |
| **T2.20 hot reload of non-listener config** | Medium | 1 | M0 ArcSwap is in place. Listener-shape config (M4 admin_https, M5 sealed paths, M6 cert paths) requires restart per the listener-shape carve-out — that stays. Tools, audit, retention, response_controls can hot-reload. |
| **#80 Live OnePasswordBackend** | Medium | 1 | M5 stub-style impl alongside #71 / #72. Operator-side `op read` + `from_file_sealed` already shippable via M5 runbook §3.1. |
| **#81 Locksmith ↔ Pipelock egress coordination** | Medium (design-track first) | 1 design + 1 impl | D-16. Locksmith publishes upstream inventory via `/admin/operator/upstreams` (HTTP) and/or `/run/locksmith/upstreams.json` (file watch). |
| **#82 D-18 inspector sidecar (LlamaFirewall)** | Medium (design-track first) | 1 design + 1 impl | Streaming-aware Unix-socket protocol; per-tool inspector config; pass/drop/modify verdicts; audit events. |
| **Live Vault / AWS Secrets Manager backends** | Medium | 1–2 | Stubs landed in M5/T5.3 with rustdoc on the implementer's contract. Live impls are post-v2. |
| **D-18 LlamaFirewall composition** | Low (depends on consumer demand) | 1 | Streaming-aware classifier integration; M7 redaction is regex-only by design. |
| **T2.11 RateLimiter** | Low (nginx/Caddy in front works as stopgap) | 1 | Issue #24. Defensive; M2.x carry-over. |
| **T2.18 field-scoped `${VAR}`** | Low | 0.5 | M0 textual expander in `LegacyString` covers dominant case. |
| **T2.27 `locksmith config reload/show`** | Low | 0.5 | Useful for ops; not blocking. |
| **T2.28/T2.29 bench subcommands** | Low | 0.5 | A-1 verification harness; useful, not blocking. |



### M7 — Response controls (final milestone)

**Goal:** Per-tool max_size_bytes, content_type_allowlist, regex redaction. Streaming first-byte latency must stay ≤100ms (R-N6).

| Task | Summary |
|------|---------|
| T7.1 | `tools[].response: { max_size_bytes, content_type_allowlist, redaction_patterns }` |
| T7.2 | `ResponseControls.apply` for non-streaming (read body, check content-type, apply redaction) |
| T7.3 | Streaming wrapper: byte-counter `Stream` adapter that emits truncation marker on cap-exceeded |
| T7.4 | Audit events: `response_redaction` (with hash of match, NOT cleartext) and `response_size_exceeded` |

**Regression check:** rerun M1 streaming tests with response controls enabled.

### Carry-overs (deferred; can land any time)

**M2.x:**
| Task | Notes |
|------|-------|
| T2.11 RateLimiter | Issue #24. Defensive; nginx/Caddy in front works as a stopgap. |
| T2.17 typed `SecretRef` | ✅ Landed in M5. |
| T2.18 field-scoped `${VAR}` | M0 textual expander handles dominant case via `LegacyString` variant. |
| T2.19 `SecretBackend` trait + `EnvBackend` | ✅ Landed in M5. |
| T2.20 hot reload + listener-shape carve-out | M0 ArcSwap is in place; full reload logic is here. The M4 listener-shape fields (`admin_https.{cert_path,key_path,host,port,enabled}`) and M5 sealed-credential paths feed in here when reload lands. M6 may surface this. |
| T2.21 startup-check sequencing (INF-2) | Daemon already fail-fast on the path that matters. |
| T2.27 `locksmith config reload/show` | Useful but not critical for M6. |
| T2.28/T2.29 bench subcommands | A-1 verification; useful, not blocking. |

**M3.x:**
| Task | Notes |
|------|-------|
| T3.7 `locksmith audit tail` | Streaming follow; needs SSE endpoint. |
| T3.9 audit-write bench | A-2 / INF-26 validation; **must run before v1.0.0 cut**. |
| T3.10 conditional async-batched | Only if T3.9 trips the >5ms p95 trigger. |

### v1.0.0 closure checklist (status)

- [x] M4 (admin HTTPS) merged. ✅
- [x] M5 (keys-at-rest) merged. ✅
- [x] M6 (mTLS infrastructure) merged. ✅
- [x] M7 (response controls) merged. ✅
- [x] All verification gates closed with self-review (T6.2, T6.5, T6.7). ✅
- [x] Threat model (`docs/v2/threat-model.md`) reviewed and merged. ✅
- [x] M4 runbook (`docs/v2/runbooks/m4-remote-management.md`) shipped. ✅
- [x] M5 runbook (`docs/v2/runbooks/m5-sealed-secrets.md`) shipped. ✅
- [x] M6 runbooks (`m6-mtls-onboarding.md`, `m6-mtls-migration.md`, `m6-mtls-revocation.md`) shipped. ✅
- [x] M7 runbook (`docs/v2/runbooks/m7-response-controls.md`) shipped. ✅
- [x] v1.0.0 tagged. ✅
- [ ] v0.7.x — agent-listener mTLS bind path (post-v2; activates M6 infrastructure).
- [ ] M3 audit-write bench (T3.9) executed; report attached to closure issue.
- [ ] If trigger tripped, T3.10 async-batched landed.
- [ ] §7 changelog v1.0.0 entry in SPEC.md.

**v2 is feature-complete.** Remaining items are post-v2 quality-of-life and validation-bench work.

---

## 4. Conventions and gotchas

### Audit data model

- `audit` table: 15 columns. Two CHECK-constrained enums (event_class, decision). See `migrations/0001_init.sql`.
- `EventClass::Operator` for state-mutating non-revocation admin actions.
- `EventClass::Security` for: auth_failure, operator_auth_failure, bootstrap_reuse_attempt, agent_revoke, agent_deregister, bootstrap_revoke. Revocation is security because it changes trust posture (T3.11 review).
- `EventClass::Proxy` for proxy hot-path events.
- `Decision::Allowed` / `Denied` / `Error`. Allowed = success. Denied = policy/auth refused. Error = upstream/system fault.

### Audit invariants (do not break)

- **Audit must never block proxy traffic** (INF-26). All audit calls in `record()`, `JsonlSink::append`, and `audit_*_failure` helpers swallow errors via `tracing::warn!`.
- **JSONL fan-out happens AFTER SQL commit**, so SQL is canonical and JSONL mirrors. If JSONL fails, SQL still has the row.
- **Retention sweep is bounded to the audit table**; the `sweep_does_not_touch_other_tables` test pins this.

### Token wire format

- Agent: `lk_<id>.<secret>`
- Operator: `lkop_<id>.<secret>`
- Bootstrap: `lkbt_<id>.<secret>`

### Two binaries

- `locksmithd` — daemon (`src/main.rs`)
- `locksmith` — CLI (`src/cli/main.rs`)

CLI subcommands: `agent`, `bootstrap`, `tool`, `audit`, `export`, `status`, `rotate`.

### Daemon runtime

`src/daemon.rs::run` is the canonical entry. It validates the admin substrate triple (`listen.admin_socket` + `database.path` + `operator_credentials_path`), opens SQLite, builds the JSONL sink (if configured), constructs the M5 `SecretResolver` with `FileSealedBackend`, walks `tools[].auth.value` through it to produce the resolved-creds map, constructs repos/auth/AdminService, spawns the agent listener + admin UDS + admin HTTPS (when enabled) + retention sweeper against a shared `ShutdownCoordinator`. The drain window awaits all four.

`AppState.config` is `Arc<ArcSwap<AppConfig>>`. `AppState.resolved_creds` is `Arc<ArcSwap<HashMap<String, SecretString>>>`. Both are shared between the agent listener and AdminService so hot reload (when it lands in T2.20) updates both surfaces atomically.

### UDS HTTP client

`src/admin/uds_client.rs`: minimal hyper 1.x http1 over `tokio::net::UnixStream`. No hyperlocal dep, no pool. Each CLI call is a fresh connection.

### CLI Transport (M4)

`src/cli/client.rs::CliClient` is an enum-dispatched Transport: `Uds(UdsClient)` or `Https { reqwest::Client, base_url }`. `from_options(socket, admin_url, ca_bundle)` picks the right one. Precedence: `--admin-url` flag → `LOCKSMITH_ADMIN_URL` env → fall back to UDS. CA bundle: `--ca-bundle` / `LOCKSMITH_CA_BUNDLE` for self-signed/private-CA deployments.

### SecretBackend dispatch (M5)

`src/secret/backend.rs::SecretResolver` is a composite dispatcher: `EnvBackend` always present; `FileSealedBackend` optional (daemon wires it; sync test path skips it); Vault/AWS variants → `NotImplemented`. The async `SecretBackend::resolve(SecretRef)` is the daemon's eager-resolve entrypoint. The sync sibling `EnvBackend::resolve_sync` exists for non-async test paths (build_app_with_audit's eager resolution).

**Don't store unresolved SecretRefs in AppState** — they're config-shape only. The proxy hot path reads `AppState.resolved_creds`, which is the post-resolution `HashMap<tool_name, SecretString>`. Tools whose credentials fail to resolve are absent from the map (degraded mode per INF-4).

### Sealed-secrets threat boundary (M5)

Locksmith does NOT do AEAD itself. systemd-creds (`LoadCredentialEncrypted=`) decrypts blobs at service start into `/run/credentials/locksmith/$NAME` (mode 0400, owned by locksmith). Locksmith reads the file. The threat model (`docs/v2/threat-model.md` §1.1) spells this out: the trust boundary is "anything readable by the locksmith uid is already trusted". Operators wanting to defend against compromised-locksmith-uid need the post-v2 HSM path.

### rustls CryptoProvider gotcha (M4)

rustls 0.23 requires an explicit process-level `CryptoProvider` when multiple are linked. Both server (axum-server) and client (reqwest with rustls-tls) pull providers transitively, so `agent_locksmith::admin::https::install_crypto_provider_once` installs `aws_lc_rs` once via `Once`. Daemon calls it from `bind_and_serve`; CLI calls it from `CliClient::from_options` when HTTPS is selected. **Don't remove this — silent failure mode is "client randomly cannot connect."**

### CLI exit codes (§4.7.2)

`0` ok | `1` generic | `2` usage | `3` auth | `4` not-found | `5` conflict.

### Config blocks (M3 + M4 + M5 additions)

```yaml
audit:                                                # M3
  retention_days: 90                                  # default
  sweep_interval_seconds: 3600                        # default (hourly)
  jsonl_path: "/var/log/..."                          # optional; absent = SQL only
  jsonl_max_bytes: 104857600                          # default 100 MiB
  jsonl_keep_files: 14                                # default

listen:
  admin_https:                                        # M4 — off by default
    enabled: true
    host: "0.0.0.0"                                   # default 127.0.0.1
    port: 9201                                        # default 9201
    cert_path: "/etc/locksmith/tls/server.crt"
    key_path: "/etc/locksmith/tls/server.key"

# tools[].auth.value (M5) — accepts both the legacy plain-string form
# (M0/M1 backward compat with INF-24 deprecation warning) AND tagged
# typed forms:
tools:
  - name: legacy
    auth:
      header: "authorization"
      value: "Bearer ${TOKEN}"                        # legacy, still works
  - name: env
    auth:
      header: "authorization"
      value:
        from_env:
          var: API_KEY
          prefix: "Bearer "                           # optional
  - name: sealed
    auth:
      header: "authorization"
      value:
        from_file_sealed:
          path: "/run/credentials/locksmith/api_key"  # systemd-creds drop path
  # from_vault and from_aws_secrets_manager are stubs in v0.6.0 (NotImplemented)
```

### YAML config parsing pipeline

`config::parse_config_str` is the canonical entry. Pipeline: env-var expansion → untyped YAML → deprecation registry → typed deserialize with `deny_unknown_fields`. Tests must use this entry; `serde_yaml::from_str` directly skips the deprecation translations.

### SQLite migrations

- Forward-only. Rollback = backup + restore.
- PRAGMAs that can't live in a transaction (synchronous, journal_mode) are applied at connection-open via `SqliteConnectOptions` + the `after_connect` hook.

### argon2 parameters

`m=4096 KiB, t=3, p=1` (Q-13). ~5ms verify on commodity hardware.

### Decoy-on-miss in authenticators

Both `BearerAuthenticator` and `OperatorAuthenticator` precompute a stored decoy hash. On invalid-credential paths they still run an argon2 verify against the decoy. Don't optimize this away — it's a security property that gate review verified.

### CI mismatch with local toolchain

Rust 1.88+ has stricter clippy defaults than CI. Always `cargo clippy --all-targets -- -D warnings` locally before commit.

### `gh` keyring quirk

Stale `GITHUB_TOKEN` env overrides keyring auth. Always invoke as `env -u GITHUB_TOKEN gh ...`.

---

## 5. Where to look

| Need | Read |
|------|------|
| Why we're building this | `docs/v2/PRD.md` |
| How we're building it | `docs/v2/SPEC.md` |
| Schema | SPEC §4.6.2 + `migrations/0001_init.sql` |
| Admin endpoints | SPEC §5 Q2 + `src/admin/uds.rs` |
| Operator-facing UX | SPEC §4.7 |
| Implementation plan | SPEC §6.2 (canonical task list) |
| Verification policy | SPEC §6.4.1 |
| Decisions | SPEC §15 (D-1..D-18) + §2 (28 resolved questions) |
| Inferred design requirements | SPEC Appendix B.4 (INF-1..INF-26) |
| Deployment-time assumptions | SPEC §2.1 (A-1..A-4) |
| M1 acceptance | `docs/v2/runbooks/m1-inference-hardening.md` |
| M4 acceptance + ops | `docs/v2/runbooks/m4-remote-management.md` |
| M5 acceptance + ops | `docs/v2/runbooks/m5-sealed-secrets.md` |
| Threat model | `docs/v2/threat-model.md` |
| Sealed-secrets worked example | `dist/examples/sealed-secrets/README.md` |
| Hardened systemd template | `dist/systemd/locksmith.service.template` |
| M6 onboarding | `docs/v2/runbooks/m6-mtls-onboarding.md` |
| M6 migration recipe | `docs/v2/runbooks/m6-mtls-migration.md` |
| M6 revocation playbook | `docs/v2/runbooks/m6-mtls-revocation.md` |
| smallstep / step-ca example | `dist/examples/smallstep/README.md` |
| M7 response-controls runbook | `docs/v2/runbooks/m7-response-controls.md` |

---

## 6. Resuming the next session

```bash
git fetch
git checkout develop
git pull

# Sanity check current state (251/251, clean lint).
cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# v2 is feature-complete. Pick a post-v2 enhancement track per §3:
# - mTLS bind path (highest priority if mTLS deployment required):
git checkout -b m6.1/agent-listener-mtls
# - Audit-write bench (validates A-2 / INF-26):
# git checkout -b post-v2/audit-bench
# - Hot reload of non-listener config:
# git checkout -b post-v2/config-hot-reload
```

Workflow that has held through M1 + M2 + M3 + M4 + M5 (and should keep holding):

- **TDD per task** (`superpowers:test-driven-development`): failing test first; do not write production code without a failing test that justifies it.
- **Verification gates self-reviewed before merge**: closed so far T2.4 (schema), T2.9 (AgentAuthenticator), T2.12 (AdminService), T3.3 (retention). Coming: T6.2 + T6.5 (mTLS validator + authenticator), T6.7 (operator mTLS).
- **Conventional commits** with the milestone in the subject and `Closes #N` in the body. `Closes` only auto-closes on merges to default branch (which is `main`); since we merge to `develop`, manually `gh issue close` after each merge.
- **Issues filed proactively** (one per §6.2 task) with labels: `milestone:M{N}`, `component:*`, `layer:*`, `kind:*`, `risk:*`, plus per-requirement labels (`R-F12`, `UC-6`, `INF-25`).
- **No PRs required** for this project — direct merge to `develop` is the standing instruction.
- **Per-milestone close-out:** branch → tasks → tests/lint → commit/push → close issues → merge `--no-ff` to `develop` → bump version → tag `v0.{milestone+1}.0` → refresh this handoff. M2, M3, M4, and M5 closure followed this exactly.

---

## 7. What success looks like for the next session

**Recommended target: pair #83 (admin-HTTPS mTLS) with #79 (CLI agent set-cert-identity wrapper).** Both close M6 runbook TODOs; both are operator-ergonomics improvements that make mTLS deployments fully usable without SQL or curl workarounds. Single session; merge → tag `v1.2.0`.

### 7.1 #83 — admin-HTTPS client-cert acceptance (T6.7 wire-side closure)

**Why this is the top recommendation:** v1.1.0 (#67) activated mTLS on the agent listener but left the admin HTTPS listener bearer-only. M6 / T6.7 already landed `OperatorAuthenticator::authenticate_cert_identity` for resolution, but the admin HTTPS listener never actually receives a client cert. After this lands, mTLS is end-to-end across all Locksmith surfaces.

Concrete acceptance for #83:
1. `listen.admin_https` config gains optional `auth_mode: bearer | mtls | both` (default `bearer` to preserve M4 behavior). Optional `mtls: { ca_bundle_path }` block on `admin_https` mirrors the agent listener's `listen.mtls` shape.
2. `src/admin/https.rs` switches its bind path on `admin_https.auth_mode`. Manual `tokio-rustls` accept loop when mtls/both — pattern is **identical to v1.1.0's `src/agent_listener.rs`**, so reuse the scaffolding (TlsAcceptor + WebPkiClientVerifier + `hyper-util` conn::auto + `service_fn` extension stamper).
3. `PeerCertDer` extension (already defined in `src/agent_listener.rs`) is reused — same per-request shape.
4. New admin-side middleware: under `Mtls`, requires a peer cert and calls `OperatorAuthenticator::authenticate_cert_identity` against the cert's CN/SAN_DNS/SAN_URI. Under `Both`, falls back to bearer when no cert. Resolved `OperatorIdentity` stamped into request extensions so admin handlers see an authenticated operator the same way the bearer path does.
5. Bootstrap-only register endpoint (`POST /admin/agent/register`) per D-10 stays open regardless of `auth_mode` — bootstrap tokens are the credential.
6. `tests/admin_https_mtls_e2e_test.rs` mints CA + server cert + operator client cert via rcgen; spins up daemon with `admin_https.auth_mode=mtls`; reqwest mTLS request hits `/admin/operator/agents`; asserts 200 + audit row records `auth_method=mtls` and `operator_name` matches the cert-identity-bound entry.

### 7.2 #79 — CLI `agent set-cert-identity` wrapper (small, ~30 min)

`AgentRepository::set_cert_identity` already exists from M6. The CLI wrapper closes the M6 onboarding-runbook TODO that currently tells operators to update the column via SQL.

Concrete acceptance for #79:
1. New `agent::AgentCmd::SetCertIdentity { id: String, cert_identity: Option<String> }` subcommand. Passing `--clear` or `cert_identity = "-"` clears the value; otherwise sets it.
2. New admin endpoint `PATCH /admin/operator/agents/{public_id}/cert_identity` accepting `{ cert_identity: Option<String> }` — operator-authed.
3. Test: subprocess CLI roundtrip — register agent → set cert_identity → query → assert; clear → assert None.
4. Update `docs/v2/runbooks/m6-mtls-onboarding.md` §4 to use the CLI command instead of the SQL workaround.

### 7.3 Session shape

Branch `post-v2/admin-https-mtls-and-set-cert-identity` off `develop`. TDD per task: failing E2E test for #83 first, then #79's CLI subprocess test. Both should fit comfortably in one session given the scaffolding from #67 and the existing `set_cert_identity` repo helper.

End of session: merge `--no-ff` → bump `v1.2.0` → tag → close #83 + #79 → refresh handoff.

### 7.4 Alternatives if blocked

| Track | Issue | Why pick this instead |
|-------|-------|----------------------|
| **T2.20 hot reload** | #70 | Bigger operational lift; gates #76 + makes #81 properly responsive. ~1 session. |
| **OnePasswordBackend** | #80 | Pragmatic; operators on 1Password get the live path. Pattern follows existing M5 stubs. ~1 session. |
| **#81 Pipelock egress design pass** | #81 | Half-session writeup; needs sign-off before impl. The trust-domain comment on the issue clarifies the auth question. |
| **#82 D-18 inspector design pass** | #82 | Half-session writeup; UDS + SO_PEERCRED is the default per the trust-domain comment. |

---

*End of handoff. Push back on anything that turns out wrong; update as you go.*
