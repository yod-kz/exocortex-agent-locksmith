# 1Password Setup for Operators (Phase H)

This guide describes how to use 1Password Environments + Service Accounts as the source-of-truth for site-repo `.env` files, materializing them at deploy time via the `op` CLI.

**The 1P substrate is opt-in.** Site repos (`openclaw-site`, `hermes-site`, `layer8-proxy-site`) work fine without it — mode-0600 `.env` on disk is a perfectly reasonable alternative for small fleets with a single operator. This guide is for operators who want one of:

- **Single source-of-truth** for secrets across multiple deploy hosts
- **Operator-role separation** (a `proxy-operator` role distinct from `agent-operator`, encoded in distinct 1P Environments + Service Accounts)
- **Audit trail** of who accessed which secret when (1P logs every Environment access)
- **Multi-operator scenarios** in the future (per-host RBAC via per-(host × product) Service Accounts)

If none of those motivate you, stop reading. Mode-0600 `.env` files maintained per-host are fine.

---

## Table of contents

1. [What ships in v1.5.0 / v2.5.0](#what-ships)
2. [Install the op CLI (beta channel required)](#install)
3. [Plan your deployment fleet](#plan)
4. [Provision per (host × product)](#provision)
5. [One-time migration from existing .env](#migrate)
6. [Verify the render](#verify)
7. [Wire into a launcher (per-site adoption)](#wire)
8. [Rotation write-back (optional)](#rotation)
9. [Operational gotchas](#gotchas)
10. [When NOT to use this](#when-not)

---

<a id="what-ships"></a>
## 1. What ships in v1.5.0 / v2.5.0

The Phase H substrate consists of three scripts in `layer8-proxy/examples/site/scripts/`:

| Script | Purpose |
|---|---|
| `render-env-from-1password.sh` | Materializes `.env` from a 1P Environment at launch time |
| `provision-host-sa.sh` | Provisions a per-(host × product) Service Account scoped to one Environment |
| `migrate-env-to-1password.sh` | One-shot helper for migrating existing `.env` values into a new Environment |
| `lib/op-writeback.sh` | Sourceable helper for rotation toolkit hooks (best-effort 1P write-back) |

Plus a hook in `rotate-operator-token.sh` that demonstrates the rotation write-back pattern (`op item edit` against the Environment's backing vault item).

The full architecture is in `agents-stack/docs/spec/v0.3.0-1password-integration.md` (especially §3.5 for the SA × Env × Keychain matrix and §4 for component design). ADR-0006 captures the locked decisions.

---

<a id="install"></a>
## 2. Install the op CLI (beta channel required)

The `op environment` subcommand is **beta-channel only** as of 2026-05-09. The Homebrew stable cask (`1password-cli`) does NOT include it.

```bash
# If stable cask is installed, remove it first
brew uninstall --cask 1password-cli

# Install the beta cask
brew install --cask 1password-cli@beta

# Verify
op --version                   # expect 2.33.0-beta.02 or later
op environment --help          # should list `read` (and possibly other subcommands as they ship)
```

If `op environment --help` returns `unknown command "environment"`, you have the stable cask. Re-run the install steps.

When 1Password promotes Environments to the stable channel (no public timeline), this guide gets a runbook entry to swap back to the regular cask.

---

<a id="plan"></a>
## 3. Plan your deployment fleet

Before creating anything in 1Password, sketch out:

- **Hosts** you'll deploy to (e.g., `mini-1`, `studio-1`)
- **Products** running on each (e.g., `openclaw`, `hermes`, `layer8-proxy`)
- **Test hosts** that need separate Environments (e.g., `jx-mbp-m5`)

For each (host × product) tuple, you'll create:

- One **Environment** in 1Password (named `<product>-<host>`)
- One **Service Account** scoped read-only to that Environment (named `<host>-<product>`)
- One **macOS Keychain entry** on that host (named `OP_SERVICE_ACCOUNT_TOKEN_<HOST>_<PRODUCT>`, uppercased, hyphens → underscores)

Plus one **operator-tools Service Account** scoped to ALL the Environments above, for ad-hoc reads from your operator-personal hosts (laptop, etc.).

> **Important: SA scope is immutable.** Once an SA is created, you cannot change which Environments it can read. Plan all Environments first, then create SAs. Adding a new Environment later means rotating the operator SA.

The full reference matrix lives in `agents-stack/docs/spec/v0.3.0-1password-integration.md` §3.5.

### Naming convention

| Thing | Convention | Example |
|---|---|---|
| Environment | `<product>-<host>` | `openclaw-mini-1` |
| Service Account | `<host>-<product>` | `mini-1-openclaw` |
| Keychain entry | `OP_SERVICE_ACCOUNT_TOKEN_<HOST>_<PRODUCT>` (upper, hyphens → `_`) | `OP_SERVICE_ACCOUNT_TOKEN_MINI_1_OPENCLAW` |

The host prefix on Keychain entries preserves global uniqueness across operator-personal hosts that may sync via iCloud Keychain. Production deploy hosts have isolated Keychains (no iCloud sync) per ADR-0006 D9.

---

<a id="provision"></a>
## 4. Provision per (host × product)

For each (host × product) tuple:

### 4.1 Create the Environment in 1P UI

1. Open 1Password (desktop or web)
2. Navigate: **Developer → Environments → + New**
3. Name it per the convention (e.g., `openclaw-mini-1`)
4. Choose the vault that should hold it (e.g., `Operations`)
5. **Capture the Environment ID** — visible in the URL or detail panel after creation. Looks like `37ahi3usek2ckxxipzk6pddi7a`.

(There's no `op environment list` in the beta CLI, so the UI is the only way to discover Environment IDs.)

### 4.2 Create the Service Account via provision-host-sa.sh

From your operator's laptop (where you're signed into 1P):

```bash
./scripts/provision-host-sa.sh \
    --host mini-1 \
    --product openclaw \
    --environment <env-id-from-step-4.1> \
    --vault Operations \
    --account your-email@example.com
```

The script:

1. Verifies you're signed into 1P (`op whoami`)
2. Verifies the Environment is accessible (`op environment read $id >/dev/null`)
3. Creates a Service Account named `mini-1-openclaw` scoped to the Environment
4. Prints the SA token (one-time only — capture it now)
5. Emits a deploy recipe with the correct host-prefixed Keychain entry name and the **non-interactive** `security add-generic-password -w "$TOKEN"` form

> **Why non-interactive matters (PASS_MAX gotcha).** The macOS `security add-generic-password -w` interactive prompt silently truncates input at 128 chars. SA tokens are ~700 chars. The interactive form will produce a malformed Keychain entry and `op environment read` will then fail with `failed to DecodeSACredentials: unexpected end of JSON input`. Always use `-w "$TOKEN"`.

### 4.3 Deploy the SA token to the target host's Keychain

Copy the recipe printed by `provision-host-sa.sh` and run it on the target host (or via SSH from your laptop):

```bash
# On mini-1 (or via ssh mini-1 'TOKEN=...; security add-...')
TOKEN='ops_eyJzaWdu...full-token-here'   # paste the full token
security add-generic-password \
    -s OP_SERVICE_ACCOUNT_TOKEN_MINI_1_OPENCLAW \
    -a your-email@example.com \
    -w "$TOKEN"
unset TOKEN

# Verify
T="$(security find-generic-password -s OP_SERVICE_ACCOUNT_TOKEN_MINI_1_OPENCLAW -w 2>/dev/null)"
echo "stored length: ${#T}"   # expect ~700
unset T
```

> **Per-host isolation.** Production agent hosts should run with **isolated login keychains** (no iCloud Keychain sync). This means the SA token added on mini-1 stays on mini-1 — a compromise of one host doesn't leak tokens to others. Operator-personal hosts (laptop, test boxes) may sync at your discretion. See ADR-0006 D9.

### 4.4 Configure site.cfg on the target host

Add (or copy from `site.cfg.example`):

```bash
# In <product>-site/site.cfg on the target host:
op_environment_id=<env-id-from-step-4.1>
op_keychain_service=OP_SERVICE_ACCOUNT_TOKEN_MINI_1_OPENCLAW

# Linux hosts only (macOS uses Keychain via op_keychain_service):
# op_token_file=$HOME/.config/op/openclaw.token
```

`site.cfg` should be **gitignored** in your site repo — it holds per-host secrets-pointer config. Ship a `site.cfg.example` with the schema instead.

### 4.5 Repeat for the operator-tools SA

The operator-tools SA is scoped to **all** your Environments at once. Use the same flow but with the operator-tools naming convention (e.g., Keychain entry `OP_SERVICE_ACCOUNT_TOKEN_LAPTOP_OPERATOR`). This SA is what you'll use for ad-hoc `op environment read` from your laptop.

---

<a id="migrate"></a>
## 5. One-time migration from existing .env

If you have an existing `.env` file with secrets you want to move into a 1P Environment:

```bash
./scripts/migrate-env-to-1password.sh \
    --env-file ./.env \
    --environment <env-id-from-step-4.1>
```

The script:

1. Backs up the source to `./.env.pre-1password.bak` (mode 0600, idempotent)
2. Parses the source (skips comments + blank lines, warns on malformed)
3. **Prints the parsed entries in paste-ready format** for you to paste into the 1P Environment's UI

It does NOT auto-write to 1P (the beta CLI's `op item edit` against an Environment's backing vault item has uncertain field semantics for arbitrary KEY=value pairs — manual paste is the safe path until `op environment update` ships).

After pasting:

1. Save the Environment in 1P
2. Verify with `op environment read <env-id>`
3. Continue to step 6 (verify the render)

The script does **not** delete the source `.env` — once you've validated the render and the host runs from the rendered file, delete it manually.

---

<a id="verify"></a>
## 6. Verify the render

```bash
# In a scratch directory (or the actual site dir)
mkdir -p /tmp/render-test && cd /tmp/render-test
echo "op_environment_id=<env-id>" > site.cfg
echo "op_keychain_service=OP_SERVICE_ACCOUNT_TOKEN_MINI_1_OPENCLAW" >> site.cfg

SITE_DIR=/tmp/render-test \
    ~/.../layer8-proxy/examples/site/scripts/render-env-from-1password.sh

# Check
ls -la .env       # expect: -rw-------
head -5 .env      # expect: KEY=value lines from the Environment
```

If you see the rendered `.env` with the right contents and mode 0600, the substrate is working end-to-end.

---

<a id="wire"></a>
## 7. Wire into a launcher (per-site adoption)

Per-site adoption is **operator's choice** — the design ships the substrate but doesn't pre-wire any site repo. To wire `render-env-from-1password.sh` into a site repo's launcher (`launch-openclaw.sh`, `launch-hermes.sh`, `deploy.sh`):

### 7.1 Copy the script into the site repo

```bash
cp layer8-proxy/examples/site/scripts/render-env-from-1password.sh \
   <your-site-repo>/scripts/render-env-from-1password.sh
```

(Optional: also copy `provision-host-sa.sh`, `migrate-env-to-1password.sh`, `lib/op-writeback.sh` if you want them per-repo. They can also live solely in `layer8-proxy/examples/site/scripts/` and be referenced from there.)

### 7.2 Add the launcher hook

In each launcher (after argument parsing, before `. "$SITE_DIR/.env"`):

```bash
# Phase H — render .env from 1Password unless --skip-render was passed.
if [[ "${SKIP_RENDER:-0}" != "1" ]]; then
    "$SITE_DIR/scripts/render-env-from-1password.sh"
fi
```

Add `--skip-render` to the launcher's argument parser:

```bash
case "$1" in
    --skip-render) SKIP_RENDER=1; shift ;;
    # ... existing cases
esac
```

### 7.3 Update site.cfg

Move `op_environment_id`, `op_keychain_service`, (and optionally `op_token_file` for Linux) into the gitignored `site.cfg` per host.

Now every launch invocation will:

1. Re-render `.env` from the 1P Environment (fail loud if 1P unreachable)
2. Source the rendered `.env`
3. Proceed with the existing launcher logic

`./launch-openclaw.sh --skip-render` lets you launch from the existing `.env` if you need to (1P outage, debugging).

---

<a id="rotation"></a>
## 8. Rotation write-back (optional)

The Phase H release wires a 1P write-back hook into `rotate-operator-token.sh` only (proof-of-pattern for OPI-6). The same shape applies to `rotate-creds-passphrase.sh` and `rotate-oauth-sealing-key.sh` if you want the rotation toolkit to push rotated values back to 1P.

### 8.1 Add `op_environment_vault_item` to site.cfg

Each 1P Environment is backed by a vault item. Capture that item's UUID (via 1P UI) and add to site.cfg:

```bash
op_environment_vault_item=<vault-item-uuid>
```

### 8.2 Wire the hook into the rotate script

After the local rotation succeeds (in `rotate-creds-passphrase.sh`, after the new passphrase is in use; in `rotate-oauth-sealing-key.sh`, after the new key is loaded):

```bash
# Phase H — best-effort 1P write-back
if [[ -f "$SITE_DIR/site.cfg" ]]; then
    # shellcheck source=/dev/null
    . "$SITE_DIR/site.cfg"
fi
if [[ -f "$SITE_DIR/scripts/lib/op-writeback.sh" ]]; then
    # shellcheck source=/dev/null
    . "$SITE_DIR/scripts/lib/op-writeback.sh"
    set +e
    op_writeback "${op_environment_vault_item:-}" "<KEY_NAME>" "$NEW_VALUE"
    OP_WB_RC=$?
    set -e
    case "$OP_WB_RC" in
        0) echo "  ✓ wrote new <name> to 1P" ;;
        1) : ;;  # silent skip
        *)
            echo "  ⚠ rotation succeeded locally but 1P write-back failed" >&2
            echo "     retry: op item edit ${op_environment_vault_item} <KEY>=<value>" >&2
            ;;
    esac
fi
```

The `lib/op-writeback.sh` function returns:

- `0` — wrote successfully
- `1` — silent skip (no `op_environment_vault_item` in site.cfg, OR `op` CLI not installed)
- `2` — attempted but failed (caller should warn + provide manual retry recipe)

Local-rotation success is always authoritative — write-back failure does not roll back.

### 8.3 Why `op item edit` not `op environment update`

The beta CLI does not expose `op environment update` as of 2026-05-09. Each Environment is backed by a vault item; editing the item via `op item edit` is the working path until the dedicated subcommand ships.

When `op environment update` ships, the `lib/op-writeback.sh` function can be updated in one place to use it. Callers don't change.

---

<a id="gotchas"></a>
## 9. Operational gotchas

### PASS_MAX 128-char prompt limit

The macOS `security add-generic-password -w` **interactive** prompt silently truncates input at 128 chars (BSD `getpass(3)` `PASS_MAX`). 1P SA tokens are ~700 chars.

Always use the **non-interactive** form:

```bash
TOKEN="$(pbpaste)"  # or read from secure source
security add-generic-password -s NAME -a label -w "$TOKEN"
unset TOKEN
```

The token IS briefly visible in `ps` during the `security` invocation. On personal Macs with no other users this is acceptable.

### Find Environment IDs via the UI

`op environment list` doesn't exist in the beta CLI. To get an Environment's UUID:

1. Open 1Password (desktop or web)
2. Developer → Environments → click the Environment
3. Copy the ID from the URL or detail panel

### SA scope is immutable

Once an SA is created with read access to a set of Environments, that set cannot be changed. Adding a new Environment to an existing SA's scope requires rotating the SA (issue new token, redeploy to all hosts that use it). Plan all Environments first.

### iCloud Keychain sync semantics

By default, `security add-generic-password` writes to the **local login keychain**, which does NOT sync via iCloud. If you want sync (e.g., for the operator-tools SA across multiple operator-personal hosts):

- Enable iCloud Keychain on each host: System Settings → Apple ID → iCloud → Passwords & Keychain
- Login keychain items will sync to iCloud
- The host-prefixed naming convention preserves global uniqueness across synced hosts

For production agent hosts (`mini-1`, `studio-1`), **leave iCloud Keychain off**. Per-host isolation honors the per-(host × product) SA boundary; otherwise a compromise of any one host leaks all SA tokens.

### .env mode is 0600

The render script creates `.env` with mode 0600 via `umask 0077` + atomic `mktemp` + `chmod` + `mv`. If your own tooling cares about mode, this is the contract.

---

<a id="when-not"></a>
## 10. When NOT to use this

Mode-0600 `.env` files maintained per-host are a perfectly fine alternative if:

- You're a single operator running a small fleet
- You don't need an audit trail of secret access
- You don't need operator-role separation enforced at the deployment layer
- Setup ceremony cost (per-host SA provisioning, Keychain management, 1P Environment maintenance) outweighs the value

Phase H ships the substrate as a **complete, optional feature**. Adopt it when your operational scale or security posture justifies the complexity. Don't adopt it just because it's there.

---

## Reference docs

- **Architecture:** `agents-stack/docs/spec/v0.3.0-1password-integration.md` (especially §3.5 SA × Env matrix, §4 component design, §6.1 operational gotchas)
- **Locked decisions:** `agents-stack/docs/adrs/0006-1password-service-account-integration.md` (D1-D9)
- **PRD:** `agents-stack/docs/prd/v0.3.0-1password-integration.md`
- **Research notes:** `agents-stack/docs/plans/2026-05-08-1password-environments-research.md`
