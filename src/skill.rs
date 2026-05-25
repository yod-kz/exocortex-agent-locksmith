//! Agent-facing skill discovery (M9 / B1 follow-up).
//!
//! `GET /skill` returns a markdown document — formatted per the
//! [agentskills.io](https://agentskills.io) convention — that an agent
//! can paste into its LLM's system prompt to learn how to use this
//! locksmith deployment. Two forms:
//!
//! - **Unauthenticated** (`shutdown_signal`-skipped, like `/livez`): a
//!   generic protocol description. Authentication shape, endpoint
//!   catalog, error envelope, what-to-do-when-401-or-403. Deliberately
//!   does NOT leak tool names, descriptions, model identifiers, or any
//!   per-agent ACL — those are reserved for the personalized form so an
//!   unauthenticated probe learns no operational detail.
//! - **Authenticated** (`/skill` with a valid `Authorization: Bearer
//!   lk_…`): the generic content PLUS a personalized section listing
//!   the agent's name, public_id, exact ACL-resolved tool list with
//!   descriptions, and an audit-debug recipe scoped to the agent.
//!
//! The generic markdown is embedded at compile time via `include_str!`
//! so every binary ships with one canonical version. There is no
//! operator-override path — one source of truth.
//!
//! Routing is in `app::build_app_full`:
//! - Unauthenticated: `GET /skill` → `unauthenticated_skill` (added to
//!   the auth middleware skip list).
//! - Authenticated: `GET /agent/skill` → `authenticated_skill` (under
//!   the same middleware as `/api/...`, so the per-agent bearer is
//!   enforced and `AgentIdentity` is stamped into request extensions
//!   before the handler runs).

use crate::auth_v2::AgentIdentity;

/// The compile-time generic skill markdown. Returned as-is for
/// unauthenticated probes; appended to the personalized section for
/// authenticated requests.
const SKILL_TEMPLATE: &str = include_str!("skill_template.md");

/// Render the unauthenticated form: the embedded template, unchanged.
pub fn render_unauthenticated() -> String {
    SKILL_TEMPLATE.to_string()
}

/// Render the personalized form: the embedded template followed by a
/// "## Personalized for `<agent_name>`" section listing the agent's
/// resolved tool list (catalog ∩ allowlist, minus denylist) with each
/// tool's name + description, and an audit-debug recipe.
///
/// `available_tools` is the pre-resolved list of `(name, description)`
/// pairs the agent may call right now — typically built by the caller
/// from the same source `/tools` uses (`catalog_listing` over the
/// registrations table, with the agent's `AgentIdentity` filter
/// applied). Keeping the catalog lookup at the caller decouples this
/// renderer from the registrations-vs-legacy-config sourcing decision
/// (Phase E shifted the source of truth from `config.tools` to the
/// registrations table; pre-Phase-E v0.2 callers still using
/// `config.active_tools_against` can pass that result instead).
pub fn render_authenticated(
    identity: &AgentIdentity,
    available_tools: &[(String, String)],
) -> String {
    let allowlist_str = identity
        .tool_allowlist
        .as_ref()
        .map(|v| format!("`[{}]`", v.join(", ")))
        .unwrap_or_else(|| "`(unrestricted — no allowlist set)`".to_string());
    let denylist_str = identity
        .tool_denylist
        .as_ref()
        .map(|v| format!("`[{}]`", v.join(", ")))
        .unwrap_or_else(|| "`(none)`".to_string());

    let mut tools_md = String::new();
    if available_tools.is_empty() {
        tools_md.push_str(
            "_No tools currently available to you._ Either your ACL excludes \
             every active tool, or no tools are active in this deployment. \
             Ask your operator to widen your allowlist or shrink your denylist.\n",
        );
    } else {
        tools_md.push_str("| Tool | Description |\n|---|---|\n");
        for (name, desc) in available_tools {
            // Trim newlines from descriptions so the markdown table
            // stays well-formed even if operators wrote multi-line YAML.
            let one_line_desc = desc.replace('\n', " ");
            tools_md.push_str(&format!("| `{}` | {} |\n", name, one_line_desc));
        }
    }

    // Phase G3 — when codex is in the agent's effective tool list, append
    // a per-tool quirks section that re-emphasizes the codex requirements
    // most likely to trip an agent up. Generic skill template covers them
    // too; this section just makes them inescapable in the personalized
    // form (the form an agent sees on first authenticated /skill fetch).
    let codex_in_acl = available_tools.iter().any(|(n, _)| n == "codex");
    let codex_quirks_md = if codex_in_acl {
        r#"
### Codex quirks (because `codex` is in your ACL)

As of v2.4.0, locksmith owns every codex-specific wire piece:

- Authorization, ChatGPT-Account-ID, OpenAI-Beta, originator (when
  missing) — all injected automatically.
- Body fields store / stream / instructions — injected/overridden
  automatically (instructions preserved if you supply your own).

Your minimal codex call:

```
POST /api/codex/responses
Authorization: Bearer $LOCKSMITH_TOKEN
Content-Type: application/json

{"model":"gpt-5.5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}
```

Streaming-only — codex `/responses` returns SSE. Your client must
handle it (locksmith forces `stream: true` regardless of what you
send). See the "Codex (OpenAI ChatGPT plan auth) — special case"
section above for the full integration boundary.
"#
    } else {
        ""
    };

    let personalized = format!(
        r#"

---

## Personalized for `{name}`

You're authenticated as **{name}** (`public_id={public_id}`).

### Tools available to you right now

{tools_md}

To call one of these tools:

```
curl -fsS -H "Authorization: Bearer $LOCKSMITH_TOKEN" \
  http://<locksmith>/api/<tool>/<upstream-path>
```

The `<upstream-path>` is forwarded verbatim to the tool's upstream — for
example, `/api/{first_tool_or_placeholder}/v1/chat/completions` reaches the
upstream's `v1/chat/completions` endpoint. Locksmith strips your
`Authorization` header and injects the configured upstream credential
before forwarding.
{codex_quirks_md}
### Your ACL

- **Allowlist**: {allowlist}
- **Denylist**: {denylist}

Both are managed by your operator via `locksmith agent modify
{public_id} --allowlist ... --denylist ...`. Re-fetch this skill after a
change to see the new tool list.

### Audit-debug recipe (operator-facing)

If you start getting 403 `tool_not_allowed`, your operator can trace:

```
locksmith audit query --event-class security --agent {public_id} \
  --since-ms <ms>
```

Recent denies for you appear with `event=authz_denied` and
`details.reason` set to either `not_in_allowlist` or `in_denylist`. 401s
appear with `event=auth_failure` and `details.reason` carrying the
specific failure mode (`missing_credential`, `malformed_token`,
`wrong_namespace`, `unknown_public_id`, `secret_mismatch`, `expired`).
"#,
        name = identity.name,
        public_id = identity.public_id,
        tools_md = tools_md,
        codex_quirks_md = codex_quirks_md,
        allowlist = allowlist_str,
        denylist = denylist_str,
        first_tool_or_placeholder = available_tools
            .first()
            .map(|(n, _)| n.as_str())
            .unwrap_or("<tool>"),
    );

    format!("{}{}", SKILL_TEMPLATE, personalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_v2::AgentIdentity;

    fn ident_with(name: &str, allow: Option<&[&str]>, deny: Option<&[&str]>) -> AgentIdentity {
        AgentIdentity {
            id: 0,
            public_id: "TESTPID12345".into(),
            name: name.into(),
            tool_allowlist: allow.map(|s| s.iter().map(|t| t.to_string()).collect()),
            tool_denylist: deny.map(|s| s.iter().map(|t| t.to_string()).collect()),
        }
    }

    fn tools(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, d)| ((*n).to_string(), (*d).to_string()))
            .collect()
    }

    #[test]
    fn unauthenticated_form_is_the_template_unchanged() {
        let s = render_unauthenticated();
        assert_eq!(s, SKILL_TEMPLATE);
    }

    #[test]
    fn unauthenticated_form_does_not_leak_specific_model_ids() {
        // Operational hygiene: the unauth form must not leak per-
        // deployment model identifiers (specific models the operator
        // chose to load). It MAY reference well-known upstream
        // protocol patterns (anthropic, openai-compatible, codex)
        // because those are public protocol names, not deployment-
        // specific configuration — every locksmith deployment that
        // touches those upstreams looks the same shape.
        //
        // Hard line: model IDs (gpt-4, claude-opus, qwen-3.5,
        // gemma-3, llama-4) and operator-side env var names
        // (LM_API_KEY, ANTHROPIC_API_KEY) leak deployment shape and
        // must stay out of the template.
        let s = render_unauthenticated().to_lowercase();
        for forbidden in [
            "gpt-4",
            "gpt-3",
            "claude-opus",
            "claude-sonnet",
            "claude-haiku",
            "qwen3.",
            "qwen-3",
            "gemma-3",
            "gemma-4",
            "llama-3",
            "llama-4",
            "mistral-",
            "lm_api_key",
            "anthropic_api_key",
            "openai_api_key",
        ] {
            assert!(
                !s.contains(forbidden),
                "unauthenticated /skill must not mention deployment-specific \
                 model IDs or env var names; found '{forbidden}' in template"
            );
        }
    }

    #[test]
    fn unauthenticated_form_advertises_personalized_form() {
        let s = render_unauthenticated();
        assert!(
            s.contains("personalized"),
            "unauth form must tell the caller about the authenticated form"
        );
        assert!(
            s.contains("Authorization: Bearer"),
            "unauth form must show the bearer auth shape so caller knows how to upgrade"
        );
    }

    #[test]
    fn authenticated_form_includes_agent_name_and_public_id() {
        let id = ident_with("agent-alpha", Some(&["things"]), None);
        let available = tools(&[("things", "Things service")]);
        let s = render_authenticated(&id, &available);
        assert!(s.contains("agent-alpha"));
        assert!(s.contains("TESTPID12345"));
        // Tool table is rendered from the caller-provided list.
        assert!(s.contains("`things`"));
        assert!(s.contains("Things service"));
        // The unauth template is preserved verbatim at the top.
        assert!(s.starts_with(SKILL_TEMPLATE));
    }

    #[test]
    fn authenticated_form_renders_tools_from_caller_provided_list() {
        // ACL filtering is the caller's responsibility (matches what
        // /tools does — `catalog_listing` applies the AgentIdentity
        // filter before returning). The renderer just emits whatever
        // it's given.
        let id = ident_with("narrow-agent", Some(&["good"]), None);
        let available = tools(&[("good", "Allowed tool")]);
        let s = render_authenticated(&id, &available);
        assert!(s.contains("`good`"), "tool in available list must appear");
        assert!(
            !s.contains("`bad`"),
            "tool not in available list must NOT appear in the personalized table"
        );
    }

    #[test]
    fn authenticated_form_handles_empty_tool_list() {
        // Empty tool list (operator's allowlist excludes everything,
        // catalog is empty, etc.) → must render a friendly explainer
        // rather than a bare empty table.
        let id = ident_with("empty-agent", Some(&["nonexistent"]), None);
        let available: Vec<(String, String)> = Vec::new();
        let s = render_authenticated(&id, &available);
        assert!(s.contains("No tools currently available to you"));
        assert!(!s.contains("`things`"));
    }

    #[test]
    fn authenticated_form_codex_quirks_section_keyed_off_available_list() {
        // Phase G3 codex section appears when codex is in the agent's
        // available tools, regardless of whether it's also in allowlist
        // (the caller already filtered).
        let id = ident_with("codex-agent", Some(&["codex"]), None);
        let with_codex = tools(&[("codex", "OpenAI Responses API")]);
        let without_codex = tools(&[("wikipedia", "Wikipedia REST")]);
        assert!(render_authenticated(&id, &with_codex).contains("Codex quirks"));
        assert!(!render_authenticated(&id, &without_codex).contains("Codex quirks"));
    }
}
