//! Phase G3/G5 — codex Responses API body fixup.
//!
//! OpenAI's `/backend-api/codex/responses` endpoint (the path that
//! backs codex CLI's Responses API) has stricter body requirements
//! than the generic OpenAI Responses API. Locksmith encodes the
//! upstream-specific quirks so agents can stay generic.
//!
//! ## Phase G3 — required fields
//!
//! - `instructions` (string, required) — the system-prompt analog.
//! - `store: false` — codex rejects `true`; no agent has a legitimate
//!   reason to want server-side storage on this endpoint.
//! - `stream: true` — codex rejects `false`; the endpoint is
//!   fundamentally streaming.
//!
//! ## Phase G5 — forbidden fields (strip on the way out)
//!
//! - `max_output_tokens` — codex returns 400 with body
//!   `{"detail":"Unsupported parameter: max_output_tokens"}` when set
//!   (ChatGPT-plan output is metered server-side, not by the client).
//!   OpenAI SDK clients (e.g. openclaw, embedded `OpenAI/JS`) emit
//!   this from per-model `maxTokens` config without knowing the
//!   codex-specific rejection. Stripping it here lets agents keep
//!   their generic per-model max-tokens configuration without
//!   carving out a special case for codex.
//!
//! Native codex CLI handles all of these because it's codex-aware.
//! Hermes-agent and openclaw, when proxied through locksmith, send a
//! generic OpenAI-compatible body — chatgpt.com 400s. Phase G2 owns
//! the `ChatGPT-Account-ID` header; G3 owns the missing-field quirks;
//! G5 owns the forbidden-field quirks. Same trust-model premise:
//! locksmith encodes upstream-specific behavior so agents stay generic.
//!
//! See agents-stack/docs/spec/v0.2.0.md "Codex body fixup (Phase G3)"
//! for the original formal design and the G3 addendum to ADR-0005.
//! G5 follows the same shape; addendum lives alongside.

use serde_json::{Map, Value};

/// Cap on inspectable body size (1 MiB). Larger bodies return
/// [`CodexBodyError::TooLarge`]; the proxy maps this to 413. Codex
/// request bodies are tiny in practice (a few KB at most), so this
/// mainly defends against pathological streaming bodies during the
/// inspect+rewrite pass.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default `instructions` injected when the agent didn't set any.
/// Operators can document an override later if this becomes a
/// soft-API; for now it's neutral phrasing.
const DEFAULT_INSTRUCTIONS: &str = "You are a helpful assistant.";

#[derive(Debug, thiserror::Error)]
pub enum CodexBodyError {
    #[error("codex body exceeds {MAX_BODY_BYTES} byte cap")]
    TooLarge,
}

/// What [`fixup`] changed. `is_noop` returns true when nothing was
/// touched — proxy.rs uses this to decide whether to emit
/// `details.codex_body_fixup` on the audit row.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FixupSummary {
    pub fields_added: Vec<&'static str>,
    pub fields_overridden: Vec<&'static str>,
    /// Phase G5 — fields stripped before forwarding because codex
    /// rejects them outright. Audit emits this so operators can
    /// trace why their request shape was modified.
    pub fields_removed: Vec<&'static str>,
}

impl FixupSummary {
    pub fn is_noop(&self) -> bool {
        self.fields_added.is_empty()
            && self.fields_overridden.is_empty()
            && self.fields_removed.is_empty()
    }
}

/// Inspect a request body destined for codex `/responses` and inject
/// missing required fields. Returns the (possibly-modified) body and
/// a summary of what changed.
///
/// Tolerant of non-JSON inputs — every parse failure path returns
/// `(body.to_vec(), FixupSummary::default())` so we never block a
/// request just because we couldn't munge it. Codex itself will
/// 400 on malformed bodies; that's the right error for the agent to
/// see.
///
/// Errors only on size cap exceeded. Caller (proxy.rs) maps to 413.
pub fn fixup(body: &[u8]) -> Result<(Vec<u8>, FixupSummary), CodexBodyError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(CodexBodyError::TooLarge);
    }

    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Ok((body.to_vec(), FixupSummary::default()));
    };

    let Value::Object(mut map) = value else {
        return Ok((body.to_vec(), FixupSummary::default()));
    };

    let mut summary = FixupSummary::default();
    apply_store_rule(&mut map, &mut summary);
    apply_stream_rule(&mut map, &mut summary);
    apply_instructions_rule(&mut map, &mut summary);
    apply_max_output_tokens_rule(&mut map, &mut summary);

    if summary.is_noop() {
        // Avoid re-serializing when we didn't change anything —
        // preserves the caller's exact bytes (formatting, key order).
        return Ok((body.to_vec(), summary));
    }

    let new_body = serde_json::to_vec(&Value::Object(map))
        .expect("re-serializing a parsed Value cannot fail");
    Ok((new_body, summary))
}

fn apply_store_rule(map: &mut Map<String, Value>, summary: &mut FixupSummary) {
    match map.get("store") {
        Some(Value::Bool(false)) => {} // already correct
        Some(_) => {
            map.insert("store".into(), Value::Bool(false));
            summary.fields_overridden.push("store");
        }
        None => {
            map.insert("store".into(), Value::Bool(false));
            summary.fields_added.push("store");
        }
    }
}

fn apply_stream_rule(map: &mut Map<String, Value>, summary: &mut FixupSummary) {
    match map.get("stream") {
        Some(Value::Bool(true)) => {} // already correct
        Some(_) => {
            map.insert("stream".into(), Value::Bool(true));
            summary.fields_overridden.push("stream");
        }
        None => {
            map.insert("stream".into(), Value::Bool(true));
            summary.fields_added.push("stream");
        }
    }
}

fn apply_instructions_rule(map: &mut Map<String, Value>, summary: &mut FixupSummary) {
    if !map.contains_key("instructions") {
        map.insert(
            "instructions".into(),
            Value::String(DEFAULT_INSTRUCTIONS.to_string()),
        );
        summary.fields_added.push("instructions");
    }
}

fn apply_max_output_tokens_rule(map: &mut Map<String, Value>, summary: &mut FixupSummary) {
    // Phase G5 — codex /responses returns 400 with body
    // `{"detail":"Unsupported parameter: max_output_tokens"}` when
    // this is set. Strip it silently; agents stay generic.
    if map.remove("max_output_tokens").is_some() {
        summary.fields_removed.push("max_output_tokens");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("output must be valid JSON")
    }

    #[test]
    fn empty_object_gets_all_three_fields() {
        let (out, summary) = fixup(b"{}").unwrap();
        let v = parse(&out);
        assert_eq!(v["store"], Value::Bool(false));
        assert_eq!(v["stream"], Value::Bool(true));
        assert_eq!(v["instructions"], Value::String(DEFAULT_INSTRUCTIONS.into()));
        assert_eq!(
            summary.fields_added,
            vec!["store", "stream", "instructions"]
        );
        assert!(summary.fields_overridden.is_empty());
    }

    #[test]
    fn store_true_is_overridden_to_false() {
        let body = json!({"store": true}).to_string();
        let (out, summary) = fixup(body.as_bytes()).unwrap();
        let v = parse(&out);
        assert_eq!(v["store"], Value::Bool(false));
        assert!(summary.fields_overridden.contains(&"store"));
        assert!(!summary.fields_added.contains(&"store"));
    }

    #[test]
    fn store_false_is_preserved_no_override() {
        let body = json!({"store": false, "stream": true, "instructions": "x"}).to_string();
        let (_out, summary) = fixup(body.as_bytes()).unwrap();
        assert!(summary.is_noop(), "store/stream/instructions all valid → noop");
    }

    #[test]
    fn stream_false_is_overridden_to_true() {
        let body = json!({"stream": false}).to_string();
        let (out, summary) = fixup(body.as_bytes()).unwrap();
        let v = parse(&out);
        assert_eq!(v["stream"], Value::Bool(true));
        assert!(summary.fields_overridden.contains(&"stream"));
    }

    #[test]
    fn instructions_user_value_is_preserved() {
        let body = json!({
            "store": false,
            "stream": true,
            "instructions": "be terse",
        })
        .to_string();
        let (out, summary) = fixup(body.as_bytes()).unwrap();
        let v = parse(&out);
        assert_eq!(v["instructions"], Value::String("be terse".into()));
        assert!(summary.is_noop());
    }

    #[test]
    fn fully_valid_body_is_noop_and_bytes_preserved() {
        // Particular formatting (whitespace, key order) survives noop.
        let body = b"{ \"instructions\": \"x\", \"stream\": true, \"store\": false }";
        let (out, summary) = fixup(body).unwrap();
        assert_eq!(out, body, "noop must preserve exact input bytes");
        assert!(summary.is_noop());
    }

    #[test]
    fn non_json_body_passes_through_unchanged() {
        let body = b"not json at all";
        let (out, summary) = fixup(body).unwrap();
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn json_array_passes_through_unchanged() {
        let body = b"[1,2,3]";
        let (out, summary) = fixup(body).unwrap();
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn json_null_passes_through_unchanged() {
        let body = b"null";
        let (out, summary) = fixup(body).unwrap();
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn malformed_json_passes_through_unchanged() {
        let body = b"{\"store\": tru";
        let (out, summary) = fixup(body).unwrap();
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn body_over_size_cap_returns_too_large() {
        let body = vec![b'a'; MAX_BODY_BYTES + 1];
        let err = fixup(&body).unwrap_err();
        assert!(matches!(err, CodexBodyError::TooLarge));
    }

    #[test]
    fn body_at_exact_size_cap_is_processed() {
        // Construct a JSON body that is exactly MAX_BODY_BYTES and
        // missing all three fields. Padding is a long instructions
        // string we then strip via override (instructions stays
        // since we set it ourselves; we rely on store/stream being
        // missing for the changed bytes).
        let prefix = b"{\"a\":\"";
        let suffix = b"\"}";
        let pad_len = MAX_BODY_BYTES - prefix.len() - suffix.len();
        let mut body = Vec::with_capacity(MAX_BODY_BYTES);
        body.extend_from_slice(prefix);
        body.extend(std::iter::repeat_n(b'x', pad_len));
        body.extend_from_slice(suffix);
        assert_eq!(body.len(), MAX_BODY_BYTES);

        let (_out, summary) = fixup(&body).expect("at-cap must be processed");
        // All three fields should be added (none were present).
        assert_eq!(
            summary.fields_added,
            vec!["store", "stream", "instructions"]
        );
    }

    #[test]
    fn fixup_summary_is_noop_recognizes_empty() {
        assert!(FixupSummary::default().is_noop());
        let mut s = FixupSummary::default();
        s.fields_added.push("x");
        assert!(!s.is_noop());
        let mut s = FixupSummary::default();
        s.fields_overridden.push("x");
        assert!(!s.is_noop());
        let mut s = FixupSummary::default();
        s.fields_removed.push("x");
        assert!(!s.is_noop());
    }

    // Phase G5 — codex rejects max_output_tokens; locksmith strips it.
    #[test]
    fn max_output_tokens_is_stripped() {
        let body = json!({
            "store": false,
            "stream": true,
            "instructions": "x",
            "max_output_tokens": 16384,
        })
        .to_string();
        let (out, summary) = fixup(body.as_bytes()).unwrap();
        let v = parse(&out);
        assert!(
            v.get("max_output_tokens").is_none(),
            "max_output_tokens must be stripped from forwarded body"
        );
        assert!(summary.fields_removed.contains(&"max_output_tokens"));
        assert!(summary.fields_added.is_empty());
        assert!(summary.fields_overridden.is_empty());
    }

    #[test]
    fn max_output_tokens_absent_is_noop_for_g5() {
        let body = json!({
            "store": false,
            "stream": true,
            "instructions": "x",
        })
        .to_string();
        let (_out, summary) = fixup(body.as_bytes()).unwrap();
        assert!(
            !summary.fields_removed.contains(&"max_output_tokens"),
            "absent param must not be reported as removed"
        );
    }

    #[test]
    fn max_output_tokens_stripped_alongside_g3_additions() {
        // Empty input gets G3 additions (store/stream/instructions);
        // explicit max_output_tokens still stripped in same pass.
        let body = json!({"max_output_tokens": 0}).to_string();
        let (out, summary) = fixup(body.as_bytes()).unwrap();
        let v = parse(&out);
        assert!(v.get("max_output_tokens").is_none());
        assert_eq!(v["store"], Value::Bool(false));
        assert_eq!(v["stream"], Value::Bool(true));
        assert_eq!(v["instructions"], Value::String(DEFAULT_INSTRUCTIONS.into()));
        assert_eq!(
            summary.fields_added,
            vec!["store", "stream", "instructions"]
        );
        assert_eq!(summary.fields_removed, vec!["max_output_tokens"]);
    }
}
