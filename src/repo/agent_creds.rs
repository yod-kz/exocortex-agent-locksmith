//! `agent_credential_overrides` repository — Phase G.
//!
//! Per-agent credential overrides. Default behavior with no rows in
//! this table is unchanged from Phase F: agents resolve credentials
//! from their registration's default `auth_spec` and (for OAuth) the
//! `default` session label.
//!
//! When an override row exists for `(agent_id, registration)`, the
//! proxy hot path swaps in the override's `auth_spec` BEFORE static-
//! credential resolution / OAuth session lookup. This lets a deployment
//! pin specific agents to their own upstream credentials (separate API
//! keys, separate ChatGPT subscriptions, etc.) without proliferating
//! registrations.
//!
//! Override `auth_spec` is always a complete [`AuthSpec`] — never a
//! partial diff. Storage cost is small (≤256 bytes per row in the
//! typical case) and resolution is one in-memory cache lookup.
//!
//! See `agents-stack/docs/spec/v0.2.0.md` "Per-agent credential
//! overrides + OAuth session labels (Phase G)" for the full design.

use super::agent::RepoError;
use crate::registrations::AuthSpec;
use sqlx::Row;
use sqlx::SqlitePool;

/// In-memory shape of an `agent_credential_overrides` row. Returned by
/// `get` / `list_for_agent`.
#[derive(Debug, Clone)]
pub struct AgentCredentialOverride {
    pub agent_id: i64,
    pub registration: String,
    pub auth_spec: AuthSpec,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Repository for the `agent_credential_overrides` table.
#[derive(Clone)]
pub struct AgentCredentialRepository {
    pool: SqlitePool,
}

impl AgentCredentialRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// UPSERT an override. Operator CLI calls this via
    /// `locksmith agent set-credential <agent> <reg> ...`. Idempotent —
    /// re-running with the same args replaces the prior row's
    /// `auth_spec` and bumps `updated_at`.
    pub async fn set(
        &self,
        agent_id: i64,
        registration: &str,
        auth_spec: &AuthSpec,
    ) -> Result<(), RepoError> {
        let auth_json = serde_json::to_string(auth_spec)?;
        let now = unix_now();
        sqlx::query(
            "INSERT INTO agent_credential_overrides \
                (agent_id, registration, auth_spec, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(agent_id, registration) DO UPDATE SET \
                auth_spec = excluded.auth_spec, \
                updated_at = excluded.updated_at",
        )
        .bind(agent_id)
        .bind(registration)
        .bind(&auth_json)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up the override for `(agent_id, registration)`. Returns
    /// `Ok(None)` when no override exists — the proxy hot path then
    /// falls back to the registration's default auth_spec.
    ///
    /// This is the single hot-path call. Hits the SQLite page cache
    /// after the first request per (agent, registration) tuple, sub-ms.
    pub async fn get(
        &self,
        agent_id: i64,
        registration: &str,
    ) -> Result<Option<AgentCredentialOverride>, RepoError> {
        let row = sqlx::query(
            "SELECT agent_id, registration, auth_spec, created_at, updated_at \
             FROM agent_credential_overrides \
             WHERE agent_id = ? AND registration = ?",
        )
        .bind(agent_id)
        .bind(registration)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let auth_json: String = row.get("auth_spec");
        let auth_spec: AuthSpec = serde_json::from_str(&auth_json)?;
        Ok(Some(AgentCredentialOverride {
            agent_id: row.get("agent_id"),
            registration: row.get("registration"),
            auth_spec,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    /// Idempotent delete. Returns `true` when a row was actually
    /// removed, `false` when no override existed for the key.
    pub async fn delete(&self, agent_id: i64, registration: &str) -> Result<bool, RepoError> {
        let res = sqlx::query(
            "DELETE FROM agent_credential_overrides \
             WHERE agent_id = ? AND registration = ?",
        )
        .bind(agent_id)
        .bind(registration)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Test-only accessor for the underlying pool. Used by FK-cascade
    /// tests that need to bypass the agent repo.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// List all overrides for a single agent. Used by
    /// `locksmith agent credentials list <agent>` for operator
    /// visibility into who's pinned to what.
    pub async fn list_for_agent(
        &self,
        agent_id: i64,
    ) -> Result<Vec<AgentCredentialOverride>, RepoError> {
        let rows = sqlx::query(
            "SELECT agent_id, registration, auth_spec, created_at, updated_at \
             FROM agent_credential_overrides \
             WHERE agent_id = ? ORDER BY registration",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let auth_json: String = row.get("auth_spec");
            let auth_spec: AuthSpec = serde_json::from_str(&auth_json)?;
            out.push(AgentCredentialOverride {
                agent_id: row.get("agent_id"),
                registration: row.get("registration"),
                auth_spec,
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            });
        }
        Ok(out)
    }
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::open_and_migrate;
    use crate::repo::AgentRepository;
    use tempfile::TempDir;

    async fn fresh() -> (TempDir, AgentRepository, AgentCredentialRepository) {
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("db.sqlite"))
            .await
            .unwrap();
        let agents = AgentRepository::new(pool.clone());
        let creds = AgentCredentialRepository::new(pool);
        (dir, agents, creds)
    }

    async fn make_agent(agents: &AgentRepository, name: &str) -> i64 {
        agents
            .create(name, None, None, None, None, None)
            .await
            .unwrap();
        let rec = agents.get_by_name(name).await.unwrap().unwrap();
        rec.id
    }

    #[tokio::test]
    async fn set_and_get_roundtrip() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        let spec = AuthSpec::Bearer {
            env_var: "LM_STUDIO_API_KEY_HERMES".to_string(),
            force_replace: false,
        };
        creds.set(id, "lmstudio", &spec).await.unwrap();
        let back = creds.get(id, "lmstudio").await.unwrap().unwrap();
        assert_eq!(back.auth_spec, spec);
        assert_eq!(back.agent_id, id);
        assert_eq!(back.registration, "lmstudio");
    }

    #[tokio::test]
    async fn get_returns_none_when_no_override() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "openclaw").await;
        assert!(creds.get(id, "lmstudio").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_is_idempotent_and_replaces_prior_value() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "OLD".into(),
                    force_replace: false,
                },
            )
            .await
            .unwrap();
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "NEW".into(),
                    force_replace: false,
                },
            )
            .await
            .unwrap();
        let back = creds.get(id, "lmstudio").await.unwrap().unwrap();
        match back.auth_spec {
            AuthSpec::Bearer { env_var, .. } => assert_eq!(env_var, "NEW"),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "X".into(),
                    force_replace: false,
                },
            )
            .await
            .unwrap();
        assert!(creds.delete(id, "lmstudio").await.unwrap());
        assert!(creds.get(id, "lmstudio").await.unwrap().is_none());
        // second delete is fine, just returns false.
        assert!(!creds.delete(id, "lmstudio").await.unwrap());
    }

    #[tokio::test]
    async fn list_for_agent_returns_all_their_overrides() {
        let (_d, agents, creds) = fresh().await;
        let h = make_agent(&agents, "hermes").await;
        let o = make_agent(&agents, "openclaw").await;
        creds
            .set(
                h,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "LM_HERMES".into(),
                    force_replace: false,
                },
            )
            .await
            .unwrap();
        creds
            .set(
                h,
                "tavily",
                &AuthSpec::Bearer {
                    env_var: "TAVILY_HERMES".into(),
                    force_replace: false,
                },
            )
            .await
            .unwrap();
        creds
            .set(
                o,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "LM_OPENCLAW".into(),
                    force_replace: false,
                },
            )
            .await
            .unwrap();

        let h_overrides = creds.list_for_agent(h).await.unwrap();
        assert_eq!(h_overrides.len(), 2);
        let names: Vec<&str> = h_overrides
            .iter()
            .map(|o| o.registration.as_str())
            .collect();
        assert!(names.contains(&"lmstudio"));
        assert!(names.contains(&"tavily"));

        let o_overrides = creds.list_for_agent(o).await.unwrap();
        assert_eq!(o_overrides.len(), 1);
        assert_eq!(o_overrides[0].registration, "lmstudio");
    }

    #[tokio::test]
    async fn override_cascades_on_agent_delete() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "X".into(),
                    force_replace: false,
                },
            )
            .await
            .unwrap();
        // Hard delete via raw SQL to exercise the FK cascade.
        sqlx::query("DELETE FROM agents WHERE id = ?")
            .bind(id)
            .execute(creds.pool())
            .await
            .unwrap();
        assert!(creds.get(id, "lmstudio").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oauth_override_with_session_label_roundtrips() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        let spec = AuthSpec::OauthDeviceCode {
            client_id: "x".into(),
            scopes: vec![],
            device_url: "https://d".into(),
            token_url: "https://t".into(),
            session_label: Some("hermes".into()),
        };
        creds.set(id, "codex", &spec).await.unwrap();
        let back = creds.get(id, "codex").await.unwrap().unwrap();
        assert_eq!(back.auth_spec.oauth_session_label(), Some("hermes"));
    }
}
