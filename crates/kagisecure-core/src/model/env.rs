//! Environments: named sets of variable bindings (vault-format §5.2).
//!
//! An `Environment` is kagisecure's first-class notion of "the set of variables a project needs".
//! It is what the MCP tools mostly operate on, and it is the only structure in the vault whose
//! *names* are routinely shown to an agent.
//!
//! Only compiled with `secret-material`, because [`VarSource::Literal`] holds a
//! [`Secret`]. The metadata mirror an agent may see is
//! [`EnvironmentSummary`], which is always available.

use serde::{Deserialize, Serialize};

use super::Secret;
use crate::proto::{
    EnvId, EnvVarSummary, EnvironmentSummary, FieldId, ItemId, VarSourceKind, VaultId,
};

/// Where an environment variable's value comes from.
///
/// `ItemField` is preferred over `Literal`: rotate the credential in one item and every
/// environment that references it follows.
#[derive(Debug, Serialize, Deserialize)]
pub enum VarSource {
    /// A value stored inline in this environment.
    Literal(#[serde(with = "super::secret::cbor")] Secret),
    /// A reference into an item's field.
    ItemField {
        /// The item.
        item: ItemId,
        /// The field within it.
        field: FieldId,
    },
    /// Declared by an agent through `add_variables`, awaiting a value from the user.
    ///
    /// Not in vault-format §5.2 as written; see ADR-0007. It exists because `add_variables` can
    /// name a variable it is not allowed to supply a value for, and the environment has to be
    /// able to hold that fact.
    Pending {
        /// The agent's explanation of what the user should paste, shown in the entry UI.
        hint: Option<String>,
    },
}

impl VarSource {
    /// The metadata-only kind tag.
    #[must_use]
    pub fn kind(&self) -> VarSourceKind {
        match self {
            Self::Literal(_) => VarSourceKind::Literal,
            Self::ItemField { .. } => VarSourceKind::ItemField,
            Self::Pending { .. } => VarSourceKind::Pending,
        }
    }

    /// Whether a value is available for this binding without further user input.
    ///
    /// An `ItemField` is optimistically `true`: whether the referenced field still exists is a
    /// question for resolution time, and answering it here would make this function an oracle
    /// over the vault's shape for no benefit.
    #[must_use]
    pub fn is_populated(&self) -> bool {
        !matches!(self, Self::Pending { .. })
    }
}

/// One named variable in an environment.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvVar {
    /// Variable name, e.g. `"STRIPE_SECRET_KEY"`. Metadata: visible to agents.
    pub name: String,
    /// Where the value comes from.
    pub source: VarSource,
}

impl EnvVar {
    /// Metadata-only view.
    #[must_use]
    pub fn summary(&self) -> EnvVarSummary {
        let (item_id, field_id) = match &self.source {
            VarSource::ItemField { item, field } => (Some(*item), Some(*field)),
            _ => (None, None),
        };
        EnvVarSummary {
            name: self.name.clone(),
            kind: self.source.kind(),
            item_id,
            field_id,
            populated: self.source.is_populated(),
            hint: match &self.source {
                VarSource::Pending { hint } => hint.clone(),
                _ => None,
            },
        }
    }
}

/// A named set of variable bindings, scoped to one logical vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct Environment {
    /// Identifier.
    pub id: EnvId,
    /// The logical vault this environment lives in.
    pub vault_id: VaultId,
    /// Display name, e.g. `"acme-api / staging"`.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Variables, in display order.
    #[serde(default)]
    pub vars: Vec<EnvVar>,
    /// Project directories commonly targeted. A UI convenience; it grants nothing.
    #[serde(default)]
    pub default_paths: Vec<String>,
    /// Whether agents may see this environment at all. Default-deny (threat-model M-9).
    #[serde(default)]
    pub agent_visible: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
}

impl Environment {
    /// A fresh, empty environment, invisible to agents.
    #[must_use]
    pub fn new(vault_id: VaultId, name: impl Into<String>) -> Self {
        let now = crate::unix_now();
        Self {
            id: EnvId::new(),
            vault_id,
            name: name.into(),
            description: None,
            vars: Vec::new(),
            default_paths: Vec::new(),
            agent_visible: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// The variable with this name, if any.
    #[must_use]
    pub fn var(&self, name: &str) -> Option<&EnvVar> {
        self.vars.iter().find(|v| v.name == name)
    }

    /// Add a variable, replacing any existing one with the same name.
    ///
    /// Replacement rather than duplication is the only sane rule: a `.env` file with the same key
    /// twice is a bug waiting to happen, and the last writer would win anyway.
    pub fn set_var(&mut self, var: EnvVar) {
        match self.vars.iter_mut().find(|v| v.name == var.name) {
            Some(existing) => *existing = var,
            None => self.vars.push(var),
        }
        self.updated_at = crate::unix_now();
    }

    /// Remove a variable by name, reporting whether it was there.
    pub fn remove_var(&mut self, name: &str) -> bool {
        let before = self.vars.len();
        self.vars.retain(|v| v.name != name);
        let removed = self.vars.len() != before;
        if removed {
            self.updated_at = crate::unix_now();
        }
        removed
    }

    /// Metadata-only view. This is what the MCP surface is allowed to return.
    #[must_use]
    pub fn summary(&self) -> EnvironmentSummary {
        EnvironmentSummary {
            id: self.id,
            vault_id: self.vault_id,
            name: self.name.clone(),
            description: self.description.clone(),
            variables: self.vars.iter().map(EnvVar::summary).collect(),
            agent_visible: self.agent_visible,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_summary_carries_names_and_binding_kinds_but_no_value() {
        let mut env = Environment::new(VaultId::new(), "acme / staging");
        env.set_var(EnvVar {
            name: "STRIPE_SECRET_KEY".to_owned(),
            source: VarSource::Literal(Secret::from_string("sk_live_do_not_leak".to_owned())),
        });
        env.set_var(EnvVar {
            name: "DATABASE_URL".to_owned(),
            source: VarSource::ItemField {
                item: ItemId::new(),
                field: FieldId::new(),
            },
        });
        env.set_var(EnvVar {
            name: "REDIS_URL".to_owned(),
            source: VarSource::Pending {
                hint: Some("paste the staging Redis URL".to_owned()),
            },
        });

        let summary = env.summary();
        assert_eq!(
            summary.variable_names(),
            ["STRIPE_SECRET_KEY", "DATABASE_URL", "REDIS_URL"]
        );
        assert_eq!(summary.variables[0].kind, VarSourceKind::Literal);
        assert!(summary.variables[0].populated);
        assert!(!summary.variables[2].populated);

        let rendered = serde_json::to_string(&summary).unwrap();
        assert!(!rendered.contains("sk_live_do_not_leak"));
    }

    #[test]
    fn setting_the_same_name_twice_replaces_rather_than_duplicates() {
        let mut env = Environment::new(VaultId::new(), "e");
        env.set_var(EnvVar {
            name: "A".to_owned(),
            source: VarSource::Pending { hint: None },
        });
        env.set_var(EnvVar {
            name: "A".to_owned(),
            source: VarSource::Literal(Secret::from_string("v".to_owned())),
        });
        assert_eq!(env.vars.len(), 1);
        assert_eq!(env.var("A").unwrap().source.kind(), VarSourceKind::Literal);
    }

    #[test]
    fn removing_reports_whether_it_did_anything() {
        let mut env = Environment::new(VaultId::new(), "e");
        env.set_var(EnvVar {
            name: "A".to_owned(),
            source: VarSource::Pending { hint: None },
        });
        assert!(env.remove_var("A"));
        assert!(!env.remove_var("A"));
    }

    #[test]
    fn an_environment_round_trips_through_cbor() {
        let mut env = Environment::new(VaultId::new(), "acme / staging");
        env.set_var(EnvVar {
            name: "A".to_owned(),
            source: VarSource::Literal(Secret::from_string("value".to_owned())),
        });
        let mut buf = Vec::new();
        ciborium::into_writer(&env, &mut buf).unwrap();
        let back: Environment = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.id, env.id);
        assert_eq!(back.vars.len(), 1);
        match &back.var("A").unwrap().source {
            VarSource::Literal(s) => assert_eq!(s.expose(), b"value"),
            other => panic!("expected a literal, got {:?}", other.kind()),
        }
    }

    #[test]
    fn a_new_environment_is_invisible_to_agents() {
        assert!(!Environment::new(VaultId::new(), "e").agent_visible);
    }
}
