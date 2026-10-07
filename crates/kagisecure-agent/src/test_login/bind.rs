//! `create_test_login`'s optional `bind` (ADR-0048, Phase 3): two variables of an environment in
//! the test-login vault bound to a test login's username and generated password, written in the
//! same transaction as the login. The person still approves the binding on the `add_variables`
//! sheet — a binding is a standing route to the value (§9).
//!
//! Nothing here reads a value: a binding names a field by id.

use kagisecure_core::Vault;
use kagisecure_core::model::{Environment, FieldId, Item, ItemId, VarSource};
use kagisecure_core::proto::{EnvId, VarName, VaultId};
use kagisecure_core::vault::Tx;
use kagisecure_ipc::protocol::{MAX_ENVIRONMENT_NAME_CHARS, TestLoginBind, TestLoginBinding};

/// A `bind` whose every name is within its documented limits.
#[derive(Clone, Debug)]
pub(crate) struct BindNames {
    pub(crate) environment: String,
    pub(crate) username_var: VarName,
    pub(crate) credential_var: VarName,
}

impl BindNames {
    /// The names of `bind`, if the environment's name is one line of 1 to 128 characters and the
    /// two variables are distinct, valid variable names.
    pub(crate) fn of(bind: &TestLoginBind) -> Option<Self> {
        let environment = bind.environment.as_str();
        if environment.trim().is_empty()
            || !kagisecure_ipc::protocol::display_text_ok(
                environment,
                MAX_ENVIRONMENT_NAME_CHARS,
                false,
            )
        {
            return None;
        }
        let username_var = VarName::new(bind.username_var.clone()).ok()?;
        let credential_var = VarName::new(bind.credential_var.clone()).ok()?;
        (username_var != credential_var).then(|| Self {
            environment: environment.to_owned(),
            username_var,
            credential_var,
        })
    }

    /// Both variable names, username first, as the sheet and the audit entry list them.
    pub(crate) fn variables(&self) -> Vec<String> {
        vec![
            self.username_var.as_str().to_owned(),
            self.credential_var.as_str().to_owned(),
        ]
    }

    fn binding(&self, environment_id: EnvId) -> TestLoginBinding {
        TestLoginBinding {
            environment_id,
            environment: self.environment.clone(),
            username_var: self.username_var.as_str().to_owned(),
            credential_var: self.credential_var.as_str().to_owned(),
        }
    }
}

/// The fields a binding points at: the login's username field and its password (the item's
/// primary secret).
#[derive(Clone, Copy, Debug)]
pub(crate) struct LoginFields {
    pub(crate) item: ItemId,
    pub(crate) username: FieldId,
    pub(crate) password: FieldId,
}

impl LoginFields {
    /// The username and password fields of `item`, if it has both.
    pub(crate) fn of(item: &Item) -> Option<Self> {
        let username = item
            .fields
            .iter()
            .find(|f| f.label.eq_ignore_ascii_case("username"))?
            .id;
        Some(Self {
            item: item.id,
            username,
            password: item.primary_secret?,
        })
    }
}

/// What a bind needs, on the vault as it is now.
#[derive(Clone, Debug)]
pub(crate) enum BindPlan {
    /// The environment already binds both variables to this login: nothing to write and nobody
    /// to ask.
    Done(TestLoginBinding),
    /// Write the bindings into this environment, or into a new one when `None`.
    Write {
        /// The existing environment, if there is one.
        environment_id: Option<EnvId>,
    },
}

/// Why a bind cannot be made. Each has one fixed answer in the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindRefusal {
    /// More than one environment in the test-login vault has that name.
    Ambiguous,
    /// The environment of that name is hidden from agents.
    Hidden,
    /// A variable of one of those names is there already, bound to something else.
    VariableTaken,
}

/// What binding `names` to `login` needs in `test_vault` (or to a login not yet written, when
/// `login` is `None`: then any variable of those names already there is someone else's).
pub(crate) fn plan(
    vault: &Vault,
    test_vault: VaultId,
    names: &BindNames,
    login: Option<LoginFields>,
) -> Result<BindPlan, BindRefusal> {
    let mut found = vault
        .environments()
        .iter()
        .filter(|e| e.vault_id == test_vault && e.name == names.environment);
    let Some(env) = found.next() else {
        return Ok(BindPlan::Write {
            environment_id: None,
        });
    };
    if found.next().is_some() {
        return Err(BindRefusal::Ambiguous);
    }
    if !env.agent_visible {
        return Err(BindRefusal::Hidden);
    }
    let mut done = true;
    for (name, field) in [
        (&names.username_var, login.map(|l| l.username)),
        (&names.credential_var, login.map(|l| l.password)),
    ] {
        match env.var(name.as_str()) {
            None => done = false,
            Some(var) => match (&var.source, login, field) {
                (VarSource::ItemField { item, field: bound }, Some(login), Some(field))
                    if *item == login.item && *bound == field => {}
                _ => return Err(BindRefusal::VariableTaken),
            },
        }
    }
    Ok(if done {
        BindPlan::Done(names.binding(env.id))
    } else {
        BindPlan::Write {
            environment_id: Some(env.id),
        }
    })
}

/// What [`apply`] wrote: the binding, and whether the environment was created for it.
pub(crate) struct Applied {
    pub(crate) binding: TestLoginBinding,
    pub(crate) created_environment: bool,
    /// Whether anything was written at all.
    pub(crate) wrote: bool,
}

/// Bind `names` to `login` inside `tx`, re-planned on the file as it is now: the environment is
/// created in the test-login vault (visible to agents) if there is none of that name.
pub(crate) fn apply(
    tx: &mut Tx<'_>,
    test_vault: VaultId,
    names: &BindNames,
    login: LoginFields,
) -> Result<Applied, BindRefusal> {
    let environment_id = match plan(tx, test_vault, names, Some(login))? {
        BindPlan::Done(binding) => {
            return Ok(Applied {
                binding,
                created_environment: false,
                wrote: false,
            });
        }
        BindPlan::Write { environment_id } => environment_id,
    };
    let bind = |env: &mut Environment| {
        env.set_var(
            names.username_var.clone(),
            VarSource::ItemField {
                item: login.item,
                field: login.username,
            },
        );
        env.set_var(
            names.credential_var.clone(),
            VarSource::ItemField {
                item: login.item,
                field: login.password,
            },
        );
    };
    match environment_id {
        Some(id) => {
            let env = tx
                .find_environment_mut(&id.to_string())
                .map_err(|_| BindRefusal::Hidden)?;
            bind(env);
            Ok(Applied {
                binding: names.binding(id),
                created_environment: false,
                wrote: true,
            })
        }
        None => {
            let mut env = Environment::new(test_vault, names.environment.clone());
            // Made through an agent's request in the agents' own vault: visible to agents.
            env.agent_visible = true;
            bind(&mut env);
            let id = env.id;
            tx.add_environment(env);
            Ok(Applied {
                binding: names.binding(id),
                created_environment: true,
                wrote: true,
            })
        }
    }
}
