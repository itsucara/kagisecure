//! Unattended sign-ins (ADR-0042 §12): `request_fill` on the unattended socket, under a login
//! grant, into the run's own browser, through ADR-0036's broker.
//!
//! The order of checks is §12.6's:
//!
//! 1. **Armed**, and 2. **in a run** — [`super::service::handle`], as for every request.
//! 3. **Arguments**: `INVALID_ARGUMENT`.
//! 4. **A login grant of this run's job** names the item, the fields and exactly the claimed
//!    origin (or one of its follow-on origins): otherwise a **strike**. Suspended, expired, used
//!    up or over the per-run limit refuse without one (implementation decision 44).
//! 5. **The item** is still a Login with that website, and changed nothing since the grant was
//!    approved: otherwise the grant is suspended.
//! 6. **The run's browser**: `FILL_UNAVAILABLE` when the job has none, or it has not connected.
//! 7. **Gates 5–9 of ADR-0036** in the run browser's own broker ([`super::browser`]), with a
//!    [`StandingPass`] in place of the sheet: the audit pre-flight, the target (the visibility
//!    rule dropped, §12.4), and the audited release. A tab in front at an origin the item is not
//!    saved for — the broker's `OriginMismatch` — is a strike, as §12.7 has it.
//!
//! After a sign-in the grant's use is counted; an identifier-first sign-in's second step and a
//! one-time code are not sign-ins of their own (§12.2, §12.5).

use std::sync::{Arc, Mutex};

use kagisecure_core::Vault;
use kagisecure_core::model::Category;
use kagisecure_core::proto::{ItemId, Outcome};
use kagisecure_core::unix_now;
use kagisecure_core::vault::machine::{GrantId, JobId, LoginField, LoginGrant};
use kagisecure_extension_ipc::origin::Origin;
use kagisecure_ipc::protocol::{
    AgentFillField, ErrorCode, Response, agent_fill_fields_ok, display_text_ok,
};

use super::runs::Run;
use super::service::{Ctx, not_granted};
use super::{Core, TOOL_GRANT, engine_entry};
use crate::extension::agent_fill::{self, AgentFillCall, AgentFillNotice, Sidecar};
use crate::vault::{REQUEST_LOCK_TIMEOUT, VaultHandle};

const INVALID_FIELDS: &str = "fields must name username, password or both, each at most once, \
                              or one_time_code on its own. Nothing was filled.";
const INVALID_ORIGIN: &str = "origin must be the https origin of the page the job's browser has \
                              open, such as https://example.com. Nothing was filled.";
const NO_RUN_BROWSER: &str = "This job has no browser of its own connected to kagisecure yet. \
                              Open the sign-in page in the browser at KAGISECURE_RUN_BROWSER_CDP \
                              and retry once.";

/// A standing login grant's permission for one fill, in place of a person's grant (ADR-0042
/// §12.6). Made only here, in the unattended engine, and only for a Login item of a machine
/// vault under a login grant of that vault that covers the origin and the fields: no personal or
/// shared item can produce one. [`crate::extension::crossing::Approved::from_standing`] is the
/// one thing that takes it.
#[derive(Debug)]
pub struct StandingPass {
    origin: String,
    item_id: String,
    fields: Vec<String>,
    label: String,
}

impl StandingPass {
    /// A pass for `fields` of `grant`'s item at `origin`, during run `run`; `None` unless `vault`
    /// is a machine vault holding exactly this grant, the item is a Login in it, and the grant
    /// covers the origin and every field.
    pub(in crate::unattended) fn issue(
        vault: &Vault,
        grant: &LoginGrant,
        run: u64,
        origin: &str,
        fields: &[AgentFillField],
    ) -> Option<Self> {
        if !vault.is_machine() {
            return None;
        }
        let held = vault
            .machine()?
            .login_grants
            .iter()
            .find(|g| g.id == grant.id)?;
        if held != grant || held.suspended.is_some() {
            return None;
        }
        let item = vault.item_by_id(&grant.item)?;
        if item.category != Category::Login || item.trashed_at.is_some() {
            return None;
        }
        if !covers(grant, origin, fields) {
            return None;
        }
        Some(Self {
            origin: origin.to_owned(),
            item_id: grant.item.to_string(),
            fields: fields.iter().map(|f| f.as_str().to_owned()).collect(),
            label: format!("grant {} run {run}", grant.id),
        })
    }

    /// The exact origin it is for.
    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    /// The item it is for, canonical.
    pub(crate) fn item_id(&self) -> &str {
        &self.item_id
    }

    /// The fields it covers, by their wire names.
    pub(crate) fn fields(&self) -> &[String] {
        &self.fields
    }

    /// `grant <g> run <r>`, for the audit detail.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }
}

/// The standing grant's name for a field. `None` for a sign-up fill's new password, which no
/// standing grant covers (ADR-0048 §7 serves it only for sealed test logins).
fn login_field(field: AgentFillField) -> Option<LoginField> {
    match field {
        AgentFillField::Username => Some(LoginField::Username),
        AgentFillField::Password => Some(LoginField::Password),
        AgentFillField::OneTimeCode => Some(LoginField::OneTimeCode),
        AgentFillField::NewPassword => None,
    }
}

/// Whether `grant` covers `fields` at `origin`: its origin or a follow-on, every field one it
/// names, and a code only with the switch on.
fn covers(grant: &LoginGrant, origin: &str, fields: &[AgentFillField]) -> bool {
    (grant.origin == origin || grant.follow_on_origins.iter().any(|o| o == origin))
        && fields.iter().all(|f| {
            login_field(*f).is_some_and(|field| grant.fields.contains(&field))
                && (*f != AgentFillField::OneTimeCode || grant.one_time_codes)
        })
}

/// What steps 4 and 5 decided.
enum Decision {
    Strike,
    Refuse(&'static str),
    Suspend(GrantId, &'static str),
    Fill(Box<LoginGrant>),
}

fn decide(
    vault: &Vault,
    job: JobId,
    item: &ItemId,
    origin: &str,
    fields: &[AgentFillField],
) -> Decision {
    let Some(machine) = vault.machine() else {
        return Decision::Strike;
    };
    let candidates: Vec<&LoginGrant> = machine
        .login_grants
        .iter()
        .filter(|g| g.job == job && g.item == *item && covers(g, origin, fields))
        .collect();
    if candidates.is_empty() {
        return Decision::Strike;
    }
    let Some(grant) = candidates.iter().find(|g| g.suspended.is_none()) else {
        return Decision::Refuse("SUSPENDED");
    };
    if unix_now() >= grant.limits.expires_at {
        return Decision::Refuse("EXPIRED");
    }
    if grant.uses >= grant.limits.total_uses {
        return Decision::Refuse("USED_UP");
    }
    let Some(saved) = vault
        .item_by_id(&grant.item)
        .filter(|i| i.category == Category::Login && i.trashed_at.is_none())
    else {
        return Decision::Suspend(grant.id, "ITEM_GONE");
    };
    if !saved.urls.contains(&grant.origin) {
        return Decision::Suspend(grant.id, "WEBSITE_CHANGED");
    }
    if saved.updated_at > grant.approved_at {
        return Decision::Suspend(grant.id, "VALUE_CHANGED");
    }
    Decision::Fill(Box::new((*grant).clone()))
}

impl Ctx<'_> {
    /// `request_fill` from a run (ADR-0042 §12.6). See the module documentation.
    pub(super) fn request_fill(
        &self,
        item_id: &ItemId,
        origin: &str,
        fields: &[AgentFillField],
    ) -> Response {
        let tool = if fields == [AgentFillField::OneTimeCode] {
            "totp_code"
        } else {
            "request_fill"
        };
        let names: Vec<String> = if agent_fill_fields_ok(fields) {
            fields.iter().map(|f| f.as_str().to_owned()).collect()
        } else {
            return Response::error(ErrorCode::InvalidArgument, INVALID_FIELDS);
        };
        // Step 3: an exact https origin.
        let claimed = match Origin::parse(origin) {
            Ok(o) if display_text_ok(origin, 2048, false) && o.scheme() == "https" => {
                o.ascii_serialization()
            }
            _ => return Response::error(ErrorCode::InvalidArgument, INVALID_ORIGIN),
        };

        // Steps 4 and 5.
        let decision = self
            .handle
            .with(|vault| decide(vault, self.run.job, item_id, &claimed, fields))
            .unwrap_or(Decision::Refuse("LOCKED"));
        let grant = match decision {
            Decision::Strike => {
                self.strike(tool, None, names, "NO_GRANT");
                return not_granted();
            }
            Decision::Refuse(reason) => return self.refuse(tool, None, names, reason),
            Decision::Suspend(grant, reason) => {
                self.suspend_login(grant, tool, names, reason);
                return not_granted();
            }
            Decision::Fill(grant) => grant,
        };

        // Step 6: the run's browser.
        let Some(browser) = self.run.browser() else {
            return self.unavailable(tool, names);
        };
        let Some(sidecar) = Sidecar::of(self.connection.identity()) else {
            return self.unavailable(tool, names);
        };
        let sidecar = sidecar.with_actor(super::service::actor(Some(self.run), self.pid));
        let item_key = item_id.to_string();

        // The per-run limit: a sign-in counts once, however many steps it takes; a code counts
        // against the codes of this run, one per sign-in.
        let continuation = browser.broker.continues(&sidecar, &item_key, fields);
        let code = fields == [AgentFillField::OneTimeCode];
        let reserved = if continuation {
            true
        } else if code {
            self.run.reserve_code(grant.id, self.run.sign_ins(grant.id))
        } else {
            self.run.reserve(grant.id, grant.limits.per_run)
        };
        if !reserved {
            return self.refuse(tool, None, names, "PER_RUN_LIMIT");
        }
        let give_back = || match (continuation, code) {
            (true, _) => {}
            (false, true) => self.run.unreserve_code(grant.id),
            (false, false) => self.run.unreserve(grant.id),
        };

        let slot = match browser
            .broker
            .admit(&sidecar, &item_key, Some(&claimed), fields)
        {
            Ok(slot) => slot,
            Err(refusal) => {
                give_back();
                let (entry, reply) = agent_fill::refused_at_gate_one(
                    refusal,
                    &sidecar,
                    &item_key,
                    Some(&claimed),
                    fields,
                );
                let _ = self.handle.record_best_effort(REQUEST_LOCK_TIMEOUT, entry);
                return reply;
            }
        };
        let pass = self
            .handle
            .with(|vault| StandingPass::issue(vault, &grant, self.run.id, &claimed, fields))
            .flatten();
        let Some(pass) = pass else {
            give_back();
            drop(slot);
            return self.refuse(tool, None, names, "LOCKED");
        };
        let call = AgentFillCall {
            handle: self.handle,
            queue: &browser.queue,
            sidecar,
            item_id: item_key,
            claimed_origin: claimed,
            fields: fields.to_vec(),
            vault_id: None,
            standing: Mutex::new(Some(pass)),
        };
        let reply = slot.serve(&call);

        // The broker's `FILL_UNAVAILABLE` says "no browser is connected" to a person's agent; to a
        // job it means the page has not asked the extension anything yet.
        let reply = match reply {
            Response::Error {
                code: ErrorCode::FillUnavailable,
                ..
            } => Response::error(ErrorCode::FillUnavailable, NO_RUN_BROWSER),
            other => other,
        };
        let filled = matches!(reply, Response::FillResult { .. });
        if !filled {
            give_back();
        } else if !continuation && !code {
            count_use(self.handle, grant.id);
        }
        if settle_notices(
            self.core,
            self.handle,
            self.run,
            &browser.broker.take_notices(),
        ) {
            return not_granted();
        }
        reply
    }

    fn unavailable(&self, tool: &str, names: Vec<String>) -> Response {
        self.core.record(kagisecure_core::audit::AuditDraft {
            tool: tool.to_owned(),
            variables: names,
            ..super::service::refusal_entry(
                Some(self.run),
                self.pid,
                self.connection,
                tool,
                None,
                Vec::new(),
                "NO_RUN_BROWSER",
            )
        });
        Response::error(ErrorCode::FillUnavailable, NO_RUN_BROWSER)
    }

    /// Suspend one login grant whose item changed.
    fn suspend_login(&self, grant: GrantId, tool: &str, names: Vec<String>, reason: &str) {
        let refusal = super::service::refusal_entry(
            Some(self.run),
            self.pid,
            self.connection,
            tool,
            None,
            names,
            reason,
        );
        let suspended = engine_entry(
            TOOL_GRANT,
            Outcome::Denied,
            format!("GRANT_SUSPENDED ({reason}) grant {grant}"),
        );
        let written = self.handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
            tx.machine_mut()?.suspend_grant(grant, unix_now(), reason);
            tx.append_audit(refusal.clone());
            tx.append_audit(suspended.clone());
            Ok(())
        });
        if !matches!(written, Some(Ok(()))) {
            self.core.record(refusal);
            self.core.record(suspended);
        }
        self.core
            .notice("SUSPENDED", Some(&self.run.job_name), reason);
    }
}

/// Count a sign-in against the grant's total, best-effort: the `Allowed` entry is already
/// committed, and a count that could not be written costs one extra use at most
/// (implementation decision 46).
fn count_use(handle: &VaultHandle, grant: GrantId) {
    let _ = handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
        if let Some(g) = tx
            .machine_mut()?
            .login_grants
            .iter_mut()
            .find(|g| g.id == grant)
        {
            g.uses = g.uses.saturating_add(1);
        }
        Ok(())
    });
}

/// Act on what the run browser's broker noticed (§12.7): a tab in front at an origin the item is
/// not saved for, or a filled password field that stopped being masked, suspends every grant of
/// the job and ends the run. Whether it did.
pub(super) fn settle_notices(
    core: &Core,
    handle: &Arc<VaultHandle>,
    run: &Run,
    notices: &[AgentFillNotice],
) -> bool {
    let reason = notices.iter().find_map(|n| match n {
        AgentFillNotice::OriginMismatch { .. } => Some("OTHER_ORIGIN"),
        AgentFillNotice::Unmasked { .. } => Some("UNATTENDED_FILL_UNMASKED"),
        _ => None,
    });
    let Some(reason) = reason else {
        return false;
    };
    let suspended = engine_entry(
        TOOL_GRANT,
        Outcome::Denied,
        format!(
            "GRANT_SUSPENDED ({reason}) job {:?} run {}",
            run.job_name, run.id
        ),
    );
    let job = run.job;
    let written = handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
        tx.machine_mut()?.suspend_job(job, unix_now(), reason);
        tx.append_audit(suspended.clone());
        Ok(())
    });
    if !matches!(written, Some(Ok(()))) {
        core.record(suspended);
    }
    run.end("STRIKE");
    core.notice("SUSPENDED", Some(&run.job_name), reason);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagisecure_core::model::{Field, Item, Secret};
    use kagisecure_core::vault::MachineVaultKey;
    use kagisecure_core::vault::machine::{
        ExecutablePin, GrantLimits, Job, PinnedExecutable, PresencePath, ScheduleTime,
    };
    use std::collections::BTreeMap;

    const SITE: &str = "https://example.com";

    fn login(vault: &mut Vault) -> ItemId {
        vault
            .transact(|tx| {
                let vault_id = tx.default_vault_id()?;
                let mut item = Item::new(vault_id, Category::Login, "Service account");
                item.urls = vec![SITE.to_owned()];
                item.fields.push(Field::public("username", "bot"));
                item.fields.push(Field::concealed(
                    "password",
                    Secret::from_string("not-a-real-password".to_owned()),
                ));
                item.agent_visible = true;
                let id = item.id;
                tx.add_item(item);
                Ok(id)
            })
            .expect("item")
    }

    fn grant(job: JobId, item: ItemId) -> LoginGrant {
        LoginGrant {
            id: GrantId::new(),
            job,
            item,
            fields: vec![LoginField::Username, LoginField::Password],
            origin: SITE.to_owned(),
            follow_on_origins: Vec::new(),
            one_time_codes: false,
            limits: GrantLimits::defaults(kagisecure_core::unix_now()),
            uses: 0,
            created_at: kagisecure_core::unix_now(),
            approved_at: kagisecure_core::unix_now(),
            presence: PresencePath::Confirmed,
            suspended: None,
            unknown: BTreeMap::new(),
        }
    }

    const BOTH: [AgentFillField; 2] = [AgentFillField::Username, AgentFillField::Password];

    #[test]
    fn a_standing_pass_exists_only_for_a_machine_vault_login_under_its_grant() {
        let dir = tempfile::tempdir().expect("tempdir");

        // A personal vault's login, under a grant naming it: no pass.
        let mut options = kagisecure_core::vault::CreateOptions::new().expect("options");
        options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
            kagisecure_core::crypto::kdf::MIN_M_KIB,
            kagisecure_core::crypto::kdf::MIN_T,
            1,
        )
        .expect("kdf");
        let (mut personal, _) =
            Vault::create(dir.path().join("p.kagivault"), b"pw", &options).expect("personal");
        let personal_item = login(&mut personal);
        let personal_grant = grant(JobId::new(), personal_item);
        assert!(StandingPass::issue(&personal, &personal_grant, 1, SITE, &BOTH).is_none());

        // A machine vault's login under its own grant: a pass, for exactly what it covers.
        let key = MachineVaultKey::generate().expect("key");
        let mut machine =
            Vault::create_machine(dir.path().join("m.kagivault"), &key, "Machine").expect("m");
        let item = login(&mut machine);
        let job = Job {
            id: JobId::new(),
            name: "post".to_owned(),
            root: PinnedExecutable {
                path: "/bin/sh".to_owned(),
                pin: ExecutablePin::Sha256(vec![0; 32]),
            },
            args: Vec::new(),
            working_dir: "/".to_owned(),
            schedule: vec![ScheduleTime::Daily { hour: 3, minute: 0 }],
            run_deadline_secs: 60,
            catch_up_secs: 0,
            run_browser: Some(PinnedExecutable {
                path: "/bin/sh".to_owned(),
                pin: ExecutablePin::Sha256(vec![0; 32]),
            }),
            created_at: kagisecure_core::unix_now(),
            presence: PresencePath::Confirmed,
            unknown: BTreeMap::new(),
        };
        let held = grant(job.id, item);
        {
            let (job, held) = (job.clone(), held.clone());
            machine
                .transact(|tx| {
                    let section = tx.machine_mut()?;
                    section.jobs.push(job);
                    section.login_grants.push(held);
                    Ok(())
                })
                .expect("grant");
        }
        let pass = StandingPass::issue(&machine, &held, 7, SITE, &BOTH).expect("a pass");
        assert_eq!(pass.origin(), SITE);
        assert_eq!(pass.item_id(), item.to_string());
        assert_eq!(pass.fields(), ["username", "password"]);
        assert_eq!(pass.label(), format!("grant {} run 7", held.id));

        // Not for another origin, a field it does not name, or a grant the vault does not hold.
        assert!(
            StandingPass::issue(&machine, &held, 7, "https://www.example.com", &BOTH).is_none()
        );
        assert!(
            StandingPass::issue(&machine, &held, 7, SITE, &[AgentFillField::OneTimeCode]).is_none()
        );
        let stranger = grant(job.id, item);
        assert!(StandingPass::issue(&machine, &stranger, 7, SITE, &BOTH).is_none());
        // Nor for the machine vault's grant presented against the personal vault.
        assert!(StandingPass::issue(&personal, &held, 7, SITE, &BOTH).is_none());
    }

    #[test]
    fn a_code_needs_the_switch_and_the_field() {
        let mut grant = LoginGrant {
            id: GrantId::new(),
            job: JobId::new(),
            item: ItemId::new(),
            fields: vec![LoginField::Username, LoginField::Password],
            origin: "https://example.com".to_owned(),
            follow_on_origins: vec!["https://id.example.com".to_owned()],
            one_time_codes: false,
            limits: kagisecure_core::vault::machine::GrantLimits::defaults(0),
            uses: 0,
            created_at: 0,
            approved_at: 0,
            presence: kagisecure_core::vault::machine::PresencePath::Confirmed,
            suspended: None,
            unknown: std::collections::BTreeMap::new(),
        };
        let both = [AgentFillField::Username, AgentFillField::Password];
        assert!(covers(&grant, "https://example.com", &both));
        assert!(covers(&grant, "https://id.example.com", &both));
        assert!(!covers(&grant, "https://www.example.com", &both));
        assert!(!covers(
            &grant,
            "https://example.com",
            &[AgentFillField::OneTimeCode]
        ));
        grant.fields.push(LoginField::OneTimeCode);
        assert!(!covers(
            &grant,
            "https://example.com",
            &[AgentFillField::OneTimeCode]
        ));
        grant.one_time_codes = true;
        assert!(covers(
            &grant,
            "https://example.com",
            &[AgentFillField::OneTimeCode]
        ));
    }
}
