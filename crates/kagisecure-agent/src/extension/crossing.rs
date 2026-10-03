//! The crossing: the one module that reads a secret out of an item for a browser.
//!
//! # Why this is a module of its own
//!
//! [ADR-0037](../../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md) states the
//! invariant the browser channel rests on: **every response that carries a secret comes from a
//! granted `ApprovalQueue::ask`, and every grant in the app went through the biometric gate.** Until
//! then it was a convention, and a convention is what the fill lease quietly broke: a live lease
//! returned early from the approval path and a password crossed with no fresh proof that a human
//! was there — which a browser- or OS-automation agent, producing input the browser marks
//! `isTrusted`, could exploit with no human at all.
//!
//! So the rule is now carried by the types and by where the code lives:
//!
//! * Every function here that produces a value takes an [`Approved`].
//! * An [`Approved`] can be made only by [`Approved::from_grant`], from a
//!   [`Grant`](crate::approval::Grant), and a `Grant` can be obtained only from the `Outcome` that
//!   `ApprovalQueue::ask` returns for a request somebody resolved with an allow. Neither type is
//!   `Clone`, so one grant is one crossing.
//! * [`Approved::from_grant`] refuses a grant whose scope — kind, origin, item, fields — is not a
//!   superset of what is about to cross, so "the value built" and "the value approved" are checked
//!   against each other rather than assumed to agree. The caller names the kind it expects, so a
//!   grant for an agent's fill (`ApprovalKind::AgentFill`, ADR-0036) and a grant for the human's
//!   own (`ApprovalKind::FillCredential`) can never stand in for each other.
//! * Nothing outside this file reads a secret. The parent module's source, and the agent-fill
//!   broker's beside this file, are scanned by `the_parent_module_never_reads_a_secret_itself` for
//!   every call that could (`expose_str`, `as_secret`, `FillValue::new`, `code_at`,
//!   `totp_generator`), so a second path to a value has to be written here, next to this comment,
//!   rather than slipped in elsewhere. The broker holds an [`Approved`] in each grant it issues
//!   (ADR-0036) and spends it only by calling [`filled`].
//!
//! What lives outside this file on purpose: the username. It is metadata the `match` reply already
//! hands the browser without a prompt (ADR-0030), and the username-only fill that writes it never
//! reaches a sheet.

use kagisecure_core::model::{Field, Item};
use kagisecure_extension_ipc::protocol::{FillField, FillValue, Response};

use crate::approval::{ApprovalKind, Grant};
use crate::unattended::login::StandingPass;

/// The field name a one-time-code request is approved and audited under.
pub(super) const TOTP_FIELD: &str = "one-time password";

/// The field name an agent's one-time-code request is approved and audited under
/// (`AgentFillField::OneTimeCode`, ADR-0036 §7.4): the name the agent asked for, like every other
/// agent-fill field.
const AGENT_CODE_FIELD: &str = "one_time_code";

/// A fill somebody granted, and the scope they granted it for.
///
/// Two constructors, and fields private to this module, so the parent module cannot build one
/// with a struct literal either: [`Self::from_grant`], from a person's grant, and — for a
/// machine-vault login under a standing login grant, with nobody present (ADR-0042 §12.6) —
/// [`Self::from_standing`], from a [`StandingPass`] only the unattended engine can make.
#[derive(Debug)]
pub(super) struct Approved {
    /// Which path asked for it: the human's own fill or an agent's.
    kind: ApprovalKind,
    /// The origin the human was shown — the frame's, for a cross-origin fill.
    origin: String,
    /// The item the human was shown.
    item_id: String,
    /// The field names the human was shown.
    fields: Vec<String>,
    /// Whether the scope was reviewed at a full sheet **earlier** in this unlock session, and this
    /// grant is the fresh presence proof on top of that review rather than the review itself.
    ///
    /// Recorded so the audit entry can say `FILL_CONFIRMED` rather than `FILL_APPROVED`: a reader
    /// can tell "the user read the sheet for this" from "the user read the sheet a few minutes ago
    /// and touched the sensor for this". Either way a human proved presence for *this* crossing.
    reviewed_earlier: bool,
    /// The standing login grant and run this fill is released under, when no person granted it.
    standing: Option<String>,
}

impl Approved {
    /// Turn a grant into permission for one crossing of `fields` from `item_id` at `origin`, on
    /// the path that asked for a grant of kind `expected`.
    ///
    /// `None` when the grant is for something else — another kind of request, another origin,
    /// another item, or a field set that does not cover what is asked. That is never expected:
    /// the grant is for the request this same call built a moment earlier. It is checked because
    /// "never expected" is exactly the kind of agreement this module exists to stop assuming.
    ///
    /// `expected` is the kind the calling path asked the queue for, and only the two browser
    /// kinds are crossings at all. It is an argument rather than a constant because there are two
    /// such paths now: the human's own fill (`FillCredential`) and an agent's
    /// (`AgentFill`, ADR-0036). Each grant satisfies only its own path — the human's approval of
    /// a page is not an agent's, and an agent's approval, which was never presence-only and never
    /// remembered, must not be spent on a request that would be (implementation decision 5).
    pub(super) fn from_grant(
        grant: Grant,
        expected: ApprovalKind,
        origin: &str,
        item_id: &str,
        fields: &[String],
    ) -> Option<Self> {
        let covers = matches!(
            expected,
            ApprovalKind::FillCredential | ApprovalKind::AgentFill
        ) && grant.kind() == expected
            && grant.origin() == Some(origin)
            && grant.item_id() == Some(item_id)
            && fields.iter().all(|f| grant.fill_fields().contains(f));
        covers.then(|| Self {
            kind: expected,
            origin: origin.to_owned(),
            item_id: item_id.to_owned(),
            fields: grant.fill_fields().to_vec(),
            reviewed_earlier: grant.presence_only(),
            standing: None,
        })
    }

    /// Turn a standing login grant's pass into permission for one crossing of `fields` from
    /// `item_id` at `origin` — the second constructor of ADR-0042 §12.6. The pass exists only for a
    /// Login item of a machine vault, under a grant naming exactly this origin
    /// ([`StandingPass`]), so no personal or shared item can reach here. `None` when the pass
    /// does not cover what is asked.
    pub(super) fn from_standing(
        pass: StandingPass,
        origin: &str,
        item_id: &str,
        fields: &[String],
    ) -> Option<Self> {
        let covers = pass.origin() == origin
            && pass.item_id() == item_id
            && fields.iter().all(|f| pass.fields().contains(f));
        covers.then(|| Self {
            kind: ApprovalKind::AgentFill,
            origin: origin.to_owned(),
            item_id: item_id.to_owned(),
            fields: pass.fields().to_vec(),
            reviewed_earlier: false,
            standing: Some(pass.label().to_owned()),
        })
    }

    /// The standing grant and run this fill is released under, if no person granted it.
    pub(super) fn standing(&self) -> Option<&str> {
        self.standing.as_deref()
    }

    /// The origin the human was shown.
    pub(super) fn origin(&self) -> &str {
        &self.origin
    }

    /// See the field.
    pub(super) fn reviewed_earlier(&self) -> bool {
        self.reviewed_earlier
    }

    /// Whether this approval names `item` and every one of `names`.
    fn covers(&self, item: &Item, names: &[&str]) -> bool {
        item.id.to_string() == self.item_id
            && names.iter().all(|n| self.fields.iter().any(|f| f == n))
    }
}

/// Build the `Filled` reply for an approved credential fill.
///
/// Takes the approval by value: one grant is one crossing, and a reply built from it uses it up.
/// The caller runs this inside the transaction that commits the fill's `Allowed` audit entry
/// ([ADR-0040](../../../../docs/decisions/0040-audit-before-release.md)), on the item as the file
/// holds it at that moment, so the value that leaves is the one the committed entry describes.
///
/// `None` when the approval does not cover this item and these fields, or the item has no
/// password to give — in both cases nothing crosses.
pub(super) fn filled(
    approved: Approved,
    item: &Item,
    wanted: &[FillField],
    username: Option<String>,
) -> Option<Response> {
    let names: Vec<&str> = wanted.iter().map(|f| f.as_str()).collect();
    if !approved.covers(item, &names) {
        return None;
    }
    let password = if wanted.contains(&FillField::Password) {
        Some(FillValue::new(password_of(item)?))
    } else {
        None
    };
    let username = wanted
        .contains(&FillField::Username)
        .then_some(username)
        .flatten();
    Some(Response::filled(
        item.id.to_string(),
        wanted,
        username,
        password,
    ))
}

/// Build the `Filled` reply for step one of an approved identifier-first agent fill (ADR-0036
/// §7.3): the username, and nothing else.
///
/// Borrows the approval rather than spending it. The username is metadata — the `match` reply
/// hands it to the browser without a prompt (ADR-0030) — so step one is not a crossing; the one
/// crossing the approval pays for is step two's password, through [`filled`] (ADR-0036,
/// implementation decision 4). It is built here anyway, beside the crossing it belongs to, so the
/// broker still names no reply that carries a field.
///
/// `None` when the approval does not name this item's username, or the item has none.
pub(super) fn username_only(
    approved: &Approved,
    item: &Item,
    username: Option<String>,
) -> Option<Response> {
    if approved.kind != ApprovalKind::AgentFill || !approved.covers(item, &["username"]) {
        return None;
    }
    let username = username?;
    Some(Response::filled(
        item.id.to_string(),
        &[FillField::Username],
        Some(username),
        None,
    ))
}

/// Build the `TotpCode` reply for an approved one-time-code request, at `now`.
///
/// By value and inside the committing transaction, for the reasons [`filled`] gives. The human's
/// approval names the field [`TOTP_FIELD`]; an agent's names `one_time_code`, the field it asked
/// for (ADR-0036 §7.4) — each only its own, so neither path's approval satisfies the other's.
///
/// `None` when the approval does not name this item's one-time password, or the item has no
/// working one.
pub(super) fn totp_code(approved: Approved, item: &Item, now: u64) -> Option<Response> {
    let field = if approved.kind == ApprovalKind::AgentFill {
        AGENT_CODE_FIELD
    } else {
        TOTP_FIELD
    };
    if !approved.covers(item, &[field]) {
        return None;
    }
    let generator = item.totp_field()?.totp_generator().ok()?;
    let code = generator.code_at(now).ok()?;
    Some(Response::TotpCode {
        item_id: item.id.to_string(),
        code: FillValue::new(code.expose_str()?.to_owned()),
        seconds_remaining: generator.seconds_remaining(now),
    })
}

/// Whether the item has a password a fill could write. Reads no value out.
///
/// Borrows: it runs before any approval — at the agent path's gate 4 and after its probe, and on
/// the extension's own paths — so it must not leave a copy of a password in a heap buffer nobody
/// zeroizes, which [`password_of`] would.
pub(super) fn has_password(item: &Item) -> bool {
    password_str(item).is_some()
}

/// Whether the item has a one-time password that generates. Reads no value out.
///
/// Like [`has_password`], it runs before any approval — at the agent path's gate 4 and on the
/// extension's own `totp` path — so it must not decode the seed into a buffer nobody zeroizes,
/// which building a generator would. It asks the field, which checks the URI in place
/// (`Field::has_working_totp`).
pub(super) fn has_working_totp(item: &Item) -> bool {
    item.totp_field().is_some_and(Field::has_working_totp)
}

/// The item's password, as a plain `String` at the moment it crosses.
///
/// The item's primary secret (`Item::primary_secret_field`): the field the vault designates by
/// id, the same one the app's "Copy password" and its presence prompt's "password" mean. Never a
/// field found by its label: a label can be changed in the edit sheet without a presence check,
/// so preferring "the field called *password*" let anything that drives the UI relabel a PIN or a
/// security answer and have it filled into a web page instead. A TOTP seed is never a primary
/// secret: filling an `otpauth://` URI into a password box would be both useless and a disclosure
/// of the shared seed.
///
/// A copy the caller owns, so it is made only where the value crosses ([`filled`]); anything that
/// only needs to know whether there is one asks [`password_str`].
fn password_of(item: &Item) -> Option<String> {
    password_str(item).map(str::to_owned)
}

/// The item's password as [`password_of`] chooses it, borrowed from the item's own zeroizing
/// buffer: no copy is made.
fn password_str(item: &Item) -> Option<&str> {
    item.primary_secret_field()
        .and_then(|f| f.value.as_secret())
        .and_then(|s| s.expose_str())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::approval::{ApprovalQueue, ApprovalRequest, ClientVerification, Decision};
    use kagisecure_core::model::{Category, Field, Secret, VaultId};

    const ORIGIN: &str = "https://example.com";
    const ITEM: &str = "item-1";

    /// A real grant of `kind`, for `ORIGIN`, `ITEM` and the password: asked, delivered and
    /// allowed through a queue, the only way one can be made.
    fn grant(kind: ApprovalKind) -> Grant {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || {
            asker.ask(ApprovalRequest {
                kind,
                origin: Some(ORIGIN.to_owned()),
                item_id: Some(ITEM.to_owned()),
                fill_fields: vec!["password".to_owned()],
                ..ApprovalRequest::default()
            })
        });
        let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
        assert!(queue.resolve(
            &delivered.id,
            &Decision::AllowOnce,
            ClientVerification::unchecked()
        ));
        thread.join().expect("asker").into_grant().expect("granted")
    }

    fn password() -> Vec<String> {
        vec!["password".to_owned()]
    }

    #[test]
    fn a_fill_grant_never_approves_an_agent_fill_and_vice_versa() {
        // Same origin, same item, same field: only the kind differs, so the kind is what refuses.
        let crossed = [
            (ApprovalKind::FillCredential, ApprovalKind::AgentFill),
            (ApprovalKind::AgentFill, ApprovalKind::FillCredential),
        ];
        for (granted, expected) in crossed {
            assert!(
                Approved::from_grant(grant(granted), expected, ORIGIN, ITEM, &password()).is_none(),
                "a {granted:?} grant approved a {expected:?} crossing"
            );
        }
        for kind in [ApprovalKind::FillCredential, ApprovalKind::AgentFill] {
            assert!(
                Approved::from_grant(grant(kind), kind, ORIGIN, ITEM, &password()).is_some(),
                "a {kind:?} grant must still approve its own crossing"
            );
        }
    }

    #[test]
    fn a_grant_for_an_env_request_approves_no_crossing_even_when_expected() {
        // Only the two browser kinds are crossings: a caller that names an env kind as the one it
        // expects gets nothing, whatever the grant says.
        for kind in [
            ApprovalKind::CreateEnvironment,
            ApprovalKind::AddVariables,
            ApprovalKind::WriteEnvFile,
            ApprovalKind::RunWithEnv,
        ] {
            assert!(Approved::from_grant(grant(kind), kind, ORIGIN, ITEM, &password()).is_none());
        }
    }

    fn login() -> Item {
        let mut item = Item::new(VaultId::new(), Category::Login, "Example");
        item.fields.push(Field::public("username", "alice"));
        item.fields
            .push(Field::concealed("password", Secret::new(b"pw".to_vec())));
        item
    }

    #[test]
    fn the_password_comes_from_the_password_field() {
        assert_eq!(password_of(&login()), Some("pw".to_owned()));
    }

    #[test]
    fn a_renamed_password_field_still_fills_but_a_totp_seed_never_does() {
        let mut item = Item::new(VaultId::new(), Category::Login, "R");
        item.fields.push(Field::totp(
            "one-time password",
            Secret::new(b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_vec()),
        ));
        item.fields.push(Field::concealed(
            "passphrase",
            Secret::new(b"correct horse".to_vec()),
        ));
        assert_eq!(
            password_of(&item),
            Some("correct horse".to_owned()),
            "the TOTP field must be skipped even though it comes first and is concealed"
        );
    }

    #[test]
    fn an_item_with_only_a_totp_seed_has_no_password_to_fill() {
        let mut item = Item::new(VaultId::new(), Category::Login, "T");
        item.fields.push(Field::totp(
            "one-time password",
            Secret::new(b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_vec()),
        ));
        assert_eq!(password_of(&item), None);
        assert!(!has_password(&item));
        assert!(has_working_totp(&item));
    }

    #[test]
    fn a_field_relabelled_password_is_not_the_password() {
        let mut item = login();
        item.fields
            .push(Field::concealed("PIN", Secret::new(b"4321".to_vec())));
        item.pin_primary_secret();
        // Relabel the PIN "password", rename the password, and move the PIN first.
        item.fields[2].label = "password".to_owned();
        item.fields[1].label = "old".to_owned();
        item.fields.swap(1, 2);
        assert_eq!(password_of(&item), Some("pw".to_owned()));
    }

    #[test]
    fn has_password_answers_what_the_crossing_would_find_without_copying_it() {
        // The borrow and the copy choose the same field, so gate 4 cannot say "there is one" for
        // an item the crossing would then find empty, or the other way round.
        let mut empty = Item::new(VaultId::new(), Category::Login, "E");
        empty
            .fields
            .push(Field::concealed("password", Secret::new(Vec::new())));
        let mut not_text = Item::new(VaultId::new(), Category::Login, "B");
        not_text
            .fields
            .push(Field::concealed("password", Secret::new(vec![0xff, 0xfe])));
        for item in [login(), empty, not_text] {
            assert_eq!(has_password(&item), password_of(&item).is_some());
            assert_eq!(
                password_str(&item).map(str::as_ptr),
                item.primary_secret_field()
                    .and_then(|f| f.value.as_secret())
                    .map(|s| s.expose().as_ptr())
                    .filter(|_| has_password(&item)),
                "the borrow points into the item's own buffer"
            );
        }
    }

    #[test]
    fn an_empty_password_is_not_a_password() {
        let mut item = Item::new(VaultId::new(), Category::Login, "E");
        item.fields
            .push(Field::concealed("password", Secret::new(Vec::new())));
        assert_eq!(password_of(&item), None);
    }

    /// The parent module is where requests are parsed, origins are matched and approvals are
    /// asked for — everything *around* a crossing. If it ever reads a secret itself, the rule that
    /// every value goes through an [`Approved`] has a hole in it, whatever the types say.
    ///
    /// The agent-fill broker (`agent_fill.rs`, ADR-0036) is the same kind of module and is held to
    /// the same rule, and one more: it holds an [`Approved`] inside each grant, but it never opens
    /// one and never builds a reply that carries a value — the `Filled` it hands the extension is
    /// the one [`filled`] builds here. So it may not name `Response::filled`, `Response::Filled`
    /// or `TotpCode` at all.
    ///
    /// A source scan is a blunt instrument, and deliberately so: it cannot be satisfied by a
    /// clever call chain, only by moving the code here, where the module documentation says what
    /// the obligation is.
    /// The second constructor (ADR-0042 §12.6) takes a [`StandingPass`], and only the unattended
    /// engine makes one: a pass issued anywhere else — the ordinary socket, the extension
    /// listener — would be a fill with nobody's approval for an item that is not a machine-vault
    /// login.
    #[test]
    fn only_the_unattended_engine_issues_a_standing_pass() {
        for (file, text) in [
            ("extension.rs", include_str!("../extension.rs")),
            ("extension/agent_fill.rs", include_str!("agent_fill.rs")),
            ("service.rs", include_str!("../service.rs")),
            ("agent.rs", include_str!("../agent.rs")),
            (
                "unattended/service.rs",
                include_str!("../unattended/service.rs"),
            ),
            ("unattended/mod.rs", include_str!("../unattended/mod.rs")),
        ] {
            assert!(
                !text.contains("StandingPass::issue"),
                "{file} issues a standing pass: only unattended/login.rs may"
            );
        }
        let crossing = include_str!("crossing.rs");
        assert_eq!(
            crossing
                .matches(["standing", ": Some("].concat().as_str())
                .count(),
            1,
            "one constructor sets `standing`: from_standing"
        );
    }

    #[test]
    fn the_parent_module_never_reads_a_secret_itself() {
        const SECRET_READS: [&str; 7] = [
            "expose_str",
            "as_secret",
            "FillValue::new",
            "FillValue(",
            "code_at",
            "totp_generator",
            "password_of",
        ];
        let parent = include_str!("../extension.rs");
        for needle in SECRET_READS {
            assert!(
                !parent.contains(needle),
                "extension.rs mentions `{needle}`: secret reads belong in extension/crossing.rs, \
                 behind an `Approved`"
            );
        }
        for (file, broker) in [
            ("agent_fill.rs", include_str!("agent_fill.rs")),
            ("agent_fill/limits.rs", include_str!("agent_fill/limits.rs")),
            // The unattended engine's half of a sign-in (ADR-0042 §12.6) makes the pass and hands
            // it to the broker; it is held to the broker's rule.
            (
                "unattended/login.rs",
                include_str!("../unattended/login.rs"),
            ),
            (
                "unattended/browser.rs",
                include_str!("../unattended/browser.rs"),
            ),
        ] {
            for needle in SECRET_READS.into_iter().chain([
                "Response::filled",
                "Filled {",
                "TotpCode",
                "FillValue",
            ]) {
                assert!(
                    !broker.contains(needle),
                    "{file} mentions `{needle}`: the broker may hold an `Approved` but builds no \
                     value itself; the reply that carries one comes from extension/crossing.rs"
                );
            }
        }
    }
}
