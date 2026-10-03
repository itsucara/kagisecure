//! ADR-0038: every value the app releases comes from a release a granted presence check produced.
//!
//! Driven entirely through the public FFI surface the app uses, with a Rust stand-in for the
//! Swift `PresenceGate` and a canary seeded as the password, the TOTP seed's account and the
//! notes. The canary must reach a caller only through a release a `Confirmed` produced — never
//! through an error, a `Debug` rendering, a view, a search or a refused release.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::channel::oneshot;
use kagisecure_ffi::{
    Clock, FfiError, FieldDraft, FieldKind, ItemDraft, ItemFilter, ItemSort, ItemView,
    MasterPasswordCheck, PresenceGate, PresenceOutcome, ReleasePurpose, VaultSession,
};

/// Seeded as the password. If these bytes reach anything but a granted release, ADR-0038 failed.
const CANARY: &str = "K4G1-R3L34S3-C4N4RY-5e1f0c2d9a8b";
/// Seeded as the notes.
const NOTE_CANARY: &str = "K4G1-N0T3S-C4N4RY-77aa01ff3c9e";
/// A TOTP seed. The seed is secret; a derived code is what a TOTP release hands out.
const TOTP_URI: &str = "otpauth://totp/ACME:ada@example.com\
    ?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30";
const MASTER: &str = "pw";

// MARK: - Gates

/// Answers from a script, and remembers every prompt it was shown.
#[derive(Default)]
struct ScriptedGate {
    answers: Mutex<VecDeque<PresenceOutcome>>,
    reasons: Mutex<Vec<String>>,
}

impl ScriptedGate {
    fn answering(answers: &[PresenceOutcome]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().copied().collect()),
            reasons: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.reasons.lock().unwrap().len()
    }

    fn reasons(&self) -> Vec<String> {
        self.reasons.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PresenceGate for ScriptedGate {
    async fn confirm(&self, reason: String) -> PresenceOutcome {
        self.reasons.lock().unwrap().push(reason);
        // An exhausted script is a person who never touched the sensor.
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(PresenceOutcome::Cancelled)
    }
}

/// Holds its prompt open until the test answers it, and says when it has been asked.
struct HeldGate {
    asked: Mutex<std::sync::mpsc::Sender<String>>,
    answer: Mutex<Option<oneshot::Receiver<PresenceOutcome>>>,
    calls: AtomicUsize,
}

impl HeldGate {
    fn new() -> (
        Arc<Self>,
        std::sync::mpsc::Receiver<String>,
        oneshot::Sender<PresenceOutcome>,
    ) {
        let (asked_tx, asked_rx) = std::sync::mpsc::channel();
        let (answer_tx, answer_rx) = oneshot::channel();
        (
            Arc::new(Self {
                asked: Mutex::new(asked_tx),
                answer: Mutex::new(Some(answer_rx)),
                calls: AtomicUsize::new(0),
            }),
            asked_rx,
            answer_tx,
        )
    }
}

#[async_trait::async_trait]
impl PresenceGate for HeldGate {
    async fn confirm(&self, reason: String) -> PresenceOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.asked.lock().unwrap().send(reason);
        let answer = self.answer.lock().unwrap().take();
        match answer {
            // A dropped sender is a prompt dismissed by the system: never a yes.
            Some(rx) => rx.await.unwrap_or(PresenceOutcome::Cancelled),
            None => PresenceOutcome::Busy,
        }
    }
}

/// A clock the test moves by hand.
struct ManualClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        })
    }

    fn advance(&self, by: Duration) {
        *self.offset.lock().unwrap() += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + *self.offset.lock().unwrap()
    }
}

// MARK: - Fixture

struct Fixture {
    _dir: tempfile::TempDir,
    dir_path: PathBuf,
    session: Arc<VaultSession>,
    item: String,
    password: String,
    totp: String,
    username: String,
    other_item: String,
    other_password: String,
}

/// A vault with a Login ("GitHub") whose password is the canary, whose one-time password is set
/// up and whose notes hold the note canary, and a second Login with its own password.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();
    let path = dir.path().join("t.kagivault").display().to_string();
    let session = VaultSession::create(
        path,
        MASTER.to_owned(),
        "Personal".to_owned(),
        Some(64),
        Some(1),
    )
    .expect("create");

    let (item, password, totp, username) = seed_login(&session, "GitHub", CANARY, true);
    let (other_item, other_password, _, _) =
        seed_login(&session, "Other", "a-different-password", false);
    Fixture {
        _dir: dir,
        dir_path,
        session,
        item,
        password,
        totp,
        username,
        other_item,
        other_password,
    }
}

/// Create a Login titled `title` with `password`, a TOTP and (if `notes`) the note canary.
/// Returns (item, password field, totp field, username field).
fn seed_login(
    session: &VaultSession,
    title: &str,
    password: &str,
    notes: bool,
) -> (String, String, String, String) {
    let created = session
        .create_item(None, "login".to_owned(), title.to_owned())
        .expect("item");
    let fields = created
        .fields
        .iter()
        .map(|f| FieldDraft {
            id: Some(f.id.clone()),
            label: f.label.clone(),
            kind: f.kind,
            concealed: f.concealed,
            value: Some(match (f.kind, f.label.as_str()) {
                (FieldKind::Totp, _) => TOTP_URI.to_owned(),
                (_, "password") => password.to_owned(),
                (_, "username") => "ada".to_owned(),
                _ => String::new(),
            }),
            section: f.section.clone(),
            agent_visible: f.agent_visible,
        })
        .collect();
    let saved = session
        .save_item(ItemDraft {
            id: created.id.clone(),
            category: created.category.clone(),
            title: created.title.clone(),
            fields,
            tags: vec!["work".to_owned()],
            urls: vec!["https://github.com".to_owned()],
            notes: notes.then(|| format!("recovery codes: {NOTE_CANARY}")),
            revision: created.revision.clone(),
        })
        .expect("save");
    let id_of = |pred: &dyn Fn(&kagisecure_ffi::FieldView) -> bool| {
        saved
            .fields
            .iter()
            .find(|f| pred(f))
            .expect("field")
            .id
            .clone()
    };
    (
        saved.id.clone(),
        id_of(&|f| f.label == "password"),
        id_of(&|f| f.kind == FieldKind::Totp),
        id_of(&|f| f.label == "username"),
    )
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

/// Run `f` on another thread and fail the test if it does not finish within `limit` — the
/// deadlock detector.
fn within<T: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("{what} did not finish within {limit:?}: a deadlock"))
}

/// One audit row as the assertions read it: (tool, outcome, detail, variables, item).
type Row = (String, String, Option<String>, Vec<String>, Option<String>);

/// The newest `n` audit rows.
fn newest(session: &VaultSession, n: u32) -> Vec<Row> {
    session
        .audit_page(n, 0)
        .into_iter()
        .map(|r| (r.tool, r.outcome, r.detail, r.variables, r.item_id))
        .collect()
}

/// Assert `haystack` holds neither canary.
fn assert_clean(what: &str, haystack: &str) {
    assert!(
        !haystack.contains(CANARY),
        "{what} leaked the canary: {haystack}"
    );
    assert!(
        !haystack.contains(NOTE_CANARY),
        "{what} leaked the note canary: {haystack}"
    );
}

/// Assert an error carries no canary in its message or its `Debug`.
fn assert_clean_error(what: &str, e: &FfiError) {
    assert_clean(what, &e.to_string());
    assert_clean(what, &format!("{e:?}"));
}

// MARK: - No gate: nothing is released

#[test]
fn with_no_gate_installed_nothing_is_released_by_any_release_call() {
    let fx = fixture();
    let s = &fx.session;

    let e = block_on(s.release_field(fx.item.clone(), fx.password.clone(), ReleasePurpose::Reveal))
        .expect_err("no gate, no field");
    assert!(matches!(e, FfiError::NoPresenceGate), "{e:?}");
    assert_clean_error("release_field", &e);

    let e = block_on(s.release_totp(fx.item.clone(), None, ReleasePurpose::Reveal))
        .expect_err("no gate, no code");
    assert!(matches!(e, FfiError::NoPresenceGate), "{e:?}");

    let e = block_on(s.release_notes(fx.item.clone(), ReleasePurpose::Reveal))
        .expect_err("no gate, no notes");
    assert!(matches!(e, FfiError::NoPresenceGate), "{e:?}");
    assert_clean_error("release_notes", &e);

    // The refusal is on record as the check being unavailable: the first one in full, the two
    // after it counted within the minute (`refusals_are_written_once_a_minute_per_reason…`).
    let row = &newest(s, 1)[0];
    assert_eq!(
        (row.0.as_str(), row.1.as_str(), row.2.as_deref()),
        ("reveal_field", "denied", Some("PRESENCE_UNAVAILABLE"))
    );
    assert_eq!(row.4.as_deref(), Some(fx.item.as_str()));
    let path = fx.dir_path.join("t.kagivault").display().to_string();
    s.lock();
    let reopened = VaultSession::unlock_with_password(path, MASTER.to_owned()).expect("reopen");
    let row = &newest(&reopened, 1)[0];
    assert_eq!(
        (row.0.as_str(), row.1.as_str(), row.2.as_deref()),
        ("release", "denied", Some("PRESENCE_UNAVAILABLE_REPEATED:2")),
        "two tools, one item: the count keeps what they share"
    );
    assert_eq!(row.4.as_deref(), Some(fx.item.as_str()));
}

#[test]
fn a_gate_can_be_installed_once_and_never_swapped() {
    let fx = fixture();
    let first = ScriptedGate::answering(&[PresenceOutcome::Cancelled]);
    let second = ScriptedGate::answering(&[PresenceOutcome::Confirmed]);
    fx.session
        .set_presence_gate(first.clone())
        .expect("first install");
    assert!(matches!(
        fx.session.set_presence_gate(second.clone()),
        Err(FfiError::Invalid { .. })
    ));

    // The first gate is the one asked; the always-yes one that tried to replace it is not.
    let e = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Copy,
    ))
    .expect_err("the first gate said no");
    assert!(matches!(e, FfiError::PresenceCancelled));
    assert_eq!(first.calls(), 1);
    assert_eq!(second.calls(), 0);
}

// MARK: - Refusals leak nothing

#[test]
fn a_cancelled_unavailable_or_busy_answer_releases_nothing_and_says_why() {
    for (answer, detail) in [
        (PresenceOutcome::Cancelled, "PRESENCE_CANCELLED"),
        (PresenceOutcome::Unavailable, "PRESENCE_UNAVAILABLE"),
        (PresenceOutcome::Busy, "PRESENCE_BUSY"),
    ] {
        let fx = fixture();
        let gate = ScriptedGate::answering(&[answer, answer, answer]);
        fx.session.set_presence_gate(gate.clone()).expect("gate");

        let field = block_on(fx.session.release_field(
            fx.item.clone(),
            fx.password.clone(),
            ReleasePurpose::Reveal,
        ));
        let notes = block_on(
            fx.session
                .release_notes(fx.item.clone(), ReleasePurpose::Reveal),
        );
        let totp = block_on(fx.session.release_totp(
            fx.item.clone(),
            Some(fx.totp.clone()),
            ReleasePurpose::Copy,
        ));
        for (what, e) in [
            ("field", field.expect_err("refused")),
            ("notes", notes.expect_err("refused")),
            ("totp", totp.expect_err("refused")),
        ] {
            match answer {
                PresenceOutcome::Cancelled => assert!(matches!(e, FfiError::PresenceCancelled)),
                PresenceOutcome::Unavailable => {
                    assert!(matches!(e, FfiError::PresenceUnavailable));
                }
                _ => assert!(matches!(e, FfiError::PresenceBusy)),
            }
            assert_clean_error(what, &e);
        }
        assert_eq!(gate.calls(), 3, "one prompt per refused release");

        // The first refusal is written in full; the two after it, within the same minute, are
        // counted and reported together at the lock.
        let row = &newest(&fx.session, 1)[0];
        assert_eq!(
            (row.0.as_str(), row.1.as_str(), row.2.as_deref()),
            ("reveal_field", "denied", Some(detail))
        );
        assert_eq!(
            row.3,
            vec!["password".to_owned()],
            "the label, never the value"
        );
        let path = fx.dir_path.join("t.kagivault").display().to_string();
        fx.session.lock();
        let reopened = VaultSession::unlock_with_password(path, MASTER.to_owned()).expect("reopen");
        let row = &newest(&reopened, 1)[0];
        assert_eq!(
            row.2.as_deref(),
            Some(format!("{detail}_REPEATED:2").as_str())
        );
        for row in newest(&reopened, 50) {
            assert_clean("an audit row", &format!("{row:?}"));
        }
    }
}

#[test]
fn nothing_the_app_can_see_without_a_release_carries_a_secret() {
    let fx = fixture();
    let view = fx.session.item(fx.item.clone()).expect("item");
    assert!(view.has_notes, "the view says there is a note");
    assert_clean("ItemView's Debug", &format!("{view:?}"));
    let listed: Vec<ItemView> = fx
        .session
        .list_items(ItemFilter::All, None, ItemSort::Title);
    assert_clean("list_items", &format!("{listed:?}"));

    // A search over note text finds nothing: a search would otherwise be an oracle a UI-driving
    // process could query one guess at a time with no prompt ever shown.
    assert!(
        fx.session
            .list_items(
                ItemFilter::All,
                Some(NOTE_CANARY.to_owned()),
                ItemSort::Title
            )
            .is_empty()
    );
    assert!(
        fx.session
            .list_items(
                ItemFilter::All,
                Some("recovery codes".to_owned()),
                ItemSort::Title
            )
            .is_empty()
    );
    assert_eq!(
        fx.session
            .list_items(ItemFilter::All, Some("github".to_owned()), ItemSort::Title)
            .len(),
        2,
        "the URL both logins share still matches, so the empty results above are not vacuous"
    );
}

// MARK: - One touch, one field

#[test]
fn every_release_asks_exactly_once_and_is_bound_to_its_own_field() {
    let fx = fixture();
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed; 8]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");

    let shown = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Reveal,
    ))
    .expect("granted");
    assert_eq!(gate.calls(), 1);
    // Showing it again, and copying the shown value, need no new touch (user decision 1)…
    assert_eq!(shown.value().expect("value"), CANARY);
    assert_eq!(shown.value().expect("value again"), CANARY);
    assert_eq!(
        shown.copy_shown_value().expect("copy of the shown value"),
        CANARY
    );
    assert_eq!(gate.calls(), 1, "no second prompt for the same shown field");
    // …and the release is bound to that field, by id.
    assert_eq!(shown.field_id(), fx.password);
    assert_eq!(shown.item_id(), fx.item);
    assert_clean("a release's Debug", &format!("{shown:?}"));

    // A different field of the same item is another touch.
    let code = block_on(
        fx.session
            .release_totp(fx.item.clone(), None, ReleasePurpose::Reveal),
    )
    .expect("granted");
    assert_eq!(gate.calls(), 2);
    assert_eq!(code.field_id(), fx.totp);
    assert_eq!(code.code_at(1_699_999_980).expect("code").code.len(), 6);

    // The same field of a different item is another touch too, and gets that item's value.
    let other = block_on(fx.session.release_field(
        fx.other_item.clone(),
        fx.other_password.clone(),
        ReleasePurpose::Copy,
    ))
    .expect("granted");
    assert_eq!(gate.calls(), 3);
    assert_eq!(other.value().expect("value"), "a-different-password");

    // A copy is one use: a second copy is a second touch, not a free re-read.
    assert!(matches!(other.value(), Err(FfiError::ReleaseEnded { .. })));
    assert!(!other.is_live());
    // And a copy's release was never shown, so it cannot claim the shown-value exemption.
    assert!(matches!(
        other.copy_shown_value(),
        Err(FfiError::Invalid { .. })
    ));

    let rows = newest(&fx.session, 4);
    assert_eq!(
        rows.iter()
            .map(|r| (r.0.as_str(), r.2.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("copy_field", Some("PRESENCE_CONFIRMED")),
            ("totp_show", Some("PRESENCE_CONFIRMED")),
            ("copy_field", Some("SHOWN_EARLIER")),
            ("reveal_field", Some("PRESENCE_CONFIRMED")),
        ]
    );
    assert!(rows.iter().all(|r| r.1 == "allowed"));
    assert_eq!(rows[0].4.as_deref(), Some(fx.other_item.as_str()));
    assert_eq!(rows[1].3, vec!["one-time password".to_owned()]);
}

/// A release names its item and field by id and nothing else. A title, an id prefix, an id in
/// another spelling or a field's label is answered exactly like an id that names nothing — the
/// same error, no prompt, no audit entry — whether or not a trashed item shares the title, so the
/// lookup is no oracle for what is in the trash. Every entry a release writes names the item.
#[test]
fn a_release_names_its_item_and_field_by_id_and_nothing_else() {
    let fx = fixture();
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed; 4]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");
    // A well-formed id no item has: the fixture's own, with its first digit changed.
    let absent_item = format!(
        "{}{}",
        if fx.item.starts_with('0') { '1' } else { '0' },
        &fx.item[1..]
    );

    // (what, item reference, field reference)
    let references = |fx: &Fixture| {
        vec![
            ("title", "GitHub".to_owned(), fx.password.clone()),
            ("id prefix", fx.item[..8].to_owned(), fx.password.clone()),
            ("upper-case id", fx.item.to_uppercase(), fx.password.clone()),
            ("braced id", format!("{{{}}}", fx.item), fx.password.clone()),
        ]
    };
    let reply = |item: String, field: String| {
        let field_reply = block_on(fx.session.release_field(
            item.clone(),
            field,
            ReleasePurpose::Copy,
        ))
        .expect_err("not an id");
        let totp_reply = block_on(fx.session.release_totp(
            item.clone(),
            None,
            ReleasePurpose::Copy,
        ))
        .expect_err("not an id");
        let notes_reply = block_on(fx.session.release_notes(item, ReleasePurpose::Reveal))
            .expect_err("not an id");
        [field_reply, totp_reply, notes_reply]
    };
    let normalised = |errors: [FfiError; 3], reference: &str| -> Vec<String> {
        errors
            .iter()
            .map(|e| {
                assert!(matches!(e, FfiError::NotPresent { .. }), "{e:?}");
                format!("{e:?}").replace(reference, "<ref>")
            })
            .collect()
    };
    let audit_before = fx.session.audit_page(1_000, 0).len();

    let absent = normalised(
        reply(absent_item.clone(), fx.password.clone()),
        &absent_item,
    );
    let mut alone = Vec::new();
    for (what, item, field) in references(&fx) {
        let got = normalised(reply(item.clone(), field), &item);
        assert_eq!(
            got, absent,
            "a release by {what} is answered like a missing item"
        );
        alone.push(got);
    }

    // A trashed item with the same title — what used to turn "not found" into "ambiguous".
    let namesake = fx
        .session
        .create_item(None, "login".to_owned(), "GitHub".to_owned())
        .expect("namesake");
    fx.session
        .set_trashed(namesake.id.clone(), true)
        .expect("trashed");
    let beside: Vec<_> = references(&fx)
        .into_iter()
        .map(|(_, item, field)| normalised(reply(item.clone(), field), &item))
        .collect();
    assert_eq!(
        alone, beside,
        "a trashed namesake changes nothing a caller can observe"
    );

    // A field named by its label rather than its id is no field.
    let by_label = block_on(fx.session.release_field(
        fx.item.clone(),
        "password".to_owned(),
        ReleasePurpose::Copy,
    ))
    .expect_err("a label is not a field id");
    assert!(
        matches!(&by_label, FfiError::NotPresent { what, .. } if what == "field"),
        "{by_label:?}"
    );

    assert_eq!(
        gate.calls(),
        0,
        "nobody is asked about something that is not an id"
    );
    assert_eq!(
        fx.session.audit_page(1_000, 0).len(),
        audit_before,
        "nothing is recorded for a release that named no item"
    );

    // By id, a release goes ahead, and its entry names the item.
    let copy = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Copy,
    ))
    .expect("granted");
    assert_eq!(copy.value().expect("value"), CANARY);
    assert_eq!(
        newest(&fx.session, 1)[0].4.as_deref(),
        Some(fx.item.as_str())
    );
}

#[test]
fn quick_access_edit_and_notes_are_audited_under_their_own_names() {
    let fx = fixture();
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed; 5]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");

    let qa = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::QuickAccessCopy,
    ))
    .expect("granted");
    assert_eq!(qa.value().expect("value"), CANARY);
    let edit = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.totp.clone(),
        ReleasePurpose::EditReveal,
    ))
    .expect("granted");
    assert!(edit.value().expect("the seed").starts_with("otpauth://"));
    let notes = block_on(
        fx.session
            .release_notes(fx.item.clone(), ReleasePurpose::Reveal),
    )
    .expect("granted");
    assert!(notes.text().expect("notes").contains(NOTE_CANARY));
    assert!(notes.copy_shown_text().expect("copy").contains(NOTE_CANARY));
    let qa_code = block_on(fx.session.release_totp(
        fx.item.clone(),
        None,
        ReleasePurpose::QuickAccessCopy,
    ))
    .expect("granted");
    qa_code.code_at(0).expect("code");
    let totp_copy = block_on(
        fx.session
            .release_totp(fx.item.clone(), None, ReleasePurpose::Copy),
    )
    .expect("granted");
    totp_copy.code_at(0).expect("code");
    assert_eq!(gate.calls(), 5);

    let rows = newest(&fx.session, 6);
    assert_eq!(
        rows.iter()
            .map(|r| (r.0.as_str(), r.2.as_deref(), r.3.clone()))
            .collect::<Vec<_>>(),
        [
            (
                "totp_copy",
                Some("PRESENCE_CONFIRMED"),
                vec!["one-time password".to_owned()]
            ),
            (
                "quick_access_copy",
                Some("PRESENCE_CONFIRMED"),
                vec!["one-time password".to_owned()]
            ),
            (
                "copy_field",
                Some("SHOWN_EARLIER"),
                vec!["notes".to_owned()]
            ),
            (
                "notes_show",
                Some("PRESENCE_CONFIRMED"),
                vec!["notes".to_owned()]
            ),
            (
                "edit_reveal",
                Some("PRESENCE_CONFIRMED"),
                vec!["one-time password".to_owned()]
            ),
            (
                "quick_access_copy",
                Some("PRESENCE_CONFIRMED"),
                vec!["password".to_owned()]
            ),
        ]
    );
    assert!(rows.iter().all(|r| r.1 == "allowed"));
    for row in fx.session.audit_page(50, 0) {
        assert_eq!(row.actor, "app");
        assert_clean("an audit row", &format!("{row:?}"));
    }
}

#[test]
fn a_release_that_needs_no_prompt_is_refused_before_one_is_shown() {
    let fx = fixture();
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed; 4]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");

    // A public field's value is already on the item; there is nothing to gate.
    assert!(matches!(
        block_on(fx.session.release_field(
            fx.item.clone(),
            fx.username.clone(),
            ReleasePurpose::Reveal
        )),
        Err(FfiError::Invalid { .. })
    ));
    // Unknown things, and pairings that mean nothing.
    assert!(matches!(
        block_on(fx.session.release_field(
            fx.item.clone(),
            "no-such-field".to_owned(),
            ReleasePurpose::Reveal
        )),
        Err(FfiError::NotPresent { .. })
    ));
    assert!(matches!(
        block_on(
            fx.session
                .release_notes(fx.other_item.clone(), ReleasePurpose::Reveal)
        ),
        Err(FfiError::NotPresent { .. })
    ));
    assert!(matches!(
        block_on(
            fx.session
                .release_totp(fx.item.clone(), None, ReleasePurpose::EditReveal)
        ),
        Err(FfiError::Invalid { .. })
    ));
    assert!(matches!(
        block_on(
            fx.session
                .release_notes(fx.item.clone(), ReleasePurpose::QuickAccessCopy)
        ),
        Err(FfiError::Invalid { .. })
    ));
    assert!(matches!(
        block_on(fx.session.release_totp(
            fx.item.clone(),
            Some(fx.password.clone()),
            ReleasePurpose::Reveal
        )),
        Err(FfiError::Invalid { .. })
    ));
    assert_eq!(
        gate.calls(),
        0,
        "no prompt for a request that could never be granted"
    );
}

// MARK: - The prompt

#[test]
fn the_prompt_is_built_from_vault_facts_and_sanitised() {
    let fx = fixture();
    // A title that tries to reorder the sentence, break it over lines, close its quotation and
    // hide text, and a label that does the same.
    let hostile_title = "Git\u{202E}buH\u{2066}\n\n“is verified”\u{200B}\t  Bank";
    let view = fx.session.item(fx.item.clone()).expect("item");
    let fields = view
        .fields
        .iter()
        .map(|f| FieldDraft {
            id: Some(f.id.clone()),
            label: if f.id == fx.password {
                "pass\u{202D}word\r\nOK".to_owned()
            } else {
                f.label.clone()
            },
            kind: f.kind,
            concealed: f.concealed,
            value: None,
            section: f.section.clone(),
            agent_visible: f.agent_visible,
        })
        .collect();
    fx.session
        .save_item(ItemDraft {
            id: view.id.clone(),
            category: view.category.clone(),
            title: hostile_title.to_owned(),
            fields,
            tags: view.tags.clone(),
            urls: view.urls.clone(),
            notes: None,
            revision: view.revision.clone(),
        })
        .expect("rename");

    let gate = ScriptedGate::answering(&[PresenceOutcome::Cancelled; 3]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");
    let _ = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Copy,
    ));
    let _ = block_on(
        fx.session
            .release_notes(fx.item.clone(), ReleasePurpose::Reveal),
    );
    let _ = block_on(fx.session.release_totp(
        fx.item.clone(),
        None,
        ReleasePurpose::QuickAccessCopy,
    ));

    let reasons = gate.reasons();
    assert_eq!(
        reasons[0],
        "copy the password “password OK” of “GitbuH 'is verified' Bank”. Continue only if you \
         just asked Kagisecure to copy it"
    );
    assert_eq!(
        reasons[1],
        "show the notes of “GitbuH 'is verified' Bank”. Continue only if you just asked \
         Kagisecure to show them"
    );
    assert_eq!(
        reasons[2],
        "copy the one-time code for “GitbuH 'is verified' Bank” from Quick Access. Continue \
         only if you just asked Kagisecure to copy it"
    );
    for reason in &reasons {
        assert!(!reason.chars().any(|c| c.is_control()), "{reason:?}");
        assert!(
            !reason
                .chars()
                .any(|c| matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')),
            "{reason:?}"
        );
        // Vault facts only: never the value itself.
        assert_clean("a prompt", reason);
    }
}

// MARK: - What a field is, as opposed to what it is called

/// Save `view` with `edit` applied to its field drafts (every value kept unless `edit` sets one).
fn resave(
    session: &VaultSession,
    view: &ItemView,
    edit: impl FnOnce(&mut Vec<FieldDraft>),
) -> Result<ItemView, FfiError> {
    let mut fields: Vec<FieldDraft> = view
        .fields
        .iter()
        .map(|f| FieldDraft {
            id: Some(f.id.clone()),
            label: f.label.clone(),
            kind: f.kind,
            concealed: f.concealed,
            value: if f.concealed { None } else { f.value.clone() },
            section: f.section.clone(),
            agent_visible: f.agent_visible,
        })
        .collect();
    edit(&mut fields);
    session.save_item(ItemDraft {
        id: view.id.clone(),
        category: view.category.clone(),
        title: view.title.clone(),
        fields,
        tags: view.tags.clone(),
        urls: view.urls.clone(),
        notes: None,
        revision: view.revision.clone(),
    })
}

/// The list's "•••• 1234" comes from the card-number field by kind. Relabelling the PIN
/// "number" — no presence check needed — must not put the PIN's digits under the title, and
/// neither may changing its kind without its value.
#[test]
fn a_card_subtitle_is_the_card_numbers_and_a_relabelled_pin_never_shows() {
    let fx = fixture();
    let card = fx
        .session
        .create_item(None, "credit-card".to_owned(), "Visa".to_owned())
        .expect("card");
    let card = resave(&fx.session, &card, |fields| {
        for f in fields.iter_mut() {
            f.value = Some(match f.label.as_str() {
                "number" => "4111 1111 1111 1234".to_owned(),
                "PIN" => "9876".to_owned(),
                "CVV" => "321".to_owned(),
                _ => String::new(),
            });
        }
    })
    .expect("filled in");
    assert_eq!(card.subtitle.as_deref(), Some("•••• 1234"));
    let number = card.fields.iter().find(|f| f.label == "number").unwrap();
    assert_eq!(number.kind, FieldKind::CreditCardNumber);
    assert_eq!(
        card.primary_secret_field_id.as_deref(),
        Some(number.id.as_str())
    );

    // The PIN takes the number's label, and the number gets another one.
    let relabelled = resave(&fx.session, &card, |fields| {
        for f in fields.iter_mut() {
            match f.label.as_str() {
                "PIN" => f.label = "number".to_owned(),
                "number" => f.label = "card".to_owned(),
                _ => {}
            }
        }
    })
    .expect("a relabel needs no presence");
    assert_eq!(
        relabelled.subtitle.as_deref(),
        Some("•••• 1234"),
        "the subtitle follows the card number's kind, not the label \"number\""
    );

    // Giving the PIN the card number's kind, without its value, is refused.
    let pin_id = card
        .fields
        .iter()
        .find(|f| f.label == "PIN")
        .unwrap()
        .id
        .clone();
    let refused = resave(&fx.session, &relabelled, |fields| {
        let pin = fields
            .iter_mut()
            .find(|f| f.id.as_deref() == Some(pin_id.as_str()));
        pin.unwrap().kind = FieldKind::CreditCardNumber;
    })
    .expect_err("a stored secret keeps its kind unless its value comes with the change");
    assert!(matches!(refused, FfiError::Invalid { .. }), "{refused:?}");
    let after = fx.session.item(card.id.clone()).expect("item");
    assert_eq!(after.subtitle.as_deref(), Some("•••• 1234"));

    // A card whose number is a plain concealed field shows no digits at all, whatever its label.
    let legacy = resave(&fx.session, &after, |fields| {
        fields.retain(|f| f.kind != FieldKind::CreditCardNumber);
        fields.push(FieldDraft {
            id: None,
            label: "number".to_owned(),
            kind: FieldKind::Concealed,
            concealed: true,
            value: Some("5500 0000 0000 0004".to_owned()),
            section: None,
            agent_visible: false,
        });
    })
    .expect("saved");
    assert_eq!(legacy.subtitle, None);
}

/// "The password" is the field the vault designates by id: relabelling another concealed field
/// "password" and moving it first changes neither which field the app is told to copy nor what
/// the presence prompt calls each one. The username is a real username field, never the subtitle.
#[test]
fn the_primary_secret_and_the_prompts_noun_survive_a_relabel_and_a_reorder() {
    let fx = fixture();
    let view = fx.session.item(fx.item.clone()).expect("item");
    assert_eq!(
        view.primary_secret_field_id.as_deref(),
        Some(fx.password.as_str())
    );
    assert_eq!(view.username.as_deref(), Some("ada"));

    // A PIN, then relabelled "password", moved first, and the real password renamed.
    let with_pin = resave(&fx.session, &view, |fields| {
        fields.push(FieldDraft {
            id: None,
            label: "PIN".to_owned(),
            kind: FieldKind::Concealed,
            concealed: true,
            value: Some("4321".to_owned()),
            section: None,
            agent_visible: false,
        });
    })
    .expect("a PIN");
    let pin = with_pin
        .fields
        .iter()
        .find(|f| f.label == "PIN")
        .unwrap()
        .id
        .clone();
    let password = fx.password.clone();
    let hostile = resave(&fx.session, &with_pin, |fields| {
        for f in fields.iter_mut() {
            if f.id.as_deref() == Some(pin.as_str()) {
                f.label = "password".to_owned();
            } else if f.id.as_deref() == Some(password.as_str()) {
                f.label = "old".to_owned();
            }
        }
        let at = fields
            .iter()
            .position(|f| f.id.as_deref() == Some(pin.as_str()))
            .unwrap();
        let moved = fields.remove(at);
        fields.insert(0, moved);
    })
    .expect("no presence needed for any of that");
    assert_eq!(
        hostile.primary_secret_field_id.as_deref(),
        Some(fx.password.as_str()),
        "the designation is by id, not by label or position"
    );

    let gate = ScriptedGate::answering(&[PresenceOutcome::Cancelled; 2]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");
    let _ = block_on(fx.session.release_field(
        fx.item.clone(),
        pin.clone(),
        ReleasePurpose::QuickAccessCopy,
    ));
    let _ = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::QuickAccessCopy,
    ));
    let reasons = gate.reasons();
    assert!(
        reasons[0].starts_with("copy the concealed field “password” of “GitHub”"),
        "{}",
        reasons[0]
    );
    assert!(
        reasons[1].starts_with("copy the password “old” of “GitHub”"),
        "{}",
        reasons[1]
    );

    // No username field: no username, even though the subtitle still shows the website.
    let no_username = resave(&fx.session, &hostile, |fields| {
        fields.retain(|f| f.label != "username");
    })
    .expect("saved");
    assert_eq!(no_username.username, None);
    assert_eq!(no_username.subtitle.as_deref(), Some("https://github.com"));
}

// MARK: - Refusals are throttled, not free vault rewrites

/// A refusal costs its caller nothing, but its audit entry costs a rewrite of the vault file. In a
/// loop, only the first refusal of a reason per minute is written; the rest are counted, and the
/// count still reaches the log as one `<detail>_REPEATED:<n>` entry — when the minute has passed,
/// before the next grant, and at the lock.
#[test]
fn refusals_are_written_once_a_minute_per_reason_and_the_burst_is_still_counted() {
    let fx = fixture();
    let clock = ManualClock::new();
    fx.session.set_clock_for_testing(clock.clone());
    let vault_file = fx.dir_path.join("t.kagivault");
    let (gate, asked, answer) = HeldGate::new();
    fx.session.set_presence_gate(gate.clone()).expect("gate");

    // One prompt up; every further release while it is up is refused PRESENCE_BUSY.
    let session = Arc::clone(&fx.session);
    let (item, field) = (fx.item.clone(), fx.password.clone());
    let held = std::thread::spawn(move || {
        block_on(session.release_field(item, field, ReleasePurpose::Reveal))
    });
    asked
        .recv_timeout(Duration::from_secs(10))
        .expect("the gate is asked");

    let busy = |fx: &Fixture| {
        let e = block_on(fx.session.release_field(
            fx.item.clone(),
            fx.password.clone(),
            ReleasePurpose::Copy,
        ))
        .expect_err("a prompt is already up");
        assert!(matches!(e, FfiError::PresenceBusy), "{e:?}");
    };
    let details = |fx: &Fixture| -> Vec<String> {
        newest(&fx.session, 1_000)
            .into_iter()
            .filter_map(|r| r.2)
            .filter(|d| d.starts_with("PRESENCE_") && !d.starts_with("PRESENCE_CONFIRMED"))
            .collect()
    };

    busy(&fx);
    let after_first = std::fs::read(&vault_file).expect("vault file");
    for _ in 0..49 {
        busy(&fx);
    }
    assert!(
        std::fs::read(&vault_file).expect("vault file") == after_first,
        "49 more refusals within the minute must not rewrite the vault file"
    );
    assert_eq!(details(&fx), ["PRESENCE_BUSY"]);

    // A minute later, the next refusal closes the window: the burst is reported, then written.
    clock.advance(Duration::from_secs(61));
    busy(&fx);
    assert_eq!(
        details(&fx),
        [
            "PRESENCE_BUSY",
            "PRESENCE_BUSY_REPEATED:49",
            "PRESENCE_BUSY"
        ],
        "newest first: the burst of 49 is on record, as one entry"
    );
    let rows = newest(&fx.session, 2);
    assert_eq!(rows[1].4.as_deref(), Some(fx.item.as_str()), "{rows:?}");
    assert_eq!(rows[1].3, vec!["password".to_owned()]);

    // Another reason has its own window.
    answer.send(PresenceOutcome::Cancelled).expect("answer");
    let refused = held.join().expect("thread").expect_err("cancelled");
    assert!(
        matches!(refused, FfiError::PresenceCancelled),
        "{refused:?}"
    );
    assert_eq!(details(&fx)[0], "PRESENCE_CANCELLED");

    // Counted but not yet written refusals ride the lock's final flush. The held gate has spent
    // its one answer, so this prompt answers `Busy` itself — still inside the open window.
    busy(&fx);
    fx.session.lock();
    let reopened =
        VaultSession::unlock_with_password(vault_file.display().to_string(), MASTER.to_owned())
            .expect("reopen");
    let on_disk: Vec<String> = reopened
        .audit_page(1_000, 0)
        .into_iter()
        .filter_map(|r| r.detail)
        .filter(|d| d.starts_with("PRESENCE_"))
        .collect();
    assert_eq!(
        on_disk[..2],
        ["PRESENCE_BUSY_REPEATED:1", "PRESENCE_CANCELLED"],
        "{on_disk:?}"
    );
}

// MARK: - Locking

#[test]
fn a_lock_while_the_prompt_is_up_answers_vault_locked_whatever_the_prompt_says() {
    let fx = fixture();
    let (gate, asked, answer) = HeldGate::new();
    fx.session.set_presence_gate(gate.clone()).expect("gate");
    let path = fx.session.path();

    let session = Arc::clone(&fx.session);
    let (item, field) = (fx.item.clone(), fx.password.clone());
    let pending = std::thread::spawn(move || {
        block_on(session.release_field(item, field, ReleasePurpose::Reveal))
    });
    asked
        .recv_timeout(Duration::from_secs(10))
        .expect("the gate is asked");

    within(Duration::from_secs(10), "lock with a prompt up", {
        let session = Arc::clone(&fx.session);
        move || session.lock()
    });
    // The person touches the sensor anyway, a moment too late.
    answer.send(PresenceOutcome::Confirmed).expect("answer");
    let result = pending.join().expect("the release thread");
    let e = result.expect_err("locked while the prompt was up");
    assert!(matches!(e, FfiError::VaultLocked), "{e:?}");
    assert_clean_error("the locked release", &e);
    assert_eq!(gate.calls.load(Ordering::SeqCst), 1);

    // Recorded by the lock itself, in the vault's last write.
    let reopened = VaultSession::unlock_with_password(path, MASTER.to_owned()).expect("reopen");
    let rows = newest(&reopened, 1);
    assert_eq!(rows[0].0, "reveal_field");
    assert_eq!(rows[0].1, "denied");
    assert_eq!(rows[0].2.as_deref(), Some("VAULT_LOCKED"));
    assert_eq!(rows[0].3, vec!["password".to_owned()]);

    // Nothing panics on a locked session, and nothing is released from it.
    assert!(!fx.session.is_unlocked());
    assert!(
        fx.session
            .list_items(ItemFilter::All, None, ItemSort::Title)
            .is_empty()
    );
    assert!(matches!(
        fx.session.item(fx.item.clone()),
        Err(FfiError::VaultLocked)
    ));
    assert!(
        fx.session
            .export_vault_key_for_platform_wrapping()
            .is_empty()
    );
    assert!(matches!(
        block_on(fx.session.release_field(
            fx.item.clone(),
            fx.password.clone(),
            ReleasePurpose::Reveal
        )),
        Err(FfiError::VaultLocked)
    ));
    assert_eq!(fx.session.path(), reopened.path());
}

#[test]
fn a_release_already_granted_stops_at_the_lock() {
    let fx = fixture();
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed; 3]);
    fx.session.set_presence_gate(gate).expect("gate");
    let field = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Reveal,
    ))
    .expect("granted");
    let notes = block_on(
        fx.session
            .release_notes(fx.item.clone(), ReleasePurpose::Reveal),
    )
    .expect("granted");
    assert_eq!(field.value().expect("value"), CANARY);

    fx.session.lock();
    for e in [
        field.value().expect_err("locked"),
        field.copy_shown_value().expect_err("locked"),
        notes.text().expect_err("locked"),
    ] {
        assert!(matches!(e, FfiError::VaultLocked), "{e:?}");
        assert_clean_error("after the lock", &e);
    }
    assert!(!field.is_live());
}

#[test]
fn a_totp_release_ends_at_its_cap_at_the_lock_and_at_close() {
    let fx = fixture();
    let clock = ManualClock::new();
    fx.session.set_clock_for_testing(clock.clone());
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed; 3]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");

    // The cap: five minutes from the touch, and use does not extend it.
    let live = block_on(
        fx.session
            .release_totp(fx.item.clone(), None, ReleasePurpose::Reveal),
    )
    .expect("granted");
    let first = live.code_at(1_699_999_980).expect("code");
    assert_eq!(live.seconds_remaining(), 300);
    clock.advance(Duration::from_secs(4 * 60 + 59));
    assert_eq!(
        live.code_at(1_699_999_980).expect("still live").code,
        first.code
    );
    assert!(live.is_live());
    clock.advance(Duration::from_secs(1));
    assert!(matches!(
        live.code_at(1_699_999_980),
        Err(FfiError::ReleaseEnded { .. })
    ));
    assert!(matches!(
        live.copy_shown_code_at(1_699_999_980),
        Err(FfiError::ReleaseEnded { .. })
    ));
    assert!(!live.is_live());

    // Close.
    let closed = block_on(fx.session.release_totp(
        fx.item.clone(),
        Some(fx.totp.clone()),
        ReleasePurpose::Reveal,
    ))
    .expect("granted");
    closed.code_at(0).expect("code before close");
    closed.close();
    assert!(matches!(
        closed.code_at(0),
        Err(FfiError::ReleaseEnded { .. })
    ));

    // The lock.
    let locked = block_on(
        fx.session
            .release_totp(fx.item.clone(), None, ReleasePurpose::Reveal),
    )
    .expect("granted");
    locked.code_at(0).expect("code before the lock");
    fx.session.lock();
    assert!(matches!(locked.code_at(0), Err(FfiError::VaultLocked)));
    assert_eq!(gate.calls(), 3);
}

// MARK: - Concurrency

#[test]
fn a_pending_prompt_blocks_neither_the_app_nor_the_agent_and_refuses_a_second_prompt() {
    let fx = fixture();
    let (gate, asked, answer) = HeldGate::new();
    fx.session.set_presence_gate(gate.clone()).expect("gate");

    // A real agent on a real socket, serving from the same vault handle.
    fx.session
        .set_vault_agent_visible(fx.session.default_vault_id().expect("vault"), true)
        .expect("share the vault");
    fx.session
        .set_agent_visible(fx.item.clone(), true)
        .expect("share the item");
    let endpoint =
        kagisecure_ffi::agent_start(Arc::clone(&fx.session), Some(socket_for(&fx.dir_path)))
            .expect("agent");

    let session = Arc::clone(&fx.session);
    let (item, field) = (fx.item.clone(), fx.password.clone());
    let pending = std::thread::spawn(move || {
        block_on(session.release_field(item, field, ReleasePurpose::Reveal))
    });
    asked
        .recv_timeout(Duration::from_secs(10))
        .expect("the gate is asked");

    // While the prompt is up: the app's own reads and writes…
    let limit = Duration::from_secs(10);
    let s = Arc::clone(&fx.session);
    within(limit, "list_items", move || {
        s.list_items(ItemFilter::All, None, ItemSort::Title)
    });
    let s = Arc::clone(&fx.session);
    within(limit, "sidebar_counts", move || s.sidebar_counts());
    let s = Arc::clone(&fx.session);
    within(limit, "create_item", move || {
        s.create_item(
            None,
            "secure-note".to_owned(),
            "Written during a prompt".to_owned(),
        )
    })
    .expect("a write");
    let s = Arc::clone(&fx.session);
    within(limit, "audit_page", move || s.audit_page(10, 0));

    // …the agent's, over its socket — including a search that must not see the note…
    let endpoint =
        kagisecure_ipc::Endpoint::parse(std::ffi::OsStr::new(&endpoint)).expect("endpoint");
    let items = within(limit, "an agent's list_items", move || {
        let mut client = kagisecure_ipc::client::Client::connect(
            &endpoint,
            kagisecure_ipc::protocol::ClientInfo {
                name: "adversarial-test".to_owned(),
                version: "0".to_owned(),
                pid: std::process::id(),
                parent_pid: None,
                argv0: "release_presence_adversarial".to_owned(),
                cwd: None,
            },
        )
        .expect("connect");
        let mut ask = |query: &str| match client
            .call(&kagisecure_ipc::protocol::Request::ListItems {
                vault_id: None,
                query: Some(query.to_owned()),
                category: None,
                limit: 50,
                cursor: None,
            })
            .expect("a reply")
        {
            kagisecure_ipc::protocol::Response::Items { items, .. } => items.len(),
            other => panic!("unexpected reply {other:?}"),
        };
        (ask("github"), ask(NOTE_CANARY), ask("recovery"))
    });
    assert_eq!(
        items,
        (1, 0, 0),
        "the agent finds the title, never the note"
    );
    let _ = kagisecure_ffi::agent_status();

    // …and a second release, which is refused at once rather than stacked behind the first.
    let s = Arc::clone(&fx.session);
    let (item, other) = (fx.item.clone(), fx.totp.clone());
    let second = within(limit, "a second release", move || {
        block_on(s.release_totp(item, Some(other), ReleasePurpose::Reveal))
    });
    assert!(matches!(second, Err(FfiError::PresenceBusy)), "{second:?}");
    assert_eq!(
        gate.calls.load(Ordering::SeqCst),
        1,
        "the second release never reached the gate"
    );

    answer.send(PresenceOutcome::Confirmed).expect("answer");
    let granted = pending.join().expect("thread").expect("granted after all");
    assert_eq!(granted.value().expect("value"), CANARY);
    kagisecure_ffi::agent_stop();

    let rows = newest(&fx.session, 50);
    assert!(
        rows.iter()
            .any(|r| r.0 == "totp_show" && r.2.as_deref() == Some("PRESENCE_BUSY"))
    );
}

/// Where this test's agent listens: a socket in the fixture's directory on Unix, a pipe named
/// after this process on Windows (which has no filesystem sockets).
fn socket_for(dir: &Path) -> String {
    if cfg!(windows) {
        format!(r"\\.\pipe\kagisecure-release-test-{}", std::process::id())
    } else {
        dir.join("a.sock").display().to_string()
    }
}

#[test]
fn an_abandoned_release_leaves_the_log_honest_and_the_next_prompt_free() {
    use std::future::Future;
    use std::task::{Context, Poll};

    let fx = fixture();
    let (gate, asked, _answer) = HeldGate::new();
    fx.session.set_presence_gate(gate).expect("gate");

    let mut fut = Box::pin(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Copy,
    ));
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
    asked.recv_timeout(Duration::from_secs(10)).expect("asked");
    // The app's task is cancelled with the prompt still up.
    drop(fut);
    fx.session.save().expect("write what was queued");

    let rows = newest(&fx.session, 1);
    assert_eq!(rows[0].0, "copy_field");
    assert_eq!(rows[0].1, "denied");
    assert_eq!(rows[0].2.as_deref(), Some("PRESENCE_CANCELLED"));

    // The abandoned release no longer holds the one-prompt slot.
    let e = within(
        Duration::from_secs(10),
        "a release after an abandoned one",
        {
            let s = Arc::clone(&fx.session);
            let (item, field) = (fx.item.clone(), fx.password.clone());
            move || block_on(s.release_field(item, field, ReleasePurpose::Copy))
        },
    );
    // The held gate has no answer left for a second call, so it says Busy itself — but the call
    // did reach the gate, which it would not have if the first release still held the slot.
    assert!(matches!(e, Err(FfiError::PresenceBusy)));
    let rows = newest(&fx.session, 1);
    assert_eq!(rows[0].2.as_deref(), Some("PRESENCE_BUSY"));
}

// MARK: - Audit is best-effort

#[cfg(unix)]
#[test]
fn a_failed_audit_save_still_releases_and_keeps_the_entry_queued() {
    let fx = fixture();
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed]);
    fx.session.set_presence_gate(gate).expect("gate");

    // Make every write fail: the vault file becomes a directory, so the transaction that would
    // record the release cannot read or replace it (the same trick core's `audit_durability`
    // test uses — a permissions trick on a directory this process owns heals itself).
    let path = PathBuf::from(fx.session.path());
    let good = std::fs::read(&path).expect("read the vault");
    std::fs::remove_file(&path).expect("remove");
    std::fs::create_dir(&path).expect("a directory where the vault was");

    let released = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Reveal,
    ));
    let durability = fx.session.audit_durability();

    std::fs::remove_dir(&path).expect("remove the directory");
    std::fs::write(&path, &good).expect("put the vault back");

    let released = released.expect("a failed audit write never withholds a person's own value");
    assert_eq!(released.value().expect("value"), CANARY);
    assert!(durability.unsaved_entries >= 1, "{durability:?}");
    assert!(durability.last_error.is_some());

    // The entry was queued, not lost: the next successful write carries it.
    fx.session.save().expect("save");
    let reopened =
        VaultSession::unlock_with_password(fx.session.path(), MASTER.to_owned()).expect("reopen");
    assert!(
        newest(&reopened, 5)
            .iter()
            .any(|r| r.0 == "reveal_field" && r.2.as_deref() == Some("PRESENCE_CONFIRMED"))
    );
}

// MARK: - Credential changes are audited (ADR-0040 step 10)

#[test]
fn credential_changes_and_the_key_export_are_audited() {
    let fx = fixture();
    let key = fx.session.export_vault_key_for_platform_wrapping();
    assert_eq!(key.len(), 32);
    fx.session
        .install_platform_slot("slot-1".to_owned(), "Touch ID".to_owned(), key)
        .expect("enrol");
    assert!(fx.session.remove_platform_slot().expect("remove"));
    assert!(
        !fx.session
            .remove_platform_slot()
            .expect("nothing to remove")
    );
    fx.session
        .change_master_password("a new password".to_owned())
        .expect("change");

    let tools: Vec<String> = newest(&fx.session, 4).into_iter().map(|r| r.0).collect();
    assert_eq!(
        tools,
        [
            "change_master_password",
            "touch_id_remove",
            "touch_id_enrol",
            "vault_key_export"
        ],
        "one entry each, and none for a removal that removed nothing"
    );
    for row in fx.session.audit_page(4, 0) {
        assert_eq!(row.actor, "app");
        assert_eq!(row.outcome, "allowed");
    }
}

// MARK: - The master-password fallback

#[test]
fn the_master_password_fallback_backs_off_exponentially() {
    let fx = fixture();
    let clock = ManualClock::new();
    fx.session.set_clock_for_testing(clock.clone());
    let s = &fx.session;

    assert_eq!(
        s.verify_master_password("wrong".to_owned())
            .expect("checked"),
        MasterPasswordCheck::Wrong {
            retry_after_ms: 1_000
        }
    );
    // Inside the back-off, even the right password is not checked.
    assert_eq!(
        s.verify_master_password(MASTER.to_owned())
            .expect("throttled"),
        MasterPasswordCheck::Throttled {
            retry_after_ms: 1_000
        }
    );
    clock.advance(Duration::from_millis(400));
    assert_eq!(
        s.verify_master_password("wrong".to_owned())
            .expect("throttled"),
        MasterPasswordCheck::Throttled {
            retry_after_ms: 600
        }
    );
    clock.advance(Duration::from_millis(600));
    assert_eq!(
        s.verify_master_password("wrong again".to_owned())
            .expect("checked"),
        MasterPasswordCheck::Wrong {
            retry_after_ms: 2_000
        }
    );
    clock.advance(Duration::from_secs(2));
    assert_eq!(
        s.verify_master_password("still wrong".to_owned())
            .expect("checked"),
        MasterPasswordCheck::Wrong {
            retry_after_ms: 4_000
        }
    );
    clock.advance(Duration::from_secs(4));
    assert_eq!(
        s.verify_master_password(MASTER.to_owned())
            .expect("checked"),
        MasterPasswordCheck::Verified
    );
    // A success resets the back-off.
    assert_eq!(
        s.verify_master_password("wrong".to_owned())
            .expect("checked"),
        MasterPasswordCheck::Wrong {
            retry_after_ms: 1_000
        }
    );

    // Locked, nothing is checked.
    clock.advance(Duration::from_secs(1));
    s.lock();
    assert!(matches!(
        s.verify_master_password(MASTER.to_owned()),
        Err(FfiError::VaultLocked)
    ));
}

#[test]
fn the_backoff_is_capped_at_five_minutes() {
    let fx = fixture();
    let clock = ManualClock::new();
    fx.session.set_clock_for_testing(clock.clone());
    let mut last = 0;
    for _ in 0..11 {
        match fx
            .session
            .verify_master_password("wrong".to_owned())
            .expect("checked")
        {
            MasterPasswordCheck::Wrong { retry_after_ms } => {
                assert!(retry_after_ms >= last);
                last = retry_after_ms;
                clock.advance(Duration::from_millis(retry_after_ms));
            }
            other => panic!("expected Wrong, got {other:?}"),
        }
    }
    assert_eq!(last, 300_000);
}

// MARK: - Audit: the fallback, failed attempts, and a target deleted mid-prompt

/// The app's gate when `LocalAuthentication` cannot run: it puts the master-password sheet up and
/// answers `Confirmed` only once `verify_master_password` said `Verified` — exactly what the Swift
/// fallback does.
struct MasterPasswordFallbackGate {
    session: Mutex<Option<Arc<VaultSession>>>,
    typed: Mutex<VecDeque<String>>,
}

impl MasterPasswordFallbackGate {
    fn typing(passwords: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(None),
            typed: Mutex::new(passwords.iter().map(|p| (*p).to_owned()).collect()),
        })
    }
}

#[async_trait::async_trait]
impl PresenceGate for MasterPasswordFallbackGate {
    async fn confirm(&self, _reason: String) -> PresenceOutcome {
        let session = self.session.lock().unwrap().clone().expect("wired");
        while let Some(password) = self.typed.lock().unwrap().pop_front() {
            if matches!(
                session.verify_master_password(password),
                Ok(MasterPasswordCheck::Verified)
            ) {
                return PresenceOutcome::Confirmed;
            }
        }
        PresenceOutcome::Cancelled
    }
}

#[test]
fn a_grant_by_the_master_password_fallback_is_audited_apart_from_presence() {
    let fx = fixture();
    let gate = MasterPasswordFallbackGate::typing(&[MASTER]);
    *gate.session.lock().unwrap() = Some(Arc::clone(&fx.session));
    fx.session.set_presence_gate(gate).expect("gate");

    let release = block_on(fx.session.release_field(
        fx.item.clone(),
        fx.password.clone(),
        ReleasePurpose::Reveal,
    ))
    .expect("the fallback confirmed it");
    assert_eq!(release.value().expect("shown"), CANARY);
    let rows = newest(&fx.session, 1);
    assert_eq!(rows[0].0, "reveal_field");
    assert_eq!(rows[0].1, "allowed");
    assert_eq!(
        rows[0].2.as_deref(),
        Some("PRESENCE_CONFIRMED_MASTER_PASSWORD"),
        "a master password is not a biometric, and the log says which it was"
    );
    assert_eq!(rows[0].3, vec!["password".to_owned()]);
}

#[test]
fn a_verified_master_password_marks_only_the_release_it_was_typed_for() {
    let fx = fixture();
    // Verified before any release is waiting: it marks nothing.
    assert!(matches!(
        fx.session.verify_master_password(MASTER.to_owned()),
        Ok(MasterPasswordCheck::Verified)
    ));
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed]);
    fx.session.set_presence_gate(gate).expect("gate");
    block_on(
        fx.session
            .release_field(fx.item.clone(), fx.password.clone(), ReleasePurpose::Copy),
    )
    .expect("confirmed");
    let rows = newest(&fx.session, 1);
    assert_eq!(rows[0].0, "copy_field");
    assert_eq!(rows[0].2.as_deref(), Some("PRESENCE_CONFIRMED"));
}

#[test]
fn wrong_master_passwords_are_audited_and_a_throttled_burst_once_per_window() {
    let fx = fixture();
    let clock = ManualClock::new();
    fx.session.set_clock_for_testing(clock.clone());
    let s = &fx.session;
    let before = s.audit_count();

    assert!(matches!(
        s.verify_master_password("guess 1".to_owned()),
        Ok(MasterPasswordCheck::Wrong { .. })
    ));
    // A burst inside the back-off: refused unchecked, and recorded once, not five times.
    for _ in 0..5 {
        assert!(matches!(
            s.verify_master_password("guess".to_owned()),
            Ok(MasterPasswordCheck::Throttled { .. })
        ));
    }
    clock.advance(Duration::from_secs(1));
    assert!(matches!(
        s.verify_master_password("guess 2".to_owned()),
        Ok(MasterPasswordCheck::Wrong { .. })
    ));
    assert!(matches!(
        s.verify_master_password("guess".to_owned()),
        Ok(MasterPasswordCheck::Throttled { .. })
    ));

    assert_eq!(s.audit_count() - before, 4);
    let rows = newest(s, 4);
    let details: Vec<(String, String, Option<String>)> = rows
        .iter()
        .map(|r| (r.0.clone(), r.1.clone(), r.2.clone()))
        .collect();
    let entry = |detail: &str| {
        (
            "verify_master_password".to_owned(),
            "denied".to_owned(),
            Some(detail.to_owned()),
        )
    };
    assert_eq!(
        details,
        vec![
            entry("MASTER_PASSWORD_THROTTLED"),
            entry("MASTER_PASSWORD_WRONG"),
            entry("MASTER_PASSWORD_THROTTLED"),
            entry("MASTER_PASSWORD_WRONG"),
        ]
    );
    for row in s.audit_page(4, 0) {
        assert_eq!(row.actor, "app");
        assert_clean("a failed attempt's audit row", &format!("{row:?}"));
        assert!(
            !format!("{row:?}").contains("guess"),
            "a typed password never reaches the log"
        );
    }
}

#[test]
fn a_wrong_master_password_names_the_release_it_was_typed_for() {
    let fx = fixture();
    let (gate, asked, answer) = HeldGate::new();
    fx.session.set_presence_gate(gate).expect("gate");
    let session = Arc::clone(&fx.session);
    let (item, field) = (fx.item.clone(), fx.password.clone());
    let pending = std::thread::spawn(move || {
        block_on(session.release_field(item, field, ReleasePurpose::Copy))
    });
    asked
        .recv_timeout(Duration::from_secs(10))
        .expect("the gate is asked");
    // The fallback sheet is up; a wrong password is typed into it.
    let s = Arc::clone(&fx.session);
    let check = within(
        Duration::from_secs(10),
        "a check with a prompt up",
        move || s.verify_master_password("not it".to_owned()),
    );
    assert!(matches!(check, Ok(MasterPasswordCheck::Wrong { .. })));
    let rows = newest(&fx.session, 1);
    assert_eq!(rows[0].0, "verify_master_password");
    assert_eq!(rows[0].2.as_deref(), Some("MASTER_PASSWORD_WRONG"));
    assert_eq!(rows[0].3, vec!["password".to_owned()]);
    assert_eq!(rows[0].4.as_deref(), Some(fx.item.as_str()));

    answer.send(PresenceOutcome::Cancelled).expect("answer");
    assert!(matches!(
        pending.join().expect("thread"),
        Err(FfiError::PresenceCancelled)
    ));
}

/// Every field of `view` as an edit that keeps its value, except `dropped`.
fn kept_fields(view: &ItemView, dropped: Option<&String>) -> Vec<FieldDraft> {
    view.fields
        .iter()
        .filter(|f| Some(&f.id) != dropped)
        .map(|f| FieldDraft {
            id: Some(f.id.clone()),
            label: f.label.clone(),
            kind: f.kind,
            concealed: f.concealed,
            value: if f.concealed { None } else { f.value.clone() },
            section: f.section.clone(),
            agent_visible: f.agent_visible,
        })
        .collect()
}

/// Start a release of `what` behind a held gate, run `meanwhile` while its prompt is up, then
/// confirm it. Returns the release's result.
fn confirm_after<T: Send + 'static>(
    fx: &Fixture,
    start: impl FnOnce(Arc<VaultSession>) -> kagisecure_ffi::FfiResult<T> + Send + 'static,
    meanwhile: impl FnOnce(&VaultSession),
) -> kagisecure_ffi::FfiResult<T> {
    let (gate, asked, answer) = HeldGate::new();
    fx.session.set_presence_gate(gate).expect("gate");
    let session = Arc::clone(&fx.session);
    let pending = std::thread::spawn(move || start(session));
    asked
        .recv_timeout(Duration::from_secs(10))
        .expect("the gate is asked");
    meanwhile(&fx.session);
    answer.send(PresenceOutcome::Confirmed).expect("answer");
    pending.join().expect("the release thread")
}

#[test]
fn a_release_whose_item_went_during_the_prompt_is_audited_failed() {
    let fx = fixture();
    let item = fx.item.clone();
    let field = fx.password.clone();
    let result = confirm_after(
        &fx,
        move |s| block_on(s.release_field(item, field, ReleasePurpose::Reveal)),
        |s| {
            let binned = s
                .set_trashed(fx.item.clone(), true)
                .expect("binned meanwhile");
            s.delete_item(binned.id, binned.revision)
                .expect("deleted meanwhile");
        },
    );
    let e = result.expect_err("nothing left to release");
    assert!(matches!(e, FfiError::NotPresent { .. }), "{e:?}");
    assert_clean_error("a release of a deleted item", &e);
    let rows = newest(&fx.session, 1);
    assert_eq!(rows[0].0, "reveal_field");
    assert_eq!(rows[0].1, "failed");
    assert_eq!(rows[0].2.as_deref(), Some("GONE_DURING_PROMPT"));
    assert_eq!(rows[0].4.as_deref(), Some(fx.item.as_str()));
}

#[test]
fn a_release_whose_field_or_notes_went_during_the_prompt_is_audited_failed() {
    // The field: removed from the item by an edit while the prompt is up.
    let fx = fixture();
    let (item, field) = (fx.item.clone(), fx.totp.clone());
    let result = confirm_after(
        &fx,
        move |s| block_on(s.release_totp(item, Some(field), ReleasePurpose::Copy)),
        |s| {
            let view = s.item(fx.item.clone()).expect("item");
            let fields = kept_fields(&view, Some(&fx.totp));
            s.save_item(ItemDraft {
                id: view.id.clone(),
                category: view.category.clone(),
                title: view.title.clone(),
                fields,
                tags: view.tags.clone(),
                urls: view.urls.clone(),
                notes: None,
                revision: view.revision.clone(),
            })
            .expect("the one-time password is removed meanwhile");
        },
    );
    assert!(matches!(result, Err(FfiError::NotPresent { .. })));
    let rows = newest(&fx.session, 1);
    assert_eq!(
        (rows[0].0.as_str(), rows[0].1.as_str(), rows[0].2.as_deref()),
        ("totp_copy", "failed", Some("GONE_DURING_PROMPT"))
    );

    // The notes: cleared by an edit while the prompt is up.
    let fx = fixture();
    let item = fx.item.clone();
    let result = confirm_after(
        &fx,
        move |s| block_on(s.release_notes(item, ReleasePurpose::Reveal)),
        |s| {
            let view = s.item(fx.item.clone()).expect("item");
            s.save_item(ItemDraft {
                id: view.id.clone(),
                category: view.category.clone(),
                title: view.title.clone(),
                fields: kept_fields(&view, None),
                tags: view.tags.clone(),
                urls: view.urls.clone(),
                notes: Some(String::new()),
                revision: view.revision.clone(),
            })
            .expect("the notes are cleared meanwhile");
        },
    );
    let e = result.expect_err("no notes left to show");
    assert!(matches!(e, FfiError::NotPresent { .. }), "{e:?}");
    assert_clean_error("a release of cleared notes", &e);
    let rows = newest(&fx.session, 1);
    assert_eq!(
        (rows[0].0.as_str(), rows[0].1.as_str(), rows[0].2.as_deref()),
        ("notes_show", "failed", Some("GONE_DURING_PROMPT"))
    );
}

// MARK: - Notes on disk are what they always were

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../kagisecure-core/tests/vectors")
}

/// The item the notes golden vectors were written from, before notes became secret.
fn golden_item(notes: bool) -> kagisecure_core::model::Item {
    use kagisecure_core::model::{Category, Field, Item, Secret, SecretText};
    let vault_id = "0b8a7d1e-2f3c-4d5e-8f60-718293a4b5c6".parse().expect("id");
    let mut item = Item::new(vault_id, Category::SecureNote, "Golden note");
    item.id = "5f0e1d2c-3b4a-4958-8776-65544332a110".parse().expect("id");
    item.created_at = 1_700_000_000;
    item.updated_at = 1_700_000_100;
    item.tags = vec!["golden".to_owned()];
    item.notes = notes
        .then(|| SecretText::new("recovery codes: 1111-2222\nline two — ünïcödé ✓".to_owned()));
    let mut field = Field::concealed("pin", Secret::from_string("4242".to_owned()));
    field.id = "9a8b7c6d-5e4f-4a3b-9c2d-1e0f0a1b2c3d".parse().expect("id");
    item.fields.push(field);
    item
}

#[test]
fn a_secret_note_encodes_byte_for_byte_as_the_plain_note_did() {
    for (file, notes) in [
        ("item-with-notes-v1.cbor", true),
        ("item-without-notes-v1.cbor", false),
    ] {
        let golden = std::fs::read(vectors().join(file)).expect("golden vector");
        let mut encoded = Vec::new();
        ciborium::into_writer(&golden_item(notes), &mut encoded).expect("encode");
        assert_eq!(encoded, golden, "{file}: the note's encoding changed");

        let decoded: kagisecure_core::model::Item =
            ciborium::from_reader(golden.as_slice()).expect("decode");
        assert_eq!(
            decoded
                .notes
                .as_ref()
                .map(kagisecure_core::model::SecretText::expose),
            golden_item(notes)
                .notes
                .as_ref()
                .map(kagisecure_core::model::SecretText::expose)
        );
        assert!(
            !format!("{decoded:?}").contains("recovery codes"),
            "notes are redacted in Debug"
        );
        let mut again = Vec::new();
        ciborium::into_writer(&decoded, &mut again).expect("re-encode");
        assert_eq!(again, golden, "{file}: a round trip changed the bytes");
    }
}

#[test]
fn a_vault_written_with_a_plain_note_opens_and_releases_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let working = dir.path().join("golden.kagivault");
    std::fs::copy(vectors().join("v1-notes-argon2id-64k.kagivault"), &working).expect("copy");
    let session = VaultSession::unlock_with_password(
        working.display().to_string(),
        "golden vector password".to_owned(),
    )
    .expect("the pre-ADR-0038 vector still opens");

    let item = session
        .list_items(ItemFilter::All, None, ItemSort::Title)
        .into_iter()
        .find(|i| i.title == "Golden note")
        .expect("the item");
    assert!(item.has_notes);
    assert!(!format!("{item:?}").contains("recovery codes"));

    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed]);
    session.set_presence_gate(gate).expect("gate");
    let notes =
        block_on(session.release_notes(item.id.clone(), ReleasePurpose::Reveal)).expect("granted");
    assert_eq!(
        notes.text().expect("text"),
        "recovery codes: 1111-2222\nline two — ünïcödé ✓"
    );
    assert!(session.audit_intact());
}

// MARK: - Editing notes without holding them

#[test]
fn an_edit_that_leaves_notes_out_keeps_them_and_an_empty_one_clears_them() {
    let fx = fixture();
    let gate = ScriptedGate::answering(&[PresenceOutcome::Confirmed; 2]);
    fx.session.set_presence_gate(gate.clone()).expect("gate");

    let view = fx.session.item(fx.item.clone()).expect("item");
    let draft = |view: &ItemView, notes: Option<String>| ItemDraft {
        id: view.id.clone(),
        category: view.category.clone(),
        title: "Renamed".to_owned(),
        fields: Vec::new(),
        tags: view.tags.clone(),
        urls: view.urls.clone(),
        notes,
        revision: view.revision.clone(),
    };
    // `fields: []` would delete every field; keep them by id with `value: None`.
    let keep = |view: &ItemView| -> Vec<FieldDraft> {
        view.fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: None,
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect()
    };

    let mut d = draft(&view, None);
    d.fields = keep(&view);
    let saved = fx.session.save_item(d).expect("rename only");
    assert!(
        saved.has_notes,
        "a draft that never saw the note must not erase it"
    );
    let notes = block_on(
        fx.session
            .release_notes(fx.item.clone(), ReleasePurpose::Reveal),
    )
    .expect("granted");
    assert!(notes.text().expect("text").contains(NOTE_CANARY));

    let mut d = draft(&saved, Some(String::new()));
    d.fields = keep(&saved);
    let cleared = fx.session.save_item(d).expect("clear the note");
    assert!(!cleared.has_notes);
    assert!(matches!(
        block_on(
            fx.session
                .release_notes(fx.item.clone(), ReleasePurpose::Reveal)
        ),
        Err(FfiError::NotPresent { .. })
    ));
    // Saving — keeping values or not — never asks the gate: only a release does.
    assert_eq!(gate.calls(), 1);
}
