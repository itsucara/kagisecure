//! The module rules, each checked on a representative function.
//!
//! The agent is a process global shared with `crate::agent`'s own tests, which run in parallel in
//! this binary, so nothing here starts or stops it; the C# suite drives it end to end instead.

use std::ptr;

use super::*;

fn slice(text: &str) -> KgsSlice {
    KgsSlice {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

fn some(text: &str) -> KgsOptSlice {
    KgsOptSlice {
        present: 1,
        value: slice(text),
    }
}

const NONE: KgsOptSlice = KgsOptSlice {
    present: 0,
    value: KgsSlice {
        ptr: ptr::null(),
        len: 0,
    },
};

fn cheap(value: u32) -> KgsOptU32 {
    KgsOptU32 { present: 1, value }
}

/// Read a buffer the caller still owns, without freeing it.
fn text(buffer: &KgsBuffer) -> String {
    if buffer.ptr.is_null() {
        return String::new();
    }
    // SAFETY: a buffer this library wrote, not yet freed.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
    String::from_utf8(bytes.to_vec()).expect("UTF-8")
}

/// Take a buffer's contents as a string and free it the way a caller must.
fn take(buffer: &mut KgsBuffer) -> String {
    let result = text(buffer);
    // SAFETY: a buffer this library just wrote, freed once.
    unsafe { kgs_buffer_free(buffer) };
    assert!(buffer.ptr.is_null(), "freeing resets the buffer");
    result
}

/// A fresh vault at KDF parameters that protect nothing, and its handle.
fn vault() -> (tempfile::TempDir, String, *mut KgsSession) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kagivault").display().to_string();
    let mut handle = ptr::null_mut();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: every slice borrows a live `&str`; the out-pointers are locals.
    let status = unsafe {
        kgs_session_create(
            slice(&path),
            slice("right"),
            slice("Personal"),
            cheap(64),
            cheap(1),
            &mut handle,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    (dir, path, handle)
}

fn create_item(session: *mut KgsSession, category: &str, title: &str) -> KgsItemView {
    let mut item = KgsItemView::default();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe {
        kgs_session_create_item(
            session,
            NONE,
            slice(category),
            slice(title),
            &mut item,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    item
}

// -------------------------------------------------------------------------------------------
// Errors and out-parameters
// -------------------------------------------------------------------------------------------

#[test]
fn a_wrong_password_is_a_status_and_a_message_not_a_handle() {
    let (_dir, path, handle) = vault();
    // SAFETY: the handle just created, freed once.
    unsafe { kgs_session_free(handle) };

    let mut handle = ptr::null_mut();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: as above.
    let status = unsafe {
        kgs_session_unlock_with_password(slice(&path), slice("wrong"), &mut handle, &mut error)
    };
    assert_eq!(status, KgsStatus::WrongCredential);
    assert!(handle.is_null(), "no handle is written on failure");
    assert_eq!(take(&mut error), "that did not unlock the vault");
}

#[test]
fn a_null_out_parameter_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kagivault");
    let text = path.display().to_string();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: the slices borrow live `&str`s; a null `out` is what is under test.
    let status = unsafe {
        kgs_session_create(
            slice(&text),
            slice("pw"),
            slice("Personal"),
            cheap(64),
            cheap(1),
            ptr::null_mut(),
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(
        !path.exists(),
        "no vault file for a handle nobody could free"
    );
    assert!(take(&mut error).contains("out-parameter"));
}

#[test]
fn a_null_error_pointer_still_reports_the_status() {
    let mut handle = ptr::null_mut();
    // SAFETY: the slices borrow live `&str`s; a null `error` is allowed.
    let status = unsafe {
        kgs_session_unlock_with_password(
            slice("Z:/there/is/no/such/vault.kagivault"),
            slice("x"),
            &mut handle,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, KgsStatus::NotFound);
    assert!(handle.is_null());
}

#[test]
fn a_null_handle_is_invalid_rather_than_a_crash() {
    let mut out = KgsBuffer::EMPTY;
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a null session is what is under test.
    let status = unsafe { kgs_session_path(ptr::null(), &mut out, &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("session handle was null"));

    let mut report = std::mem::MaybeUninit::<KgsImportReport>::uninit();
    // SAFETY: a null plan is what is under test; `report` is never read.
    let status = unsafe { kgs_import_plan_report(ptr::null(), report.as_mut_ptr(), &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("import plan handle was null"));
}

#[test]
fn a_panic_is_a_status_not_an_unwind_into_the_caller() {
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: `error` is a local.
    let status = unsafe { call(&mut error, || panic!("a deliberate test panic")) };
    assert_eq!(status, KgsStatus::Panic);
    assert_eq!(take(&mut error), "kagisecure panicked");
}

// -------------------------------------------------------------------------------------------
// Strings, bytes and lists going in
// -------------------------------------------------------------------------------------------

#[test]
fn a_non_utf8_string_argument_is_invalid_rather_than_lossily_decoded() {
    let bad = [0xff, 0xfe];
    let mut handle = ptr::null_mut();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: `bad` outlives the call.
    let status = unsafe {
        kgs_session_unlock_with_password(
            KgsSlice {
                ptr: bad.as_ptr(),
                len: bad.len(),
            },
            slice("x"),
            &mut handle,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("UTF-8"));
}

#[test]
fn a_non_empty_slice_or_list_with_a_null_pointer_is_invalid() {
    let (_dir, _path, session) = vault();
    let mut out = std::mem::MaybeUninit::<KgsFieldView>::uninit();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a null pointer with a length is what is under test; it is never dereferenced.
    let status = unsafe {
        kgs_session_field(
            session,
            KgsSlice {
                ptr: ptr::null(),
                len: 4,
            },
            slice("f"),
            out.as_mut_ptr(),
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("null pointer"));

    let item = create_item(session, "login", "GitHub");
    let id = text(&item.id);
    let draft = KgsItemDraft {
        id: slice(&id),
        category: slice("login"),
        title: slice("GitHub"),
        fields: KgsFieldDraftList {
            ptr: ptr::null(),
            len: 3,
        },
        tags: KgsSliceList {
            ptr: ptr::null(),
            len: 0,
        },
        urls: KgsSliceList {
            ptr: ptr::null(),
            len: 0,
        },
        notes: NONE,
        revision: slice(""),
    };
    let mut saved = KgsItemView::default();
    // SAFETY: as above.
    let status = unsafe { kgs_session_save_item(session, &draft, &mut saved, &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("null pointer"));

    let mut item = item;
    // SAFETY: records this library wrote, freed once; the handle, freed once.
    unsafe {
        kgs_item_view_free(&mut item);
        kgs_session_free(session);
    }
}

#[test]
fn a_draft_crosses_whole_and_an_absent_string_stays_different_from_an_empty_one() {
    let (_dir, _path, session) = vault();
    let mut item = create_item(session, "login", "GitHub");
    let id = text(&item.id);
    let revision = text(&item.revision);

    let fields = [KgsFieldDraft {
        id: NONE,
        label: slice("recovery"),
        kind: KgsFieldKind::Concealed as u32,
        concealed: 1,
        value: some("s3cret\0with a NUL"),
        section: NONE,
        agent_visible: 0,
    }];
    let tags = [slice("work"), slice("鍵")];
    let draft = KgsItemDraft {
        id: slice(&id),
        category: slice("login"),
        title: slice("GitHub (work)"),
        fields: KgsFieldDraftList {
            ptr: fields.as_ptr(),
            len: fields.len(),
        },
        tags: KgsSliceList {
            ptr: tags.as_ptr(),
            len: tags.len(),
        },
        urls: KgsSliceList {
            ptr: ptr::null(),
            len: 0,
        },
        notes: some("a note"),
        revision: slice(&revision),
    };
    let mut saved = KgsItemView::default();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: every slice and list borrows a local that outlives the call.
    let status = unsafe { kgs_session_save_item(session, &draft, &mut saved, &mut error) };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));

    assert_eq!(text(&saved.title), "GitHub (work)");
    assert_eq!(saved.tags.len, 2);
    // SAFETY: `len` elements this library wrote.
    let saved_tags = unsafe { std::slice::from_raw_parts(saved.tags.ptr, saved.tags.len) };
    assert_eq!(text(&saved_tags[1]), "鍵");
    assert_eq!(saved.fields.len, 1);
    // SAFETY: as above.
    let field = unsafe { &*saved.fields.ptr };
    assert_eq!(field.concealed, 1);
    assert_eq!(
        field.value.present, 0,
        "a concealed value never rides along"
    );
    assert!(field.value.value.ptr.is_null(), "an absent value is zeroed");
    assert_eq!(
        saved.has_notes, 1,
        "the note is not on the view, only that it exists"
    );

    let field_id = text(&field.id);
    let gate = Gate::answering(KgsPresenceOutcome::Confirmed as u32);
    gate.install(session);
    assert_eq!(
        reveal(session, &id, &field_id),
        Ok("s3cret\0with a NUL".to_owned()),
        "a NUL is data, not an end marker"
    );

    // An absent description and an empty one: the core keeps neither, but the absent one must
    // not be read at all — its slice is deliberately garbage.
    let garbage = KgsOptSlice {
        present: 0,
        value: KgsSlice {
            ptr: std::ptr::dangling::<u8>(),
            len: 99,
        },
    };
    let mut env = std::mem::MaybeUninit::<KgsEnvironmentView>::uninit();
    // SAFETY: an absent optional's slice is never read, which is what is under test.
    let status = unsafe {
        kgs_session_create_environment(
            session,
            slice("Deploy"),
            garbage,
            env.as_mut_ptr(),
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok);
    // SAFETY: written on `Ok`.
    let mut env = unsafe { env.assume_init() };
    assert_eq!(env.description.present, 0);

    // SAFETY: records this library wrote, freed once each; the handle, freed once.
    unsafe {
        kgs_environment_view_free(&mut env);
        kgs_item_view_free(&mut saved);
        kgs_item_view_free(&mut item);
        kgs_session_free(session);
    }
}

// -------------------------------------------------------------------------------------------
// Enums
// -------------------------------------------------------------------------------------------

#[test]
fn an_unknown_enum_tag_is_invalid() {
    let recipe = KgsGeneratorRecipe {
        mode: 9,
        length: 20,
        words: 4,
        separator: 0,
        lowercase: 1,
        uppercase: 1,
        digits: 1,
        symbols: 0,
        avoid_ambiguous: 0,
        capitalize: 0,
        include_digit: 0,
    };
    let mut out = KgsBuffer::EMPTY;
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: locals.
    let status = unsafe { kgs_generate_password(&recipe, &mut out, &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(out.ptr.is_null());
    assert!(take(&mut error).contains("unknown generator mode"));

    let (_dir, _path, session) = vault();
    let filter = KgsItemFilter {
        tag: 42,
        value: slice(""),
    };
    let mut list = KgsItemViewArray::default();
    // SAFETY: a live handle; locals.
    let status =
        unsafe { kgs_session_list_items(session, &filter, NONE, 0, &mut list, &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("unknown item filter"));
    let filter = KgsItemFilter {
        tag: KgsItemFilterTag::All as u32,
        value: slice(""),
    };
    // SAFETY: as above.
    let status =
        unsafe { kgs_session_list_items(session, &filter, NONE, 77, &mut list, &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("unknown item sort"));
    // SAFETY: the handle, freed once.
    unsafe { kgs_session_free(session) };
}

#[test]
fn every_tag_round_trips_through_its_uniffi_enum() {
    for tag in 0..14 {
        let kind = KgsFieldKind::parse(tag).expect("a known field kind");
        assert_eq!(KgsFieldKind::tag(kind), tag);
    }
    assert!(KgsFieldKind::parse(14).is_err());
    for tag in 0..5 {
        assert_eq!(
            KgsImportFormat::tag(KgsImportFormat::parse(tag).unwrap()),
            tag
        );
    }
    assert!(KgsImportFormat::parse(5).is_err());
    for tag in 0..6 {
        assert_eq!(
            KgsApprovalAction::tag(KgsApprovalAction::parse(tag).unwrap()),
            tag
        );
    }
    assert_eq!(KgsApprovalAction::AgentFill as u32, 5);
    assert_eq!(KgsApprovalAction::CreateTestLogin as u32, 6);
    assert_eq!(KgsApprovalAction::StoreCommandOutput as u32, 7);
    assert!(KgsApprovalAction::parse(6).is_err());
}

// -------------------------------------------------------------------------------------------
// Lists and records coming out, and freeing them
// -------------------------------------------------------------------------------------------

#[test]
fn a_list_comes_out_whole_and_frees_to_zero_idempotently() {
    let (_dir, _path, session) = vault();
    for title in ["b", "a", "c"] {
        let mut item = create_item(session, "login", title);
        // SAFETY: a record this library wrote, freed once.
        unsafe { kgs_item_view_free(&mut item) };
    }
    let filter = KgsItemFilter {
        tag: KgsItemFilterTag::Category as u32,
        value: slice("login"),
    };
    let mut list = KgsItemViewArray::default();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe {
        kgs_session_list_items(
            session,
            &filter,
            NONE,
            KgsItemSort::Title as u32,
            &mut list,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok);
    // SAFETY: `len` elements this library wrote.
    let items = unsafe { std::slice::from_raw_parts(list.ptr, list.len) };
    let titles: Vec<String> = items.iter().map(|i| text(&i.title)).collect();
    assert_eq!(titles, ["a", "b", "c"]);
    assert!(items.iter().all(|i| i.fields.len > 0));

    // SAFETY: freed once, then again: the second must be a no-op.
    unsafe {
        kgs_item_view_array_free(&mut list);
        assert!(list.ptr.is_null() && list.len == 0 && list.cap == 0);
        kgs_item_view_array_free(&mut list);
        kgs_item_view_array_free(ptr::null_mut());
        kgs_session_free(session);
    }
}

#[test]
fn an_empty_list_is_readable_and_freeable() {
    let (_dir, _path, session) = vault();
    let mut list = KgsEnvironmentViewArray::default();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe { kgs_session_environments(session, &mut list, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(list.len, 0);
    // SAFETY: freed once; the handle, freed once.
    unsafe {
        kgs_environment_view_array_free(&mut list);
        kgs_session_free(session);
    }
}

#[test]
fn an_absent_optional_record_is_zeroed_so_it_can_be_freed_unconditionally() {
    let (_dir, _path, session) = vault();
    let mut details = std::mem::MaybeUninit::<KgsOptVaultConflictDetails>::uninit();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe { kgs_session_conflict_details(session, details.as_mut_ptr(), &mut error) };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    // SAFETY: written on `Ok`.
    let mut details = unsafe { details.assume_init() };
    assert_eq!(details.present, 0, "a fresh vault has no conflict");
    assert!(details.value.file_fingerprint.value.ptr.is_null());
    // SAFETY: a zeroed record is a valid argument to its free; the handle, freed once.
    unsafe {
        kgs_vault_conflict_details_free(&mut details.value);
        kgs_session_free(session);
    }
}

#[test]
fn a_nested_record_frees_every_level() {
    let mut setup = std::mem::MaybeUninit::<KgsExtensionSetup>::uninit();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: locals.
    let status =
        unsafe { kgs_extension_setup(some("Z:/nowhere/at/all"), setup.as_mut_ptr(), &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    // SAFETY: written on `Ok`.
    let mut setup = unsafe { setup.assume_init() };
    assert_eq!(text(&setup.host_name), "com.kagisecure.nmhost");
    assert!(setup.manifests.len > 0);
    // SAFETY: freed once.
    unsafe { kgs_extension_setup_free(&mut setup) };
    assert!(setup.manifests.ptr.is_null());
    assert!(setup.extension_id.ptr.is_null());
}

#[test]
fn bytes_cross_without_a_text_assumption_in_either_direction() {
    let (_dir, path, session) = vault();
    let mut key = KgsBuffer::EMPTY;
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe { kgs_session_export_vault_key(session, &mut key, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(key.len, 32);
    // SAFETY: the handle, freed once.
    unsafe { kgs_session_free(session) };

    let mut handle = ptr::null_mut();
    // SAFETY: `key` is live until freed below.
    let status = unsafe {
        kgs_session_unlock_with_vault_key(
            slice(&path),
            KgsSlice {
                ptr: key.ptr,
                len: key.len,
            },
            &mut handle,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok);
    // SAFETY: each freed once.
    unsafe {
        kgs_buffer_free(&mut key);
        kgs_session_free(handle);
    }
}

#[test]
fn verify_master_password_answers_for_the_session_in_memory_and_is_rate_limited() {
    let (_dir, path, session) = vault();
    let check = |password: &str| {
        let mut error = KgsBuffer::EMPTY;
        let mut out = KgsMasterPasswordCheck {
            tag: 99,
            retry_after_ms: 99,
        };
        // SAFETY: a live handle; locals.
        let status = unsafe {
            kgs_session_verify_master_password(session, slice(password), &mut out, &mut error)
        };
        assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
        out
    };
    let verified = check("right");
    assert_eq!(verified.tag, KgsMasterPasswordCheckTag::Verified as u32);
    assert_eq!(verified.retry_after_ms, 0);

    // The file going away (or being swapped) does not change the answer: nothing is read.
    std::fs::remove_file(&path).unwrap();
    let wrong = check("wrong");
    assert_eq!(wrong.tag, KgsMasterPasswordCheckTag::Wrong as u32);
    assert_eq!(
        wrong.retry_after_ms, 1000,
        "one second after the first failure"
    );

    // And the back-off crosses the ABI too: the right password is not even checked yet.
    let throttled = check("right");
    assert_eq!(throttled.tag, KgsMasterPasswordCheckTag::Throttled as u32);
    assert!(throttled.retry_after_ms > 0);
    // SAFETY: the handle, freed once.
    unsafe { kgs_session_free(session) };
}

#[test]
fn platform_slot_info_is_one_record_with_one_free() {
    let (_dir, path, session) = vault();
    let mut error = KgsBuffer::EMPTY;
    let mut id = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe { kgs_session_vault_file_id_bytes(session, &mut id, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(id.len, 16);
    let mut hex = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe { kgs_session_vault_file_id(session, &mut hex, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    // SAFETY: a live buffer.
    let raw = unsafe { std::slice::from_raw_parts(id.ptr, id.len) };
    let expected: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        take(&mut hex),
        expected,
        "the hex id and the raw id are one id"
    );

    let mut info = std::mem::MaybeUninit::<KgsPlatformSlotInfo>::uninit();
    // SAFETY: locals.
    let status = unsafe { kgs_platform_slot_info(slice(&path), info.as_mut_ptr(), &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    // SAFETY: written on `Ok`.
    let mut info = unsafe { info.assume_init() };
    // SAFETY: both buffers are live.
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(info.vault_id.ptr, info.vault_id.len).to_vec(),
            std::slice::from_raw_parts(id.ptr, id.len).to_vec(),
        )
    };
    assert_eq!(a, b, "the file's id is the session's id");
    assert_eq!(info.slot_id.present, 0);
    assert_eq!(info.wrapped_key.present, 0);
    // SAFETY: each freed once.
    unsafe {
        kgs_platform_slot_info_free(&mut info);
        kgs_buffer_free(&mut id);
        kgs_session_free(session);
    }
    assert!(info.vault_id.ptr.is_null());
}

// -------------------------------------------------------------------------------------------
// The agent, without starting it
// -------------------------------------------------------------------------------------------

#[test]
fn agent_calls_that_need_no_listener_follow_the_same_rules() {
    let mut error = KgsBuffer::EMPTY;
    let mut resolved = 1u8;
    let decision = KgsApprovalDecision {
        tag: KgsApprovalDecisionTag::Deny as u32,
        ttl_seconds: 0,
        uses: 0,
    };
    let verification = KgsClientVerification {
        verified: 0,
        evidence: slice(""),
    };
    // SAFETY: locals. The id is one the shared queue can never have minted.
    let status = unsafe {
        kgs_agent_resolve(
            slice("req-capi-test-no-such-request"),
            &decision,
            &verification,
            &mut resolved,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(resolved, 0, "an unknown id is `false`, not an error");

    let bad = KgsApprovalDecision { tag: 7, ..decision };
    // SAFETY: as above.
    let status = unsafe {
        kgs_agent_resolve(
            slice("req-capi-test-no-such-request"),
            &bad,
            &verification,
            &mut resolved,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("unknown approval decision"));

    // SAFETY: locals.
    let status = unsafe { kgs_agent_revoke_lease(slice("not-a-uuid"), &mut resolved, &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("not a lease id"));

    // SAFETY: a null out-parameter is what is under test.
    let status = unsafe { kgs_agent_status(ptr::null_mut(), &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("out-parameter"));
}

// -------------------------------------------------------------------------------------------
// The presence gate and the releases (ADR-0038)
// -------------------------------------------------------------------------------------------

/// A scripted presence check behind the C callback: answers `answer`, records every sentence it
/// was asked to show, and — when `fallback` is set — first checks that master password on the
/// session, from inside the callback, the way the Windows app's fallback does.
struct Gate {
    answer: u32,
    fallback: Option<&'static str>,
    session: std::sync::atomic::AtomicPtr<KgsSession>,
    reasons: std::sync::Mutex<Vec<String>>,
}

impl Gate {
    fn answering(answer: u32) -> &'static Self {
        Box::leak(Box::new(Self {
            answer,
            fallback: None,
            session: std::sync::atomic::AtomicPtr::new(ptr::null_mut()),
            reasons: std::sync::Mutex::new(Vec::new()),
        }))
    }

    fn with_fallback(password: &'static str) -> &'static Self {
        Box::leak(Box::new(Self {
            answer: KgsPresenceOutcome::Confirmed as u32,
            fallback: Some(password),
            session: std::sync::atomic::AtomicPtr::new(ptr::null_mut()),
            reasons: std::sync::Mutex::new(Vec::new()),
        }))
    }

    fn install(&'static self, session: *mut KgsSession) {
        assert_eq!(self.try_install(session), KgsStatus::Ok);
    }

    fn try_install(&'static self, session: *mut KgsSession) -> KgsStatus {
        self.session
            .store(session, std::sync::atomic::Ordering::SeqCst);
        let mut error = KgsBuffer::EMPTY;
        // SAFETY: `self` is leaked, so `context` outlives the session; `confirm` never unwinds
        // past its own `catch_unwind`.
        let status = unsafe {
            kgs_session_set_presence_gate(
                session,
                Some(confirm),
                ptr::from_ref(self).cast_mut().cast(),
                &mut error,
            )
        };
        if !error.ptr.is_null() {
            take(&mut error);
        }
        status
    }

    fn reasons(&self) -> Vec<String> {
        self.reasons.lock().unwrap().clone()
    }
}

unsafe extern "C" fn confirm(context: *mut std::ffi::c_void, reason: KgsSlice) -> u32 {
    std::panic::catch_unwind(|| {
        // SAFETY: the context `Gate::try_install` passed: a leaked `Gate`.
        let gate = unsafe { &*context.cast::<Gate>() };
        // SAFETY: Rust's own sentence, borrowed for this call.
        let reason = unsafe { reason.string() }.expect("the reason is UTF-8");
        gate.reasons.lock().unwrap().push(reason);
        if let Some(password) = gate.fallback {
            let session = gate.session.load(std::sync::atomic::Ordering::SeqCst);
            let mut out = KgsMasterPasswordCheck::default();
            let mut error = KgsBuffer::EMPTY;
            // SAFETY: the live session this gate was installed on, re-entered on the same thread
            // with no vault lock held (ADR-0038 §3).
            let status = unsafe {
                kgs_session_verify_master_password(session, slice(password), &mut out, &mut error)
            };
            if status != KgsStatus::Ok || out.tag != KgsMasterPasswordCheckTag::Verified as u32 {
                return KgsPresenceOutcome::Cancelled as u32;
            }
        }
        gate.answer
    })
    .unwrap_or(KgsPresenceOutcome::Cancelled as u32)
}

/// A login with one concealed field holding `secret`, and its item and field ids.
fn login_with_secret(session: *mut KgsSession, secret: &str) -> (String, String, String) {
    let mut item = create_item(session, "login", "GitHub");
    let id = text(&item.id);
    let revision = text(&item.revision);
    let fields = [KgsFieldDraft {
        id: NONE,
        label: slice("password"),
        kind: KgsFieldKind::Concealed as u32,
        concealed: 1,
        value: some(secret),
        section: NONE,
        agent_visible: 0,
    }];
    let draft = KgsItemDraft {
        id: slice(&id),
        category: slice("login"),
        title: slice("GitHub"),
        fields: KgsFieldDraftList {
            ptr: fields.as_ptr(),
            len: fields.len(),
        },
        tags: KgsSliceList {
            ptr: ptr::null(),
            len: 0,
        },
        urls: KgsSliceList {
            ptr: ptr::null(),
            len: 0,
        },
        notes: some("recovery words"),
        revision: slice(&revision),
    };
    let mut saved = KgsItemView::default();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: every slice and list borrows a local that outlives the call.
    let status = unsafe { kgs_session_save_item(session, &draft, &mut saved, &mut error) };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    // SAFETY: one field, written by this library.
    let field_id = text(&unsafe { &*saved.fields.ptr }.id);
    let revision = text(&saved.revision);
    // SAFETY: records this library wrote, freed once each.
    unsafe {
        kgs_item_view_free(&mut saved);
        kgs_item_view_free(&mut item);
    }
    (id, field_id, revision)
}

/// Release a field for `Reveal` and read it: the value, or the status that refused it.
fn reveal(session: *mut KgsSession, item: &str, field: &str) -> Result<String, KgsStatus> {
    let mut release = ptr::null_mut();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe {
        kgs_session_release_field(
            session,
            slice(item),
            slice(field),
            KgsReleasePurpose::Reveal as u32,
            &mut release,
            &mut error,
        )
    };
    if status != KgsStatus::Ok {
        assert!(release.is_null(), "no handle is written on failure");
        take(&mut error);
        return Err(status);
    }
    let mut value = KgsBuffer::EMPTY;
    // SAFETY: the handle just written.
    let status = unsafe { kgs_field_release_value(release, &mut value, &mut error) };
    // SAFETY: freed once.
    unsafe { kgs_field_release_free(release) };
    if status == KgsStatus::Ok {
        Ok(take(&mut value))
    } else {
        take(&mut error);
        Err(status)
    }
}

#[test]
fn with_no_gate_installed_nothing_is_released_and_nobody_is_asked() {
    let (_dir, _path, session) = vault();
    let (item, field, _) = login_with_secret(session, "canary-no-gate");
    assert_eq!(
        reveal(session, &item, &field),
        Err(KgsStatus::NoPresenceGate)
    );

    // A null callback installs nothing: still no gate, still no release.
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a null function pointer is what is under test.
    let status =
        unsafe { kgs_session_set_presence_gate(session, None, ptr::null_mut(), &mut error) };
    assert_eq!(status, KgsStatus::Invalid);
    assert!(take(&mut error).contains("null"));
    assert_eq!(
        reveal(session, &item, &field),
        Err(KgsStatus::NoPresenceGate)
    );

    let mut notes = ptr::null_mut();
    // SAFETY: a live handle; locals.
    let status = unsafe {
        kgs_session_release_notes(
            session,
            slice(&item),
            KgsReleasePurpose::Reveal as u32,
            &mut notes,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::NoPresenceGate);
    assert!(notes.is_null());
    take(&mut error);
    // SAFETY: the handle, freed once.
    unsafe { kgs_session_free(session) };
}

#[test]
fn only_a_confirmed_answer_releases_and_an_unknown_answer_is_a_cancel() {
    for (answer, expected) in [
        (
            KgsPresenceOutcome::Cancelled as u32,
            KgsStatus::PresenceCancelled,
        ),
        (
            KgsPresenceOutcome::Unavailable as u32,
            KgsStatus::PresenceUnavailable,
        ),
        (KgsPresenceOutcome::Busy as u32, KgsStatus::PresenceBusy),
        (77, KgsStatus::PresenceCancelled),
        (u32::MAX, KgsStatus::PresenceCancelled),
    ] {
        let (_dir, _path, session) = vault();
        let (item, field, _) = login_with_secret(session, "canary-refused");
        let gate = Gate::answering(answer);
        gate.install(session);
        assert_eq!(reveal(session, &item, &field), Err(expected), "{answer}");
        assert_eq!(gate.reasons().len(), 1, "asked exactly once");
        // SAFETY: the handle, freed once.
        unsafe { kgs_session_free(session) };
    }
}

#[test]
fn the_callback_is_shown_rusts_sentence_and_a_second_gate_is_refused() {
    let (_dir, _path, session) = vault();
    let (item, field, _) = login_with_secret(session, "canary-sentence");
    let first = Gate::answering(KgsPresenceOutcome::Cancelled as u32);
    first.install(session);
    let second = Gate::answering(KgsPresenceOutcome::Confirmed as u32);
    assert_eq!(
        second.try_install(session),
        KgsStatus::Invalid,
        "a gate that always says yes cannot replace the first"
    );
    assert_eq!(
        reveal(session, &item, &field),
        Err(KgsStatus::PresenceCancelled)
    );
    assert!(second.reasons().is_empty());
    let reasons = first.reasons();
    assert_eq!(reasons.len(), 1);
    assert!(
        reasons[0].contains("“GitHub”") && reasons[0].contains("Continue only if"),
        "{}",
        reasons[0]
    );
    // SAFETY: the handle, freed once.
    unsafe { kgs_session_free(session) };
}

#[test]
fn a_release_reads_the_vault_and_ends_at_lock() {
    let (_dir, _path, session) = vault();
    let (item, field, _) = login_with_secret(session, "canary-lock");
    Gate::answering(KgsPresenceOutcome::Confirmed as u32).install(session);

    let mut release = ptr::null_mut();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe {
        kgs_session_release_field(
            session,
            slice(&item),
            slice(&field),
            KgsReleasePurpose::Reveal as u32,
            &mut release,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    let mut state = KgsReleaseState::default();
    // SAFETY: a live release; locals.
    let status = unsafe { kgs_field_release_state(release, &mut state, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(state.is_live, 1);
    assert_eq!(state.purpose, KgsReleasePurpose::Reveal as u32);
    assert!(state.seconds_remaining > 0 && state.seconds_remaining <= 300);

    // SAFETY: a live handle.
    assert_eq!(
        unsafe { kgs_session_lock(session, &mut error) },
        KgsStatus::Ok
    );
    let mut unlocked = 1u8;
    // SAFETY: a live handle; locals.
    let status = unsafe { kgs_session_is_unlocked(session, &mut unlocked, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(unlocked, 0);

    let mut value = KgsBuffer::EMPTY;
    // SAFETY: the release is still a live handle; only the vault behind it is gone.
    let status = unsafe { kgs_field_release_value(release, &mut value, &mut error) };
    assert_ne!(status, KgsStatus::Ok, "nothing is read after the lock");
    assert!(value.ptr.is_null());
    assert!(!take(&mut error).contains("canary-lock"));
    // SAFETY: each freed once.
    unsafe {
        kgs_field_release_free(release);
        kgs_session_free(session);
    }
}

#[test]
fn a_totp_and_a_notes_release_cross_the_abi() {
    let (_dir, _path, session) = vault();
    let (item, _, _) = login_with_secret(session, "canary-notes");
    Gate::answering(KgsPresenceOutcome::Confirmed as u32).install(session);

    let mut notes = ptr::null_mut();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe {
        kgs_session_release_notes(
            session,
            slice(&item),
            KgsReleasePurpose::Reveal as u32,
            &mut notes,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    let mut text_out = KgsBuffer::EMPTY;
    // SAFETY: the release just written.
    let status = unsafe { kgs_notes_release_text(notes, &mut text_out, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(take(&mut text_out), "recovery words");
    // A shown value can be copied once more without a new touch.
    // SAFETY: as above.
    let status = unsafe { kgs_notes_release_copy_shown_text(notes, &mut text_out, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    assert_eq!(take(&mut text_out), "recovery words");
    // SAFETY: as above.
    assert_eq!(
        unsafe { kgs_notes_release_close(notes, &mut error) },
        KgsStatus::Ok
    );
    // SAFETY: as above.
    let status = unsafe { kgs_notes_release_text(notes, &mut text_out, &mut error) };
    assert_eq!(status, KgsStatus::ReleaseEnded);
    take(&mut error);

    // The login has no one-time password: refused before anyone is asked.
    let mut totp = ptr::null_mut();
    // SAFETY: a live handle; locals.
    let status = unsafe {
        kgs_session_release_totp(
            session,
            slice(&item),
            NONE,
            KgsReleasePurpose::Reveal as u32,
            &mut totp,
            &mut error,
        )
    };
    assert_eq!(status, KgsStatus::NotPresent);
    assert!(totp.is_null());
    take(&mut error);
    // SAFETY: each freed once.
    unsafe {
        kgs_notes_release_free(notes);
        kgs_session_free(session);
    }
}

#[test]
fn the_master_password_fallback_runs_inside_the_callback_and_is_audited_as_such() {
    let (_dir, _path, session) = vault();
    let (item, field, _) = login_with_secret(session, "canary-fallback");
    Gate::with_fallback("right").install(session);
    assert_eq!(
        reveal(session, &item, &field),
        Ok("canary-fallback".to_owned())
    );

    let mut rows = KgsAuditRowArray::default();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: a live handle; locals.
    let status = unsafe { kgs_session_audit_page(session, 20, 0, &mut rows, &mut error) };
    assert_eq!(status, KgsStatus::Ok);
    // SAFETY: `len` rows this library wrote.
    let rows_slice = unsafe { std::slice::from_raw_parts(rows.ptr, rows.len) };
    assert!(
        rows_slice.iter().any(|row| row.detail.present == 1
            && text(&row.detail.value) == "PRESENCE_CONFIRMED_MASTER_PASSWORD"),
        "the grant says which password was typed"
    );
    // SAFETY: each freed once.
    unsafe {
        kgs_audit_row_array_free(&mut rows);
        kgs_session_free(session);
    }
}

#[test]
fn an_edit_that_sends_no_value_keeps_the_stored_one_and_a_stale_delete_is_refused() {
    let (_dir, _path, session) = vault();
    let (item, field, revision) = login_with_secret(session, "canary-kept");
    let fields = [KgsFieldDraft {
        id: some(&field),
        label: slice("password"),
        kind: KgsFieldKind::Concealed as u32,
        concealed: 1,
        value: NONE,
        section: NONE,
        agent_visible: 0,
    }];
    let draft = KgsItemDraft {
        id: slice(&item),
        category: slice("login"),
        title: slice("GitHub, renamed"),
        fields: KgsFieldDraftList {
            ptr: fields.as_ptr(),
            len: fields.len(),
        },
        tags: KgsSliceList {
            ptr: ptr::null(),
            len: 0,
        },
        urls: KgsSliceList {
            ptr: ptr::null(),
            len: 0,
        },
        notes: NONE,
        revision: slice(&revision),
    };
    let mut saved = KgsItemView::default();
    let mut error = KgsBuffer::EMPTY;
    // SAFETY: every slice and list borrows a local that outlives the call.
    let status = unsafe { kgs_session_save_item(session, &draft, &mut saved, &mut error) };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    assert_eq!(saved.has_notes, 1, "an absent note keeps the stored one");
    let fresh = text(&saved.revision);

    // The same draft again is stale now: the item changed since `revision` was read.
    // SAFETY: as above.
    let status = unsafe { kgs_session_save_item(session, &draft, &mut saved, &mut error) };
    assert_eq!(status, KgsStatus::ItemChangedElsewhere);
    take(&mut error);

    Gate::answering(KgsPresenceOutcome::Confirmed as u32).install(session);
    assert_eq!(reveal(session, &item, &field), Ok("canary-kept".to_owned()));

    // Delete for good needs the item in the Trash and at the revision the row showed.
    let mut trashed = KgsItemView::default();
    // SAFETY: a live handle; locals.
    let status =
        unsafe { kgs_session_set_trashed(session, slice(&item), 1, &mut trashed, &mut error) };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    // SAFETY: as above.
    let status =
        unsafe { kgs_session_delete_item(session, slice(&item), slice(&fresh), &mut error) };
    assert_eq!(
        status,
        KgsStatus::ItemChangedElsewhere,
        "trashing changed it"
    );
    take(&mut error);
    let current = text(&trashed.revision);
    // SAFETY: as above.
    let status =
        unsafe { kgs_session_delete_item(session, slice(&item), slice(&current), &mut error) };
    assert_eq!(status, KgsStatus::Ok, "{}", take(&mut error));
    // SAFETY: each freed once.
    unsafe {
        kgs_item_view_free(&mut trashed);
        kgs_item_view_free(&mut saved);
        kgs_session_free(session);
    }
}
