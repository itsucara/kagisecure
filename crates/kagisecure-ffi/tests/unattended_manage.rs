//! The app's calls for unattended jobs (ADR-0042 Phase 3), over a real personal vault: copying an
//! environment in, creating a job with its grant in one step, the overview, re-approval by a
//! copy, revoking, the summary and its acknowledgement.

use kagisecure_ffi::{
    FieldDraft, ItemDraft, UnattendedJobDraft, UnattendedLoginDraft, UnattendedPresence,
    UnattendedTimeView, VaultSession, unattended_acknowledge_summary, unattended_audit_page,
    unattended_copy_environment, unattended_copy_login, unattended_create_job,
    unattended_login_grants, unattended_machine_logins, unattended_overview,
    unattended_reenable_grant, unattended_revoke_job, unattended_summary,
};

const VALUE: &str = "machine-copy-canary-51a7";

fn personal(dir: &std::path::Path) -> std::sync::Arc<VaultSession> {
    let path = dir.join("personal.kagivault");
    VaultSession::create(
        path.to_string_lossy().into_owned(),
        "pw".to_owned(),
        "Personal".to_owned(),
        Some(64),
        Some(1),
    )
    .expect("create")
}

fn draft(env: &str, dir: &std::path::Path) -> UnattendedJobDraft {
    UnattendedJobDraft {
        name: "Nightly deploy".to_owned(),
        program: "/bin/sh".to_owned(),
        arguments: vec!["-c".to_owned(), "true".to_owned()],
        working_dir: dir.to_string_lossy().into_owned(),
        schedule: vec![UnattendedTimeView {
            weekday: None,
            hour: 2,
            minute: 30,
        }],
        environment_id: env.to_owned(),
        variables: Vec::new(),
        command: None,
        command_arguments: None,
        expires_in_days: 0,
        run_browser: None,
        logins: Vec::new(),
    }
}

#[test]
fn an_environment_is_copied_and_a_job_created_with_its_grant_in_one_step() {
    let dir = tempfile::tempdir().expect("tempdir");
    let session = personal(dir.path());
    let env = session
        .create_environment("deploy".to_owned(), None)
        .expect("env");
    session
        .set_variable_value(env.id.clone(), "TOKEN".to_owned(), VALUE.to_owned())
        .expect("value");

    let empty = unattended_overview(session.clone()).expect("overview");
    assert!(!empty.has_machine_vault);

    let machine_env = unattended_copy_environment(
        session.clone(),
        env.id.clone(),
        UnattendedPresence::Confirmed,
    )
    .expect("copy");
    let job = unattended_create_job(
        session.clone(),
        draft(&machine_env, dir.path()),
        UnattendedPresence::Confirmed,
    )
    .expect("job");

    let overview = unattended_overview(session.clone()).expect("overview");
    assert!(overview.has_machine_vault);
    assert_eq!(overview.environments.len(), 1);
    assert_eq!(overview.environments[0].variable_names, ["TOKEN"]);
    assert_eq!(
        overview.environments[0].copied_from.as_deref(),
        Some(env.id.as_str())
    );
    assert_eq!(overview.jobs.len(), 1);
    let listed = &overview.jobs[0];
    assert_eq!(listed.id, job);
    assert_eq!(listed.grants.len(), 1, "the grant came with the job");
    let grant = &listed.grants[0];
    assert_eq!(grant.command, "/bin/sh");
    assert_eq!(grant.arguments, ["-c", "true"]);
    assert_eq!(grant.variables, ["TOKEN"]);
    assert_eq!(grant.total_uses, 60);
    assert!(grant.suspended_reason.is_none());

    // Copying again updates the copy in place: one environment, still one grant, no suspension.
    let again = unattended_copy_environment(
        session.clone(),
        env.id.clone(),
        UnattendedPresence::Confirmed,
    )
    .expect("copy again");
    assert_eq!(again, machine_env);
    assert_eq!(
        unattended_overview(session.clone())
            .expect("overview")
            .environments
            .len(),
        1
    );

    // The machine log names the decisions and never the value.
    let rows = unattended_audit_page(session.clone(), 50, 0).expect("log");
    assert!(rows.iter().any(|r| {
        r.detail
            .as_deref()
            .is_some_and(|d| d.starts_with("JOB_CREATED"))
    }));
    assert!(!format!("{rows:?}").contains(VALUE));

    // The person's own decisions are not "While you were away".
    let summary = unattended_summary(session.clone()).expect("summary");
    assert_eq!(summary.total, 0, "{summary:?}");
    unattended_acknowledge_summary(session.clone()).expect("ack");
    assert_eq!(
        unattended_summary(session.clone()).expect("summary").total,
        0
    );

    // Revoking needs nothing and takes the grant with the job.
    assert!(unattended_revoke_job(session.clone(), job.clone()).expect("revoke"));
    assert!(
        unattended_overview(session.clone())
            .expect("overview")
            .jobs
            .is_empty()
    );
    assert!(!unattended_revoke_job(session, job).expect("again"));
}

#[test]
fn a_job_needs_full_paths_and_a_real_folder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let session = personal(dir.path());
    let env = session
        .create_environment("deploy".to_owned(), None)
        .expect("env");
    session
        .set_variable_value(env.id.clone(), "TOKEN".to_owned(), VALUE.to_owned())
        .expect("value");
    let machine_env =
        unattended_copy_environment(session.clone(), env.id, UnattendedPresence::Confirmed)
            .expect("copy");

    let mut relative = draft(&machine_env, dir.path());
    relative.program = "sh".to_owned();
    assert!(
        unattended_create_job(session.clone(), relative, UnattendedPresence::Confirmed).is_err()
    );
    let mut missing = draft(&machine_env, dir.path());
    missing.working_dir = dir.path().join("nowhere").to_string_lossy().into_owned();
    assert!(
        unattended_create_job(session.clone(), missing, UnattendedPresence::Confirmed).is_err()
    );
    let mut no_env = draft(&machine_env, dir.path());
    no_env.environment_id = "00000000-0000-4000-8000-000000000000".to_owned();
    assert!(unattended_create_job(session, no_env, UnattendedPresence::Confirmed).is_err());
}

// -------------------------------------------------------------------------------------------------
// Unattended sign-ins (ADR-0042 §12, Phase 5)
// -------------------------------------------------------------------------------------------------

const LOGIN_PASSWORD: &str = "machine-login-canary-9c3e";

/// A personal login saved for `https://service.example/login` and a plain http site.
fn personal_login(session: &VaultSession) -> String {
    let created = session
        .create_item(None, "login".to_owned(), "Service bot".to_owned())
        .expect("create");
    let fields = created
        .fields
        .iter()
        .map(|f| FieldDraft {
            id: Some(f.id.clone()),
            label: f.label.clone(),
            kind: f.kind,
            concealed: f.concealed,
            value: Some(match f.label.as_str() {
                "password" => LOGIN_PASSWORD.to_owned(),
                "username" => "bot".to_owned(),
                _ => String::new(),
            }),
            section: f.section.clone(),
            agent_visible: f.agent_visible,
        })
        .collect();
    session
        .save_item(ItemDraft {
            id: created.id.clone(),
            category: created.category.clone(),
            title: created.title.clone(),
            fields,
            tags: Vec::new(),
            urls: vec![
                "https://service.example/login".to_owned(),
                "http://plain.example".to_owned(),
            ],
            notes: None,
            revision: created.revision.clone(),
        })
        .expect("save")
        .id
}

#[test]
fn a_login_is_copied_in_and_a_job_that_only_signs_in_is_created_with_its_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let session = personal(dir.path());
    let personal_item = personal_login(&session);

    let machine_item = unattended_copy_login(
        session.clone(),
        personal_item.clone(),
        UnattendedPresence::Confirmed,
    )
    .expect("copy");
    let logins = unattended_machine_logins(session.clone()).expect("logins");
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].id, machine_item);
    assert_eq!(logins[0].username.as_deref(), Some("bot"));
    assert_eq!(
        logins[0].origins,
        ["https://service.example"],
        "https only, exact"
    );
    assert_eq!(
        logins[0].copied_from.as_deref(),
        Some(personal_item.as_str())
    );

    // A job with no environment and one login: the run browser is pinned as the job's.
    let mut sign_in = draft("", dir.path());
    sign_in.run_browser = Some("/bin/sh".to_owned());
    sign_in.logins = vec![UnattendedLoginDraft {
        item_id: machine_item.clone(),
        origin: "https://service.example".to_owned(),
        follow_on_origins: Vec::new(),
        one_time_codes: false,
    }];
    let job = unattended_create_job(
        session.clone(),
        sign_in.clone(),
        UnattendedPresence::Confirmed,
    )
    .expect("job");
    let grants = unattended_login_grants(session.clone()).expect("grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].job_id, job);
    assert_eq!(grants[0].origin, "https://service.example");
    assert_eq!(grants[0].fields, ["username", "password"]);
    assert!(!grants[0].one_time_codes);
    let overview = unattended_overview(session.clone()).expect("overview");
    assert!(overview.jobs[0].grants.is_empty(), "no command grant");

    // Copying again updates the one copy; its grant stays and is re-approved, not suspended.
    let again = unattended_copy_login(
        session.clone(),
        personal_item,
        UnattendedPresence::Confirmed,
    )
    .expect("again");
    assert_eq!(again, machine_item);
    assert_eq!(
        unattended_machine_logins(session.clone())
            .expect("logins")
            .len(),
        1
    );
    assert!(
        unattended_login_grants(session.clone()).expect("grants")[0]
            .suspended_reason
            .is_none()
    );

    // Codes need the login to have a one-time password; an origin must be one of its websites.
    let mut codes = sign_in.clone();
    codes.logins[0].one_time_codes = true;
    assert!(unattended_create_job(session.clone(), codes, UnattendedPresence::Confirmed).is_err());
    let mut elsewhere = sign_in.clone();
    elsewhere.logins[0].origin = "https://other.example".to_owned();
    assert!(
        unattended_create_job(session.clone(), elsewhere, UnattendedPresence::Confirmed).is_err()
    );
    // Nothing at all to do is refused.
    let mut nothing = sign_in;
    nothing.logins.clear();
    assert!(
        unattended_create_job(session.clone(), nothing, UnattendedPresence::Confirmed).is_err()
    );

    // Re-enabling a login grant that is not suspended does nothing.
    assert!(
        !unattended_reenable_grant(
            session.clone(),
            grants[0].id.clone(),
            UnattendedPresence::Confirmed
        )
        .expect("reenable")
    );

    // The logs name the decisions, never the password.
    let rows = unattended_audit_page(session.clone(), 50, 0).expect("log");
    assert!(rows.iter().any(|r| {
        r.detail
            .as_deref()
            .is_some_and(|d| d.starts_with("LOGIN_COPIED"))
    }));
    assert!(rows.iter().any(|r| {
        r.detail
            .as_deref()
            .is_some_and(|d| d.starts_with("LOGIN_GRANT_CREATED"))
    }));
    assert!(!format!("{rows:?}").contains(LOGIN_PASSWORD));
    assert!(!format!("{:?}", session.audit_page(50, 0)).contains(LOGIN_PASSWORD));
}
