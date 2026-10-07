//! End to end on one machine: a bundle made as the Mac makes it, imported as a host imports it,
//! and requests answered — over the engine directly and over the socket.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use kagisecure_core::vault::machine::{ExecutablePin, PresencePath, file_sha256};
use kagisecure_host::bundle::{self, BundleContents, BundleEnvironment, BundleVariable, Value};
use kagisecure_host::engine::Engine;
use kagisecure_host::grant::{ArgPattern, HostGrant};
use kagisecure_host::identity;
use kagisecure_host::protocol::{Request, Response};
use kagisecure_host::spec::GrantsFile;
use kagisecure_host::store::Store;
use kagisecure_shared::DeviceSecret;

/// The deploy key stand-in. Searched for everywhere it must not be.
const CANARY: &str =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nkgs-canary-7f3a9c\n-----END OPENSSH PRIVATE KEY-----";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const VAR: &str = "ITSUSTAR_DEPLOY_SSH_KEY";

/// Records what it was given: standard input (to a file only), its environment, its arguments.
/// Echoes its input to standard output, so masking is tested too.
const SCRIPT: &str = r#"#!/bin/sh
out="$(dirname "$0")/out"
cat > "$out/stdin"
env > "$out/env"
printf '%s\n' "$@" > "$out/argv"
cat "$out/stdin"
echo "deployed $2"
"#;

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    script: PathBuf,
    owner: DeviceSecret,
    host_public: kagisecure_shared::DevicePublic,
    sequence: u64,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let state = root.join("state");
        let work = root.join("work");
        std::fs::create_dir_all(work.join("out")).unwrap();
        let script = work.join("deploy");
        std::fs::write(&script, SCRIPT).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let store = Store::new(&state);
        store.ensure_dir().unwrap();
        let host = identity::create(&state).unwrap();
        let owner = DeviceSecret::generate().unwrap();
        identity::trust_owner(&state, owner.public()).unwrap();
        Self {
            _tmp: tmp,
            root,
            state,
            script,
            owner,
            host_public: host.public().clone(),
            sequence: 0,
        }
    }

    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    fn engine(&self) -> Engine {
        Engine::new(Store::new(&self.state))
    }

    fn grant(&self) -> HostGrant {
        let now = kagisecure_core::unix_now();
        HostGrant {
            name: "deploy-staging".to_owned(),
            environment: "app-deploy".to_owned(),
            variables: vec![VAR.to_owned()],
            executable: kagisecure_core::vault::machine::PinnedExecutable {
                path: self.script.display().to_string(),
                pin: ExecutablePin::Sha256(file_sha256(&self.script).unwrap().to_vec()),
            },
            args: vec![
                ArgPattern::Literal("staging".to_owned()),
                ArgPattern::CommitSha,
                ArgPattern::Literal("--key-from-stdin".to_owned()),
            ],
            working_dir: self.work().display().to_string(),
            run_as: None,
            timeout_secs: 30,
            limits: kagisecure_core::vault::machine::GrantLimits {
                per_run: 1,
                total_uses: 3,
                expires_at: now + 3600,
            },
            created_at: now,
        }
    }

    fn contents(&self, grants: Vec<HostGrant>) -> BundleContents {
        BundleContents {
            v: bundle::CONTENTS_VERSION,
            host_name: "build-1".to_owned(),
            created_at: kagisecure_core::unix_now(),
            presence: PresencePath::ConfirmedMasterPassword,
            environments: vec![BundleEnvironment {
                name: "app-deploy".to_owned(),
                variables: vec![BundleVariable {
                    name: VAR.to_owned(),
                    value: Value::new(CANARY.as_bytes().to_vec()),
                }],
            }],
            grants,
        }
    }

    fn make(&mut self, signer: &DeviceSecret, contents: &BundleContents) -> Vec<u8> {
        self.sequence += 1;
        bundle::make(signer, &self.host_public, self.sequence, contents).unwrap()
    }

    fn import_default(&mut self) {
        let contents = self.contents(vec![self.grant()]);
        let owner =
            DeviceSecret::from_device_key(&self.owner.to_device_key("o", 0).unwrap()).unwrap();
        let bytes = self.make(&owner, &contents);
        self.engine().import(&bytes).unwrap();
    }

    fn request(&self, args: &[&str]) -> Request {
        let mut argv = vec![self.script.display().to_string()];
        argv.extend(args.iter().map(|s| (*s).to_owned()));
        Request {
            grant: "deploy-staging".to_owned(),
            argv,
            cwd: self.work().display().to_string(),
        }
    }

    fn good(&self) -> Request {
        self.request(&["staging", COMMIT, "--key-from-stdin"])
    }

    fn out(&self, name: &str) -> String {
        std::fs::read_to_string(self.work().join("out").join(name)).unwrap_or_default()
    }
}

fn reason(r: &Response) -> &str {
    match r {
        Response::Refused { reason, .. } => reason,
        Response::Ran { .. } => "RAN",
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Every file under `dir`, recursively.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn the_key_reaches_the_command_on_stdin_and_nowhere_else() {
    let mut f = Fixture::new();
    f.import_default();
    let response = f.engine().handle(&f.good());
    let Response::Ran {
        exit_code,
        stdout,
        stderr,
        timed_out,
    } = &response
    else {
        panic!("refused: {response:?}");
    };
    assert_eq!(*exit_code, Some(0), "stderr: {stderr}");
    assert!(!timed_out);

    // The command got exactly the ADR-0047 frame on its standard input.
    assert_eq!(f.out("stdin"), format!("{VAR}\0{CANARY}\0"));
    assert_eq!(
        f.out("argv"),
        format!("staging\n{COMMIT}\n--key-from-stdin\n")
    );

    // Canary sweep: not in the child's environment, not in the response, and not in any file
    // the host keeps — audit log, state, the bundle at rest.
    assert!(
        !f.out("env").contains("kgs-canary"),
        "the key is in the environment"
    );
    let json = serde_json::to_string(&response).unwrap();
    assert!(!json.contains("kgs-canary"), "the key came back: {json}");
    assert!(stdout.contains("[kagisecure:redacted:"), "masked: {stdout}");
    assert!(stdout.contains(&format!("deployed {COMMIT}")));
    for path in files(&f.state) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !contains(&bytes, "kgs-canary"),
            "the key is in {}",
            path.display()
        );
    }
    let audit = Store::new(&f.state).audit_lines().unwrap();
    assert!(audit.iter().any(|l| l.contains("\"RELEASED\"")));
    assert!(audit.iter().any(|l| l.contains("\"FINISHED\"")));
}

#[test]
fn a_commit_that_is_not_forty_hex_is_a_strike_and_suspends() {
    let mut f = Fixture::new();
    f.import_default();
    for bad in ["HEAD", "0123456", "--upload-pack=evil"] {
        let mut f2 = Fixture::new();
        f2.import_default();
        let r = f2
            .engine()
            .handle(&f2.request(&["staging", bad, "--key-from-stdin"]));
        assert_eq!(reason(&r), "ARGUMENTS_MISMATCH", "{bad}");
        assert_eq!(reason(&f2.engine().handle(&f2.good())), "SUSPENDED");
        assert!(f2.out("stdin").is_empty(), "nothing ran");
    }
    // An extra argument, a missing one, another target.
    for args in [
        vec![
            "staging",
            COMMIT,
            "--key-from-stdin",
            "--force-during-calls",
        ],
        vec!["staging", COMMIT],
        vec!["prod", COMMIT, "--key-from-stdin"],
    ] {
        let mut f2 = Fixture::new();
        f2.import_default();
        assert_eq!(
            reason(&f2.engine().handle(&f2.request(&args))),
            "ARGUMENTS_MISMATCH"
        );
    }
    assert_eq!(reason(&f.engine().handle(&f.good())), "RAN");
}

#[test]
fn another_working_directory_or_executable_is_a_strike() {
    let mut f = Fixture::new();
    f.import_default();
    let mut r = f.good();
    r.cwd = f.root.display().to_string();
    assert_eq!(reason(&f.engine().handle(&r)), "CWD_MISMATCH");

    let mut f = Fixture::new();
    f.import_default();
    let mut r = f.good();
    r.argv[0] = "/bin/sh".to_owned();
    assert_eq!(reason(&f.engine().handle(&r)), "EXECUTABLE_MISMATCH");
    assert_eq!(reason(&f.engine().handle(&f.good())), "SUSPENDED");
}

#[test]
fn a_changed_executable_suspends_until_a_new_bundle() {
    let mut f = Fixture::new();
    f.import_default();
    std::fs::write(&f.script, format!("{SCRIPT}\necho changed\n")).unwrap();
    assert_eq!(reason(&f.engine().handle(&f.good())), "PIN_CHANGED");
    assert!(f.out("stdin").is_empty(), "nothing ran");
    // Restoring the file does not lift the suspension: only the owner does.
    std::fs::write(&f.script, SCRIPT).unwrap();
    assert_eq!(reason(&f.engine().handle(&f.good())), "SUSPENDED");
    // A new bundle (the owner re-approving) does.
    f.import_default();
    assert_eq!(reason(&f.engine().handle(&f.good())), "RAN");
}

#[test]
fn unknown_grants_expired_grants_and_used_up_grants_are_refused() {
    let mut f = Fixture::new();
    f.import_default();
    let mut r = f.good();
    r.grant = "deploy-prod".to_owned();
    assert_eq!(reason(&f.engine().handle(&r)), "NO_SUCH_GRANT");
    for _ in 0..3 {
        assert_eq!(reason(&f.engine().handle(&f.good())), "RAN");
    }
    assert_eq!(reason(&f.engine().handle(&f.good())), "USED_UP");

    let mut f = Fixture::new();
    let mut g = f.grant();
    g.created_at -= 7200;
    g.limits.expires_at = kagisecure_core::unix_now() - 1;
    let contents = f.contents(vec![g]);
    let owner = DeviceSecret::from_device_key(&f.owner.to_device_key("o", 0).unwrap()).unwrap();
    let bytes = f.make(&owner, &contents);
    f.engine().import(&bytes).unwrap();
    assert_eq!(reason(&f.engine().handle(&f.good())), "EXPIRED");
}

#[test]
fn import_refuses_tampering_strangers_replays_and_bad_contents() {
    let mut f = Fixture::new();
    let owner = DeviceSecret::from_device_key(&f.owner.to_device_key("o", 0).unwrap()).unwrap();
    let contents = f.contents(vec![f.grant()]);
    let good = f.make(&owner, &contents);

    let mut tampered = good.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x40;
    assert!(f.engine().import(&tampered).is_err(), "tampered accepted");

    let stranger = DeviceSecret::generate().unwrap();
    let foreign = f.make(&stranger, &contents);
    let err = f.engine().import(&foreign).unwrap_err().to_string();
    assert!(err.contains("does not trust"), "{err}");

    f.engine().import(&good).unwrap();
    let err = f.engine().import(&good).unwrap_err().to_string();
    assert!(err.contains("not newer"), "{err}");

    // A bundle whose grant releases a variable it does not carry never leaves the Mac.
    let mut g = f.grant();
    g.variables = vec!["OTHER".to_owned()];
    assert!(bundle::make(&owner, &f.host_public, 99, &f.contents(vec![g])).is_err());
    // Nor one pinning by code signature.
    let mut g = f.grant();
    g.executable.pin = ExecutablePin::CodeSigning {
        team_id: "T".to_owned(),
        signing_id: "S".to_owned(),
    };
    assert!(bundle::make(&owner, &f.host_public, 99, &f.contents(vec![g])).is_err());

    // The refused imports changed nothing: the good bundle still answers.
    assert_eq!(reason(&f.engine().handle(&f.good())), "RAN");
}

#[test]
fn a_swapped_bundle_file_on_disk_is_refused() {
    let mut f = Fixture::new();
    f.import_default();
    let mut bytes = std::fs::read(f.state.join("bundle.kgsb")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(f.state.join("bundle.kgsb"), bytes).unwrap();
    assert_eq!(reason(&f.engine().handle(&f.good())), "NO_BUNDLE");
}

#[test]
fn the_socket_answers_and_accepts_nothing_but_a_run_request() {
    let mut f = Fixture::new();
    f.import_default();
    let socket = f.root.join("host.sock");
    let listener = kagisecure_host::server::bind(&socket).unwrap();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    let engine = std::sync::Arc::new(f.engine());
    let served = std::sync::Arc::clone(&engine);
    std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            kagisecure_host::server::handle(&served, stream.unwrap());
        }
    });
    let r = kagisecure_host::client::request(&socket, &f.good()).unwrap();
    assert_eq!(reason(&r), "RAN");

    // There is no approval message: anything but {grant, argv, cwd} is refused unread.
    use std::io::{BufRead as _, Write as _};
    let mut s = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    s.write_all(b"{\"grant\":\"deploy-staging\",\"argv\":[],\"cwd\":\"/\",\"approve\":true}\n")
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(s).read_line(&mut line).unwrap();
    assert!(line.contains("BAD_REQUEST"), "{line}");
}

#[test]
fn a_grants_file_becomes_the_grant_it_describes() {
    let f = Fixture::new();
    let spec = f.root.join("grants.json");
    std::fs::write(
        &spec,
        serde_json::json!({ "grants": [ {
            "name": "deploy-staging",
            "variables": [VAR],
            "command": [f.script.display().to_string(), "staging", "{commit}", "--key-from-stdin"],
            "working_dir": f.work().display().to_string(),
            "run_as": "deploy",
            "hash_from": "work/deploy",
        } ] })
        .to_string(),
    )
    .unwrap();
    let file = GrantsFile::read(&spec).unwrap();
    let g = file.grants[0]
        .to_grant("app-deploy", 1000, &f.root)
        .unwrap();
    let mut want = f.grant();
    want.run_as = Some("deploy".to_owned());
    want.created_at = 1000;
    want.timeout_secs = g.timeout_secs;
    want.limits = g.limits;
    assert_eq!(g, want);
    assert_eq!(g.limits.expires_at, 1000 + 90 * 24 * 60 * 60);
}

#[test]
fn run_as_starts_the_command_as_that_account_with_its_home() {
    use std::os::unix::fs::MetadataExt as _;
    let mut f = Fixture::new();
    // This test's own account, under a name of its own: changing to another account needs
    // privileges a test does not have. What is checked is that the lookup, the ids and the
    // account's environment reach the child.
    let meta = std::fs::metadata(&f.state).unwrap();
    let home = f.root.join("home-of-builder");
    std::fs::create_dir_all(&home).unwrap();
    let passwd = f.root.join("passwd");
    std::fs::write(
        &passwd,
        format!(
            "builder:x:{}:{}:Builder:{}:/bin/sh\n",
            meta.uid(),
            meta.gid(),
            home.display()
        ),
    )
    .unwrap();
    let mut g = f.grant();
    g.run_as = Some("builder".to_owned());
    let contents = f.contents(vec![g.clone()]);
    let owner = DeviceSecret::from_device_key(&f.owner.to_device_key("o", 0).unwrap()).unwrap();
    let bytes = f.make(&owner, &contents);
    let engine = Engine::with_passwd(Store::new(&f.state), &passwd);
    engine.import(&bytes).unwrap();
    assert_eq!(reason(&engine.handle(&f.good())), "RAN");
    let env = f.out("env");
    assert!(env.contains(&format!("HOME={}", home.display())), "{env}");
    assert!(env.contains("USER=builder"), "{env}");

    // An account that does not exist is refused, and is not a strike.
    let mut g2 = g;
    g2.run_as = Some("nobody-here".to_owned());
    let bytes = f.make(&owner, &f.contents(vec![g2]));
    engine.import(&bytes).unwrap();
    assert_eq!(reason(&engine.handle(&f.good())), "RUN_AS_UNKNOWN");
    assert_eq!(reason(&engine.handle(&f.good())), "RUN_AS_UNKNOWN");
}
