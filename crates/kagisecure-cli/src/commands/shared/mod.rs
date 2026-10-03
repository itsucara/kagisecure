//! `kagisecure shared ...`: shared vaults from the command line (ADR-0035).
//!
//! A shared vault is its own file beside the personal vault: `<personal vault>.shared/<32 hex
//! vault id>.kagishared` ([`kagisecure_shared::replica`]). Every command here first unlocks the
//! personal vault — exactly like every other CLI command — because that is where this computer's
//! shared-vault device keys live (ADR-0035 §5); it then finds the one device key among them that
//! opens the shared vault a `<vault>` argument names, the way [`resolve_vault`] does.
//!
//! **A device key is generated once per (computer, shared vault)**: `shared create` and
//! `shared join`/`invite` (on the admin's side) each mint a fresh one and add it to the personal
//! vault, rather than reusing one across vaults — the same thing
//! [`kagisecure_shared::admin::enroll`] itself does for every invitation. So a personal vault
//! that has created or joined several shared vaults holds one device key per vault, and the only
//! way to tell which is which is to try opening the replica with each — there is no index kept
//! anywhere else, and none of this needs a change to `kagisecure-shared` to work.

use std::path::Path;

use anyhow::{Context, Result, bail};
use kagisecure_core::Vault;
use kagisecure_core::proto::VaultId;
use kagisecure_shared::admin;
use kagisecure_shared::replica::{Replica, list_replicas, replica_path};
use kagisecure_shared::roster::{MemberId, RosterWarning, Verification};
use kagisecure_shared::view::SharedView;
use kagisecure_shared::{DeviceKeyId, DeviceSecret};

use crate::cli::{
    NoSuchSharedVault, SharedCreateArgs, SharedExportArgs, SharedImportArgs, SharedInviteArgs,
    SharedJoinArgs, SharedListArgs, SharedRebuildArgs, SharedRemoveArgs, SharedRoleArgs,
    SharedRotationListArgs, SharedSetDirArgs, SharedStatusArgs, SharedSyncArgs,
};
use crate::commands::transact_patiently;
use crate::prompt::SecretInput;

mod access;
pub mod env;
pub mod item;

pub use access::agent_access;

/// A shared vault's replica, opened with the one device key on this computer that fits it.
pub(super) struct Opened {
    pub(super) device: DeviceSecret,
    pub(super) replica: Replica,
}

fn open_personal(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

/// Print the threat-model.md W-22 caveat when adding a device key has just raised the personal
/// vault to `format_ver` 2 for the first time — the obligation `docs/roadmap.md` M10 records
/// against "whichever phase's CLI first creates a device key a person can run", which is this one
/// (`shared create` and `shared join` are the only two). Does nothing on every other write, which
/// leaves `Vault::format_upgrade_backup` at `None`.
fn note_format_upgrade(personal: &Vault) {
    let Some(backup) = personal.format_upgrade_backup() else {
        return;
    };
    println!();
    println!(
        "This personal vault just created its first shared-vault device key, which required \
         raising its format. The file as it was before that is kept at:"
    );
    println!();
    println!("    {}", backup.display());
    println!();
    println!(
        "That copy still opens with the master password and recovery code that are current now \
         — even after either is changed later — and holds every item this vault held at the time. \
         Changing the master password or reissuing the recovery code does not close that door on \
         its own (the vault's own key never changes): `kagisecure recover` offers to delete every \
         `<vault>.bak-*` file for exactly that reason. Keep the backup only as long as you might \
         need it."
    );
}

/// This device's view of an opened shared vault: every accepted item and environment version,
/// merged last-writer-wins ([`kagisecure_shared::merge`]).
pub(super) fn view_of(opened: &Opened) -> Result<SharedView> {
    Ok(SharedView::compute(
        opened.replica.vault_id(),
        &opened.replica.genesis(),
        &opened.replica.envelopes(),
        &opened.device,
    )?)
}

/// Lower-case hex, for printing an id this build has no `Display` for from here (a member id) —
/// see the module documentation on why nothing in `kagisecure-shared` needed to change for this.
pub(super) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse `what`'s value as exactly `N` bytes of lower- or upper-case hex.
pub(super) fn hex_decode<const N: usize>(what: &str, s: &str) -> Result<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{what} must be {} hex characters, got {s:?}", N * 2);
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("checked hex digits above");
    }
    Ok(out)
}

/// Open the replica of shared vault `vault_id` beside `personal_path`, trying every one of
/// `personal`'s active device keys until one of them fits it (module documentation).
fn open_for(personal_path: &Path, personal: &Vault, vault_id: &VaultId) -> Result<Opened> {
    let path = replica_path(personal_path, vault_id);
    let mut last_err: Option<kagisecure_shared::SharedError> = None;
    for key in personal.active_device_keys() {
        let device = DeviceSecret::from_device_key(key)?;
        match Replica::open(&path, &device) {
            Ok(replica) => return Ok(Opened { device, replica }),
            // Not this device key's replica: try the next one, quickly — `Replica::open` checks
            // the header before it ever attempts to decrypt the local section.
            Err(kagisecure_shared::SharedError::ReplicaMismatch(_)) => continue,
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) => Err(e.into()),
        None => Err(NoSuchSharedVault(format!(
            "no device key on this computer opens the shared vault {vault_id}"
        ))
        .into()),
    }
}

/// Resolve `reference` — a shared vault's id, a unique prefix of it, or its exact name — to the
/// one replica it names, the same convention [`kagisecure_core::Vault::find_item`] uses for an
/// item.
pub(super) fn resolve_vault(
    personal_path: &Path,
    personal: &Vault,
    reference: &str,
) -> Result<Opened> {
    let ids = list_replicas(personal_path)?;
    let id_matches: Vec<VaultId> = ids
        .iter()
        .copied()
        .filter(|id| {
            let text = id.to_string();
            text == reference || (reference.len() >= 4 && text.starts_with(reference))
        })
        .collect();

    // An id, or an unambiguous prefix of one, was named: open exactly that replica, and let a
    // failure to open it (a damaged file, no device key on this computer that fits it) be the
    // error reported, rather than folding it into "no shared vault matches" the way the name
    // search below would have to.
    match id_matches.len() {
        1 => return open_for(personal_path, personal, &id_matches[0]),
        0 => {}
        _ => {
            return Err(NoSuchSharedVault(format!(
                "{reference:?} matches more than one shared vault; use its full id"
            ))
            .into());
        }
    }

    // Otherwise `reference` might be a name, and the only way to know is to open each replica
    // this device can and check its local state — one this device cannot open is silently
    // skipped here, since it was never a candidate unless its id also matched, handled above.
    let mut hits: Vec<Opened> = Vec::new();
    for id in ids {
        let Ok(opened) = open_for(personal_path, personal, &id) else {
            continue;
        };
        if opened.replica.local().vault_name.as_deref() == Some(reference) {
            hits.push(opened);
        }
    }
    match hits.len() {
        1 => Ok(hits.pop().expect("length checked above")),
        0 => Err(NoSuchSharedVault(format!("no shared vault matches {reference:?}")).into()),
        _ => Err(NoSuchSharedVault(format!(
            "{reference:?} matches more than one shared vault; use its id"
        ))
        .into()),
    }
}

/// Create a shared vault, with this computer as its first admin.
///
/// # Errors
///
/// If the personal vault cannot be opened or written, or creating the shared vault fails.
pub fn create(path: &Path, args: &SharedCreateArgs, input: &mut SecretInput) -> Result<()> {
    let mut personal = open_personal(path, input)?;
    let now = kagisecure_core::unix_now();

    let device = DeviceSecret::generate()?;
    let mut key_slot = Some(device.to_device_key(&args.device_label, now)?);
    transact_patiently(&mut personal, |tx| {
        tx.add_device_key(
            key_slot
                .take()
                .expect("the transaction commits at most once"),
            "shared create",
        )
    })?;
    note_format_upgrade(&personal);

    let replica = admin::create::create(path, &device, &args.name, args.dir.as_deref(), now)?;
    let vault_id = *replica.vault_id();
    println!("Created shared vault {vault_id}");
    println!("  name    {}", args.name);
    println!("  device  {} ({})", device.id(), args.device_label);
    if let Some(dir) = &args.dir {
        println!("  exchange {}", dir.display());
    } else {
        println!("  exchange (none configured — set one with `kagisecure shared set-dir`)");
    }
    println!();
    println!(
        "Invite another computer: `kagisecure shared invite {vault_id} --name <label> --role \
         reader|writer|admin --out <file>`."
    );
    Ok(())
}

/// List shared vaults with a replica beside this vault file.
///
/// # Errors
///
/// If the personal vault cannot be opened, or its `.shared` directory cannot be read.
pub fn list(path: &Path, args: &SharedListArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let ids = list_replicas(path)?;

    #[derive(serde::Serialize)]
    struct Row {
        vault_id: String,
        name: Option<String>,
        exchange_dir: Option<String>,
        members: usize,
        devices: usize,
        error: Option<String>,
    }

    let mut rows = Vec::new();
    for id in ids {
        match open_for(path, &personal, &id) {
            Ok(opened) => {
                let view = view_of(&opened)?;
                let snapshot = view.roster().snapshot();
                rows.push(Row {
                    vault_id: id.to_string(),
                    name: opened.replica.local().vault_name.clone(),
                    exchange_dir: opened.replica.local().exchange_dir.clone(),
                    members: snapshot.members().filter(|m| m.active).count(),
                    devices: snapshot.active_devices().count(),
                    error: None,
                });
            }
            Err(e) => rows.push(Row {
                vault_id: id.to_string(),
                name: None,
                exchange_dir: None,
                members: 0,
                devices: 0,
                error: Some(e.to_string()),
            }),
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No shared vaults yet. Create one with `kagisecure shared create <name>`.");
        return Ok(());
    }

    println!(
        "{:<38}  {:<24}  {:>7}  {:>7}  EXCHANGE",
        "ID", "NAME", "MEMBERS", "DEVICES"
    );
    for row in &rows {
        match &row.error {
            None => println!(
                "{:<38}  {:<24}  {:>7}  {:>7}  {}",
                row.vault_id,
                crate::commands::item::truncate(row.name.as_deref().unwrap_or("(unnamed)"), 24),
                row.members,
                row.devices,
                row.exchange_dir.as_deref().unwrap_or("(none)")
            ),
            Some(e) => println!("{:<38}  (could not open: {e})", row.vault_id),
        }
    }
    Ok(())
}

/// Show one shared vault's members, devices and warnings.
///
/// # Errors
///
/// If the personal vault cannot be opened or `--vault` does not resolve.
pub fn status(path: &Path, args: &SharedStatusArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let view = view_of(&opened)?;
    let roster = view.roster();
    let snapshot = roster.snapshot();

    if args.json {
        #[derive(serde::Serialize)]
        struct MemberRow {
            id: String,
            role: &'static str,
        }
        #[derive(serde::Serialize)]
        struct DeviceRow {
            id: String,
            member: String,
            verified: &'static str,
            this_device: bool,
        }
        #[derive(serde::Serialize)]
        struct Out {
            vault_id: String,
            name: Option<String>,
            exchange_dir: Option<String>,
            members: Vec<MemberRow>,
            devices: Vec<DeviceRow>,
            warnings: Vec<&'static str>,
        }
        let out = Out {
            vault_id: opened.replica.vault_id().to_string(),
            name: opened.replica.local().vault_name.clone(),
            exchange_dir: opened.replica.local().exchange_dir.clone(),
            members: snapshot
                .members()
                .filter(|m| m.active)
                .map(|m| MemberRow {
                    id: hex_encode(m.id.as_bytes()),
                    role: m.role.name(),
                })
                .collect(),
            devices: snapshot
                .active_devices()
                .map(|d| DeviceRow {
                    id: d.public.id().to_string(),
                    member: hex_encode(d.member.as_bytes()),
                    verified: verification_word(d.verified),
                    this_device: d.public.id() == opened.device.id(),
                })
                .collect(),
            warnings: roster.warnings().iter().map(|w| warning_text(*w)).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("vault    {}", opened.replica.vault_id());
    println!(
        "name     {}",
        opened
            .replica
            .local()
            .vault_name
            .as_deref()
            .unwrap_or("(unnamed)")
    );
    println!(
        "exchange {}",
        opened
            .replica
            .local()
            .exchange_dir
            .as_deref()
            .unwrap_or("(none configured)")
    );
    println!();
    println!("Members:");
    for m in snapshot.members().filter(|m| m.active) {
        println!("  {}  role={}", hex_encode(m.id.as_bytes()), m.role.name());
    }
    println!();
    println!("Devices:");
    for d in snapshot.active_devices() {
        println!(
            "  {}  member={}  verified={}{}",
            d.public.id(),
            hex_encode(d.member.as_bytes()),
            verification_word(d.verified),
            if d.public.id() == opened.device.id() {
                "  (this device)"
            } else {
                ""
            }
        );
    }
    let warnings = roster.warnings();
    if !warnings.is_empty() {
        println!();
        println!("Warnings:");
        for w in warnings {
            println!("  {}", warning_text(w));
        }
    }
    Ok(())
}

fn verification_word(v: Option<Verification>) -> &'static str {
    match v {
        Some(v) => v.name(),
        None => "(creator's device)",
    }
}

fn warning_text(w: RosterWarning) -> &'static str {
    match w {
        RosterWarning::FewAdmins => {
            "fewer than two admins are left; losing the last one would freeze the roster"
        }
        RosterWarning::Frozen => "no admin is left; the roster is frozen and cannot change",
    }
}

/// Invite a device to a shared vault: one file and a passphrase, shown once.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, neither `--member` nor
/// `--role` was given, this device is not an admin, or the invitation file cannot be written.
pub fn invite(path: &Path, args: &SharedInviteArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let now = kagisecure_core::unix_now();

    let joining = match (&args.member, args.role) {
        (Some(member_hex), _) => {
            let member = MemberId::from_bytes(hex_decode::<16>("--member", member_hex)?);
            admin::enroll::Joining::ExistingMember(member)
        }
        (None, Some(role)) => admin::enroll::Joining::NewMember(role),
        (None, None) => bail!(
            "pass --role reader|writer|admin for a new member, or --member <id> for an existing \
             one"
        ),
    };

    let invite = admin::enroll::invite(
        &mut opened.replica,
        &opened.device,
        joining,
        &args.name,
        now,
    )?;
    std::fs::write(&args.out, &invite.file)
        .with_context(|| format!("writing {}", args.out.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.out, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", args.out.display()))?;
    }

    println!("Wrote invitation to {}", args.out.display());
    println!("Device {} added, unverified.", invite.device);
    println!();
    println!("Passphrase — shown once here, and never stored:");
    println!();
    println!(
        "    {}",
        invite.passphrase.expose_str().unwrap_or("<not text>")
    );
    println!();
    println!(
        "Send the file and say the passphrase over two different channels. Both together open \
         the vault as this device."
    );
    Ok(())
}

/// Join a shared vault from an invitation file and its passphrase.
///
/// # Errors
///
/// If the personal vault cannot be opened, the file cannot be read, or the passphrase is wrong.
pub fn join(path: &Path, args: &SharedJoinArgs, input: &mut SecretInput) -> Result<()> {
    let mut personal = open_personal(path, input)?;
    let bytes =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let passphrase = input.read("Invitation passphrase")?;
    let now = kagisecure_core::unix_now();

    let (replica, device) =
        admin::enroll::join(&mut personal, &bytes, &passphrase, args.dir.as_deref(), now)?;
    note_format_upgrade(&personal);

    println!("Joined shared vault {}", replica.vault_id());
    if let Some(name) = &replica.local().vault_name {
        println!("  name    {name}");
    }
    println!("  device  {}", device.id());
    if let Some(dir) = &args.dir {
        println!("  exchange {}", dir.display());
    }
    Ok(())
}

/// Remove a device or a member from a shared vault.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, neither or both of
/// `--device`/`--member` were given, or this device is not an admin.
pub fn remove(path: &Path, args: &SharedRemoveArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let now = kagisecure_core::unix_now();

    match (&args.device, &args.member) {
        (Some(device_hex), None) => {
            let device_id = DeviceKeyId::from_bytes(hex_decode::<32>("--device", device_hex)?);
            let epoch = admin::remove::remove_device(
                &mut opened.replica,
                &opened.device,
                device_id,
                args.reason,
                now,
            )?;
            println!(
                "Removed device {device_id} from shared vault {}",
                opened.replica.vault_id()
            );
            println!("New epoch {epoch}");
        }
        (None, Some(member_hex)) => {
            let member = MemberId::from_bytes(hex_decode::<16>("--member", member_hex)?);
            let epoch = admin::remove::remove_member(
                &mut opened.replica,
                &opened.device,
                member,
                args.reason,
                now,
            )?;
            println!(
                "Removed member {} and every device of theirs from shared vault {}",
                hex_encode(member.as_bytes()),
                opened.replica.vault_id()
            );
            println!("New epoch {epoch}");
        }
        (Some(_), Some(_)) => bail!("pass --device or --member, not both"),
        (None, None) => bail!("pass --device <id> or --member <id>"),
    }
    Ok(())
}

/// Change a member's role.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, or this device is not an
/// admin.
pub fn role(path: &Path, args: &SharedRoleArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let member = MemberId::from_bytes(hex_decode::<16>("member", &args.member)?);
    let now = kagisecure_core::unix_now();
    admin::remove::set_role(&mut opened.replica, &opened.device, member, args.role, now)?;
    println!(
        "{} is now {}",
        hex_encode(member.as_bytes()),
        args.role.name()
    );
    Ok(())
}

/// List what a removed device could have read (informational; nothing is enforced).
///
/// # Errors
///
/// If the personal vault cannot be opened or `--vault` does not resolve.
pub fn rotation_list(
    path: &Path,
    args: &SharedRotationListArgs,
    input: &mut SecretInput,
) -> Result<()> {
    let personal = open_personal(path, input)?;
    let opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let view = view_of(&opened)?;
    let exposed = kagisecure_shared::rotation::rotation_list(&view);

    if args.json {
        #[derive(serde::Serialize)]
        struct Row {
            device: String,
            epochs: Vec<String>,
            items: Vec<String>,
            envs: Vec<String>,
        }
        let rows: Vec<Row> = exposed
            .iter()
            .map(|e| Row {
                device: e.device.to_string(),
                epochs: e.epochs.iter().map(ToString::to_string).collect(),
                items: e
                    .objects
                    .iter()
                    .filter_map(|o| match o {
                        kagisecure_shared::view::ObjectId::Item(id) => Some(id.to_string()),
                        kagisecure_shared::view::ObjectId::Env(_) => None,
                    })
                    .collect(),
                envs: e
                    .objects
                    .iter()
                    .filter_map(|o| match o {
                        kagisecure_shared::view::ObjectId::Env(id) => Some(id.to_string()),
                        kagisecure_shared::view::ObjectId::Item(_) => None,
                    })
                    .collect(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if exposed.is_empty() {
        println!("No removed device was ever sent a key. Nothing to rotate.");
        return Ok(());
    }
    for e in &exposed {
        let items = e
            .objects
            .iter()
            .filter(|o| matches!(o, kagisecure_shared::view::ObjectId::Item(_)))
            .count();
        let envs = e.objects.len() - items;
        println!("device {}", e.device);
        println!(
            "  epochs   {}",
            e.epochs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "  exposed  {items} item(s), {envs} environment(s) — rotate them with `kagisecure \
             shared item set` / `shared env add-var`"
        );
    }
    Ok(())
}

fn print_import_summary(summary: &admin::exchange::ImportSummary) {
    if summary.records_added == 0 {
        println!("Nothing new.");
        return;
    }
    println!("Imported {} new record(s).", summary.records_added);
    if !summary.items.is_empty() {
        println!("  items  {}", summary.items.join(", "));
    }
    if !summary.envs.is_empty() {
        println!("  envs   {}", summary.envs.join(", "));
    }
    if summary.roster_changed {
        println!("  the roster changed");
    }
}

/// Import from, then export to, the configured exchange folder.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, or no exchange folder is
/// configured.
pub fn sync(path: &Path, args: &SharedSyncArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let summary = admin::exchange::sync(&mut opened.replica, &opened.device)?;
    print_import_summary(&summary);
    Ok(())
}

/// Import records from a folder or a bundle file.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, neither or both of
/// `--bundle`/`--dir` were given, or the source cannot be read or parsed.
pub fn import(path: &Path, args: &SharedImportArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let summary = match (&args.bundle, &args.dir) {
        (Some(file), None) => {
            let bytes =
                std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            admin::exchange::import_bundle(&mut opened.replica, &opened.device, &bytes)?
        }
        (None, Some(dir)) => admin::exchange::import_dir(&mut opened.replica, &opened.device, dir)?,
        _ => bail!("pass exactly one of --bundle <file> or --dir <folder>"),
    };
    print_import_summary(&summary);
    Ok(())
}

/// Export every record to a folder, or write the whole replica as a bundle file.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, neither or both of
/// `--bundle`/`--dir` were given, or the destination cannot be written.
pub fn export(path: &Path, args: &SharedExportArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let opened = resolve_vault(path, &personal, &args.shared_vault)?;
    match (&args.bundle, &args.dir) {
        (Some(file), None) => {
            let bytes = admin::exchange::export_bundle(&opened.replica)?;
            std::fs::write(file, &bytes).with_context(|| format!("writing {}", file.display()))?;
            println!(
                "Wrote {} record(s) to {}",
                opened.replica.records().count(),
                file.display()
            );
        }
        (None, Some(dir)) => {
            let written = admin::exchange::export_dir(&opened.replica, dir)?;
            println!("Wrote {written} new record(s) to {}", dir.display());
        }
        _ => bail!("pass exactly one of --bundle <file> or --dir <folder>"),
    }
    Ok(())
}

/// Rebuild a replica that no longer opens, from a folder or a bundle file.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve to exactly one replica
/// file, neither or both of `--from-dir`/`--from-bundle` were given, or no device key on this
/// computer fits the rebuilt roster.
pub fn rebuild(path: &Path, args: &SharedRebuildArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    // A broken replica cannot be asked its own name (decision 85), so this matches only against
    // the ids named by the `.shared` directory's file names — the one thing `list_replicas`
    // never has to decrypt anything to know.
    let reference = args.shared_vault.as_str();
    let candidates: Vec<VaultId> = list_replicas(path)?
        .into_iter()
        .filter(|id| {
            let text = id.to_string();
            text == reference || (reference.len() >= 4 && text.starts_with(reference))
        })
        .collect();
    let vault_id = match candidates[..] {
        [id] => id,
        [] => bail!("no shared vault replica matches {reference:?}"),
        _ => bail!("{reference:?} matches more than one shared vault replica; use its full id"),
    };

    let now = kagisecure_core::unix_now();
    let bundle_bytes;
    let source = match (&args.from_dir, &args.from_bundle) {
        (Some(dir), None) => kagisecure_shared::replica::RebuildSource::Dir(dir),
        (None, Some(file)) => {
            bundle_bytes =
                std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            kagisecure_shared::replica::RebuildSource::Bundle(&bundle_bytes)
        }
        _ => bail!("pass exactly one of --from-dir <folder> or --from-bundle <file>"),
    };

    let target = replica_path(path, &vault_id);
    let mut last_err = None;
    for key in personal.active_device_keys() {
        let device = DeviceSecret::from_device_key(key)?;
        match Replica::rebuild_from(&target, &device, source, now) {
            Ok(replica) => {
                println!("Rebuilt shared vault {}", replica.vault_id());
                return Ok(());
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(match last_err {
        Some(e) => e.into(),
        None => NoSuchSharedVault(format!(
            "no device key on this personal vault fits the shared vault {vault_id}"
        ))
        .into(),
    })
}

/// Set or change the folder this device syncs a shared vault through.
///
/// # Errors
///
/// If the personal vault cannot be opened or `--vault` does not resolve.
pub fn set_dir(path: &Path, args: &SharedSetDirArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    admin::exchange::set_exchange_dir(&mut opened.replica, &opened.device, Some(&args.dir))?;
    println!(
        "Shared vault {} now syncs through {}",
        opened.replica.vault_id(),
        args.dir.display()
    );
    Ok(())
}
