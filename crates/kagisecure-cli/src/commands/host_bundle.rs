//! `kagisecure host-bundle`: signed bundles for headless hosts (ADR-0043).
//!
//! The signing key is this computer's shared-vault device key, held in the personal vault body;
//! the values come from the machine vault, whose key the personal vault also holds. Opening the
//! personal vault with the master password is the presence proof the bundle records
//! (`PRESENCE_CONFIRMED_MASTER_PASSWORD`).

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use kagisecure_core::Vault;
use kagisecure_core::vault::machine::{PresencePath, machine_vault_path};
use kagisecure_host::bundle::{
    self, BundleContents, BundleEnvironment, BundleVariable, CONTENTS_VERSION, Value,
};
use kagisecure_host::identity::{public_from_text, public_to_text};
use kagisecure_host::spec::GrantsFile;
use kagisecure_shared::DeviceSecret;

use crate::cli::HostBundleExportArgs;
use crate::commands::{cli_draft, transact_patiently};
use crate::prompt::SecretInput;

fn open_personal(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

/// This computer's device key: the personal vault's first active one, created if there is none.
fn device(personal: &mut Vault) -> Result<DeviceSecret> {
    if let Some(key) = personal.active_device_keys().next() {
        return Ok(DeviceSecret::from_device_key(key)?);
    }
    let device = DeviceSecret::generate()?;
    let mut slot = Some(device.to_device_key("this Mac", kagisecure_core::unix_now())?);
    transact_patiently(personal, |tx| {
        tx.add_device_key(
            slot.take().expect("the transaction commits at most once"),
            "host-bundle",
        )
    })?;
    if let Some(backup) = personal.format_upgrade_backup() {
        println!(
            "Created this computer's device key, which raised the personal vault's format; the \
             file as it was is kept at {}",
            backup.display()
        );
    }
    Ok(device)
}

/// `kagisecure host-bundle owner-key`.
///
/// # Errors
///
/// If the personal vault cannot be opened or written.
pub fn owner_key(path: &Path, input: &mut SecretInput) -> Result<()> {
    let mut personal = open_personal(path, input)?;
    let device = device(&mut personal)?;
    println!("Owner key   {}", public_to_text(device.public()));
    println!("Fingerprint {}", device.public().fingerprint());
    println!();
    println!("On the host: sudo kagisecure-host init --owner <the owner key above>");
    Ok(())
}

/// `kagisecure host-bundle export`.
///
/// # Errors
///
/// If the vaults cannot be opened, the grants file or host key is wrong, a variable is missing,
/// or the bundle cannot be written.
pub fn export(path: &Path, args: &HostBundleExportArgs, input: &mut SecretInput) -> Result<()> {
    let host_key_text = match args.host_key.strip_prefix('@') {
        Some(file) => std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?,
        None => args.host_key.clone(),
    };
    let host = public_from_text(&host_key_text).context("--host-key")?;
    let file = GrantsFile::read(&args.grants)?;
    let base = args
        .grants
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), Path::to_path_buf);
    let now = kagisecure_core::unix_now();
    let specs: Vec<_> = file
        .grants
        .iter()
        .filter(|g| args.only.is_empty() || args.only.contains(&g.name))
        .collect();
    for wanted in &args.only {
        if !file.grants.iter().any(|g| &g.name == wanted) {
            bail!("the grants file has no grant called {wanted:?}");
        }
    }
    if specs.is_empty() {
        bail!("no grant selected");
    }
    let grants = specs
        .iter()
        .map(|s| s.to_grant(&args.environment, now, &base))
        .collect::<kagisecure_host::Result<Vec<_>>>()?;

    let mut personal = open_personal(path, input)?;
    let owner = device(&mut personal)?;
    let Some(machine_key) = personal.machine_vault_key() else {
        bail!("this personal vault has no machine vault yet; arm unattended jobs in the app first");
    };
    let machine = Vault::open_machine(machine_vault_path(path), machine_key)
        .context("opening the machine vault")?;
    let mut names: Vec<String> = Vec::new();
    for g in &grants {
        for v in &g.variables {
            if !names.contains(v) {
                names.push(v.clone());
            }
        }
    }
    let injections = machine
        .resolve_environment(&args.environment, Some(&names))
        .with_context(|| format!("reading {:?} from the machine vault", args.environment))?;
    let contents = BundleContents {
        v: CONTENTS_VERSION,
        host_name: args.host.clone(),
        created_at: now,
        presence: PresencePath::ConfirmedMasterPassword,
        environments: vec![BundleEnvironment {
            name: args.environment.clone(),
            variables: injections
                .iter()
                .map(|i| BundleVariable {
                    name: i.name.to_string(),
                    value: Value::new(i.value.expose().to_vec()),
                })
                .collect(),
        }],
        grants,
    };
    let sequence = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let bytes = bundle::make(&owner, &host, sequence, &contents)?;

    // Audit before release (ADR-0040): the bundle is written only once its entry is durable.
    let mut draft = cli_draft("host_bundle_export");
    draft.variables = names.clone();
    draft.target_path = Some(args.out.display().to_string());
    draft.detail = Some(format!(
        "HOST {} {} BUNDLE {sequence} GRANTS {:?}",
        args.host,
        host.fingerprint(),
        contents.grants.iter().map(|g| &g.name).collect::<Vec<_>>()
    ));
    personal.queue_audit(draft);
    personal
        .flush_audit()
        .context("nothing was written: the audit log cannot be written")?;
    kagisecure_host::store::write_atomic(&args.out, &bytes)?;

    println!(
        "Wrote {} (bundle {sequence}) for host {:?}",
        args.out.display(),
        args.host
    );
    println!("  host        {}", host.fingerprint());
    println!("  signed by   {}", owner.public().fingerprint());
    println!(
        "  values      {} from {:?}",
        names.join(", "),
        args.environment
    );
    for g in &contents.grants {
        println!("  grant       {}  {}", g.name, g.command_line());
        println!(
            "              in {} as {}",
            g.working_dir,
            g.run_as.as_deref().unwrap_or("(host account)")
        );
    }
    println!();
    println!(
        "Under these grants the host hands {} to the commands above with nobody watching; anything \
         that can change what those commands do on the host can obtain it.",
        names.join(", ")
    );
    println!("Copy the file to the host and run: sudo kagisecure-host import <file>");
    Ok(())
}
