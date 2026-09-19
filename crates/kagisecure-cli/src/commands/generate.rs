//! `kagisecure generate` and `kagisecure totp`.
//!
//! Both print secret material to the terminal, which is the CLI's documented exception (see the
//! crate docs and ADR-0005): a generated password the user asked for is of no use anywhere else,
//! and a one-time code has to be readable to be typed. Neither writes to the audit log — the log
//! records what an *agent* did, and these are the user's own hands — and neither ever reaches a
//! process argument, where `ps` would see it.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Result, bail};
use kagisecure_core::generator::{CharacterOptions, Recipe, Separator, WordOptions};
use kagisecure_core::{Error, Vault};

use crate::cli::{GenerateArgs, TotpArgs};
use crate::prompt::SecretInput;

/// Print one or more generated passwords.
///
/// # Errors
///
/// If the recipe cannot be satisfied, or the operating system generator fails.
pub fn generate(args: &GenerateArgs) -> Result<()> {
    let separator: Separator = args.separator.parse()?;
    let recipe = match args.words {
        Some(words) => Recipe::Words(WordOptions {
            words,
            separator,
            capitalize: args.capitalize,
            include_digit: args.include_digit,
        }),
        None => Recipe::Characters(CharacterOptions {
            length: args.length,
            lowercase: !args.no_lowercase,
            uppercase: !args.no_uppercase,
            digits: !args.no_digits,
            symbols: !args.no_symbols,
            avoid_ambiguous: args.avoid_ambiguous,
        }),
    };

    if args.count == 0 {
        bail!("--count must be at least 1");
    }

    for _ in 0..args.count {
        let password = recipe.generate()?;
        let text = password
            .expose_str()
            .ok_or_else(|| anyhow::anyhow!("the generator produced non-text output"))?;
        println!("{text}");
    }

    if args.strength {
        // Standard error, so `kagisecure generate | pbcopy` still copies only the password.
        let strength = recipe.strength();
        eprintln!(
            "{:.0} bits — {}",
            strength.bits,
            strength.level.label().to_lowercase()
        );
    }
    Ok(())
}

/// Print (or copy) an item's current one-time password.
///
/// # Errors
///
/// If the vault cannot be opened, the item or field does not resolve, the field is not a
/// one-time password, or `--copy` is used where there is no `pbcopy`.
pub fn totp(path: &Path, args: &TotpArgs, input: &mut SecretInput) -> Result<()> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    let vault = Vault::open_with_password(path, password.as_bytes())?;

    let (item_ref, field_ref) = match args.item.split_once('/') {
        Some((item, field)) => (item, Some(field)),
        None => (args.item.as_str(), None),
    };
    let item = vault.find_item(item_ref)?;

    let field = match field_ref {
        Some(reference) => item.field(reference).ok_or_else(|| Error::FieldNotFound {
            item: item_ref.to_owned(),
            field: reference.to_owned(),
        })?,
        None => item.totp_field().ok_or_else(|| Error::FieldNotFound {
            item: item_ref.to_owned(),
            field: "one-time password".to_owned(),
        })?,
    };

    let generator = field.totp_generator()?;
    let now = kagisecure_core::unix_now();
    let code = generator.code_at(now)?;
    let text = code
        .expose_str()
        .ok_or_else(|| anyhow::anyhow!("the code is not text"))?;
    let remaining = generator.seconds_remaining(now);

    if args.copy {
        copy_to_clipboard(text)?;
        // The code itself stays off stdout when it went to the clipboard: the point of --copy is
        // that it does not land in a scrollback buffer.
        eprintln!("Copied {} digits, valid for {remaining}s.", text.len());
    } else {
        println!("{text}");
        eprintln!("valid for {remaining}s");
    }
    Ok(())
}

/// Hand a value to the system clipboard.
///
/// macOS only, and by spawning `pbcopy` rather than linking AppKit: the CLI is a plain Rust
/// binary that also builds on Linux, and a clipboard dependency for one flag is not a trade worth
/// making. The value goes down `pbcopy`'s standard input, never into its argv.
fn copy_to_clipboard(value: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("--copy needs macOS; pipe the code to your own clipboard tool instead");
    }
    let mut child = Command::new("/usr/bin/pbcopy")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run /usr/bin/pbcopy: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("pbcopy has no standard input"))?
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        bail!("pbcopy exited with {status}");
    }
    Ok(())
}
