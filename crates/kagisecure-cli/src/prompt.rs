//! Reading secrets from the user without letting them near argv, a log, or the terminal echo.

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Source of secret input: either the terminal, or lines of standard input for scripted use.
pub struct SecretInput {
    lines: Option<std::vec::IntoIter<Zeroizing<String>>>,
}

impl SecretInput {
    /// Build a reader. When `from_stdin`, standard input is drained now and served line by line.
    ///
    /// # Errors
    ///
    /// If standard input cannot be read.
    pub fn new(from_stdin: bool) -> Result<Self> {
        if !from_stdin {
            return Ok(Self { lines: None });
        }
        use std::io::Read;
        let mut raw = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut raw)
            .context("reading secrets from standard input")?;
        let lines: Vec<Zeroizing<String>> = raw
            .lines()
            .map(|l| Zeroizing::new(l.trim_end_matches('\r').to_owned()))
            .collect();
        Ok(Self {
            lines: Some(lines.into_iter()),
        })
    }

    /// The next secret: a line of standard input, or a hidden terminal prompt.
    ///
    /// # Errors
    ///
    /// If standard input has run out, or the terminal prompt fails (no controlling terminal).
    pub fn read(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        match self.lines.as_mut() {
            Some(lines) => lines
                .next()
                .ok_or_else(|| anyhow::anyhow!("standard input ran out while reading {prompt}")),
            None => rpassword::prompt_password(format!("{prompt}: "))
                .map(Zeroizing::new)
                .with_context(|| format!("reading {prompt}")),
        }
    }

    /// The next secret, asked for twice and compared.
    ///
    /// When reading from standard input there is nothing to mistype, so the confirmation is
    /// skipped and one line is consumed.
    ///
    /// # Errors
    ///
    /// If the two entries differ, or reading fails.
    pub fn read_confirmed(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        let first = self.read(prompt)?;
        if self.lines.is_some() {
            return Ok(first);
        }
        let again = self.read(&format!("{prompt} (again)"))?;
        if first != again {
            bail!("the two entries did not match");
        }
        Ok(first)
    }
}

/// Reject an empty master password rather than silently creating an unprotected vault.
///
/// # Errors
///
/// If the password is empty.
pub fn require_non_empty(password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("an empty master password is not accepted");
    }
    Ok(())
}
