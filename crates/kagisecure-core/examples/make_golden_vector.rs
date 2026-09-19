//! Writes the golden vault vector used by `tests/vault.rs`.
//!
//! Golden vectors are added the day a `format_ver` is released and **never edited**
//! (vault-format §9 rule 4). This example exists so that adding the next one is a documented,
//! repeatable act rather than a one-off shell session; it refuses to overwrite an existing file.
//!
//! ```text
//! cargo run -p kagisecure-core --example make_golden_vector
//! ```

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Category, Field, Item, Secret};
use kagisecure_core::vault::{CreateOptions, Vault};

const PASSWORD: &[u8] = b"golden vector password";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/v1-argon2id-64k.kagivault");
    if path.exists() {
        eprintln!(
            "{} already exists; refusing to overwrite it.",
            path.display()
        );
        std::process::exit(1);
    }
    std::fs::create_dir_all(path.parent().expect("vectors directory"))?;

    let options = CreateOptions {
        // Deliberately not the default profile: opening this file proves the reader takes its
        // parameters from the header.
        kdf: KdfParams::new(64, 1, 1)?,
        vault_name: "Golden".to_owned(),
        kdf_hint: Some("golden-vector".to_owned()),
    };
    let (mut vault, code) = Vault::create(&path, PASSWORD, &options)?;

    let mut item = Item::new(
        vault.default_vault_id()?,
        Category::ApiCredential,
        "Golden vector",
    );
    item.fields.push(Field::public("username", "vector"));
    item.fields.push(Field::concealed(
        "token",
        Secret::from_string("vector-token-value".to_owned()),
    ));
    item.tags.push("golden".to_owned());
    vault.add_item(item);
    vault.save()?;

    println!("wrote {}", path.display());
    println!("password:      {}", String::from_utf8_lossy(PASSWORD));
    println!("recovery code: {}", *code.display());
    println!("This file is a test fixture. Its 'secrets' are public by construction.");
    Ok(())
}
