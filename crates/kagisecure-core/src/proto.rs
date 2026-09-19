//! Metadata-only types.
//!
//! This module is compiled **with and without** the `secret-material` feature. It is the surface
//! that an unprivileged consumer (the M2 MCP sidecar) is allowed to see: identifiers, labels,
//! categories, counts and timestamps. Nothing here can hold a secret value, because
//! [`Secret`](crate::model::Secret) is not in scope for it.
//!
//! Metadata disclosure is deliberate and documented (threat-model A4 / M-9).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Generate a fresh random (v4) identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Ok(Self(s.parse()?))
            }
        }
    };
}

id_newtype!(
    /// Identifies a logical vault inside a vault file.
    VaultId
);
id_newtype!(
    /// Identifies an item.
    ItemId
);
id_newtype!(
    /// Identifies a field within an item.
    FieldId
);
id_newtype!(
    /// Identifies an environment (vault-format §5.2).
    EnvId
);
id_newtype!(
    /// Identifies an approval lease (mcp-server.md §5).
    LeaseId
);

/// Item categories. Twelve first-class kinds styled after 1Password 8's category set
/// (ui-spec.md §5), plus `Environment` (kagisecure's own addition, not a 1Password category) and
/// an `Other(String)` fallback that preserves anything this build does not know (vault-format
/// §5, import.md §2.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    /// Username + password + URLs.
    Login,
    /// A bare password.
    Password,
    /// Free-form encrypted note.
    SecureNote,
    /// Card number, expiry, CVV, cardholder.
    CreditCard,
    /// Name, address, contact fields.
    Identity,
    /// API key / token style credential.
    ApiCredential,
    /// Host, port, credentials.
    Server,
    /// Database connection details.
    Database,
    /// Private key, public key, fingerprint, passphrase.
    SshKey,
    /// License key, licensed-to, version.
    SoftwareLicense,
    /// An attachment plus notes.
    Document,
    /// A set of environment variables.
    Environment,
    /// Any category this build does not know; preserved verbatim on round-trip.
    Other(String),
}

impl Category {
    /// The canonical lower-case name used on the command line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Login => "login",
            Self::Password => "password",
            Self::SecureNote => "secure-note",
            Self::CreditCard => "credit-card",
            Self::Identity => "identity",
            Self::ApiCredential => "api-credential",
            Self::Server => "server",
            Self::Database => "database",
            Self::SshKey => "ssh-key",
            Self::SoftwareLicense => "software-license",
            Self::Document => "document",
            Self::Environment => "environment",
            Self::Other(s) => s,
        }
    }
}

/// One row of a category's default-field template (vault-format §5.4).
///
/// Metadata only: a label, a kind and whether the field will hold secret material. It never
/// carries a value, which is why it can live in this module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldTemplate {
    /// The label the new field starts with.
    pub label: String,
    /// The field kind.
    pub kind: FieldKind,
    /// Whether the field holds secret material.
    pub concealed: bool,
}

impl FieldTemplate {
    fn public(label: &str, kind: FieldKind) -> Self {
        Self {
            label: label.to_owned(),
            kind,
            concealed: false,
        }
    }

    fn concealed(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            kind: FieldKind::Concealed,
            concealed: true,
        }
    }

    /// A field that holds secret material but is not rendered as a masked password — today, only
    /// a TOTP seed, whose `otpauth://` URI is secret while its *display* is a live code.
    fn secret(label: &str, kind: FieldKind) -> Self {
        Self {
            label: label.to_owned(),
            kind,
            concealed: true,
        }
    }
}

impl Category {
    /// Every first-class category, in the order ui-spec.md §5 lists them.
    ///
    /// [`Category::Other`] is deliberately absent: it exists to preserve what a future or foreign
    /// version wrote, not to be offered in a "New item" menu.
    #[must_use]
    pub fn first_class() -> Vec<Self> {
        vec![
            Self::Login,
            Self::Password,
            Self::SecureNote,
            Self::CreditCard,
            Self::Identity,
            Self::ApiCredential,
            Self::Server,
            Self::Database,
            Self::SshKey,
            Self::SoftwareLicense,
            Self::Document,
            Self::Environment,
        ]
    }

    /// A display name suitable for a menu or a sidebar row.
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::Login => "Login".to_owned(),
            Self::Password => "Password".to_owned(),
            Self::SecureNote => "Secure Note".to_owned(),
            Self::CreditCard => "Credit Card".to_owned(),
            Self::Identity => "Identity".to_owned(),
            Self::ApiCredential => "API Credential".to_owned(),
            Self::Server => "Server".to_owned(),
            Self::Database => "Database".to_owned(),
            Self::SshKey => "SSH Key".to_owned(),
            Self::SoftwareLicense => "Software License".to_owned(),
            Self::Document => "Document".to_owned(),
            Self::Environment => "Environment".to_owned(),
            Self::Other(s) => s.clone(),
        }
    }

    /// The SF Symbol name ui-spec.md §5 pairs with this category.
    ///
    /// It lives here rather than in Swift so that the app and any later UI agree on the icon set
    /// without a second table to keep in sync. It is a string constant, not a rendering decision.
    #[must_use]
    pub fn symbol_name(&self) -> &'static str {
        match self {
            Self::Login => "person.crop.circle",
            Self::Password => "key",
            Self::SecureNote => "note.text",
            Self::CreditCard => "creditcard",
            Self::Identity => "person.text.rectangle",
            Self::ApiCredential => "chevron.left.forwardslash.chevron.right",
            Self::Server => "server.rack",
            Self::Database => "cylinder.split.1x2",
            Self::SshKey => "terminal",
            Self::SoftwareLicense => "checkmark.seal",
            Self::Document => "paperclip",
            Self::Environment => "list.bullet.rectangle",
            Self::Other(_) => "questionmark.square.dashed",
        }
    }

    /// The fields a "+ New" flow starts this category's items with (vault-format §5.4).
    ///
    /// A starting point, not a constraint: every field stays freely addable and removable
    /// afterwards. [`Category::Other`] has no template — an unknown category's fields come from
    /// whatever wrote them.
    #[must_use]
    pub fn default_fields(&self) -> Vec<FieldTemplate> {
        use FieldKind as K;
        match self {
            // `website` is deliberately not a template field: `Item::urls` is the one place a
            // website lives (ADR-0029), and the "+ New" flow's Websites editor writes there
            // directly rather than through a `Field`.
            Self::Login => vec![
                FieldTemplate::public("username", K::Text),
                FieldTemplate::concealed("password"),
                FieldTemplate::secret("one-time password", K::Totp),
            ],
            Self::Password => vec![FieldTemplate::concealed("password")],
            Self::SecureNote => Vec::new(),
            Self::CreditCard => vec![
                FieldTemplate::public("cardholder name", K::Text),
                FieldTemplate::concealed("number"),
                FieldTemplate::public("expiry", K::MonthYear),
                FieldTemplate::concealed("CVV"),
                FieldTemplate::concealed("PIN"),
                FieldTemplate::public("issuer", K::Text),
            ],
            Self::Identity => vec![
                FieldTemplate::public("first name", K::Text),
                FieldTemplate::public("last name", K::Text),
                FieldTemplate::public("email", K::Email),
                FieldTemplate::public("phone", K::Phone),
                FieldTemplate::public("address", K::Address),
            ],
            Self::ApiCredential => vec![
                FieldTemplate::concealed("key"),
                FieldTemplate::public("endpoint", K::Url),
            ],
            Self::Server => vec![
                FieldTemplate::public("hostname", K::Text),
                FieldTemplate::public("username", K::Text),
                FieldTemplate::concealed("password"),
            ],
            Self::Database => vec![
                FieldTemplate::public("hostname", K::Text),
                FieldTemplate::public("port", K::Text),
                FieldTemplate::public("username", K::Text),
                FieldTemplate::concealed("password"),
            ],
            Self::SshKey => vec![
                FieldTemplate::concealed("private key"),
                FieldTemplate::public("public key", K::Text),
                FieldTemplate::public("fingerprint", K::Text),
                FieldTemplate::concealed("passphrase"),
            ],
            Self::SoftwareLicense => vec![
                FieldTemplate::concealed("license key"),
                FieldTemplate::public("licensed to", K::Text),
                FieldTemplate::public("version", K::Text),
                FieldTemplate::public("email", K::Email),
            ],
            Self::Document => Vec::new(),
            Self::Environment => Vec::new(),
            Self::Other(_) => Vec::new(),
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad` rather than `write_str`, so `{:<16}` in a table actually pads.
        f.pad(self.as_str())
    }
}

impl std::str::FromStr for Category {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(
            match s.to_ascii_lowercase().replace(['_', ' '], "-").as_str() {
                "login" => Self::Login,
                "password" => Self::Password,
                "secure-note" | "securenote" | "note" => Self::SecureNote,
                "credit-card" | "creditcard" | "card" => Self::CreditCard,
                "identity" => Self::Identity,
                "api-credential" | "apicredential" | "api" => Self::ApiCredential,
                "server" => Self::Server,
                "database" | "db" => Self::Database,
                "ssh-key" | "sshkey" | "ssh" => Self::SshKey,
                "software-license" | "softwarelicense" | "license" => Self::SoftwareLicense,
                "document" | "doc" => Self::Document,
                "environment" | "env" => Self::Environment,
                other => Self::Other(other.to_owned()),
            },
        )
    }
}

/// The kind of a field. Purely descriptive: whether a field is *concealed* is decided by the
/// value it holds, not by this tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldKind {
    /// Plain text.
    Text,
    /// Password-like; rendered masked in every UI.
    Concealed,
    /// Email address.
    Email,
    /// URL.
    Url,
    /// Telephone number.
    Phone,
    /// A date.
    Date,
    /// A month/year pair (card expiry).
    MonthYear,
    /// A TOTP seed (`otpauth://` URI).
    Totp,
    /// A choice from a fixed list.
    Menu,
    /// Credit card number.
    CreditCardNumber,
    /// Credit card brand.
    CreditCardType,
    /// A postal address.
    Address,
    /// A reference to another item.
    Reference,
    /// A file attachment.
    File,
}

impl FieldKind {
    /// The canonical lower-case name used on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Concealed => "concealed",
            Self::Email => "email",
            Self::Url => "url",
            Self::Phone => "phone",
            Self::Date => "date",
            Self::MonthYear => "month-year",
            Self::Totp => "totp",
            Self::Menu => "menu",
            Self::CreditCardNumber => "credit-card-number",
            Self::CreditCardType => "credit-card-type",
            Self::Address => "address",
            Self::Reference => "reference",
            Self::File => "file",
        }
    }
}

impl std::fmt::Display for FieldKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// Metadata about one field. Carries the label, never the value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSummary {
    /// Field identifier.
    pub id: FieldId,
    /// Human label, e.g. `"password"`. Visible to agents when the item is `agent_visible`.
    pub label: String,
    /// Descriptive kind.
    pub kind: FieldKind,
    /// Whether the value is secret material.
    pub concealed: bool,
    /// Whether the field holds a value at all. A boolean, deliberately not a length
    /// (mcp-server.md §2.4).
    pub has_value: bool,
    /// Optional 1PUX-style section name.
    pub section: Option<String>,
    /// Per-field agent visibility override.
    pub agent_visible: bool,
}

/// Metadata about one item. Carries labels, never values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummary {
    /// Item identifier.
    pub id: ItemId,
    /// Logical vault the item belongs to.
    pub vault_id: VaultId,
    /// Item title.
    pub title: String,
    /// Item category.
    pub category: Category,
    /// Tags.
    pub tags: Vec<String>,
    /// Field metadata, in order.
    pub fields: Vec<FieldSummary>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
    /// Whether the item is exposed to agents at all (default `false`, threat-model M-9).
    pub agent_visible: bool,
    /// Whether the item is in the trash. Trashed items are never offered to agents.
    #[serde(default)]
    pub trashed: bool,
}

/// Metadata about a logical vault inside a vault file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSummary {
    /// Logical vault identifier.
    pub id: VaultId,
    /// Display name.
    pub name: String,
    /// Number of items it holds.
    pub item_count: usize,
    /// Number of environments it holds.
    pub environment_count: usize,
    /// Whether agents may see it at all.
    pub agent_visible: bool,
}

/// Where an environment variable's value comes from (vault-format §5.2).
///
/// This is the *kind* of the binding, never the binding's value: `Literal` says a value is stored
/// inline, it does not say what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VarSourceKind {
    /// A value stored inline in the environment.
    Literal,
    /// A reference to a field of an item.
    ItemField,
    /// Declared by an agent, not yet filled in by the user (mcp-server.md §2.6).
    Pending,
}

impl VarSourceKind {
    /// The canonical lower-case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::ItemField => "item-field",
            Self::Pending => "pending",
        }
    }
}

impl std::fmt::Display for VarSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// Metadata about one environment variable. Carries the name and the binding, never a value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVarSummary {
    /// Variable name, e.g. `"STRIPE_SECRET_KEY"`. Visible to agents.
    pub name: String,
    /// Where the value comes from.
    pub kind: VarSourceKind,
    /// For [`VarSourceKind::ItemField`], the item referenced.
    pub item_id: Option<ItemId>,
    /// For [`VarSourceKind::ItemField`], the field referenced.
    pub field_id: Option<FieldId>,
    /// Whether a value is available for this variable right now. A boolean, not a length.
    pub populated: bool,
    /// Optional hint an agent supplied to explain what the user should paste.
    pub hint: Option<String>,
}

/// Metadata about one environment. Carries names, never values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSummary {
    /// Environment identifier.
    pub id: EnvId,
    /// Logical vault the environment belongs to.
    pub vault_id: VaultId,
    /// Display name, e.g. `"acme-api / staging"`.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Variables, in order.
    pub variables: Vec<EnvVarSummary>,
    /// Whether agents may see this environment at all (default-deny, threat-model M-9).
    pub agent_visible: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
}

impl EnvironmentSummary {
    /// Just the variable names, in order — what `list_environments` puts in front of a model.
    #[must_use]
    pub fn variable_names(&self) -> Vec<String> {
        self.variables.iter().map(|v| v.name.clone()).collect()
    }
}

/// How a recorded action ended (vault-format §8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The action was performed.
    Allowed,
    /// The user declined the approval.
    Denied,
    /// The action failed for a reason other than a denial.
    ///
    /// The default, so that a half-built record that escapes an early return is recorded as a
    /// failure rather than as a success.
    #[default]
    Failed,
}

impl Outcome {
    /// The canonical lower-case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// What kind of access a lease grants (mcp-server.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseKind {
    /// Writing a `.env` file into a directory.
    EnvFile,
    /// Running one command in one directory.
    RunCommand,
}

impl LeaseKind {
    /// The canonical lower-case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnvFile => "env-file",
            Self::RunCommand => "run-command",
        }
    }
}

impl std::fmt::Display for LeaseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// Metadata about one active lease, for display and for `kagisecure audit`/the app's lease list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseSummary {
    /// Lease identifier.
    pub id: LeaseId,
    /// The environment the lease is scoped to.
    pub environment_id: EnvId,
    /// The canonical directory the lease is scoped to.
    pub directory: String,
    /// The variable names the lease covers.
    pub variables: Vec<String>,
    /// What the lease permits.
    pub kind: LeaseKind,
    /// The verified-or-not caller the lease was minted for.
    pub client_identity: String,
    /// Unix seconds at which the lease expires.
    pub expires_at: u64,
    /// Uses left before the lease dies.
    pub uses_remaining: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_honours_field_width_so_tables_line_up() {
        assert_eq!(format!("[{:<10}]", Category::Login), "[login     ]");
        assert_eq!(format!("[{:<10}]", FieldKind::Concealed), "[concealed ]");
    }

    fn all_named_categories() -> Vec<Category> {
        vec![
            Category::Login,
            Category::Password,
            Category::SecureNote,
            Category::CreditCard,
            Category::Identity,
            Category::ApiCredential,
            Category::Server,
            Category::Database,
            Category::SshKey,
            Category::SoftwareLicense,
            Category::Document,
            Category::Environment,
        ]
    }

    #[test]
    fn category_names_round_trip_through_the_command_line_form() {
        for c in all_named_categories() {
            let parsed: Category = c.as_str().parse().unwrap();
            assert_eq!(parsed, c);
        }
    }

    #[test]
    fn unknown_categories_are_preserved_rather_than_coerced() {
        let parsed: Category = "Crypto Wallet".parse().unwrap();
        assert_eq!(parsed, Category::Other("crypto-wallet".to_owned()));
    }

    #[test]
    fn every_category_round_trips_through_cbor() {
        // The on-disk representation (vault-format.md §5): each unit variant serializes as its
        // externally-tagged CBOR text-string tag, `Other(String)` as a one-key map. Adding new
        // unit variants must not change how the existing ones are encoded.
        let mut cases = all_named_categories();
        cases.push(Category::Other("crypto-wallet".to_owned()));

        for c in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&c, &mut buf).unwrap();
            let decoded: Category = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(decoded, c);
        }
    }
}
