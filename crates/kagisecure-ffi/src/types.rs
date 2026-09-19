//! The records and enums that cross the boundary.
//!
//! These are flat, owned, UniFFI-shaped mirrors of the core's types. They exist because UniFFI
//! needs plain data with no lifetimes and no generics, not because the app needs a different
//! model: every field here maps one-to-one onto something in [`kagisecure_core`], and the
//! conversions live in this file so there is exactly one place they can go wrong.
//!
//! Identifiers cross as strings. UUIDs have no UniFFI primitive, and a string is what Swift will
//! use as a `List` selection value anyway; the core parses them back.

use kagisecure_core::model::{Field, FieldValue, Item};
use kagisecure_core::proto;

/// How a field's value should be presented and edited (vault-format.md §5, ui-spec.md §4.2).
///
/// Mirrors [`kagisecure_core::proto::FieldKind`] exactly. Whether a field is *concealed* is a
/// property of the value it holds, not of this tag — `FieldView::concealed` says that.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FieldKind {
    /// Plain text.
    Text,
    /// Password-like; rendered masked.
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
    /// A TOTP seed. Display is M5; M3 stores and edits it as text.
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
    pub(crate) fn from_core(k: proto::FieldKind) -> Self {
        use proto::FieldKind as K;
        match k {
            K::Text => Self::Text,
            K::Concealed => Self::Concealed,
            K::Email => Self::Email,
            K::Url => Self::Url,
            K::Phone => Self::Phone,
            K::Date => Self::Date,
            K::MonthYear => Self::MonthYear,
            K::Totp => Self::Totp,
            K::Menu => Self::Menu,
            K::CreditCardNumber => Self::CreditCardNumber,
            K::CreditCardType => Self::CreditCardType,
            K::Address => Self::Address,
            K::Reference => Self::Reference,
            K::File => Self::File,
        }
    }

    pub(crate) fn to_core(self) -> proto::FieldKind {
        use proto::FieldKind as K;
        match self {
            Self::Text => K::Text,
            Self::Concealed => K::Concealed,
            Self::Email => K::Email,
            Self::Url => K::Url,
            Self::Phone => K::Phone,
            Self::Date => K::Date,
            Self::MonthYear => K::MonthYear,
            Self::Totp => K::Totp,
            Self::Menu => K::Menu,
            Self::CreditCardNumber => K::CreditCardNumber,
            Self::CreditCardType => K::CreditCardType,
            Self::Address => K::Address,
            Self::Reference => K::Reference,
            Self::File => K::File,
        }
    }
}

/// A category, as a sidebar row or a "+ New" menu entry needs it.
///
/// `id` is the canonical lower-case name the core parses (`"login"`, `"secure-note"`, …) and is
/// what the app sends back; the other two fields are for rendering only.
#[derive(Clone, Debug, uniffi::Record)]
pub struct CategoryInfo {
    /// Canonical name, e.g. `"credit-card"`.
    pub id: String,
    /// Display name, e.g. `"Credit Card"`.
    pub display_name: String,
    /// SF Symbol name from ui-spec.md §5.
    pub symbol_name: String,
}

impl CategoryInfo {
    pub(crate) fn from_core(c: &proto::Category) -> Self {
        Self {
            id: c.as_str().to_owned(),
            display_name: c.display_name(),
            symbol_name: c.symbol_name().to_owned(),
        }
    }
}

/// One field of an item, as the detail pane renders it.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FieldView {
    /// Field identifier.
    pub id: String,
    /// Human label.
    pub label: String,
    /// How to present it.
    pub kind: FieldKind,
    /// Whether the value is secret material and must be masked.
    pub concealed: bool,
    /// Whether there is a value at all. For a concealed field this is the only thing the detail
    /// pane knows until the user asks to reveal it — deliberately not a length.
    pub has_value: bool,
    /// The value, for a field that is not secret material. `None` for a concealed field: the
    /// plaintext is fetched on demand through `VaultSession::reveal_field`, so a rendered list of
    /// fields never carries every secret in the item.
    pub value: Option<String>,
    /// Optional section name.
    pub section: Option<String>,
    /// Per-field agent visibility override (ui-spec.md §4.4).
    pub agent_visible: bool,
}

impl FieldView {
    pub(crate) fn from_core(f: &Field) -> Self {
        Self {
            id: f.id.to_string(),
            label: f.label.clone(),
            kind: FieldKind::from_core(f.kind),
            concealed: f.value.is_secret(),
            has_value: f.value.has_value(),
            value: f.value.as_public().map(str::to_owned),
            section: f.section.clone(),
            agent_visible: f.agent_visible,
        }
    }
}

/// One item, as the list and detail panes render it.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemView {
    /// Item identifier.
    pub id: String,
    /// The logical vault it lives in.
    pub vault_id: String,
    /// Canonical category name.
    pub category: String,
    /// Display name of the category.
    pub category_display_name: String,
    /// SF Symbol for the category.
    pub category_symbol: String,
    /// Title.
    pub title: String,
    /// Fields, in display order.
    pub fields: Vec<FieldView>,
    /// Tags.
    pub tags: Vec<String>,
    /// Associated URLs.
    pub urls: Vec<String>,
    /// Free-form note.
    pub notes: Option<String>,
    /// Favourited.
    pub favorite: bool,
    /// Archived.
    pub archived: bool,
    /// In the trash.
    pub trashed: bool,
    /// Visible to agents (ui-spec.md §4.4). `false` on every newly created item.
    pub agent_visible: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
    /// The one-line subtitle the item list shows under the title (ui-spec.md §3).
    ///
    /// Computed here rather than in Swift so that the "username for a Login, hostname for a
    /// Server, masked last four for a card" rule has one implementation. It is never a secret: a
    /// concealed field contributes nothing to it, except a card number's last four digits, which
    /// ui-spec.md §3 asks for explicitly.
    pub subtitle: Option<String>,
}

impl ItemView {
    pub(crate) fn from_core(item: &Item) -> Self {
        Self {
            id: item.id.to_string(),
            vault_id: item.vault_id.to_string(),
            category: item.category.as_str().to_owned(),
            category_display_name: item.category.display_name(),
            category_symbol: item.category.symbol_name().to_owned(),
            title: item.title.clone(),
            fields: item.fields.iter().map(FieldView::from_core).collect(),
            tags: item.tags.clone(),
            urls: item.urls.clone(),
            notes: item.notes.clone(),
            favorite: item.favorite,
            archived: item.archived,
            trashed: item.is_trashed(),
            agent_visible: item.agent_visible,
            created_at: item.created_at,
            updated_at: item.updated_at,
            subtitle: subtitle(item),
        }
    }
}

/// The item list's one-line subtitle. Public values only; see [`ItemView::subtitle`].
fn subtitle(item: &Item) -> Option<String> {
    use proto::Category as C;

    let public = |label: &str| {
        item.fields
            .iter()
            .find(|f| f.label.eq_ignore_ascii_case(label))
            .and_then(|f| f.value.as_public())
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };

    match item.category {
        C::Login | C::Identity => public("username").or_else(|| item.urls.first().cloned()),
        C::Server | C::Database => public("hostname"),
        C::ApiCredential => public("endpoint"),
        C::CreditCard => {
            // The number is secret material, so the last four have to come from the secret
            // itself. ui-spec.md §3 asks for exactly this and nothing more.
            let field = item
                .fields
                .iter()
                .find(|f| f.label.eq_ignore_ascii_case("number"))?;
            let secret = field.value.as_secret()?;
            let digits: Vec<u8> = secret
                .expose()
                .iter()
                .copied()
                .filter(u8::is_ascii_digit)
                .collect();
            (digits.len() >= 4).then(|| {
                let last4 = String::from_utf8_lossy(&digits[digits.len() - 4..]).into_owned();
                format!("•••• {last4}")
            })
        }
        _ => item.urls.first().cloned(),
    }
}

/// A field as the edit sheet hands it back.
///
/// `id` is `None` for a field the user has just added; the core mints one. `value` is the
/// plaintext the user typed — see [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md)
/// crossing 2 — and is interpreted as secret material when `concealed` is set.
#[derive(Clone, Debug, uniffi::Record)]
pub struct FieldDraft {
    /// Existing field identifier, or `None` for a new field.
    pub id: Option<String>,
    /// Human label.
    pub label: String,
    /// How to present it.
    pub kind: FieldKind,
    /// Whether the value is secret material.
    pub concealed: bool,
    /// The value.
    pub value: String,
    /// Optional section name.
    pub section: Option<String>,
    /// Per-field agent visibility override.
    pub agent_visible: bool,
}

/// An item as the edit sheet hands it back.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ItemDraft {
    /// The item being edited.
    pub id: String,
    /// Canonical category name.
    pub category: String,
    /// Title.
    pub title: String,
    /// Fields, in the order they should be stored.
    pub fields: Vec<FieldDraft>,
    /// Tags.
    pub tags: Vec<String>,
    /// Associated URLs.
    pub urls: Vec<String>,
    /// Free-form note.
    pub notes: Option<String>,
}

/// Which sidebar section the item list is showing (ui-spec.md §2.2).
///
/// Filtering is a core concern, not a Swift one: "All Items" meaning "not archived and not
/// trashed" is a rule about the model, and if Swift owned it, the CLI and the app could disagree
/// about what a user's vault contains.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ItemFilter {
    /// Every item that is neither archived nor trashed.
    All,
    /// Favourites, excluding archived and trashed.
    Favorites,
    /// One category, excluding archived and trashed.
    Category {
        /// Canonical category name.
        category: String,
    },
    /// One tag, excluding archived and trashed.
    Tag {
        /// The tag.
        tag: String,
    },
    /// Archived items.
    Archive,
    /// Trashed items.
    Trash,
}

/// The item list's sort order (ui-spec.md §3).
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ItemSort {
    /// Title, A–Z, case-insensitive.
    Title,
    /// Most recently modified first.
    DateModified,
    /// Most recently created first.
    DateCreated,
    /// Category, then title.
    Category,
}

/// The counts the sidebar shows next to its rows.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SidebarCounts {
    /// Items in "All Items".
    pub all: u32,
    /// Favourites.
    pub favorites: u32,
    /// Archived items.
    pub archive: u32,
    /// Trashed items.
    pub trash: u32,
    /// Per-category counts, in catalogue order. Categories with no items are present with a zero
    /// count: ui-spec.md §2.2 wants the row shown and greyed, not hidden.
    pub categories: Vec<TagCount>,
    /// Per-tag counts, sorted by tag.
    pub tags: Vec<TagCount>,
}

/// A name and how many items carry it. Used for both categories and tags.
#[derive(Clone, Debug, uniffi::Record)]
pub struct TagCount {
    /// The category's canonical name, or the tag.
    pub name: String,
    /// How many items.
    pub count: u32,
}

/// A logical vault inside the vault file (vault-format.md §2.2).
#[derive(Clone, Debug, uniffi::Record)]
pub struct VaultView {
    /// Identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Items it holds, trashed and archived included.
    pub item_count: u32,
    /// Whether agents may see it at all.
    pub agent_visible: bool,
}

/// Where one environment variable's value comes from (vault-format.md §5.2, ADR-0007 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum VarBinding {
    /// A value typed into the app and stored inline in this environment.
    Literal,
    /// A reference into an item's field — preferred: rotate once, every environment follows.
    ItemField,
    /// Declared by an agent through `add_variables` and still waiting for the user to supply a
    /// value (mcp-server.md §2.6). This is what the "Pending" badge renders.
    Pending,
}

/// One variable in an environment. Its **name** and its binding — never its value.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EnvVarView {
    /// Variable name, e.g. `"STRIPE_SECRET_KEY"`.
    pub name: String,
    /// Where the value comes from.
    pub binding: VarBinding,
    /// The item referenced, for [`VarBinding::ItemField`].
    pub item_id: Option<String>,
    /// The field referenced, for [`VarBinding::ItemField`].
    pub field_id: Option<String>,
    /// Whether a value is available right now. A boolean, not a length.
    pub populated: bool,
    /// The agent's explanation of what the user should paste, for a pending variable.
    pub hint: Option<String>,
}

/// An environment, for the sidebar's "Agent access" section (ui-spec.md §2.2, §10.4).
///
/// Names and bindings only, never values — the same rule the MCP surface follows. `variables` is
/// what the environment editor renders; `variable_names` is the same list flattened, kept because
/// most callers want only that.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EnvironmentView {
    /// Identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Variable names, in order.
    pub variable_names: Vec<String>,
    /// The variables in full, in order.
    pub variables: Vec<EnvVarView>,
    /// How many are still waiting for a value from the user.
    pub pending_count: u32,
    /// Whether agents may see it.
    pub agent_visible: bool,
}

impl EnvironmentView {
    /// Build from the core model.
    pub(crate) fn from_core(env: &kagisecure_core::model::Environment) -> Self {
        let variables: Vec<EnvVarView> = env
            .vars
            .iter()
            .map(|v| {
                let summary = v.summary();
                EnvVarView {
                    name: summary.name,
                    binding: match summary.kind {
                        kagisecure_core::proto::VarSourceKind::Literal => VarBinding::Literal,
                        kagisecure_core::proto::VarSourceKind::ItemField => VarBinding::ItemField,
                        kagisecure_core::proto::VarSourceKind::Pending => VarBinding::Pending,
                    },
                    item_id: summary.item_id.map(|i| i.to_string()),
                    field_id: summary.field_id.map(|f| f.to_string()),
                    populated: summary.populated,
                    hint: summary.hint,
                }
            })
            .collect();
        Self {
            id: env.id.to_string(),
            name: env.name.clone(),
            description: env.description.clone(),
            variable_names: variables.iter().map(|v| v.name.clone()).collect(),
            pending_count: u32::try_from(variables.iter().filter(|v| !v.populated).count())
                .unwrap_or(u32::MAX),
            variables,
            agent_visible: env.agent_visible,
        }
    }
}

/// How the current session unlocked the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UnlockKind {
    /// The master password.
    Password,
    /// The printable recovery code. The app should ask for a new master password afterwards.
    RecoveryCode,
    /// The platform keystore — Touch ID on macOS.
    PlatformKey,
}

/// Whether `value` should be stored as secret material.
pub(crate) fn field_value(concealed: bool, value: String) -> FieldValue {
    if concealed {
        FieldValue::Secret(kagisecure_core::Secret::from_string(value))
    } else {
        FieldValue::Public(value)
    }
}
