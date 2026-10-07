//! Every fieldless enum's tag, as it crosses: a `u32`.
//!
//! The `#[repr(u32)]` enums here are the *names* of those tags. They are never a field or an
//! argument type — a value C# made up must be an error, and a Rust enum holding an out-of-range
//! discriminant is undefined behaviour — but csbindgen generates each into C# as an internal
//! `enum : uint`, and the public C# enums take their values from them, so a renumbering here fails
//! to compile there rather than silently meaning something else.
//!
//! Each tag enum has one conversion pair, [`tags!`]-generated: `tag` (UniFFI enum → `u32`) and
//! `parse` (`u32` → UniFFI enum, or [`FfiError::Invalid`] naming the tag).

use crate::agent::{ApprovalAction, PeerRequirementKind};
use crate::{
    DuplicatePolicyView, FfiError, FfiResult, FieldKind, GeneratorMode, ImportDropKindView,
    ImportFormat, ImportItemActionView, ItemSort, PresenceOutcome, ReleasePurpose, StrengthBucket,
    TotpAlgorithm, UnlockKind, VarBinding, VaultConflictKindView, WordSeparator,
};

/// `tag` and `parse` for a tag enum whose variants are named exactly like the UniFFI enum's.
macro_rules! tags {
    ($kgs:ident, $what:literal, $ffi:ident { $($variant:ident),+ $(,)? }) => {
        impl $kgs {
            /// The tag for `value`.
            #[allow(dead_code, reason = "every tag enum gets both directions")]
            pub(crate) fn tag(value: $ffi) -> u32 {
                match value {
                    $($ffi::$variant => Self::$variant as u32,)+
                }
            }

            /// The value `tag` names, or [`FfiError::Invalid`].
            #[allow(dead_code, reason = "every tag enum gets both directions")]
            pub(crate) fn parse(tag: u32) -> FfiResult<$ffi> {
                $(if tag == Self::$variant as u32 {
                    return Ok($ffi::$variant);
                })+
                Err(FfiError::invalid(format!(concat!("unknown ", $what, " {}"), tag)))
            }
        }
    };
}

/// [`FieldKind`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsFieldKind {
    /// Plain text.
    Text = 0,
    /// Password-like; rendered masked.
    Concealed = 1,
    /// Email address.
    Email = 2,
    /// URL.
    Url = 3,
    /// Telephone number.
    Phone = 4,
    /// A date.
    Date = 5,
    /// A month/year pair.
    MonthYear = 6,
    /// A TOTP seed.
    Totp = 7,
    /// A choice from a fixed list.
    Menu = 8,
    /// Credit card number.
    CreditCardNumber = 9,
    /// Credit card brand.
    CreditCardType = 10,
    /// A postal address.
    Address = 11,
    /// A reference to another item.
    Reference = 12,
    /// A file attachment.
    File = 13,
}
tags!(
    KgsFieldKind,
    "field kind",
    FieldKind {
        Text,
        Concealed,
        Email,
        Url,
        Phone,
        Date,
        MonthYear,
        Totp,
        Menu,
        CreditCardNumber,
        CreditCardType,
        Address,
        Reference,
        File,
    }
);

/// [`ItemSort`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsItemSort {
    /// Title, A–Z.
    Title = 0,
    /// Most recently modified first.
    DateModified = 1,
    /// Most recently created first.
    DateCreated = 2,
    /// Category, then title.
    Category = 3,
}
tags!(
    KgsItemSort,
    "item sort",
    ItemSort {
        Title,
        DateModified,
        DateCreated,
        Category,
    }
);

/// [`UnlockKind`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsUnlockKind {
    /// The master password.
    Password = 0,
    /// The printable recovery code.
    RecoveryCode = 1,
    /// The platform keystore.
    PlatformKey = 2,
}
tags!(
    KgsUnlockKind,
    "unlock kind",
    UnlockKind {
        Password,
        RecoveryCode,
        PlatformKey,
    }
);

/// [`VarBinding`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsVarBinding {
    /// Stored inline in the environment.
    Literal = 0,
    /// A reference into an item's field.
    ItemField = 1,
    /// Declared by an agent, still waiting for a value.
    Pending = 2,
}
tags!(
    KgsVarBinding,
    "variable binding",
    VarBinding {
        Literal,
        ItemField,
        Pending,
    }
);

/// [`GeneratorMode`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsGeneratorMode {
    /// Random characters.
    Characters = 0,
    /// Memorable words.
    Words = 1,
}
tags!(
    KgsGeneratorMode,
    "generator mode",
    GeneratorMode { Characters, Words }
);

/// [`WordSeparator`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsWordSeparator {
    /// `-`
    Hyphen = 0,
    /// `_`
    Underscore = 1,
    /// `.`
    Period = 2,
    /// A space.
    Space = 3,
    /// Nothing at all.
    None = 4,
}
tags!(
    KgsWordSeparator,
    "separator",
    WordSeparator {
        Hyphen,
        Underscore,
        Period,
        Space,
        None,
    }
);

/// [`StrengthBucket`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsStrengthBucket {
    /// Under 28 bits.
    VeryWeak = 0,
    /// 28–39 bits.
    Weak = 1,
    /// 40–59 bits.
    Fair = 2,
    /// 60–79 bits.
    Good = 3,
    /// 80 bits and up.
    Excellent = 4,
}
tags!(
    KgsStrengthBucket,
    "strength bucket",
    StrengthBucket {
        VeryWeak,
        Weak,
        Fair,
        Good,
        Excellent,
    }
);

/// [`TotpAlgorithm`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsTotpAlgorithm {
    /// HMAC-SHA-1.
    Sha1 = 0,
    /// HMAC-SHA-256.
    Sha256 = 1,
    /// HMAC-SHA-512.
    Sha512 = 2,
}
tags!(
    KgsTotpAlgorithm,
    "TOTP algorithm",
    TotpAlgorithm {
        Sha1,
        Sha256,
        Sha512,
    }
);

/// [`ApprovalAction`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsApprovalAction {
    /// `create_environment`.
    CreateEnvironment = 0,
    /// `add_variables`.
    AddVariables = 1,
    /// `write_env_file`.
    WriteEnvFile = 2,
    /// `run_with_env`.
    RunWithEnv = 3,
    /// A browser extension wants to fill a credential.
    FillCredential = 4,
    /// An agent asks for a login to be typed into a browser tab (ADR-0036).
    ///
    /// Here only because the conversion from [`ApprovalAction`] is exhaustive. Windows never
    /// offers agent fills — `request_fill` answers `FILL_UNAVAILABLE` there before anything is
    /// asked — so a Windows host never receives this tag in practice, and the facts such a sheet
    /// would show are not in [`crate::capi::KgsApprovalRequest`] (see "What is not here" in the
    /// module docs). A host that does receive it denies it.
    AgentFill = 5,
    /// An agent asks for a test login at a site outside the allowed origins (ADR-0048 §3).
    ///
    /// Here only because the conversion from [`ApprovalAction`] is exhaustive. Agent test logins
    /// are macOS only today, so a Windows host never receives this tag in practice, and the facts
    /// such a sheet would show are not in [`crate::capi::KgsApprovalRequest`]. A host that does
    /// receive it denies it.
    CreateTestLogin = 6,
    /// An agent asks to run a command and store its output in the vault (ADR-0049).
    ///
    /// Here only because the conversion from [`ApprovalAction`] is exhaustive. The agent refuses
    /// `store_command_output` on Windows before anything is asked, so a Windows host never
    /// receives this tag in practice. A host that does receive it denies it.
    StoreCommandOutput = 7,
}
tags!(
    KgsApprovalAction,
    "approval action",
    ApprovalAction {
        CreateEnvironment,
        AddVariables,
        WriteEnvFile,
        RunWithEnv,
        FillCredential,
        AgentFill,
        CreateTestLogin,
        StoreCommandOutput,
    }
);

/// The tags of [`crate::ApprovalDecision`], an enum with data; see [`crate::capi::KgsApprovalDecision`].
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsApprovalDecisionTag {
    /// Allow once.
    AllowOnce = 0,
    /// Allow for a TTL and a use count.
    AllowSession = 1,
    /// Refuse.
    Deny = 2,
}

/// The tags of [`crate::ItemFilter`], an enum with data; see [`crate::capi::KgsItemFilter`].
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsItemFilterTag {
    /// Every live item.
    All = 0,
    /// Favourites.
    Favorites = 1,
    /// One category; the payload is its canonical name.
    Category = 2,
    /// One tag; the payload is the tag.
    Tag = 3,
    /// Archived items.
    Archive = 4,
    /// Trashed items.
    Trash = 5,
}

/// [`ImportFormat`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsImportFormat {
    /// 1Password's archive.
    OnePux = 0,
    /// Apple Passwords CSV.
    AppleCsv = 1,
    /// Chromium CSV.
    ChromiumCsv = 2,
    /// Firefox CSV.
    FirefoxCsv = 3,
    /// 1Password CSV.
    OnePasswordCsv = 4,
}
tags!(
    KgsImportFormat,
    "import format",
    ImportFormat {
        OnePux,
        AppleCsv,
        ChromiumCsv,
        FirefoxCsv,
        OnePasswordCsv,
    }
);

/// [`DuplicatePolicyView`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsDuplicatePolicy {
    /// Leave the existing item alone.
    Skip = 0,
    /// Overwrite what the source carries.
    Update = 1,
    /// Import it as a second item.
    KeepBoth = 2,
}
tags!(
    KgsDuplicatePolicy,
    "duplicate policy",
    DuplicatePolicyView {
        Skip,
        Update,
        KeepBoth,
    }
);

/// [`ImportItemActionView`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsImportItemAction {
    /// Add it.
    Create = 0,
    /// Overwrite the match.
    Update = 1,
    /// Leave the match alone.
    Skip = 2,
    /// Add it beside the match.
    KeepBoth = 3,
}
tags!(
    KgsImportItemAction,
    "import item action",
    ImportItemActionView {
        Create,
        Update,
        Skip,
        KeepBoth,
    }
);

/// [`ImportDropKindView`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsImportDropKind {
    /// A file attachment.
    Attachment = 0,
    /// A passkey.
    Passkey = 1,
    /// An unreadable password-history entry.
    PasswordHistory = 2,
    /// A breach-report flag.
    WatchtowerFlag = 3,
    /// An empty form field.
    EmptyFormField = 4,
    /// Something unrecognized.
    UnknownEntry = 5,
}
tags!(
    KgsImportDropKind,
    "import drop kind",
    ImportDropKindView {
        Attachment,
        Passkey,
        PasswordHistory,
        WatchtowerFlag,
        EmptyFormField,
        UnknownEntry,
    }
);

/// [`PeerRequirementKind`]'s tags (ADR-0032).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsPeerRequirementKind {
    /// One of our own helpers: signed with the same key as this build.
    OwnHelper = 0,
    /// A browser: signed by the publisher its executable name maps to.
    Browser = 1,
}
tags!(
    KgsPeerRequirementKind,
    "peer requirement kind",
    PeerRequirementKind { OwnHelper, Browser }
);

/// [`PresenceOutcome`]'s tags: what the presence gate's `confirm` callback returns.
///
/// A value the callback returns that is not one of these is read as `Cancelled` — never as
/// `Confirmed` — so a C# bug fails closed (see [`crate::capi::kgs_session_set_presence_gate`]).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsPresenceOutcome {
    /// A person proved presence. The one answer that releases anything.
    Confirmed = 0,
    /// The person dismissed the prompt, or the check failed.
    Cancelled = 1,
    /// No presence check can run on this PC right now.
    Unavailable = 2,
    /// Another prompt is already up; this one was refused rather than queued.
    Busy = 3,
}
tags!(
    KgsPresenceOutcome,
    "presence outcome",
    PresenceOutcome {
        Confirmed,
        Cancelled,
        Unavailable,
        Busy,
    }
);

/// [`ReleasePurpose`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsReleasePurpose {
    /// Show the value in the detail pane.
    Reveal = 0,
    /// Copy it without showing it. One use.
    Copy = 1,
    /// Copy from a quick-access surface. One use.
    QuickAccessCopy = 2,
    /// Show one concealed value inside the edit sheet.
    EditReveal = 3,
}
tags!(
    KgsReleasePurpose,
    "release purpose",
    ReleasePurpose {
        Reveal,
        Copy,
        QuickAccessCopy,
        EditReveal,
    }
);

/// [`VaultConflictKindView`]'s tags.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsVaultConflictKind {
    /// An older or different history of this vault was put at the path.
    Diverged = 0,
    /// A different vault file sits at the path.
    Replaced = 1,
    /// The file at the path cannot be parsed.
    Unreadable = 2,
    /// The file is gone.
    Removed = 3,
}
tags!(
    KgsVaultConflictKind,
    "vault conflict kind",
    VaultConflictKindView {
        Diverged,
        Replaced,
        Unreadable,
        Removed,
    }
);

/// [`crate::MasterPasswordCheck`]'s variant, as the `tag` of a
/// [`crate::capi::KgsMasterPasswordCheck`].
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsMasterPasswordCheckTag {
    /// The password is this vault's master password.
    Verified = 0,
    /// It is not; `retry_after_ms` says when the next attempt will be checked.
    Wrong = 1,
    /// Not checked at all; `retry_after_ms` says when an attempt will be.
    Throttled = 2,
}

/// [`crate::KeepAppVersionOutcome`]'s variant, as the `tag` of a
/// [`crate::capi::KgsKeepAppVersionOutcome`].
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsKeepAppVersionOutcomeTag {
    /// The file now holds this session's version.
    Overwritten = 0,
    /// The file already continued this session's; nothing was written.
    NoLongerInConflict = 1,
    /// The file changed again since the confirmation; `details` describes it now.
    FileChangedAgain = 2,
}
