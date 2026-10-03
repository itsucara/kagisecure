//! Items, fields, categories, the sidebar, logical vaults, environments and audit rows.

use super::{
    KgsBuffer, KgsBufferArray, KgsFieldKind, KgsItemFilterTag, KgsOptBuffer, KgsOptSlice, KgsSlice,
    KgsSliceList, KgsVarBinding, Release, borrow_list, free,
};
use crate::agent::AuditRowView;
use crate::{
    CategoryInfo, EnvVarView, EnvironmentView, FfiError, FfiResult, FieldDraft, FieldView,
    ItemDraft, ItemFilter, ItemView, SidebarCounts, TagCount, VaultView,
};

// -------------------------------------------------------------------------------------------
// Categories
// -------------------------------------------------------------------------------------------

/// [`CategoryInfo`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsCategoryInfo {
    /// Canonical name, e.g. `"credit-card"`.
    pub id: KgsBuffer,
    /// Display name.
    pub display_name: KgsBuffer,
    /// SF Symbol name. The Windows app maps it to its own glyphs.
    pub symbol_name: KgsBuffer,
}

impl KgsCategoryInfo {
    pub(crate) fn new(c: CategoryInfo) -> Self {
        Self {
            id: KgsBuffer::from_string(c.id),
            display_name: KgsBuffer::from_string(c.display_name),
            symbol_name: KgsBuffer::from_string(c.symbol_name),
        }
    }
}

impl Release for KgsCategoryInfo {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.display_name.release();
            self.symbol_name.release();
        }
    }
}

/// A list of [`KgsCategoryInfo`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsCategoryInfoArray {
    /// First element.
    pub ptr: *mut KgsCategoryInfo,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsCategoryInfoArray, KgsCategoryInfo);

// -------------------------------------------------------------------------------------------
// Fields and items
// -------------------------------------------------------------------------------------------

/// [`FieldView`]. `value` is absent for a concealed field: its plaintext crosses only through
/// `kgs_session_reveal_field`.
#[repr(C)]
#[derive(Debug)]
pub struct KgsFieldView {
    /// Field identifier.
    pub id: KgsBuffer,
    /// Human label.
    pub label: KgsBuffer,
    /// A [`KgsFieldKind`] tag.
    pub kind: u32,
    /// 0 or 1: the value is secret material.
    pub concealed: u8,
    /// 0 or 1: there is a value at all.
    pub has_value: u8,
    /// The value, for a field that is not concealed.
    pub value: KgsOptBuffer,
    /// Optional section name.
    pub section: KgsOptBuffer,
    /// 0 or 1: per-field agent visibility.
    pub agent_visible: u8,
}

impl KgsFieldView {
    pub(crate) fn new(f: FieldView) -> Self {
        Self {
            id: KgsBuffer::from_string(f.id),
            label: KgsBuffer::from_string(f.label),
            kind: KgsFieldKind::tag(f.kind),
            concealed: u8::from(f.concealed),
            has_value: u8::from(f.has_value),
            value: KgsOptBuffer::from_string(f.value),
            section: KgsOptBuffer::from_string(f.section),
            agent_visible: u8::from(f.agent_visible),
        }
    }
}

impl Release for KgsFieldView {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.label.release();
            self.value.release();
            self.section.release();
        }
    }
}

/// A list of [`KgsFieldView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsFieldViewArray {
    /// First element.
    pub ptr: *mut KgsFieldView,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsFieldViewArray, KgsFieldView);

/// [`ItemView`]. Free with [`kgs_item_view_free`].
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsItemView {
    /// Item identifier.
    pub id: KgsBuffer,
    /// The logical vault it lives in.
    pub vault_id: KgsBuffer,
    /// Canonical category name.
    pub category: KgsBuffer,
    /// Display name of the category.
    pub category_display_name: KgsBuffer,
    /// SF Symbol for the category.
    pub category_symbol: KgsBuffer,
    /// Title.
    pub title: KgsBuffer,
    /// Fields, in display order.
    pub fields: KgsFieldViewArray,
    /// Tags.
    pub tags: KgsBufferArray,
    /// Associated URLs.
    pub urls: KgsBufferArray,
    /// 0 or 1: whether the item has a note. Never the note itself — that is a release
    /// ([`crate::capi::kgs_session_release_notes`], ADR-0038 user decision 3).
    pub has_notes: u8,
    /// 0 or 1.
    pub favorite: u8,
    /// 0 or 1.
    pub archived: u8,
    /// 0 or 1.
    pub trashed: u8,
    /// 0 or 1.
    pub agent_visible: u8,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
    /// The item list's one-line subtitle. Never a secret.
    pub subtitle: KgsOptBuffer,
    /// The username, if the item has one. Never a secret.
    pub username: KgsOptBuffer,
    /// The id of the field this item designates as its primary secret, if any.
    pub primary_secret_field_id: KgsOptBuffer,
    /// An opaque fingerprint of the item as read; hand it back unchanged in
    /// [`KgsItemDraft::revision`] and to [`crate::capi::kgs_session_delete_item`].
    pub revision: KgsBuffer,
}

impl KgsItemView {
    pub(crate) fn new(v: ItemView) -> Self {
        Self {
            id: KgsBuffer::from_string(v.id),
            vault_id: KgsBuffer::from_string(v.vault_id),
            category: KgsBuffer::from_string(v.category),
            category_display_name: KgsBuffer::from_string(v.category_display_name),
            category_symbol: KgsBuffer::from_string(v.category_symbol),
            title: KgsBuffer::from_string(v.title),
            fields: KgsFieldViewArray::collect(v.fields, KgsFieldView::new),
            tags: KgsBufferArray::strings(v.tags),
            urls: KgsBufferArray::strings(v.urls),
            has_notes: u8::from(v.has_notes),
            favorite: u8::from(v.favorite),
            archived: u8::from(v.archived),
            trashed: u8::from(v.trashed),
            agent_visible: u8::from(v.agent_visible),
            created_at: v.created_at,
            updated_at: v.updated_at,
            subtitle: KgsOptBuffer::from_string(v.subtitle),
            username: KgsOptBuffer::from_string(v.username),
            primary_secret_field_id: KgsOptBuffer::from_string(v.primary_secret_field_id),
            revision: KgsBuffer::from_string(v.revision),
        }
    }
}

impl Release for KgsItemView {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.vault_id.release();
            self.category.release();
            self.category_display_name.release();
            self.category_symbol.release();
            self.title.release();
            self.fields.release();
            self.tags.release();
            self.urls.release();
            self.subtitle.release();
            self.username.release();
            self.primary_secret_field_id.release();
            self.revision.release();
        }
    }
}

/// A list of [`KgsItemView`]. Free with [`kgs_item_view_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsItemViewArray {
    /// First element.
    pub ptr: *mut KgsItemView,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsItemViewArray, KgsItemView);

/// [`FieldDraft`], going in. ADR-0008 crossing 2: `value` is the plaintext the user typed, or
/// absent to keep the field's stored value — the edit sheet is never handed a concealed value to
/// send back (ADR-0038 user decision 4).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsFieldDraft {
    /// Existing field identifier, or absent for a new field.
    pub id: KgsOptSlice,
    /// Human label.
    pub label: KgsSlice,
    /// A [`KgsFieldKind`] tag.
    pub kind: u32,
    /// 0 or 1: the value is secret material.
    pub concealed: u8,
    /// The new value, or absent to keep the stored one.
    pub value: KgsOptSlice,
    /// Optional section name.
    pub section: KgsOptSlice,
    /// 0 or 1.
    pub agent_visible: u8,
}

impl KgsFieldDraft {
    /// # Safety
    ///
    /// Every slice inside must satisfy [`KgsSlice`]'s contract.
    unsafe fn to_ffi(self) -> FfiResult<FieldDraft> {
        // SAFETY: forwarded to the caller.
        unsafe {
            Ok(FieldDraft {
                id: self.id.string()?,
                label: self.label.string()?,
                kind: KgsFieldKind::parse(self.kind)?,
                concealed: self.concealed != 0,
                value: self.value.string()?,
                section: self.section.string()?,
                agent_visible: self.agent_visible != 0,
            })
        }
    }
}

/// A borrowed list of [`KgsFieldDraft`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsFieldDraftList {
    /// First element. May be null only when `len` is zero.
    pub ptr: *const KgsFieldDraft,
    /// How many.
    pub len: usize,
}

/// [`ItemDraft`], going in.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsItemDraft {
    /// The item being edited.
    pub id: KgsSlice,
    /// Canonical category name.
    pub category: KgsSlice,
    /// Title.
    pub title: KgsSlice,
    /// Fields, in the order they should be stored.
    pub fields: KgsFieldDraftList,
    /// Tags.
    pub tags: KgsSliceList,
    /// Associated URLs.
    pub urls: KgsSliceList,
    /// The note: absent keeps the stored note, empty removes it, anything else replaces it.
    pub notes: KgsOptSlice,
    /// [`KgsItemView::revision`] as it stood when the edit began.
    pub revision: KgsSlice,
}

impl KgsItemDraft {
    /// # Safety
    ///
    /// Every slice and list inside must satisfy its type's contract.
    pub(crate) unsafe fn to_ffi(self) -> FfiResult<ItemDraft> {
        // SAFETY: forwarded to the caller.
        unsafe {
            let fields = borrow_list(self.fields.ptr, self.fields.len)?
                .iter()
                .map(|f| f.to_ffi())
                .collect::<FfiResult<Vec<_>>>()?;
            Ok(ItemDraft {
                id: self.id.string()?,
                category: self.category.string()?,
                title: self.title.string()?,
                fields,
                tags: self.tags.strings()?,
                urls: self.urls.strings()?,
                notes: self.notes.string()?,
                revision: self.revision.string()?,
            })
        }
    }
}

/// [`ItemFilter`] — an enum with data — as a tag and one payload slot.
///
/// `value` is read only for the two variants that carry a string and ignored for the rest.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsItemFilter {
    /// A [`KgsItemFilterTag`].
    pub tag: u32,
    /// The category's canonical name for `Category`, the tag for `Tag`.
    pub value: KgsSlice,
}

impl KgsItemFilter {
    /// # Safety
    ///
    /// `value` must satisfy [`KgsSlice::bytes`]'s contract.
    pub(crate) unsafe fn to_ffi(self) -> FfiResult<ItemFilter> {
        use KgsItemFilterTag as T;
        Ok(match self.tag {
            t if t == T::All as u32 => ItemFilter::All,
            t if t == T::Favorites as u32 => ItemFilter::Favorites,
            t if t == T::Category as u32 => ItemFilter::Category {
                // SAFETY: forwarded to the caller.
                category: unsafe { self.value.string() }?,
            },
            t if t == T::Tag as u32 => ItemFilter::Tag {
                // SAFETY: forwarded to the caller.
                tag: unsafe { self.value.string() }?,
            },
            t if t == T::Archive as u32 => ItemFilter::Archive,
            t if t == T::Trash as u32 => ItemFilter::Trash,
            other => return Err(FfiError::invalid(format!("unknown item filter {other}"))),
        })
    }
}

// -------------------------------------------------------------------------------------------
// Sidebar and logical vaults
// -------------------------------------------------------------------------------------------

/// [`TagCount`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsTagCount {
    /// The category's canonical name, or the tag.
    pub name: KgsBuffer,
    /// How many items.
    pub count: u32,
}

impl Release for KgsTagCount {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.name.release() };
    }
}

/// A list of [`KgsTagCount`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsTagCountArray {
    /// First element.
    pub ptr: *mut KgsTagCount,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsTagCountArray, KgsTagCount);

fn tag_count(t: TagCount) -> KgsTagCount {
    KgsTagCount {
        name: KgsBuffer::from_string(t.name),
        count: t.count,
    }
}

/// [`SidebarCounts`]. Free with [`kgs_sidebar_counts_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsSidebarCounts {
    /// Items in "All Items".
    pub all: u32,
    /// Favourites.
    pub favorites: u32,
    /// Archived items.
    pub archive: u32,
    /// Trashed items.
    pub trash: u32,
    /// Per-category counts, in catalogue order.
    pub categories: KgsTagCountArray,
    /// Per-tag counts, sorted by tag.
    pub tags: KgsTagCountArray,
}

impl KgsSidebarCounts {
    pub(crate) fn new(c: SidebarCounts) -> Self {
        Self {
            all: c.all,
            favorites: c.favorites,
            archive: c.archive,
            trash: c.trash,
            categories: KgsTagCountArray::collect(c.categories, tag_count),
            tags: KgsTagCountArray::collect(c.tags, tag_count),
        }
    }
}

impl Release for KgsSidebarCounts {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.categories.release();
            self.tags.release();
        }
    }
}

/// [`VaultView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsVaultView {
    /// Identifier.
    pub id: KgsBuffer,
    /// Display name.
    pub name: KgsBuffer,
    /// Items it holds, trashed and archived included.
    pub item_count: u32,
    /// 0 or 1.
    pub agent_visible: u8,
}

impl KgsVaultView {
    pub(crate) fn new(v: VaultView) -> Self {
        Self {
            id: KgsBuffer::from_string(v.id),
            name: KgsBuffer::from_string(v.name),
            item_count: v.item_count,
            agent_visible: u8::from(v.agent_visible),
        }
    }
}

impl Release for KgsVaultView {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.name.release();
        }
    }
}

/// A list of [`KgsVaultView`]. Free with [`kgs_vault_view_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsVaultViewArray {
    /// First element.
    pub ptr: *mut KgsVaultView,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsVaultViewArray, KgsVaultView);

// -------------------------------------------------------------------------------------------
// Environments
// -------------------------------------------------------------------------------------------

/// [`EnvVarView`]: a variable's name and binding, never its value.
#[repr(C)]
#[derive(Debug)]
pub struct KgsEnvVarView {
    /// Variable name.
    pub name: KgsBuffer,
    /// A [`KgsVarBinding`] tag.
    pub binding: u32,
    /// The item referenced, for an item-field binding.
    pub item_id: KgsOptBuffer,
    /// The field referenced, for an item-field binding.
    pub field_id: KgsOptBuffer,
    /// 0 or 1: a value is available.
    pub populated: u8,
    /// The agent's hint, for a pending variable.
    pub hint: KgsOptBuffer,
}

impl KgsEnvVarView {
    fn new(v: EnvVarView) -> Self {
        Self {
            name: KgsBuffer::from_string(v.name),
            binding: KgsVarBinding::tag(v.binding),
            item_id: KgsOptBuffer::from_string(v.item_id),
            field_id: KgsOptBuffer::from_string(v.field_id),
            populated: u8::from(v.populated),
            hint: KgsOptBuffer::from_string(v.hint),
        }
    }
}

impl Release for KgsEnvVarView {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.name.release();
            self.item_id.release();
            self.field_id.release();
            self.hint.release();
        }
    }
}

/// A list of [`KgsEnvVarView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsEnvVarViewArray {
    /// First element.
    pub ptr: *mut KgsEnvVarView,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsEnvVarViewArray, KgsEnvVarView);

/// [`EnvironmentView`]. Free with [`kgs_environment_view_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsEnvironmentView {
    /// Identifier.
    pub id: KgsBuffer,
    /// Display name.
    pub name: KgsBuffer,
    /// Optional description.
    pub description: KgsOptBuffer,
    /// Variable names, in order.
    pub variable_names: KgsBufferArray,
    /// The variables in full, in order.
    pub variables: KgsEnvVarViewArray,
    /// How many are still waiting for a value.
    pub pending_count: u32,
    /// 0 or 1.
    pub agent_visible: u8,
}

impl KgsEnvironmentView {
    pub(crate) fn new(e: EnvironmentView) -> Self {
        Self {
            id: KgsBuffer::from_string(e.id),
            name: KgsBuffer::from_string(e.name),
            description: KgsOptBuffer::from_string(e.description),
            variable_names: KgsBufferArray::strings(e.variable_names),
            variables: KgsEnvVarViewArray::collect(e.variables, KgsEnvVarView::new),
            pending_count: e.pending_count,
            agent_visible: u8::from(e.agent_visible),
        }
    }
}

impl Release for KgsEnvironmentView {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.name.release();
            self.description.release();
            self.variable_names.release();
            self.variables.release();
        }
    }
}

/// A list of [`KgsEnvironmentView`]. Free with [`kgs_environment_view_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsEnvironmentViewArray {
    /// First element.
    pub ptr: *mut KgsEnvironmentView,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsEnvironmentViewArray, KgsEnvironmentView);

// -------------------------------------------------------------------------------------------
// Audit
// -------------------------------------------------------------------------------------------

/// [`AuditRowView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsAuditRow {
    /// Position in the chain.
    pub seq: u64,
    /// Unix seconds.
    pub timestamp: u64,
    /// `"cli"`, `"app"` or `"mcp"`.
    pub actor: KgsBuffer,
    /// The tool or subcommand.
    pub tool: KgsBuffer,
    /// `"allowed"`, `"denied"` or `"failed"`.
    pub outcome: KgsBuffer,
    /// Environment involved.
    pub environment_id: KgsOptBuffer,
    /// Item involved.
    pub item_id: KgsOptBuffer,
    /// Variable names.
    pub variables: KgsBufferArray,
    /// Target path involved.
    pub target_path: KgsOptBuffer,
    /// A short machine-readable reason.
    pub detail: KgsOptBuffer,
}

impl KgsAuditRow {
    pub(crate) fn new(r: AuditRowView) -> Self {
        Self {
            seq: r.seq,
            timestamp: r.timestamp,
            actor: KgsBuffer::from_string(r.actor),
            tool: KgsBuffer::from_string(r.tool),
            outcome: KgsBuffer::from_string(r.outcome),
            environment_id: KgsOptBuffer::from_string(r.environment_id),
            item_id: KgsOptBuffer::from_string(r.item_id),
            variables: KgsBufferArray::strings(r.variables),
            target_path: KgsOptBuffer::from_string(r.target_path),
            detail: KgsOptBuffer::from_string(r.detail),
        }
    }
}

impl Release for KgsAuditRow {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.actor.release();
            self.tool.release();
            self.outcome.release();
            self.environment_id.release();
            self.item_id.release();
            self.variables.release();
            self.target_path.release();
            self.detail.release();
        }
    }
}

/// A list of [`KgsAuditRow`]. Free with [`kgs_audit_row_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsAuditRowArray {
    /// First element.
    pub ptr: *mut KgsAuditRow,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsAuditRowArray, KgsAuditRow);

// -------------------------------------------------------------------------------------------
// Frees
// -------------------------------------------------------------------------------------------

/// Free a [`KgsCategoryInfoArray`] and everything in it.
///
/// # Safety
///
/// `list` must be null, or point to a list this library wrote (or a zeroed one), not modified
/// since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_category_info_array_free(list: *mut KgsCategoryInfoArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsItemView`] and everything in it.
///
/// # Safety
///
/// `item` must be null, or point to a record this library wrote (or a zeroed one), not modified
/// since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_item_view_free(item: *mut KgsItemView) {
    // SAFETY: forwarded to the caller.
    unsafe { free(item) }
}

/// Free a [`KgsItemViewArray`] and everything in it.
///
/// # Safety
///
/// As [`kgs_category_info_array_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_item_view_array_free(list: *mut KgsItemViewArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsFieldView`] and everything in it.
///
/// # Safety
///
/// As [`kgs_item_view_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_field_view_free(field: *mut KgsFieldView) {
    // SAFETY: forwarded to the caller.
    unsafe { free(field) }
}

/// Free a [`KgsSidebarCounts`] and everything in it.
///
/// # Safety
///
/// As [`kgs_item_view_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_sidebar_counts_free(counts: *mut KgsSidebarCounts) {
    // SAFETY: forwarded to the caller.
    unsafe { free(counts) }
}

/// Free a [`KgsVaultViewArray`] and everything in it.
///
/// # Safety
///
/// As [`kgs_category_info_array_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_vault_view_array_free(list: *mut KgsVaultViewArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsEnvironmentView`] and everything in it.
///
/// # Safety
///
/// As [`kgs_item_view_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_environment_view_free(environment: *mut KgsEnvironmentView) {
    // SAFETY: forwarded to the caller.
    unsafe { free(environment) }
}

/// Free a [`KgsEnvironmentViewArray`] and everything in it.
///
/// # Safety
///
/// As [`kgs_category_info_array_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_environment_view_array_free(list: *mut KgsEnvironmentViewArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsAuditRowArray`] and everything in it.
///
/// # Safety
///
/// As [`kgs_category_info_array_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_audit_row_array_free(list: *mut KgsAuditRowArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}
