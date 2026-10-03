//! The agent (ADR-0014) and the browser-extension listener: process globals, so free functions.
//!
//! [`kgs_agent_next_request`] is the one call in this ABI that blocks by design; the module docs'
//! Threading section says how to call it. Everything else returns promptly.

use std::sync::Arc;

use super::{
    KgsApprovalAction, KgsApprovalDecisionTag, KgsBuffer, KgsBufferArray, KgsOptBool, KgsOptBuffer,
    KgsOptSlice, KgsOptU32, KgsPeerRequirementKind, KgsSession, KgsSlice, KgsStatus, Release, call,
    free, read, session as live, slot,
};
use crate::agent::{
    AgentStatusView, ApprovalDecision, ApprovalRequestView, BrowserManifestView,
    ClientVerificationView, ExtensionSetupView, ExtensionStatusView, FillLeaseView, LeaseView,
    McpSnippetView,
};
use crate::{FfiError, FfiResult};

// -------------------------------------------------------------------------------------------
// Records
// -------------------------------------------------------------------------------------------

/// [`ApprovalRequestView`]: metadata only — names, paths, counts. Free with
/// [`kgs_approval_request_free`].
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsApprovalRequest {
    /// Quote this back to [`kgs_agent_resolve`].
    pub id: KgsBuffer,
    /// A [`KgsApprovalAction`] tag.
    pub action: u32,
    /// 0 or 1: granting mints a lease.
    pub mints_lease: u8,
    /// The caller's self-reported name.
    pub client_name: KgsBuffer,
    /// The peer's process id.
    pub client_pid: KgsOptU32,
    /// 0 or 1: that pid came from the kernel.
    pub client_pid_from_kernel: u8,
    /// The executable behind that pid.
    pub client_executable: KgsOptBuffer,
    /// The directory the sidecar was started in. Self-reported.
    pub client_cwd: KgsOptBuffer,
    /// The environment involved.
    pub environment_id: KgsOptBuffer,
    /// Its display name.
    pub environment_name: KgsOptBuffer,
    /// The canonical target directory.
    pub directory: KgsOptBuffer,
    /// The exact file that would be written.
    pub target_path: KgsOptBuffer,
    /// Variable names.
    pub variables: KgsBufferArray,
    /// The resolved argv, for `run_with_env`.
    pub command: KgsBufferArray,
    /// Whether the target is gitignored; absent outside a work tree.
    pub gitignored: KgsOptBool,
    /// 0 or 1: the caller asked to replace an existing file.
    pub overwrite_requested: u8,
    /// Whether a file is already at the target.
    pub target_exists: KgsOptBool,
    /// Whether kagisecure wrote that file in this unlock session.
    pub target_written_by_us: KgsOptBool,
    /// The TTL the agent asked for.
    pub requested_ttl_seconds: u64,
    /// The use count the lease would carry.
    pub requested_uses: u32,
    /// The ceiling the TTL control must respect.
    pub max_ttl_seconds: u64,
    /// Unix seconds the request arrived.
    pub created_at: u64,
    /// Unix seconds it self-denies.
    pub expires_at: u64,
    /// The fill origin.
    pub origin: KgsOptBuffer,
    /// The top-level page's origin, when it differs. May be the literal `"null"`.
    pub top_origin: KgsOptBuffer,
    /// 0 or 1: the embedder could not be established.
    pub top_origin_unknown: u8,
    /// The item that would be filled.
    pub item_id: KgsOptBuffer,
    /// Its title.
    pub item_title: KgsOptBuffer,
    /// Which fields would be written. Names.
    pub fill_fields: KgsBufferArray,
    /// The browser.
    pub browser: KgsOptBuffer,
    /// That browser's pid.
    pub browser_pid: KgsOptU32,
    /// That browser's executable path.
    pub browser_executable: KgsOptBuffer,
    /// 0 or 1: the peer is an app extension we ship.
    pub browser_is_app_extension: u8,
    /// The extension's self-reported id.
    pub extension_id: KgsOptBuffer,
    /// 0 or 1: ask only for a fresh presence check, not the sheet (ADR-0037). The check itself is
    /// never skipped; a cancelled or unavailable one is a denial.
    pub presence_only: u8,
}

impl KgsApprovalRequest {
    fn new(r: ApprovalRequestView) -> Self {
        Self {
            id: KgsBuffer::from_string(r.id),
            action: KgsApprovalAction::tag(r.action),
            mints_lease: u8::from(r.mints_lease),
            client_name: KgsBuffer::from_string(r.client_name),
            client_pid: KgsOptU32::from_option(r.client_pid),
            client_pid_from_kernel: u8::from(r.client_pid_from_kernel),
            client_executable: KgsOptBuffer::from_string(r.client_executable),
            client_cwd: KgsOptBuffer::from_string(r.client_cwd),
            environment_id: KgsOptBuffer::from_string(r.environment_id),
            environment_name: KgsOptBuffer::from_string(r.environment_name),
            directory: KgsOptBuffer::from_string(r.directory),
            target_path: KgsOptBuffer::from_string(r.target_path),
            variables: KgsBufferArray::strings(r.variables),
            command: KgsBufferArray::strings(r.command),
            gitignored: KgsOptBool::from_option(r.gitignored),
            overwrite_requested: u8::from(r.overwrite_requested),
            target_exists: KgsOptBool::from_option(r.target_exists),
            target_written_by_us: KgsOptBool::from_option(r.target_written_by_us),
            requested_ttl_seconds: r.requested_ttl_seconds,
            requested_uses: r.requested_uses,
            max_ttl_seconds: r.max_ttl_seconds,
            created_at: r.created_at,
            expires_at: r.expires_at,
            origin: KgsOptBuffer::from_string(r.origin),
            top_origin: KgsOptBuffer::from_string(r.top_origin),
            top_origin_unknown: u8::from(r.top_origin_unknown),
            item_id: KgsOptBuffer::from_string(r.item_id),
            item_title: KgsOptBuffer::from_string(r.item_title),
            fill_fields: KgsBufferArray::strings(r.fill_fields),
            browser: KgsOptBuffer::from_string(r.browser),
            browser_pid: KgsOptU32::from_option(r.browser_pid),
            browser_executable: KgsOptBuffer::from_string(r.browser_executable),
            browser_is_app_extension: u8::from(r.browser_is_app_extension),
            extension_id: KgsOptBuffer::from_string(r.extension_id),
            presence_only: u8::from(r.presence_only),
        }
    }
}

impl Release for KgsApprovalRequest {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.client_name.release();
            self.client_executable.release();
            self.client_cwd.release();
            self.environment_id.release();
            self.environment_name.release();
            self.directory.release();
            self.target_path.release();
            self.variables.release();
            self.command.release();
            self.origin.release();
            self.top_origin.release();
            self.item_id.release();
            self.item_title.release();
            self.fill_fields.release();
            self.browser.release();
            self.browser_executable.release();
            self.extension_id.release();
        }
    }
}

/// An optional [`KgsApprovalRequest`]. `value` is all-zero when absent; free `value` with
/// [`kgs_approval_request_free`] either way.
#[repr(C)]
#[derive(Debug)]
pub struct KgsOptApprovalRequest {
    /// 1 if a request arrived, 0 if the wait timed out.
    pub present: u8,
    /// The request; all-zero when absent.
    pub value: KgsApprovalRequest,
}

/// A list of [`KgsApprovalRequest`]. Free with [`kgs_approval_request_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsApprovalRequestArray {
    /// First element.
    pub ptr: *mut KgsApprovalRequest,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsApprovalRequestArray, KgsApprovalRequest);

/// [`ApprovalDecision`] — an enum with data — going in. `ttl_seconds` and `uses` are read only for
/// [`KgsApprovalDecisionTag::AllowSession`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsApprovalDecision {
    /// A [`KgsApprovalDecisionTag`].
    pub tag: u32,
    /// Seconds, for `AllowSession`.
    pub ttl_seconds: u64,
    /// Uses, for `AllowSession`.
    pub uses: u32,
}

impl KgsApprovalDecision {
    fn to_ffi(self) -> FfiResult<ApprovalDecision> {
        use KgsApprovalDecisionTag as T;
        Ok(match self.tag {
            t if t == T::AllowOnce as u32 => ApprovalDecision::AllowOnce,
            t if t == T::AllowSession as u32 => ApprovalDecision::AllowSession {
                ttl_seconds: self.ttl_seconds,
                uses: self.uses,
            },
            t if t == T::Deny as u32 => ApprovalDecision::Deny,
            other => {
                return Err(FfiError::invalid(format!(
                    "unknown approval decision {other}"
                )));
            }
        })
    }
}

/// [`ClientVerificationView`], going in: the host's code-signature verdict.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsClientVerification {
    /// 0 or 1.
    pub verified: u8,
    /// One line of evidence.
    pub evidence: KgsSlice,
}

impl KgsClientVerification {
    /// # Safety
    ///
    /// `evidence` must satisfy [`KgsSlice`]'s contract.
    unsafe fn to_ffi(self) -> FfiResult<ClientVerificationView> {
        Ok(ClientVerificationView {
            verified: self.verified != 0,
            // SAFETY: forwarded to the caller.
            evidence: unsafe { self.evidence.string() }?,
        })
    }
}

/// [`LeaseView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsLease {
    /// Identifier, for Revoke.
    pub id: KgsBuffer,
    /// The environment it is scoped to.
    pub environment_id: KgsBuffer,
    /// The canonical directory it is scoped to.
    pub directory: KgsBuffer,
    /// The variable names it covers.
    pub variables: KgsBufferArray,
    /// `"env-file"` or `"run-command"`.
    pub kind: KgsBuffer,
    /// The caller it was minted for.
    pub client_identity: KgsBuffer,
    /// Unix seconds it dies at.
    pub expires_at: u64,
    /// Uses left.
    pub uses_remaining: u32,
}

impl KgsLease {
    fn new(l: LeaseView) -> Self {
        Self {
            id: KgsBuffer::from_string(l.id),
            environment_id: KgsBuffer::from_string(l.environment_id),
            directory: KgsBuffer::from_string(l.directory),
            variables: KgsBufferArray::strings(l.variables),
            kind: KgsBuffer::from_string(l.kind),
            client_identity: KgsBuffer::from_string(l.client_identity),
            expires_at: l.expires_at,
            uses_remaining: l.uses_remaining,
        }
    }
}

impl Release for KgsLease {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.environment_id.release();
            self.directory.release();
            self.variables.release();
            self.kind.release();
            self.client_identity.release();
        }
    }
}

/// A list of [`KgsLease`]. Free with [`kgs_lease_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsLeaseArray {
    /// First element.
    pub ptr: *mut KgsLease,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsLeaseArray, KgsLease);

/// [`AgentStatusView`]. Free with [`kgs_agent_status_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsAgentStatus {
    /// 0 or 1: the endpoint is bound and being accepted on.
    pub running: u8,
    /// Where it is listening. Empty when it is not.
    pub endpoint: KgsBuffer,
    /// Approvals waiting for a human.
    pub pending_approvals: u32,
    /// Live leases.
    pub active_leases: u32,
    /// 0 or 1: the vault behind it is still unlocked.
    pub vault_unlocked: u8,
}

impl KgsAgentStatus {
    fn new(s: AgentStatusView) -> Self {
        Self {
            running: u8::from(s.running),
            endpoint: KgsBuffer::from_string(s.endpoint),
            pending_approvals: s.pending_approvals,
            active_leases: s.active_leases,
            vault_unlocked: u8::from(s.vault_unlocked),
        }
    }
}

impl Release for KgsAgentStatus {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.endpoint.release() };
    }
}

/// [`McpSnippetView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsMcpSnippet {
    /// Display name.
    pub title: KgsBuffer,
    /// `"shell"`, `"json"` or `"toml"`.
    pub language: KgsBuffer,
    /// The text the copy button copies.
    pub body: KgsBuffer,
    /// Where it goes.
    pub config_path: KgsOptBuffer,
}

impl KgsMcpSnippet {
    fn new(s: McpSnippetView) -> Self {
        Self {
            title: KgsBuffer::from_string(s.title),
            language: KgsBuffer::from_string(s.language),
            body: KgsBuffer::from_string(s.body),
            config_path: KgsOptBuffer::from_string(s.config_path),
        }
    }
}

impl Release for KgsMcpSnippet {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.title.release();
            self.language.release();
            self.body.release();
            self.config_path.release();
        }
    }
}

/// A list of [`KgsMcpSnippet`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsMcpSnippetArray {
    /// First element.
    pub ptr: *mut KgsMcpSnippet,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsMcpSnippetArray, KgsMcpSnippet);

/// [`McpSetupView`]. Free with [`kgs_mcp_setup_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsMcpSetup {
    /// The absolute path to `kagisecure-mcp`, if it could be found.
    pub sidecar_path: KgsOptBuffer,
    /// One entry per client.
    pub snippets: KgsMcpSnippetArray,
}

impl Release for KgsMcpSetup {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.sidecar_path.release();
            self.snippets.release();
        }
    }
}

/// [`ExtensionStatusView`], without its two Safari members (see the module docs). Free with
/// [`kgs_extension_status_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsExtensionStatus {
    /// 0 or 1: the extension endpoint is bound and being accepted on.
    pub running: u8,
    /// Where it is listening. Empty when it is not.
    pub endpoint: KgsBuffer,
    /// How many native hosts are connected.
    pub connected_hosts: u32,
    /// How many fill leases are alive.
    pub fill_leases: u32,
    /// 0 or 1: the vault behind it is still unlocked.
    pub vault_unlocked: u8,
}

impl KgsExtensionStatus {
    fn new(s: ExtensionStatusView) -> Self {
        Self {
            running: u8::from(s.running),
            endpoint: KgsBuffer::from_string(s.endpoint),
            connected_hosts: s.connected_hosts,
            fill_leases: s.fill_leases,
            vault_unlocked: u8::from(s.vault_unlocked),
        }
    }
}

impl Release for KgsExtensionStatus {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.endpoint.release() };
    }
}

/// [`FillLeaseView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsFillLease {
    /// The origin it covers.
    pub origin: KgsBuffer,
    /// The item it covers.
    pub item_id: KgsBuffer,
    /// That item's title.
    pub item_title: KgsBuffer,
    /// Which fields it covers. Names.
    pub fields: KgsBufferArray,
    /// The browser it was minted for.
    pub client_identity: KgsBuffer,
    /// Unix seconds it dies at.
    pub expires_at: u64,
}

impl KgsFillLease {
    fn new(l: FillLeaseView) -> Self {
        Self {
            origin: KgsBuffer::from_string(l.origin),
            item_id: KgsBuffer::from_string(l.item_id),
            item_title: KgsBuffer::from_string(l.item_title),
            fields: KgsBufferArray::strings(l.fields),
            client_identity: KgsBuffer::from_string(l.client_identity),
            expires_at: l.expires_at,
        }
    }
}

impl Release for KgsFillLease {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.origin.release();
            self.item_id.release();
            self.item_title.release();
            self.fields.release();
            self.client_identity.release();
        }
    }
}

/// A list of [`KgsFillLease`]. Free with [`kgs_fill_lease_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsFillLeaseArray {
    /// First element.
    pub ptr: *mut KgsFillLease,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsFillLeaseArray, KgsFillLease);

/// [`BrowserManifestView`], going out.
#[repr(C)]
#[derive(Debug)]
pub struct KgsBrowserManifest {
    /// The browser's display name.
    pub browser: KgsBuffer,
    /// The absolute path of the file the button would write.
    pub path: KgsBuffer,
    /// Exactly what would be written there.
    pub body: KgsBuffer,
    /// 0 or 1: that browser appears to be installed.
    pub browser_installed: u8,
    /// 0 or 1: that exact file is already in place.
    pub installed: u8,
    /// Windows only: the `HKEY_CURRENT_USER` subkey the install button also sets. Absent on macOS.
    pub registry_key: KgsOptBuffer,
}

impl KgsBrowserManifest {
    fn new(m: BrowserManifestView) -> Self {
        Self {
            browser: KgsBuffer::from_string(m.browser),
            path: KgsBuffer::from_string(m.path),
            body: KgsBuffer::from_string(m.body),
            browser_installed: u8::from(m.browser_installed),
            installed: u8::from(m.installed),
            registry_key: KgsOptBuffer::from_string(m.registry_key),
        }
    }
}

impl Release for KgsBrowserManifest {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.browser.release();
            self.path.release();
            self.body.release();
            self.registry_key.release();
        }
    }
}

/// A list of [`KgsBrowserManifest`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsBrowserManifestArray {
    /// First element.
    pub ptr: *mut KgsBrowserManifest,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsBrowserManifestArray, KgsBrowserManifest);

/// [`BrowserManifestView`], going in: the record the screen is showing, handed back.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsBrowserManifestRef {
    /// The browser's display name.
    pub browser: KgsSlice,
    /// The absolute path to write.
    pub path: KgsSlice,
    /// What to write there.
    pub body: KgsSlice,
    /// 0 or 1.
    pub browser_installed: u8,
    /// 0 or 1.
    pub installed: u8,
    /// The registry subkey the record came out with, handed back unchanged.
    pub registry_key: KgsOptSlice,
}

impl KgsBrowserManifestRef {
    /// # Safety
    ///
    /// Every slice must satisfy [`KgsSlice`]'s contract.
    unsafe fn to_ffi(self) -> FfiResult<BrowserManifestView> {
        // SAFETY: forwarded to the caller.
        unsafe {
            Ok(BrowserManifestView {
                browser: self.browser.string()?,
                path: self.path.string()?,
                body: self.body.string()?,
                browser_installed: self.browser_installed != 0,
                installed: self.installed != 0,
                registry_key: self.registry_key.string()?,
            })
        }
    }
}

/// [`ExtensionSetupView`], without its `safari` member (see the module docs). Free with
/// [`kgs_extension_setup_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsExtensionSetup {
    /// The absolute path to `kagisecure-nmhost`, if it could be found.
    pub nmhost_path: KgsOptBuffer,
    /// The pinned extension id.
    pub extension_id: KgsBuffer,
    /// The native messaging host name.
    pub host_name: KgsBuffer,
    /// One entry per browser, installed browsers first.
    pub manifests: KgsBrowserManifestArray,
}

impl Release for KgsExtensionSetup {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.nmhost_path.release();
            self.extension_id.release();
            self.host_name.release();
            self.manifests.release();
        }
    }
}

// -------------------------------------------------------------------------------------------
// The agent
// -------------------------------------------------------------------------------------------

/// [`crate::agent_start`]. An absent `socket_path` is the per-user default; on Windows a present
/// one is a **named pipe name** (`kagisecure-mine.sock` or `\\.\pipe\kagisecure-mine.sock`), and
/// a filesystem path is refused. `out` is the endpoint it bound.
///
/// # Safety
///
/// Module rules; `session` a live handle. The agent takes its own reference to the session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_start(
    session: *const KgsSession,
    socket_path: KgsOptSlice,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session = Arc::clone(live(session)?);
            let endpoint = crate::agent_start(session, socket_path.string()?)?;
            out.write(KgsBuffer::from_string(endpoint));
            Ok(())
        })
    }
}

/// [`crate::agent_stop`]. Idempotent.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_stop(error: *mut KgsBuffer) -> KgsStatus {
    // SAFETY: `error` is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            crate::agent_stop();
            Ok(())
        })
    }
}

/// [`crate::agent_status`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_status(
    out: *mut KgsAgentStatus,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsAgentStatus::new(crate::agent_status()));
            Ok(())
        })
    }
}

/// [`crate::agent_next_request`]. **Blocks** the calling thread for up to `timeout_ms`; call it
/// from a dedicated background thread, in a loop, with a short timeout (see the module docs'
/// Threading section). `out.present` is 0 when the wait timed out.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_next_request(
    timeout_ms: u32,
    out: *mut KgsOptApprovalRequest,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(match crate::agent_next_request(timeout_ms) {
                Some(request) => KgsOptApprovalRequest {
                    present: 1,
                    value: KgsApprovalRequest::new(request),
                },
                None => KgsOptApprovalRequest {
                    present: 0,
                    value: KgsApprovalRequest::default(),
                },
            });
            Ok(())
        })
    }
}

/// [`crate::agent_pending_requests`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_pending_requests(
    out: *mut KgsApprovalRequestArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsApprovalRequestArray::collect(
                crate::agent_pending_requests(),
                KgsApprovalRequest::new,
            ));
            Ok(())
        })
    }
}

/// [`crate::agent_resolve`]. `out` is 0 when the id is no longer live — normally because the
/// request timed out while the user was deciding. That is not an error.
///
/// # Safety
///
/// Module rules; `decision` and `verification` valid for a read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_resolve(
    request_id: KgsSlice,
    decision: *const KgsApprovalDecision,
    verification: *const KgsClientVerification,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let decision = read(decision, "decision")?.to_ffi()?;
            let verification = read(verification, "verification")?.to_ffi()?;
            let live = crate::agent_resolve(request_id.string()?, decision, verification);
            out.write(u8::from(live));
            Ok(())
        })
    }
}

/// [`crate::agent_leases`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_leases(
    out: *mut KgsLeaseArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsLeaseArray::collect(crate::agent_leases(), KgsLease::new));
            Ok(())
        })
    }
}

/// [`crate::agent_revoke_lease`]. `out` is 0 or 1: whether there was such a live lease.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_revoke_lease(
    lease_id: KgsSlice,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(crate::agent_revoke_lease(lease_id.string()?)?));
            Ok(())
        })
    }
}

/// [`crate::agent_revoke_all_leases`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_revoke_all_leases(error: *mut KgsBuffer) -> KgsStatus {
    // SAFETY: `error` is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            crate::agent_revoke_all_leases();
            Ok(())
        })
    }
}

/// [`crate::agent_take_lock_request`]. `out` is 0 or 1; reading it clears it.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_take_lock_request(
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(crate::agent_take_lock_request()));
            Ok(())
        })
    }
}

/// [`crate::mcp_setup`]. On Windows `bundle_helpers_dir` is the directory the app installed
/// `kagisecure-mcp.exe` into.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_mcp_setup(
    bundle_helpers_dir: KgsOptSlice,
    out: *mut KgsMcpSetup,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let setup = crate::mcp_setup(bundle_helpers_dir.string()?);
            out.write(KgsMcpSetup {
                sidecar_path: KgsOptBuffer::from_string(setup.sidecar_path),
                snippets: KgsMcpSnippetArray::collect(setup.snippets, KgsMcpSnippet::new),
            });
            Ok(())
        })
    }
}

// -------------------------------------------------------------------------------------------
// The browser-extension listener
// -------------------------------------------------------------------------------------------

/// [`crate::agent::extension_start`], with no Safari socket and no team id (both macOS-only).
/// `socket_path` means what [`kgs_agent_start`]'s does.
///
/// # Safety
///
/// Module rules; `session` a live handle. The listener takes its own reference to the session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_start(
    session: *const KgsSession,
    socket_path: KgsOptSlice,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session = Arc::clone(live(session)?);
            let endpoint =
                crate::agent::extension_start(session, socket_path.string()?, None, None)?;
            out.write(KgsBuffer::from_string(endpoint));
            Ok(())
        })
    }
}

/// [`crate::agent::extension_stop`]. Idempotent.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_stop(error: *mut KgsBuffer) -> KgsStatus {
    // SAFETY: `error` is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            crate::agent::extension_stop();
            Ok(())
        })
    }
}

/// [`crate::agent::extension_status`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_status(
    out: *mut KgsExtensionStatus,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsExtensionStatus::new(crate::agent::extension_status()));
            Ok(())
        })
    }
}

/// [`crate::agent::extension_fill_leases`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_fill_leases(
    out: *mut KgsFillLeaseArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsFillLeaseArray::collect(
                crate::agent::extension_fill_leases(),
                KgsFillLease::new,
            ));
            Ok(())
        })
    }
}

/// [`crate::agent::extension_revoke_fill_lease`]. `out` is 0 or 1.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_revoke_fill_lease(
    origin: KgsSlice,
    item_id: KgsSlice,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let revoked =
                crate::agent::extension_revoke_fill_lease(origin.string()?, item_id.string()?);
            out.write(u8::from(revoked));
            Ok(())
        })
    }
}

/// [`crate::agent::extension_revoke_all_fill_leases`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_revoke_all_fill_leases(error: *mut KgsBuffer) -> KgsStatus {
    // SAFETY: `error` is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            crate::agent::extension_revoke_all_fill_leases();
            Ok(())
        })
    }
}

/// [`crate::agent::extension_setup`], with no plugins directory and no team id (both
/// Safari-only), and without the Safari half of the answer.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_setup(
    bundle_helpers_dir: KgsOptSlice,
    out: *mut KgsExtensionSetup,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let ExtensionSetupView {
                nmhost_path,
                extension_id,
                host_name,
                manifests,
                safari: _,
            } = crate::agent::extension_setup(bundle_helpers_dir.string()?, None, None);
            out.write(KgsExtensionSetup {
                nmhost_path: KgsOptBuffer::from_string(nmhost_path),
                extension_id: KgsBuffer::from_string(extension_id),
                host_name: KgsBuffer::from_string(host_name),
                manifests: KgsBrowserManifestArray::collect(manifests, KgsBrowserManifest::new),
            });
            Ok(())
        })
    }
}

/// [`crate::agent::extension_install_manifest`].
///
/// # Safety
///
/// Module rules; `manifest` valid for a read, its slices satisfying [`KgsSlice`]'s contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_install_manifest(
    manifest: *const KgsBrowserManifestRef,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let manifest = read(manifest, "manifest")?.to_ffi()?;
            crate::agent::extension_install_manifest(manifest)
        })
    }
}

/// [`crate::agent::extension_uninstall_manifest`]. A file that was not there is success.
///
/// # Safety
///
/// As [`kgs_extension_install_manifest`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_uninstall_manifest(
    manifest: *const KgsBrowserManifestRef,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let manifest = read(manifest, "manifest")?.to_ffi()?;
            crate::agent::extension_uninstall_manifest(manifest)
        })
    }
}

// -------------------------------------------------------------------------------------------
// Frees
// -------------------------------------------------------------------------------------------

/// Free a [`KgsApprovalRequest`] — including the `value` of a [`KgsOptApprovalRequest`], present
/// or not.
///
/// # Safety
///
/// `request` must be null, or point to a record this library wrote (or a zeroed one), not
/// modified since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_approval_request_free(request: *mut KgsApprovalRequest) {
    // SAFETY: forwarded to the caller.
    unsafe { free(request) }
}

/// Free a [`KgsApprovalRequestArray`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_approval_request_array_free(list: *mut KgsApprovalRequestArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsLeaseArray`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_lease_array_free(list: *mut KgsLeaseArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsAgentStatus`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_agent_status_free(status: *mut KgsAgentStatus) {
    // SAFETY: forwarded to the caller.
    unsafe { free(status) }
}

/// Free a [`KgsMcpSetup`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_mcp_setup_free(setup: *mut KgsMcpSetup) {
    // SAFETY: forwarded to the caller.
    unsafe { free(setup) }
}

/// Free a [`KgsExtensionStatus`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_status_free(status: *mut KgsExtensionStatus) {
    // SAFETY: forwarded to the caller.
    unsafe { free(status) }
}

/// Free a [`KgsFillLeaseArray`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_fill_lease_array_free(list: *mut KgsFillLeaseArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsExtensionSetup`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_extension_setup_free(setup: *mut KgsExtensionSetup) {
    // SAFETY: forwarded to the caller.
    unsafe { free(setup) }
}

// -------------------------------------------------------------------------------------------
// Peer code signatures (ADR-0032)
// -------------------------------------------------------------------------------------------

/// [`ClientVerificationView`], going out: what [`kgs_verify_peer_code_signature`] concluded.
/// Free with [`kgs_client_verification_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsClientVerificationOut {
    /// 0 or 1.
    pub verified: u8,
    /// One line of evidence, for the sheet and the audit entry.
    pub evidence: KgsBuffer,
}

impl Release for KgsClientVerificationOut {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.evidence.release() };
    }
}

/// [`crate::agent::verify_peer_code_signature`]. `requirement` is a [`KgsPeerRequirementKind`] tag.
///
/// Hashes the whole executable, so it blocks for as long as reading the file takes: call it off
/// the UI thread. Hand the verdict back unchanged through [`kgs_agent_resolve`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_verify_peer_code_signature(
    pid: u32,
    executable: KgsSlice,
    requirement: u32,
    out: *mut KgsClientVerificationOut,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let ClientVerificationView { verified, evidence } =
                crate::agent::verify_peer_code_signature(
                    pid,
                    executable.string()?,
                    KgsPeerRequirementKind::parse(requirement)?,
                );
            out.write(KgsClientVerificationOut {
                verified: u8::from(verified),
                evidence: KgsBuffer::from_string(evidence),
            });
            Ok(())
        })
    }
}

/// Free a [`KgsClientVerificationOut`].
///
/// # Safety
///
/// As [`kgs_approval_request_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_client_verification_free(verification: *mut KgsClientVerificationOut) {
    // SAFETY: forwarded to the caller.
    unsafe { free(verification) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagisecure_agent::approval::ApprovalRequest;

    #[test]
    fn an_agent_fill_request_crosses_the_c_abi_as_its_tag_alone() {
        let view = ApprovalRequestView::from(ApprovalRequest::for_agent_fill(
            crate::agent::tests::agent_fill_facts("https://login.example.com"),
        ));
        let mut request = KgsApprovalRequest::new(view);
        assert_eq!(request.action, KgsApprovalAction::AgentFill as u32);
        assert_eq!(request.action, 5, "the tag is part of the ABI");
        assert_eq!(request.mints_lease, 0);
        assert_eq!(request.presence_only, 0);
        assert_eq!(
            KgsApprovalAction::parse(request.action).ok(),
            Some(crate::agent::ApprovalAction::AgentFill)
        );
        // SAFETY: a record this library wrote, freed once.
        unsafe { kgs_approval_request_free(&mut request) };
        assert!(request.id.ptr.is_null(), "freed to zero");
    }
}
