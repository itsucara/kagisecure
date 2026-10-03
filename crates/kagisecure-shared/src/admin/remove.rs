//! Removing a device or a member, and changing a role (ADR-0035 §11; addendum, decision 83,
//! under the trusted-admin amendment).
//!
//! A removal is one transaction of two records: the roster record, then a new epoch wrapped to
//! every device left, named after the removal so it is minted in the roster that no longer has
//! the removed device. Everything written from then on is under a key the removed device never
//! had; what it could read before, it still can ([`crate::rotation`] lists what that was). There
//! are no cuts: records the removed device wrote before its removal stand.
//!
//! Two changes are refused because they cannot be undone from this device: removing this very
//! device or its own member (the new epoch would be minted by a device already out of the
//! roster), and leaving the vault with no admin, which would freeze its roster.

use crate::device::{DeviceKeyId, DevicePublic, DeviceSecret};
use crate::epoch::EpochOp;
use crate::epoch_key::{EpochId, EpochKey};
use crate::error::{Result, SharedError};
use crate::record::RecordId;
use crate::replica::{Replica, ReplicaTx};
use crate::roster::{MemberId, RemovalReason, Role, RosterOp, RosterState};
use crate::write::{Draft, publish};

/// The roster `tx` would have with `envelope` added.
fn roster_with(tx: &ReplicaTx<'_>, envelope: &crate::record::Envelope) -> Result<RosterState> {
    let mut records = tx.envelopes();
    records.push(envelope.clone());
    RosterState::compute(tx.vault_id(), &tx.genesis(), &records)
}

/// Write `op`, refusing it if the roster after it has no admin; then, for a removal, a new
/// epoch wrapped to every device left.
fn change(
    replica: &mut Replica,
    admin: &DeviceSecret,
    now: u64,
    op: impl FnOnce(&RosterState) -> Result<RosterOp>,
    rotate: bool,
) -> Result<(RecordId, Option<EpochId>)> {
    let (written, epoch) = replica.transact(admin, |tx| {
        let mut draft = Draft::begin(tx, admin)?;
        draft.require(admin, Role::Admin)?;
        let op = op(draft.view.roster())?;
        let heads = draft.view.roster().heads().to_vec();
        let envelope = op.sign(admin, draft.header(heads, vec![], None, now))?;
        let after = roster_with(tx, &envelope)?;
        if after.snapshot().admin_count() == 0 {
            return Err(SharedError::Refused(
                "that would leave the shared vault with no admin",
            ));
        }
        if after.role_of(&admin.id()).is_none() {
            return Err(SharedError::Refused(
                "remove this device, or its member, from another admin device",
            ));
        }
        let height = draft.view.key_ring().next_height();
        let changed = draft.wrote(tx, envelope);
        let mut written = vec![changed];
        let mut minted = None;
        if rotate {
            let epoch = EpochId::derive(tx.vault_id(), &admin.id(), draft.seq());
            let key = EpochKey::generate()?;
            let recipients: Vec<DevicePublic> = after
                .snapshot()
                .active_devices()
                .map(|d| d.public.clone())
                .collect();
            let recipients: Vec<&DevicePublic> = recipients.iter().collect();
            let op = EpochOp::new_epoch(tx.vault_id(), epoch, height, &key, &recipients)?;
            let header = draft.header(vec![changed], vec![], Some(epoch), now);
            written.push(draft.wrote(tx, op.sign(admin, header)?));
            minted = Some(epoch);
        }
        Ok((written, minted))
    })?;
    publish(replica, &written)?;
    Ok((written[0], epoch))
}

/// Remove `device` from the vault, and mint a new epoch for every device left. Returns the new
/// epoch.
///
/// # Errors
///
/// [`SharedError::Refused`] unless this is an admin device, if `device` is not an active device
/// of the vault or is this device, or if no admin would be left; and as [`Replica::transact`].
pub fn remove_device(
    replica: &mut Replica,
    admin: &DeviceSecret,
    device: DeviceKeyId,
    reason: RemovalReason,
    now: u64,
) -> Result<EpochId> {
    let (_, epoch) = change(
        replica,
        admin,
        now,
        |roster| {
            if !roster.snapshot().device(&device).is_some_and(|d| d.active) {
                return Err(SharedError::Refused("that is not an active device"));
            }
            Ok(RosterOp::RemoveDevice { device, reason })
        },
        true,
    )?;
    Ok(epoch.expect("a removal mints an epoch"))
}

/// Remove `member` and every device of theirs, and mint a new epoch for every device left.
/// Returns the new epoch.
///
/// # Errors
///
/// As [`remove_device`], for a member.
pub fn remove_member(
    replica: &mut Replica,
    admin: &DeviceSecret,
    member: MemberId,
    reason: RemovalReason,
    now: u64,
) -> Result<EpochId> {
    let (_, epoch) = change(
        replica,
        admin,
        now,
        |roster| {
            if !roster.snapshot().member(&member).is_some_and(|m| m.active) {
                return Err(SharedError::Refused("that is not an active member"));
            }
            Ok(RosterOp::RemoveMember { member, reason })
        },
        true,
    )?;
    Ok(epoch.expect("a removal mints an epoch"))
}

/// Give `member` the role `role`.
///
/// # Errors
///
/// [`SharedError::Refused`] unless this is an admin device, if `member` is not an active member
/// or already holds `role`, or if no admin would be left; and as [`Replica::transact`].
pub fn set_role(
    replica: &mut Replica,
    admin: &DeviceSecret,
    member: MemberId,
    role: Role,
    now: u64,
) -> Result<RecordId> {
    let (record, _) = change(
        replica,
        admin,
        now,
        |roster| match roster.snapshot().member(&member) {
            Some(m) if m.active && m.role != role => Ok(RosterOp::SetRole { member, role }),
            Some(m) if m.active => Err(SharedError::Refused("the member already has that role")),
            _ => Err(SharedError::Refused("that is not an active member")),
        },
        false,
    )?;
    Ok(record)
}
