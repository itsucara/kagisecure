//! Creating a shared vault (ADR-0035 §6; addendum, decisions 21, 41, 81).
//!
//! [`create`] writes the vault's first two records, both signed by this device: the genesis,
//! which makes this device's person the vault's first member and an admin, and the creation
//! epoch (height 0), wrapped to this device alone. They are the replica's first records, and
//! the genesis is the one the replica's header trusts from then on.

use std::path::Path;

use kagisecure_core::proto::VaultId;
use uuid::Uuid;

use crate::device::DeviceSecret;
use crate::epoch::EpochOp;
use crate::epoch_key::{EpochId, EpochKey};
use crate::error::Result;
use crate::record::NewRecord;
use crate::replica::{LocalState, Replica, replica_path};
use crate::roster::{MemberId, RosterOp};

/// Create a shared vault called `name` beside the personal vault at `personal_vault`, with
/// this device as its first admin, and return its replica. The name is kept in this device's
/// local state and carried by invitations, never in a record (decision 81). With
/// `exchange_dir`, that directory is configured and the first records are exported to it.
///
/// # Errors
///
/// [`crate::SharedError::LimitExceeded`] for a name over 128 characters; the generator
/// failing; and whatever creating the replica refuses.
pub fn create(
    personal_vault: &Path,
    device: &DeviceSecret,
    name: &str,
    exchange_dir: Option<&Path>,
    now: u64,
) -> Result<Replica> {
    super::check_label(name)?;
    let vault_id = VaultId(Uuid::from_bytes(kagisecure_core::crypto::random::array()?));
    let genesis = RosterOp::Genesis {
        suite: device.public().suite(),
        member: MemberId::generate()?,
        device: device.public().clone(),
        labels: None,
    }
    .sign(
        device,
        NewRecord {
            vault_id,
            seq: 0,
            prev: None,
            parents: vec![],
            roster: vec![],
            epoch: None,
            created_at: now,
        },
    )?;
    let epoch_id = EpochId::derive(&vault_id, &device.id(), 1);
    let key = EpochKey::generate()?;
    let epoch = EpochOp::new_epoch(&vault_id, epoch_id, 0, &key, &[device.public()])?.sign(
        device,
        NewRecord {
            vault_id,
            seq: 1,
            prev: Some(genesis.id()),
            parents: vec![],
            roster: vec![genesis.id()],
            epoch: Some(epoch_id),
            created_at: now,
        },
    )?;
    let local = LocalState {
        vault_name: Some(name.to_owned()),
        exchange_dir: exchange_dir.map(super::exchange::path_text).transpose()?,
        ..LocalState::default()
    };
    let ids = [genesis.id(), epoch.id()];
    let replica = Replica::create(
        &replica_path(personal_vault, &vault_id),
        device,
        vault_id,
        genesis.id(),
        &[genesis, epoch],
        local,
        now,
    )?;
    crate::write::publish(&replica, &ids)?;
    Ok(replica)
}
