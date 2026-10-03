//! The rotation list: what a removed device could read (ADR-0035 §12; addendum, decision 84).
//!
//! Informational only. Removing a device mints a new epoch, so nothing written afterwards
//! reaches it; what was written before under an epoch it held, it may have kept. For each
//! device removed from the roster, [`rotation_list`] names the epochs it held and the items and
//! environments with a version written under one of them — the values a person may want to
//! change at their source. Nothing here is enforced, and nothing refuses a write.

use std::collections::BTreeSet;

use crate::device::DeviceKeyId;
use crate::epoch_key::EpochId;
use crate::view::{ObjectId, SharedView};

/// What one removed device could read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exposure {
    /// The removed device.
    pub device: DeviceKeyId,
    /// The epochs whose keys it was sent.
    pub epochs: Vec<EpochId>,
    /// The items and environments with a version under one of those epochs, in id order.
    pub objects: Vec<ObjectId>,
}

/// Every device removed from `view`'s roster that was sent an epoch key, with what it could
/// read, in device id order.
#[must_use]
pub fn rotation_list(view: &SharedView) -> Vec<Exposure> {
    let ring = view.key_ring();
    let snapshot = view.roster().snapshot();
    let recipients: BTreeSet<DeviceKeyId> = ring
        .epochs()
        .values()
        .flat_map(|info| info.recipients.iter().copied())
        .collect();
    recipients
        .into_iter()
        .filter(|device| snapshot.device(device).is_some_and(|d| !d.active))
        .map(|device| {
            let epochs: Vec<EpochId> = ring
                .epochs()
                .values()
                .filter(|info| info.recipients.contains(&device))
                .map(|info| info.id)
                .collect();
            let objects: BTreeSet<ObjectId> = view
                .accepted()
                .values()
                .filter(|version| {
                    view.roster()
                        .verified(&version.record())
                        .and_then(|r| r.body().epoch())
                        .is_some_and(|epoch| epochs.contains(epoch))
                })
                .map(|version| version.version().object())
                .collect();
            Exposure {
                device,
                epochs,
                objects: objects.into_iter().collect(),
            }
        })
        .collect()
}
