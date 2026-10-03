//! Which of a shared vault's items, fields and environments this device's agents may see
//! (ADR-0035 §14; decision 22).
//!
//! Agent visibility is this device's own setting: it lives in the replica's local section,
//! never in a record, so changing it writes nothing another member receives and no member can
//! change it for someone else's agents. Everything starts hidden, as a personal item or
//! environment does (threat-model M-9). A person changes it in the app or with `kagisecure env
//! agent-access --shared-vault`; an agent never can, which is why this lives under
//! [`crate::admin`], beyond what an agent-facing process may name.

use kagisecure_core::proto::{EnvId, FieldId, ItemId};

use crate::device::DeviceSecret;
use crate::error::Result;
use crate::replica::Replica;

/// Let this device's agents see item `id`, or not. Hiding an item hides its fields too, so an
/// item shown again later does not bring back a field the person forgot about — the rule the
/// personal vault follows.
///
/// # Errors
///
/// As [`Replica::transact`].
pub fn set_item(
    replica: &mut Replica,
    device: &DeviceSecret,
    id: ItemId,
    visible: bool,
) -> Result<()> {
    replica.transact(device, |tx| {
        let local = tx.local_mut();
        if visible {
            local.agent_visible_items.insert(id);
        } else {
            local.agent_visible_items.remove(&id);
            local.agent_visible_fields.remove(&id);
        }
        Ok(())
    })
}

/// Let this device's agents see field `field` of item `item` — its label and kind, never its
/// value — or not.
///
/// # Errors
///
/// As [`Replica::transact`].
pub fn set_field(
    replica: &mut Replica,
    device: &DeviceSecret,
    item: ItemId,
    field: FieldId,
    visible: bool,
) -> Result<()> {
    replica.transact(device, |tx| {
        let local = tx.local_mut();
        let fields = local.agent_visible_fields.entry(item).or_default();
        if visible {
            fields.insert(field);
        } else {
            fields.remove(&field);
        }
        if fields.is_empty() {
            local.agent_visible_fields.remove(&item);
        }
        Ok(())
    })
}

/// Let this device's agents see environment `id` — its name and its variables' names — and
/// ask for its values to be released, or not.
///
/// # Errors
///
/// As [`Replica::transact`].
pub fn set_env(
    replica: &mut Replica,
    device: &DeviceSecret,
    id: EnvId,
    visible: bool,
) -> Result<()> {
    replica.transact(device, |tx| {
        let local = tx.local_mut();
        if visible {
            local.agent_visible_envs.insert(id);
        } else {
            local.agent_visible_envs.remove(&id);
        }
        Ok(())
    })
}
