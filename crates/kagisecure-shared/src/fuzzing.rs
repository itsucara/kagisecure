//! Entry points for the `cargo-fuzz` targets in the repository root's `fuzz/` crate, compiled
//! only with the `fuzzing` feature, which no workspace crate enables (and in this crate's own
//! tests, which run the same entry points as properties).
//!
//! A record's body is decoded only after its signature verifies, so a fuzzer that mutates whole
//! records never gets past the signature to the decoder: [`decode_record_body`] hands it the
//! decoder directly. For the same reason a fuzzer never writes a genesis that verifies, so
//! [`roster_script`] reads its input as a script instead — which of four fixed test devices
//! writes what roster operation, naming which earlier records as heads — and
//! signs the records itself, so that every input is a record set a roster is really computed
//! from. Nothing here returns anything secret; the keys are fixed, public test keys.

use kagisecure_core::proto::VaultId;
use uuid::Uuid;

use crate::device::{DeviceKeyId, DeviceSecret};
use crate::record::{Envelope, NewRecord, RecordBody, RecordId, RecordKind};
use crate::roster::{MemberId, RemovalReason, Role, RosterOp, RosterState, Verification};
use crate::suite::Suite;

/// Decode `bytes` as a record body, as verification would once the signature holds, and throw
/// the result away. Must never panic.
pub fn decode_record_body(bytes: &[u8]) {
    let _ = RecordBody::decode(bytes, None);
}

/// The most records a script writes.
const SCRIPT_RECORDS: usize = 48;
/// How many devices a script writes as.
const DEVICES: usize = 4;

/// The vault every script writes to.
fn script_vault() -> VaultId {
    VaultId(Uuid::from_bytes([0x5c; 16]))
}

/// Script device `n`: fixed, public test keys.
fn script_device(n: usize) -> DeviceSecret {
    let n = u8::try_from(n).expect("a few devices");
    let mut secret = [n.wrapping_mul(29) ^ 0x3c; 64];
    secret[0] = n;
    secret[32] = n ^ 0x80;
    DeviceSecret::from_secret_bytes(&secret).expect("a test key")
}

fn script_member(n: usize) -> MemberId {
    MemberId::from_bytes([u8::try_from(n).expect("a few members") + 1; 16])
}

/// One device writing records in order, as a real one does — or, when told to, forking its own
/// chain to write a second record at a `seq` it already used.
struct ScriptWriter {
    device: DeviceSecret,
    seq: u64,
    prev: Option<RecordId>,
    last: Vec<(u64, RecordId)>,
}

/// Build the record set `data` describes: the genesis by device 0, then one record per six
/// bytes. Returns the genesis id and the records, or `None` for a script too short to start.
#[must_use]
pub fn roster_script(data: &[u8]) -> Option<(RecordId, Vec<Envelope>)> {
    let mut writers: Vec<ScriptWriter> = (0..DEVICES)
        .map(|n| ScriptWriter {
            device: script_device(n),
            seq: 0,
            prev: None,
            last: Vec::new(),
        })
        .collect();
    let ids: Vec<DeviceKeyId> = writers.iter().map(|w| w.device.id()).collect();
    let mut salt = 0u64;
    let mut sign = |writer: &mut ScriptWriter, op: &RosterOp, roster: Vec<RecordId>, fork: bool| {
        salt += 1;
        let (seq, prev) = if fork && writer.seq > 0 {
            let (seq, _) = writer.last[writer.last.len() - 1];
            (
                seq,
                writer
                    .last
                    .get(writer.last.len().wrapping_sub(2))
                    .map(|(_, id)| *id),
            )
        } else {
            (writer.seq, writer.prev)
        };
        let record = NewRecord {
            vault_id: script_vault(),
            seq,
            prev,
            parents: vec![],
            roster,
            epoch: None,
            created_at: 1_790_000_000 + seq,
        };
        let mut record_salt = [0u8; 16];
        record_salt[..8].copy_from_slice(&salt.to_be_bytes());
        let payload = op.to_payload().ok()?;
        let envelope = Envelope::sign_plain_salted(
            &writer.device,
            RecordKind::Roster,
            record,
            payload,
            record_salt,
        )
        .ok()?;
        if !fork || writer.seq == 0 {
            writer.last.push((writer.seq, envelope.id()));
            writer.seq += 1;
            writer.prev = Some(envelope.id());
        }
        Some(envelope)
    };

    let genesis_op = RosterOp::Genesis {
        suite: Suite::X25519Ed25519V1,
        member: script_member(0),
        device: writers[0].device.public().clone(),
        labels: None,
    };
    let genesis = sign(&mut writers[0], &genesis_op, vec![], false)?;
    let genesis_id = genesis.id();
    let mut records = vec![genesis];
    for step in data.as_chunks::<6>().0.iter().take(SCRIPT_RECORDS) {
        let author = usize::from(step[0]) % DEVICES;
        let target = usize::from(step[1]) % DEVICES;
        let role = match step[2] % 3 {
            0 => Role::Reader,
            1 => Role::Writer,
            _ => Role::Admin,
        };
        let pick = |b: u8| records[usize::from(b) % records.len()].id();
        let mut heads = vec![pick(step[3])];
        if step[4] & 1 == 1 {
            let other = pick(step[4] >> 1);
            if !heads.contains(&other) {
                heads.push(other);
            }
        }
        let op = match step[2] / 3 % 6 {
            0 => RosterOp::AddMember {
                member: script_member(target),
                role,
                labels: None,
            },
            1 => RosterOp::AddDevice {
                member: script_member(target),
                device: writers[target].device.public().clone(),
                verified: Verification::InPerson,
                labels: None,
            },
            2 => RosterOp::RemoveDevice {
                device: ids[target],
                reason: RemovalReason::Compromised,
            },
            3 => RosterOp::RemoveMember {
                member: script_member(target),
                reason: RemovalReason::Left,
            },
            4 => RosterOp::SetRole {
                member: script_member(target),
                role,
            },
            _ => RosterOp::Unknown {
                op: "future".to_owned(),
            },
        };
        if matches!(op, RosterOp::Unknown { .. }) {
            continue;
        }
        let fork = step[5] & 3 == 3;
        if let Some(envelope) = sign(&mut writers[author], &op, heads, fork) {
            records.push(envelope);
        }
    }
    Some((genesis_id, records))
}

/// Compute the roster of `data`'s script, and ask every record's authority and the roster at
/// every record. Must never panic, and must end.
pub fn drive_roster_script(data: &[u8]) -> Option<RosterState> {
    let (genesis, records) = roster_script(data)?;
    let state = RosterState::compute(&script_vault(), &genesis, &records).ok()?;
    for record in &records {
        let _ = state.authority(&record.id());
    }
    let _ = state.digest();
    Some(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Any script: the roster computes, and the same records in reverse give the same
        /// roster.
        #[test]
        fn any_script_computes_and_does_not_depend_on_record_order(
            data in proptest::collection::vec(any::<u8>(), 0..240),
        ) {
            if let Some((genesis, records)) = roster_script(&data) {
                let state = RosterState::compute(&script_vault(), &genesis, &records).unwrap();
                let mut reversed = records.clone();
                reversed.reverse();
                let again = RosterState::compute(&script_vault(), &genesis, &reversed).unwrap();
                prop_assert_eq!(state.digest(), again.digest());
                let _ = drive_roster_script(&data);
            }
        }
    }

    #[test]
    fn a_script_reaches_admins_and_removals() {
        // Device 0 adds member 1 as an admin and their device, who then removes member 0.
        // Byte 2 is the operation times three plus the role.
        let data = [
            0, 1, 2, 0, 0, 0, // add member 1, admin
            0, 1, 3, 1, 0, 0, // add device 1 for member 1
            1, 0, 9, 2, 0, 0, // device 1 removes member 0
        ];
        let state = drive_roster_script(&data).unwrap();
        assert_eq!(state.role_of(&script_device(1).id()), Some(Role::Admin));
        assert_eq!(state.role_of(&script_device(0).id()), None);
    }
}
