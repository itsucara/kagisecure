//! Tests of the roster's honest behaviour: one order on every replica, admins changing the
//! roster, a removal stopping a device, the unknown operation, a single genesis.

use proptest::prelude::*;

use super::*;
use crate::test_support::{Writer, test_vault};

pub(crate) fn member(n: u8) -> MemberId {
    MemberId::from_bytes([n; MEMBER_ID_LEN])
}

pub(crate) fn genesis_op(creator: &Writer, m: MemberId) -> RosterOp {
    RosterOp::Genesis {
        suite: Suite::X25519Ed25519V1,
        member: m,
        device: creator.public(),
        labels: Some(b"sealed labels".to_vec()),
    }
}

pub(crate) fn add_member(m: MemberId, role: Role) -> RosterOp {
    RosterOp::AddMember {
        member: m,
        role,
        labels: None,
    }
}

pub(crate) fn add_device(m: MemberId, device: &Writer) -> RosterOp {
    RosterOp::AddDevice {
        member: m,
        device: device.public(),
        verified: Verification::InPerson,
        labels: None,
    }
}

pub(crate) fn remove_device(device: &Writer) -> RosterOp {
    RosterOp::RemoveDevice {
        device: device.id(),
        reason: RemovalReason::Retired,
    }
}

/// A record set and its genesis.
pub(crate) struct Records {
    pub(crate) records: Vec<Envelope>,
    pub(crate) genesis: RecordId,
}

impl Records {
    pub(crate) fn create(creator: &mut Writer, m: MemberId) -> Self {
        let genesis = creator.roster(&genesis_op(creator, m), &[]);
        Self {
            genesis: genesis.id(),
            records: vec![genesis],
        }
    }

    pub(crate) fn push(&mut self, envelope: Envelope) -> RecordId {
        let id = envelope.id();
        self.records.push(envelope);
        id
    }

    pub(crate) fn compute(&self) -> RosterState {
        RosterState::compute(&test_vault(), &self.genesis, &self.records).unwrap()
    }
}

/// Alice creates the vault; Bob joins with `role`, on one device. Returns the records and the
/// id of Bob's device's addition.
pub(crate) fn alice_and_bob(alice: &mut Writer, bob: &Writer, role: Role) -> (Records, RecordId) {
    let mut records = Records::create(alice, member(1));
    let g = records.genesis;
    let added = records.push(alice.roster(&add_member(member(2), role), &[g]));
    let device = records.push(alice.roster(&add_device(member(2), bob), &[added]));
    (records, device)
}

#[test]
fn a_genesis_alone_makes_its_creator_the_only_admin() {
    let mut alice = Writer::new(1);
    let records = Records::create(&mut alice, member(1));
    let state = records.compute();
    assert_eq!(state.role_of(&alice.id()), Some(Role::Admin));
    assert_eq!(state.heads(), &[records.genesis]);
    assert_eq!(state.warnings(), vec![RosterWarning::FewAdmins]);
    assert!(state.ignored().is_empty() && state.waiting().is_empty());
    assert!(!state.is_read_only() && !state.is_frozen());
}

#[test]
fn an_admin_adds_members_and_devices_and_a_non_admin_cannot() {
    let mut alice = Writer::new(1);
    let mut bob = Writer::new(2);
    let (mut records, device) = alice_and_bob(&mut alice, &bob, Role::Writer);
    let by_writer = records.push(bob.roster(&add_member(member(3), Role::Admin), &[device]));
    let state = records.compute();
    assert_eq!(state.role_of(&bob.id()), Some(Role::Writer));
    assert_eq!(state.ignored().get(&by_writer), Some(&Ignored::NotAdmin));
    assert!(state.snapshot().member(&member(3)).is_none());
    assert_eq!(state.heads(), &[device]);
    assert_eq!(state.order().len(), 3);
}

/// A removal stops a device from the point it is removed: what it wrote before stays, what it
/// writes after is ignored, and its other records hold no authority named after the removal.
#[test]
fn a_removal_stops_a_device() {
    let mut alice = Writer::new(1);
    let mut bob = Writer::new(2);
    let (mut records, head) = alice_and_bob(&mut alice, &bob, Role::Admin);
    let before = records.push(bob.roster(&add_member(member(3), Role::Reader), &[head]));
    let removal = records.push(alice.roster(&remove_device(&bob), &[before]));
    let after = records.push(bob.roster(&add_member(member(4), Role::Reader), &[removal]));
    let item = records.push(bob.ack(&[removal], None, vec![]));
    let old_item = records.push(bob.ack(&[before], None, vec![]));
    let state = records.compute();
    assert!(state.snapshot().member(&member(3)).is_some());
    assert_eq!(state.ignored().get(&after), Some(&Ignored::NotADevice));
    assert!(state.snapshot().member(&member(4)).is_none());
    assert_eq!(state.role_of(&bob.id()), None);
    assert_eq!(
        state.authority(&item),
        Err(Refusal::Ignored(Ignored::NotADevice))
    );
    assert_eq!(state.authority(&old_item), Ok(Role::Admin));
    assert_eq!(state.warnings(), vec![RosterWarning::FewAdmins]);
}

#[test]
fn removing_the_last_admin_freezes_the_roster() {
    let mut alice = Writer::new(1);
    let mut records = Records::create(&mut alice, member(1));
    let g = records.genesis;
    records.push(alice.roster(&remove_device(&alice.fork()), &[g]));
    let state = records.compute();
    assert!(state.is_frozen());
    assert_eq!(state.warnings(), vec![RosterWarning::Frozen]);
}

#[test]
fn an_unknown_operation_from_an_admin_makes_the_vault_read_only() {
    let mut alice = Writer::new(1);
    let mut bob = Writer::new(2);
    let (mut records, head) = alice_and_bob(&mut alice, &bob, Role::Writer);
    let unknown = cbor::encode(&cbor::map(vec![(
        cbor::text("op"),
        cbor::text("merge-vaults"),
    )]));
    let header = bob.header(&[head], None);
    let by_writer = Envelope::sign_plain(&bob.device, RecordKind::Roster, header, unknown.clone());
    records.push(bob.wrote(by_writer.unwrap()));
    assert!(!records.compute().is_read_only());
    let header = alice.header(&[head], None);
    let by_admin = Envelope::sign_plain(&alice.device, RecordKind::Roster, header, unknown);
    records.push(alice.wrote(by_admin.unwrap()));
    assert!(records.compute().is_read_only());
}

#[test]
fn there_is_one_genesis_and_it_must_be_this_vaults() {
    let mut alice = Writer::new(1);
    let mut records = Records::create(&mut alice, member(1));
    let mut again = Writer::new(1);
    let second = records.push(again.roster(&genesis_op(&again, member(9)), &[]));
    let state = records.compute();
    assert!(matches!(
        state.ignored().get(&second),
        Some(Ignored::Duplicate | Ignored::Malformed(_) | Ignored::SecondGenesis)
    ));
    assert!(state.snapshot().member(&member(9)).is_none());
    let not_genesis = records.records[0].id();
    let elsewhere = kagisecure_core::proto::VaultId(uuid::Uuid::from_bytes([0x11; 16]));
    assert!(matches!(
        RosterState::compute(&elsewhere, &not_genesis, &records.records),
        Err(SharedError::InvalidGenesis(_))
    ));
    assert!(matches!(
        RosterState::compute(
            &test_vault(),
            &RecordId::from_bytes([1; 32]),
            &records.records
        ),
        Err(SharedError::GenesisMissing)
    ));
}

#[test]
fn a_record_whose_heads_are_missing_waits_and_applies_once_they_arrive() {
    let mut alice = Writer::new(1);
    let mut records = Records::create(&mut alice, member(1));
    let g = records.genesis;
    let first = alice.roster(&add_member(member(2), Role::Reader), &[g]);
    let second = records.push(alice.roster(&add_member(member(3), Role::Reader), &[first.id()]));
    let state = records.compute();
    assert_eq!(
        state.waiting().get(&second),
        Some(&Waiting::MissingHead(first.id()))
    );
    records.push(first);
    let state = records.compute();
    assert!(state.waiting().is_empty());
    assert!(state.snapshot().member(&member(3)).is_some());
}

#[test]
fn devices_share_no_key_and_limits_hold() {
    let mut alice = Writer::new(1);
    let bob = Writer::new(2);
    let (mut records, head) = alice_and_bob(&mut alice, &bob, Role::Reader);
    let again = records.push(alice.roster(&add_device(member(2), &bob), &[head]));
    let state = records.compute();
    assert!(matches!(
        state.ignored().get(&again),
        Some(Ignored::Invalid(_))
    ));
    let mut head = again;
    for n in 3..=40 {
        head = records.push(alice.roster(&add_member(member(n), Role::Reader), &[head]));
    }
    let state = records.compute();
    assert_eq!(state.snapshot().members().count(), MAX_MEMBERS);
}

#[test]
fn records_past_the_limit_are_ignored() {
    let mut alice = Writer::new(1);
    let bob = Writer::new(2);
    let (mut records, mut head) = alice_and_bob(&mut alice, &bob, Role::Writer);
    for n in 0..MAX_ROSTER_RECORDS {
        let role = if n % 2 == 0 {
            Role::Reader
        } else {
            Role::Writer
        };
        let op = RosterOp::SetRole {
            member: member(2),
            role,
        };
        head = records.push(alice.roster(&op, &[head]));
    }
    let state = records.compute();
    assert_eq!(state.order().len(), MAX_ROSTER_RECORDS);
    assert_eq!(state.ignored().get(&head), Some(&Ignored::LimitExceeded));
}

#[test]
fn an_equivocation_keeps_the_smaller_record_id() {
    let mut alice = Writer::new(1);
    let bob = Writer::new(2);
    let (mut records, head) = alice_and_bob(&mut alice, &bob, Role::Admin);
    let mut fork = alice.fork();
    let one = records.push(alice.roster(&add_member(member(5), Role::Reader), &[head]));
    let two = records.push(fork.roster(&add_member(member(6), Role::Reader), &[head]));
    let (kept, dropped) = if one < two { (one, two) } else { (two, one) };
    let state = records.compute();
    assert_eq!(state.ignored().get(&dropped), Some(&Ignored::Duplicate));
    assert!(state.order().contains(&kept));
}

#[test]
fn operations_round_trip_and_what_is_not_understood_stays_unknown() {
    let alice = Writer::new(1);
    for op in [
        genesis_op(&alice, member(1)),
        add_member(member(2), Role::Writer),
        add_device(member(2), &alice),
        remove_device(&alice),
        RosterOp::RemoveMember {
            member: member(2),
            reason: RemovalReason::Left,
        },
        RosterOp::SetRole {
            member: member(2),
            role: Role::Admin,
        },
    ] {
        let payload = op.to_payload().unwrap();
        assert_eq!(RosterOp::from_payload(&payload).unwrap(), op);
    }
    let with = |entries: Vec<(Value, Value)>| cbor::encode(&cbor::map(entries));
    for payload in [
        with(vec![(cbor::text("op"), cbor::text("retire"))]),
        with(vec![
            (cbor::text("op"), cbor::text("set-role")),
            (cbor::text("member"), cbor::bytes(&[2; 16])),
            (cbor::text("role"), cbor::text("owner")),
        ]),
    ] {
        assert!(matches!(
            RosterOp::from_payload(&payload).unwrap(),
            RosterOp::Unknown { .. }
        ));
    }
    let missing = with(vec![(cbor::text("op"), cbor::text("set-role"))]);
    assert!(RosterOp::from_payload(&missing).is_err());
    assert!(RosterOp::Unknown { op: "x".into() }.to_payload().is_err());
}

/// A record set with a removal, a demotion, an ignored record and a waiting one.
fn eventful() -> &'static Records {
    static RECORDS: std::sync::OnceLock<Records> = std::sync::OnceLock::new();
    RECORDS.get_or_init(|| {
        let mut alice = Writer::new(1);
        let mut bob = Writer::new(2);
        let carol = Writer::new(3);
        let (mut records, head) = alice_and_bob(&mut alice, &bob, Role::Admin);
        let c = records.push(bob.roster(&add_member(member(3), Role::Writer), &[head]));
        let cd = records.push(bob.roster(&add_device(member(3), &carol), &[c]));
        let demote = RosterOp::SetRole {
            member: member(2),
            role: Role::Writer,
        };
        records.push(alice.roster(&demote, &[head]));
        records.push(bob.roster(&add_member(member(4), Role::Reader), &[cd]));
        records.push(alice.roster(&remove_device(&carol), &[cd]));
        records.push(alice.roster(
            &add_member(member(7), Role::Reader),
            &[RecordId::from_bytes([0xee; 32])],
        ));
        records
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Any order, any repetition: one roster.
    #[test]
    fn the_roster_does_not_depend_on_the_order_records_arrive_in(
        keys in proptest::collection::vec(any::<u64>(), 16),
        repeats in proptest::collection::vec(any::<prop::sample::Index>(), 0..8),
    ) {
        let records = eventful();
        let expected = records.compute().digest();
        let mut shuffled: Vec<(u64, Envelope)> = records
            .records
            .iter()
            .enumerate()
            .map(|(i, e)| (keys[i % keys.len()] ^ (i as u64), e.clone()))
            .collect();
        for index in &repeats {
            let e = records.records[index.index(records.records.len())].clone();
            shuffled.push((index.index(usize::MAX) as u64, e));
        }
        shuffled.sort_by_key(|(key, _)| *key);
        let shuffled: Vec<Envelope> = shuffled.into_iter().map(|(_, e)| e).collect();
        let state = RosterState::compute(&test_vault(), &records.genesis, &shuffled).unwrap();
        prop_assert_eq!(state.digest(), expected);
    }
}
