//! Who may ask for agent fills: blocks, and the one-flow-at-a-time slot's refusal
//! ([ADR-0036](../../../../../docs/decisions/0036-agent-requested-browser-fill.md) §9, as amended
//! on 2026-10-03).
//!
//! Bookkeeping only. Nothing here touches the vault, the approval queue or a browser: the broker
//! asks `Limits::check` at gate 1 and tells it when the human pressed **Deny and block this
//! agent**.
//!
//! # What was removed on 2026-10-03
//!
//! The owner chose convenience over approval-fatigue protection: there is no longer a per-agent
//! sheet budget, no sticky denial that answers a repeated request without a sheet, and no block
//! after repeated origin mismatches. A mismatch is still refused and reported (§9.4); it just no
//! longer escalates. `Limits::denied`, `Limits::sheet_raised` and `Limits::origin_mismatch` stay
//! as no-ops so the broker's call sites read the same.
//!
//! # Who "the agent" is
//!
//! An [`AgentKey`]: the sidecar's parent executable, as the kernel resolved it — never the name
//! the agent reports, which it chooses.
//!
//! # What survives what
//!
//! Blocks live in the process-wide broker and survive a vault lock.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How long **Deny and block this agent** blocks it (§9.3): thirty minutes.
pub const DENY_AND_BLOCK: Duration = Duration::from_secs(30 * 60);

/// Who a limit applies to: the sidecar's kernel-resolved parent executable.
pub type AgentKey = String;

/// Why an agent is blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentFillBlockReason {
    /// The human pressed **Deny and block this agent** (§9.3). Lifts by itself after
    /// [`DENY_AND_BLOCK`].
    DeniedAndBlocked,
    /// A second origin mismatch in one unlock session (§9.4). Lifts only when the human unblocks
    /// it.
    OriginMismatch,
}

/// One blocked agent, for the blocks list in Agent access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentFillBlock {
    /// The key it is blocked under: the parent executable's path. What `unblock` takes.
    pub key: AgentKey,
    /// The self-reported name of the agent whose request set the block. Display only; quote it.
    pub agent_name: String,
    /// Why.
    pub reason: AgentFillBlockReason,
    /// How long it has left, or `None` for a block that lasts until the human lifts it.
    pub remaining: Option<Duration>,
}

/// Why gate 1 refused a request without a sheet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The agent is blocked (§9.3, §9.4).
    Blocked,
    /// No longer produced (sticky denials were removed on 2026-10-03); kept so the refusal
    /// wording and audit mapping stay exhaustive.
    #[allow(dead_code)]
    DeniedEarlier,
    /// No longer produced (the sheet budget was removed on 2026-10-03); kept for the same reason.
    #[allow(dead_code)]
    RateLimited {
        /// Whether this refusal is the one the human hears about.
        first: bool,
    },
    /// Another agent fill is in progress; they are served one at a time.
    Busy,
}

#[derive(Debug)]
struct Block {
    agent_name: String,
    reason: AgentFillBlockReason,
    /// `None`: until unblocked.
    until: Option<Instant>,
}

/// The limits' state. Owned by the broker, behind its mutex.
#[derive(Debug, Default)]
pub(crate) struct Limits {
    blocks: BTreeMap<AgentKey, Block>,
}

impl Limits {
    /// Gate 1's verdict for `agent`: refused only while it is blocked. The other arguments are
    /// what the removed budget and sticky denials keyed on, kept so the call site is unchanged.
    pub(crate) fn check(
        &mut self,
        agent: &str,
        _item_id: &str,
        _origin: Option<&str>,
        now: Instant,
        _raises_sheet: bool,
    ) -> Result<(), Refusal> {
        self.prune(now);
        if self.blocks.contains_key(agent) {
            return Err(Refusal::Blocked);
        }
        Ok(())
    }

    /// A sheet is about to be raised for `agent`. Nothing is counted any more.
    pub(crate) fn sheet_raised(&mut self, _agent: &str, _now: Instant) {}

    /// The human denied (or let time out) a request. Nothing sticks any more: the next identical
    /// request raises its own sheet.
    pub(crate) fn denied(&mut self, _agent: &str, _item_id: &str, _origin: &str, _now: Instant) {}

    /// Block `agent`: for [`DENY_AND_BLOCK`], or until unblocked. A block that is already there
    /// is never shortened.
    pub(crate) fn block(
        &mut self,
        agent: &str,
        agent_name: &str,
        reason: AgentFillBlockReason,
        now: Instant,
    ) {
        let until = match reason {
            AgentFillBlockReason::DeniedAndBlocked => Some(now + DENY_AND_BLOCK),
            AgentFillBlockReason::OriginMismatch => None,
        };
        let longer = match self.blocks.get(agent) {
            None => true,
            Some(existing) => match (existing.until, until) {
                (None, _) => false,
                (Some(_), None) => true,
                (Some(old), Some(new)) => new > old,
            },
        };
        if longer {
            self.blocks.insert(
                agent.to_owned(),
                Block {
                    agent_name: agent_name.to_owned(),
                    reason,
                    until,
                },
            );
        }
    }

    /// `agent`'s tab in front was on a site the item is not saved for. Never blocks any more;
    /// always `false`.
    pub(crate) fn origin_mismatch(
        &mut self,
        _agent: &str,
        _agent_name: &str,
        _now: Instant,
    ) -> bool {
        false
    }

    /// Lift `agent`'s block. Returns whether there was one.
    pub(crate) fn unblock(&mut self, agent: &str) -> bool {
        self.blocks.remove(agent).is_some()
    }

    /// Every block in force, by key.
    pub(crate) fn blocks(&mut self, now: Instant) -> Vec<AgentFillBlock> {
        self.prune(now);
        self.blocks
            .iter()
            .map(|(key, block)| AgentFillBlock {
                key: key.clone(),
                agent_name: block.agent_name.clone(),
                reason: block.reason,
                remaining: block
                    .until
                    .map(|until| until.saturating_duration_since(now)),
            })
            .collect()
    }

    /// A vault lock ended the unlock session. Nothing here is per session any more.
    pub(crate) fn new_unlock_session(&mut self) {}

    /// Forget whatever has run out, so nothing grows without bound.
    fn prune(&mut self, now: Instant) {
        self.blocks
            .retain(|_, block| block.until.is_none_or(|until| now < until));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "/usr/local/bin/node";
    const OTHER: &str = "/usr/bin/python3";
    const ITEM: &str = "item-1";
    const ORIGIN: &str = "https://login.example.com";

    fn at(start: Instant, minutes: u64) -> Instant {
        start + Duration::from_secs(minutes * 60)
    }

    #[test]
    fn deny_and_block_is_thirty_minutes() {
        assert_eq!(DENY_AND_BLOCK, Duration::from_secs(1800));
    }

    #[test]
    fn nothing_but_a_block_refuses() {
        let start = Instant::now();
        let mut limits = Limits::default();
        for minute in 0..20 {
            limits.sheet_raised(AGENT, at(start, minute));
            limits.denied(AGENT, ITEM, ORIGIN, at(start, minute));
            assert!(!limits.origin_mismatch(AGENT, "a", at(start, minute)));
            assert_eq!(
                limits.check(AGENT, ITEM, Some(ORIGIN), at(start, minute), true),
                Ok(()),
                "minute {minute}"
            );
        }
        assert!(limits.blocks(at(start, 20)).is_empty());
    }

    #[test]
    fn a_block_is_per_key_and_never_shortened() {
        let start = Instant::now();
        let mut limits = Limits::default();
        limits.block(AGENT, "a", AgentFillBlockReason::OriginMismatch, start);
        limits.block(AGENT, "b", AgentFillBlockReason::DeniedAndBlocked, start);
        let blocks = limits.blocks(at(start, 45));
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].reason, AgentFillBlockReason::OriginMismatch);
        assert_eq!(blocks[0].remaining, None);
        assert_eq!(limits.check(OTHER, ITEM, Some(ORIGIN), start, true), Ok(()));
        assert!(limits.unblock(AGENT));
        assert!(!limits.unblock(AGENT));
        assert_eq!(limits.check(AGENT, ITEM, Some(ORIGIN), start, true), Ok(()));
    }

    #[test]
    fn a_timed_block_runs_out() {
        let start = Instant::now();
        let mut limits = Limits::default();
        limits.block(AGENT, "a", AgentFillBlockReason::DeniedAndBlocked, start);
        assert_eq!(
            limits.blocks(at(start, 10))[0].remaining,
            Some(Duration::from_secs(20 * 60))
        );
        assert_eq!(
            limits.check(AGENT, ITEM, Some(ORIGIN), at(start, 29), false),
            Err(Refusal::Blocked)
        );
        assert_eq!(
            limits.check(AGENT, ITEM, Some(ORIGIN), at(start, 30), true),
            Ok(())
        );
        assert!(limits.blocks(at(start, 30)).is_empty());
    }
}
