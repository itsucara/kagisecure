//! How often an agent may create test logins
//! ([ADR-0048](../../../../docs/decisions/0048-agent-test-logins.md) §11): at most
//! [`CREATES_PER_WINDOW`] in any [`CREATE_WINDOW`], per agent.
//!
//! Bookkeeping only, like `extension/agent_fill/limits.rs`, whose shape this copies. Nothing here
//! touches the vault or the approval queue.
//!
//! # Who "the agent" is
//!
//! The sidecar's parent executable as the kernel resolved it (`Sidecar::of`) — never the name
//! the agent reports, and never the IPC connection, so reconnecting does not reset the count.
//!
//! # What survives what
//!
//! The counts live in the process-wide [`super::TestLoginBroker`] and survive a vault lock.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// The window the create limit is counted over: ten minutes.
pub const CREATE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How many creates one agent may make inside [`CREATE_WINDOW`].
pub const CREATES_PER_WINDOW: usize = 10;

/// The per-agent create counts. Owned by the broker, behind its mutex.
#[derive(Debug, Default)]
pub(crate) struct Limits {
    creates: BTreeMap<String, VecDeque<Instant>>,
}

impl Limits {
    /// Reserve one create for `agent` at `now`, or `false` when it has had
    /// [`CREATES_PER_WINDOW`] in the last [`CREATE_WINDOW`]. A reservation that does not end in a
    /// create is handed back with [`Self::release`].
    pub(crate) fn reserve(&mut self, agent: &str, now: Instant) -> bool {
        let times = self.creates.entry(agent.to_owned()).or_default();
        while times
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= CREATE_WINDOW)
        {
            times.pop_front();
        }
        if times.len() >= CREATES_PER_WINDOW {
            return false;
        }
        times.push_back(now);
        true
    }

    /// Hand back the reservation `agent` took at `at`: the request created nothing.
    pub(crate) fn release(&mut self, agent: &str, at: Instant) {
        if let Some(times) = self.creates.get_mut(agent)
            && let Some(index) = times.iter().rposition(|t| *t == at)
        {
            times.remove(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_creates_in_ten_minutes_then_refused_until_the_oldest_ages_out() {
        let mut limits = Limits::default();
        let start = Instant::now();
        for i in 0..CREATES_PER_WINDOW {
            assert!(limits.reserve("/bin/agent", start + Duration::from_secs(i as u64)));
        }
        assert!(!limits.reserve("/bin/agent", start + Duration::from_secs(60)));
        assert!(limits.reserve("/bin/other", start), "per agent");
        assert!(limits.reserve("/bin/agent", start + CREATE_WINDOW));
    }

    #[test]
    fn a_released_reservation_does_not_count() {
        let mut limits = Limits::default();
        let now = Instant::now();
        for _ in 0..CREATES_PER_WINDOW {
            assert!(limits.reserve("a", now));
        }
        limits.release("a", now);
        assert!(limits.reserve("a", now));
        assert!(!limits.reserve("a", now));
    }
}
