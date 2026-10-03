//! When a job runs: calendar times in the Mac's local time (ADR-0042 §4), and the clock that says
//! what time it is.
//!
//! This crate has no time-zone database. Local time is Unix time plus the UTC offset the system
//! reports right now (`/bin/date +%z`), asked again on every scheduler tick, so a daylight-saving
//! change is picked up within one tick (implementation decision 11).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use kagisecure_core::vault::machine::{ScheduleTime, Weekday};

const DAY: i64 = 24 * 60 * 60;

/// What time it is, for the scheduler. A trait so tests can move time.
pub trait Clock: Send + Sync {
    /// Unix seconds.
    fn now_unix(&self) -> u64;
    /// The local offset from UTC, in seconds, now.
    fn utc_offset(&self) -> i64;
}

/// The real clock: the system's time and its current UTC offset.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        kagisecure_core::unix_now()
    }

    fn utc_offset(&self) -> i64 {
        system_utc_offset().unwrap_or(0)
    }
}

/// A clock a test sets by hand.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: AtomicU64,
    offset: AtomicI64,
}

impl ManualClock {
    /// A clock at `now`, with UTC offset `offset` seconds.
    #[must_use]
    pub fn new(now: u64, offset: i64) -> Self {
        Self {
            now: AtomicU64::new(now),
            offset: AtomicI64::new(offset),
        }
    }

    /// Move the clock to `now`.
    pub fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn utc_offset(&self) -> i64 {
        self.offset.load(Ordering::SeqCst)
    }
}

/// The system's current UTC offset, from `/bin/date +%z` (`+0900`, `-0530`). `None` when it
/// cannot be asked or answers something else.
fn system_utc_offset() -> Option<i64> {
    #[cfg(unix)]
    {
        let out = std::process::Command::new("/bin/date")
            .arg("+%z")
            .output()
            .ok()?;
        parse_offset(std::str::from_utf8(&out.stdout).ok()?.trim())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// `±HHMM` as seconds east of UTC.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_offset(text: &str) -> Option<i64> {
    let (sign, digits) = match text.as_bytes().first()? {
        b'+' => (1, &text[1..]),
        b'-' => (-1, &text[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i64 = digits[..2].parse().ok()?;
    let minutes: i64 = digits[2..].parse().ok()?;
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Monday = 0 … Sunday = 6, for local day number `day` (days since 1970-01-01, a Thursday).
fn weekday_index(day: i64) -> i64 {
    (day + 3).rem_euclid(7)
}

fn weekday_number(weekday: Weekday) -> i64 {
    match weekday {
        Weekday::Monday => 0,
        Weekday::Tuesday => 1,
        Weekday::Wednesday => 2,
        Weekday::Thursday => 3,
        Weekday::Friday => 4,
        Weekday::Saturday => 5,
        Weekday::Sunday => 6,
    }
}

/// The latest scheduled time at or before `now_local` (local seconds: Unix time plus the UTC
/// offset), in local seconds. `None` for an empty schedule.
#[must_use]
pub fn latest_occurrence(schedule: &[ScheduleTime], now_local: i64) -> Option<i64> {
    let today = now_local.div_euclid(DAY);
    schedule
        .iter()
        .map(|time| match *time {
            ScheduleTime::Daily { hour, minute } => {
                let at = today * DAY + i64::from(hour) * 3600 + i64::from(minute) * 60;
                if at <= now_local { at } else { at - DAY }
            }
            ScheduleTime::Weekly {
                weekday,
                hour,
                minute,
            } => {
                let back = (weekday_index(today) - weekday_number(weekday)).rem_euclid(7);
                let at = (today - back) * DAY + i64::from(hour) * 3600 + i64::from(minute) * 60;
                if at <= now_local { at } else { at - 7 * DAY }
            }
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-27 is a Sunday; 12:00 UTC that day.
    const SUNDAY_NOON: i64 = 1_790_510_400;

    #[test]
    fn the_reference_day_is_a_sunday() {
        assert_eq!(weekday_index(SUNDAY_NOON.div_euclid(DAY)), 6);
    }

    #[test]
    fn a_daily_time_is_today_or_yesterday() {
        let daily = [ScheduleTime::Daily {
            hour: 11,
            minute: 30,
        }];
        assert_eq!(
            latest_occurrence(&daily, SUNDAY_NOON),
            Some(SUNDAY_NOON - 1800)
        );
        let later = [ScheduleTime::Daily {
            hour: 13,
            minute: 0,
        }];
        assert_eq!(
            latest_occurrence(&later, SUNDAY_NOON),
            Some(SUNDAY_NOON + 3600 - DAY)
        );
        let exactly = [ScheduleTime::Daily {
            hour: 12,
            minute: 0,
        }];
        assert_eq!(latest_occurrence(&exactly, SUNDAY_NOON), Some(SUNDAY_NOON));
    }

    #[test]
    fn a_weekly_time_is_within_the_last_seven_days() {
        let friday = [ScheduleTime::Weekly {
            weekday: Weekday::Friday,
            hour: 12,
            minute: 0,
        }];
        assert_eq!(
            latest_occurrence(&friday, SUNDAY_NOON),
            Some(SUNDAY_NOON - 2 * DAY)
        );
        let sunday_later = [ScheduleTime::Weekly {
            weekday: Weekday::Sunday,
            hour: 18,
            minute: 0,
        }];
        assert_eq!(
            latest_occurrence(&sunday_later, SUNDAY_NOON),
            Some(SUNDAY_NOON + 6 * 3600 - 7 * DAY)
        );
    }

    #[test]
    fn the_latest_of_several_times_wins() {
        let both = [
            ScheduleTime::Daily { hour: 1, minute: 0 },
            ScheduleTime::Weekly {
                weekday: Weekday::Sunday,
                hour: 11,
                minute: 59,
            },
        ];
        assert_eq!(
            latest_occurrence(&both, SUNDAY_NOON),
            Some(SUNDAY_NOON - 60)
        );
        assert_eq!(latest_occurrence(&[], SUNDAY_NOON), None);
    }

    #[test]
    fn offsets_parse_both_ways() {
        assert_eq!(parse_offset("+0900"), Some(9 * 3600));
        assert_eq!(parse_offset("-0530"), Some(-(5 * 3600 + 30 * 60)));
        assert_eq!(parse_offset("+0000"), Some(0));
        assert_eq!(parse_offset("0900"), None);
        assert_eq!(parse_offset("+09"), None);
    }
}
