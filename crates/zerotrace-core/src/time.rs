//! Time handling for deadlines that must not be cheatable.
//!
//! # Why the deadline is wall-clock based
//!
//! `Instant` uses `CLOCK_MONOTONIC` on Unix and `QueryPerformanceCounter` on
//! Windows. Neither advances while the machine is suspended. A deadline
//! measured only monotonically could therefore be postponed indefinitely by
//! closing a laptop lid, which is precisely the scenario a deadman switch
//! exists for.
//!
//! So the deadline is an absolute wall-clock time, which advances through
//! suspend. Monotonic time is kept alongside it purely as a cross-check.
//!
//! # Why elapsed time is the maximum of the two
//!
//! Wall clock is attacker-controllable: set the clock back and the deadline
//! recedes. Monotonic is not, but it under-counts across suspend. Taking the
//! larger of the two means:
//!
//! - a clock rollback cannot buy time, because monotonic still advanced
//! - a suspend still counts, because the wall clock still advanced
//!
//! Neither manipulation extends the deadline, which is the property that
//! matters.

use serde::{Deserialize, Serialize};

/// A pairing of wall-clock and monotonic readings taken at the same moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeAnchor {
    /// Seconds since the Unix epoch.
    pub wall: i64,
    /// Monotonic seconds since an arbitrary origin that survives only for the
    /// life of the process.
    pub monotonic: u64,
}

/// What comparing the two clocks revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClockAnomaly {
    None,
    /// The wall clock moved backwards relative to monotonic time.
    Rollback { seconds: i64 },
    /// The wall clock jumped forward far more than monotonic time did.
    ///
    /// Not treated as an attack on its own: an NTP correction after a long
    /// power-off looks exactly like this. It is surfaced so a policy can
    /// decide, rather than acted on here.
    Jump { seconds: i64 },
}

impl ClockAnomaly {
    pub fn label(&self) -> &'static str {
        match self {
            ClockAnomaly::None => "NONE",
            ClockAnomaly::Rollback { .. } => "ROLLBACK",
            ClockAnomaly::Jump { .. } => "FORWARD JUMP",
        }
    }
    pub fn is_suspicious(&self) -> bool {
        matches!(self, ClockAnomaly::Rollback { .. })
    }
}

/// Tolerance before a forward divergence is called a jump.
///
/// Suspend routinely produces a large legitimate divergence, so this is
/// deliberately generous. It is a reporting threshold, not a security control.
pub const JUMP_TOLERANCE_SECONDS: i64 = 3600;

/// Elapsed time between two anchors, and any anomaly seen.
///
/// The returned duration is never negative and is never smaller than the
/// monotonic elapsed time, so no clock manipulation can shorten it.
pub fn elapsed_between(from: TimeAnchor, to: TimeAnchor) -> (u64, ClockAnomaly) {
    let wall_delta = to.wall - from.wall;
    let mono_delta = to.monotonic.saturating_sub(from.monotonic);

    let anomaly = if wall_delta < 0 {
        ClockAnomaly::Rollback { seconds: -wall_delta }
    } else if wall_delta - (mono_delta as i64) > JUMP_TOLERANCE_SECONDS {
        // A forward divergence is expected across suspend; report, do not act.
        ClockAnomaly::Jump { seconds: wall_delta - mono_delta as i64 }
    } else if (mono_delta as i64) - wall_delta > JUMP_TOLERANCE_SECONDS {
        // Monotonic ran ahead of the wall clock: the clock was set back.
        ClockAnomaly::Rollback { seconds: mono_delta as i64 - wall_delta }
    } else {
        ClockAnomaly::None
    };

    let wall_elapsed = wall_delta.max(0) as u64;
    (wall_elapsed.max(mono_delta), anomaly)
}

/// Reads both clocks. `monotonic_origin` fixes the process-local origin.
pub fn now(monotonic_origin: std::time::Instant) -> TimeAnchor {
    TimeAnchor {
        wall: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        monotonic: monotonic_origin.elapsed().as_secs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(wall: i64, monotonic: u64) -> TimeAnchor {
        TimeAnchor { wall, monotonic }
    }

    #[test]
    fn normal_progress_reports_the_elapsed_time() {
        let (e, a) = elapsed_between(anchor(1000, 0), anchor(1600, 600));
        assert_eq!(e, 600);
        assert_eq!(a, ClockAnomaly::None);
    }

    #[test]
    fn a_clock_rollback_cannot_buy_time() {
        // The wall clock is wound back an hour, but monotonic advanced 600s.
        let (elapsed, anomaly) = elapsed_between(anchor(10_000, 0), anchor(6_400, 600));
        assert_eq!(elapsed, 600, "rollback must not reduce elapsed time");
        assert!(matches!(anomaly, ClockAnomaly::Rollback { .. }));
        assert!(anomaly.is_suspicious());
    }

    #[test]
    fn suspend_still_counts_toward_the_deadline() {
        // Three days of wall time, no monotonic time: a suspended laptop.
        let three_days = 3 * 24 * 3600;
        let (elapsed, anomaly) = elapsed_between(anchor(0, 0), anchor(three_days, 0));
        assert_eq!(elapsed, three_days as u64, "sleep must count");
        // Reported as a forward jump, but not treated as an attack.
        assert!(matches!(anomaly, ClockAnomaly::Jump { .. }));
        assert!(!anomaly.is_suspicious());
    }

    #[test]
    fn elapsed_time_is_never_negative() {
        let (e, _) = elapsed_between(anchor(10_000, 100), anchor(0, 100));
        assert_eq!(e, 0);
    }

    #[test]
    fn elapsed_is_never_less_than_monotonic() {
        for wall_delta in [-5000i64, -1, 0, 1, 5000] {
            let (e, _) = elapsed_between(anchor(0, 0), anchor(wall_delta, 900));
            assert!(e >= 900, "wall_delta {wall_delta} produced {e}");
        }
    }

    #[test]
    fn small_divergence_is_not_flagged() {
        let (_, a) = elapsed_between(anchor(0, 0), anchor(610, 600));
        assert_eq!(a, ClockAnomaly::None);
    }
}
