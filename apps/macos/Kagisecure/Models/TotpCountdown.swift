import Foundation

import KagisecureFFI

/// The arithmetic behind the countdown ring (ui-spec.md §4.2).
///
/// Pure functions over `(secondsRemaining, period)`, deliberately separated from the view so the
/// roadmap's "no visible drift after a ten-minute soak" criterion can be asserted in a test that
/// runs in milliseconds rather than watched for ten minutes. Rust owns the definition of
/// `secondsRemaining` — `Totp::seconds_remaining`, always in `1...period` — and this file owns
/// only how that becomes a fraction of a circle and a colour.
enum TotpCountdown {
    /// Codes this close to expiry are drawn in the warning colour.
    static let warningSeconds: UInt32 = 5

    /// How much of the ring is still filled, in `0...1`.
    ///
    /// Full at the instant a code is minted and approaching empty as its window closes. Rust
    /// reports `period` at the top of a window and `1` in its final second, so the fraction is
    /// `secondsRemaining / period` — the ring never reaches a hard zero, which is correct: a code
    /// with one second left is still a usable code, and a ring that emptied completely would say
    /// otherwise.
    static func fraction(secondsRemaining: UInt32, period: UInt32) -> Double {
        guard period > 0 else { return 0 }
        let clamped = min(secondsRemaining, period)
        return Double(clamped) / Double(period)
    }

    /// Whether the code is about to roll over, so the UI can warn before it does.
    static func isExpiring(secondsRemaining: UInt32) -> Bool {
        secondsRemaining <= warningSeconds
    }

    /// The Unix second at which the current window ends and a new code appears.
    ///
    /// The view refreshes on this rather than on a fixed one-second cadence started at render
    /// time, which is what keeps a long-lived window from drifting: each tick recomputes from the
    /// wall clock instead of counting its own ticks.
    static func windowEnd(now: UInt64, secondsRemaining: UInt32) -> UInt64 {
        now + UInt64(secondsRemaining)
    }

    /// Group a code for reading: `123456` becomes `123 456`, `12345678` becomes `1234 5678`.
    ///
    /// Six- and seven-digit codes split down the middle-ish in threes, eight-digit codes in
    /// fours, which is how every authenticator app renders them and how a person reads a number
    /// aloud while typing it somewhere else.
    static func grouped(_ code: String) -> String {
        let size = code.count % 2 == 0 && code.count >= 8 ? 4 : 3
        var out: [String] = []
        var index = code.startIndex
        while index < code.endIndex {
            let next = code.index(index, offsetBy: size, limitedBy: code.endIndex) ?? code.endIndex
            out.append(String(code[index..<next]))
            index = next
        }
        return out.joined(separator: " ")
    }

    /// The current Unix second, as the FFI wants it.
    static func unixNow() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970))
    }
}

/// A `TotpCodeView` plus the moment it was computed for, so a view can tell a stale render from a
/// fresh one without asking Rust again.
struct TotpSnapshot: Equatable {
    let code: String
    let secondsRemaining: UInt32
    let period: UInt32
    let caption: String?

    init(_ view: TotpCodeView) {
        code = view.code
        secondsRemaining = view.secondsRemaining
        period = view.params.period
        caption = view.params.caption
    }

    var fraction: Double {
        TotpCountdown.fraction(secondsRemaining: secondsRemaining, period: period)
    }

    var isExpiring: Bool {
        TotpCountdown.isExpiring(secondsRemaining: secondsRemaining)
    }

    var grouped: String {
        TotpCountdown.grouped(code)
    }
}
