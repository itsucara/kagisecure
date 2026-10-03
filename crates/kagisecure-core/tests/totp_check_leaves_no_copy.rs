//! Asking whether a one-time-password field works must not leave its seed behind.
//!
//! `Field::has_working_totp` runs before anything is approved — on the browser extension's own
//! `totp` path and at an agent fill's gate 4 — so it runs for requests nobody has said yes to, as
//! often as they are made. Parsing the `otpauth://` URI into a generator used to percent-decode
//! the secret parameter into a plain `String` and drop it unzeroized, so every such question left
//! a copy of the seed in freed heap memory.
//!
//! This binary installs a global allocator that, while armed, looks inside every buffer handed
//! back to it — freed, or left behind by a reallocation — for the seed, in the Base32 form the URI
//! carries and in the decoded bytes. A buffer that still holds either when it is released is a
//! copy nobody zeroized. One test, so no other test's allocations run while it is armed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kagisecure_core::model::{Field, Secret};
use kagisecure_core::totp::base32_decode;

/// A seed distinctive enough that finding it in a freed buffer is unambiguous.
const SEED_B32: &str = "KRUGS4ZAONSWKZBAO5UWY3BANZXXIIDMNFXGOZLS";

/// The decoded seed, filled in before the allocator is armed (decoding it allocates).
static SEED_BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

static ARMED: AtomicBool = AtomicBool::new(false);
static COPIES: AtomicUsize = AtomicUsize::new(0);

struct Scanning;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Look at a buffer being given back. Allocates nothing.
///
/// # Safety
///
/// `ptr` must point to `len` readable bytes.
unsafe fn inspect(ptr: *const u8, len: usize) {
    if !ARMED.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: the caller hands over a live allocation of `len` bytes.
    let buffer = unsafe { std::slice::from_raw_parts(ptr, len) };
    let decoded = SEED_BYTES.get().map_or(&[][..], Vec::as_slice);
    if contains(buffer, SEED_B32.as_bytes()) || contains(buffer, decoded) {
        COPIES.fetch_add(1, Ordering::SeqCst);
    }
}

// SAFETY: every call is forwarded to `System` unchanged; `inspect` only reads a buffer before it
// is released.
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is live for `layout.size()` bytes until the call below.
        unsafe {
            inspect(ptr, layout.size());
            System.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the old buffer is live until `System.realloc` moves or keeps it; whatever it
        // held may be left behind in the old one.
        unsafe {
            inspect(ptr, layout.size());
            System.realloc(ptr, layout, new_size)
        }
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

/// Run `f` with the allocator armed, and return how many released buffers held the seed.
fn copies_left_by(f: impl FnOnce()) -> usize {
    COPIES.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    COPIES.load(Ordering::SeqCst)
}

fn totp_field(uri: String) -> Field {
    Field::totp("one-time password", Secret::from_string(uri))
}

#[test]
fn has_working_totp_does_not_copy_the_seed() {
    SEED_BYTES.get_or_init(|| base32_decode(SEED_B32).expect("a valid seed"));
    let uris = [
        format!("otpauth://totp/Example:alice?secret={SEED_B32}&issuer=Example"),
        // Lower case, a percent-escaped letter and a `+`, which decode to the same seed.
        format!(
            "otpauth://totp/alice?secret=%4B{}+&digits=8&period=30",
            SEED_B32[1..].to_ascii_lowercase()
        ),
    ];
    for uri in uris {
        let field = totp_field(uri);

        // The detector works: an ordinary copy of the URI, dropped, is caught.
        let value = field.value.as_secret().and_then(Secret::expose_str);
        assert_eq!(
            copies_left_by(|| drop(value.map(str::to_owned))),
            usize::from(value.is_some_and(|v| v.contains(SEED_B32))),
            "the scanning allocator must see a plain copy"
        );

        // The question asked before any approval leaves nothing behind.
        let mut working = false;
        assert_eq!(copies_left_by(|| working = field.has_working_totp()), 0);
        assert!(working, "the field does generate codes");

        // Neither does building the generator and dropping it: the seed is decoded straight into
        // the buffer its `Secret` owns, which is zeroized on drop.
        assert_eq!(
            copies_left_by(|| {
                let generator = field.totp_generator().expect("a generator");
                drop(generator.code_at(1_000_000_000).expect("a code"));
            }),
            0
        );
    }

    // A setup that does not generate is answered the same way, and leaves nothing either.
    let truncated = totp_field(format!("otpauth://totp/a?secret={SEED_B32}Q&digits=6"));
    let mut working = true;
    assert_eq!(copies_left_by(|| working = truncated.has_working_totp()), 0);
    assert!(!working);
}
