//! The shared signing clock, judged by a process that asked it FIRST.
//!
//! `signing::clock::now()` memoises one floored second for the life of the
//! process, and the unit tests in `signing.rs` pin what stays true regardless of
//! who initialised it: stability across reads, and byte-identical signatures
//! across a real second boundary. What they cannot pin is where the value came
//! from — the memo belongs to whichever call initialises it, so every other test
//! in that binary (anything that signs, and one that deliberately sleeps past a
//! boundary) makes "the floored instant is the second the raw clock showed"
//! false by construction. It failed CI over two Linux jobs that way. Here this
//! file's process asks the clock before anything else can, so the property it
//! judges holds exactly when the code under test earns it.

use std::time::{SystemTime, UNIX_EPOCH};

use openfirma_browser::signing::clock;

#[test]
fn the_first_call_of_a_process_reports_the_second_the_raw_clock_shows() {
    // Before/after around the FIRST call: an unfloored `now()` drifts out of
    // this window, a constant fails the second reading below, and a clock that
    // rounds up or truncates to anything coarser shows as a mismatch here.
    let before = SystemTime::now();
    let t = clock::now();
    let after = SystemTime::now();

    assert_eq!(t, clock::now(), "one process, one second");
    let whole = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(
        t,
        UNIX_EPOCH + std::time::Duration::from_secs(whole),
        "the memoised instant is a whole second, no sub-second residue"
    );
    let raw_floor = before.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let raw_ceil = after.duration_since(UNIX_EPOCH).unwrap().as_secs();
    assert!(
        whole >= raw_floor && whole <= raw_ceil,
        "the memoised second {whole} belongs to the window the raw clock \
         showed ({raw_floor}..={raw_ceil})"
    );
}
