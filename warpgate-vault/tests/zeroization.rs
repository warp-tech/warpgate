//! Does `Zeroizing` actually clear the buffer before it is freed?
//!
//! Everywhere else this is taken on faith: no ordinary test can look at memory
//! after a value is dropped, so the claim that credentials are wiped has never
//! been checked. Dumping the process was the obvious approach and is not
//! usable — attaching a debugger to the gateway takes longer than any test can
//! wait.
//!
//! This looks in the one place the answer is unambiguous: the allocator. A
//! global allocator that inspects each block on the way out can say exactly
//! whether the bytes were still there when it was handed back.
//!
//! The control case is what gives this teeth. A plain `String` holding the same
//! canary must be found on free — if it is not, the detector is broken and the
//! `Zeroizing` result would mean nothing.
//!
//! What this file does *not* do, said plainly so nobody reads more into it:
//! it demonstrates the class — a buffer that grows leaves copies of what it
//! held, one reserved up front does not — but it is not a reliable guard on any
//! single call site. Whether a freed block is still observable depends on where
//! the growth boundaries fall relative to the secret and on what the allocator
//! does with the block afterwards, so a genuine regression guard would need the
//! allocator to record freed blocks rather than sample them.
//!
//! The measurements go through `login_payload` itself rather than a copy of its
//! shape written beside it — a test that rebuilds the safe pattern inline stays
//! green when the shipped one is reverted. That is why the function is `pub`,
//! and it is not the same thing as a guarantee that reverting it fails here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use warpgate_vault::{grown_without_leaving_a_copy, login_payload};
use zeroize::Zeroizing;

/// Long enough that a match is this test's data and not something the runtime
/// happened to be holding.
const CANARY: &[u8] = b"WARPGATE-ZEROIZE-CANARY-9f3a1c7e5b2d";

static WATCHING: AtomicBool = AtomicBool::new(false);
static SIGHTINGS: AtomicUsize = AtomicUsize::new(0);

struct WatchfulAllocator;

// The allocator has to read raw memory that is about to be released, which is
// exactly the observation this file exists to make.
#[allow(
    unsafe_code,
    reason = "reading a block on its way back to the allocator is the measurement"
)]
unsafe impl GlobalAlloc for WatchfulAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.load(Ordering::Relaxed) && layout.size() >= CANARY.len() {
            // No allocation here, and no formatting: anything that allocates
            // would re-enter this function.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(CANARY.len()).any(|window| window == CANARY) {
                SIGHTINGS.fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchfulAllocator = WatchfulAllocator;

/// The counter is global, so only one test may be watching at a time — without
/// this, a canary freed by one test is counted by another and every result here
/// becomes noise.
static WATCH: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs a whole test while holding the watch, so that another test's *setup* —
/// which allocates canaries outside any measurement window — cannot be counted
/// here. Serialising only the windows was not enough, and the symptom was
/// numbers that moved between runs.
fn watched<R>(body: impl FnOnce(&Watcher) -> R) -> R {
    let guard = WATCH.lock().unwrap_or_else(|e| e.into_inner());
    let result = body(&Watcher);
    drop(guard);
    result
}

struct Watcher;

impl Watcher {
    /// Counts canaries in blocks freed while `body` runs. Prepare fixtures
    /// outside it: anything allocated in here is part of the measurement.
    fn sightings_while(&self, body: impl FnOnce()) -> usize {
        SIGHTINGS.store(0, Ordering::Relaxed);
        WATCHING.store(true, Ordering::Relaxed);
        body();
        WATCHING.store(false, Ordering::Relaxed);
        SIGHTINGS.load(Ordering::Relaxed)
    }
}

/// Proves the detector works. Without this, a `Zeroizing` result of zero could
/// mean the wiping happened or that nothing was ever being watched.
#[test]
fn a_plain_string_is_still_readable_when_it_is_freed() {
    let seen = watched(|w| {
        w.sightings_while(|| {
            let secret = String::from_utf8(CANARY.to_vec()).unwrap();
            drop(secret);
        })
    });

    assert!(
        seen > 0,
        "the canary was not seen on free, so this file cannot measure anything"
    );
}

#[test]
fn a_zeroizing_string_is_gone_before_it_is_freed() {
    let seen = watched(|w| {
        w.sightings_while(|| {
            let secret = Zeroizing::new(String::from_utf8(CANARY.to_vec()).unwrap());
            drop(secret);
        })
    });

    assert_eq!(seen, 0, "the credential was still in the freed block");
}

#[derive(serde::Serialize)]
struct AppRoleLogin<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

/// Which primitive leaves a copy behind, measured one at a time.
///
/// Every measurement window contains the operation under test and nothing else.
/// An earlier version prepared its fixture inside the window — `format!` to
/// build the file contents — and counted that instead, which is how a
/// measurement can look decisive and mean nothing.
#[test]
fn the_primitives_that_leak_are_the_ones_that_grow_a_buffer() {
    watched(|w| the_primitives(w));
}

/// Does the response reader leave copies behind when a body outgrows its
/// reservation?
///
/// `read_bounded` reserves 32 KiB and refuses only past 256 KiB, so anything
/// between the two grows the buffer. Every caller of it carries a credential:
/// the Vault token, an AppRole secret ID, a cloud identity JWT.
///
/// Measured through the function the reader actually calls rather than a copy
/// of its shape, which is why `login_payload` is public: a test that grows a
/// bare `Vec` and reports on that measures itself.
///
/// **What this does not cover, named rather than implied.** It drives
/// `grown_without_leaving_a_copy`, which is the helper. It does not drive
/// `read_bounded`, which is the call site — so a `read_bounded` that stopped
/// calling the helper, or called it on the wrong branch, would leave this test
/// green. Two ways out of that: exercise `read_bounded` here, or say plainly
/// which one is covered.
///
/// This is the second. Driving `read_bounded` needs a `reqwest::Response`, so
/// an HTTP server, hyper's own buffering and reqwest's own copies — all of them
/// inside the window this file's allocator watcher is measuring. The canary
/// would then be counted in somebody else's freed buffers as readily as in
/// ours, and the test would fail for a cause we cannot fix, which is worse than
/// a test that says what it does not check.
#[test]
fn growing_the_response_buffer_leaves_nothing_in_freed_memory() {
    const RESERVE: usize = 32 * 1024;

    let (control, measured) = watched(|w| {
        // Prepared outside both windows: only the growth is under measurement.
        let chunk = {
            let mut c = vec![b'x'; 8192];
            c[..CANARY.len()].copy_from_slice(CANARY);
            c
        };

        // The control: a plain `Vec` that grows by reallocating, so a clean
        // result below means the buffer is wiped and not that the detector is
        // blind. Without this the whole test could pass by measuring nothing.
        let control = w.sightings_while(|| {
            let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(RESERVE));
            while buf.len() < RESERVE * 2 {
                buf.extend_from_slice(&chunk);
            }
            drop(buf);
        });

        // The shipped path.
        let measured = w.sightings_while(|| {
            let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(RESERVE));
            while buf.len() < RESERVE * 2 {
                buf = grown_without_leaving_a_copy(buf, chunk.len());
                buf.extend_from_slice(&chunk);
            }
            drop(buf);
        });

        (control, measured)
    });

    println!("growing a bare Vec left {control}; growing through the reader left {measured}");
    assert!(
        control > 0,
        "the detector saw nothing even from an unwiped buffer, so a clean \
         result here would mean nothing"
    );
    assert_eq!(
        measured, 0,
        "the reader left {measured} copies of a credential in freed memory"
    );
}

fn the_primitives(w: &Watcher) {
    let canary = std::str::from_utf8(CANARY).unwrap();
    let contents = format!("{canary}\n");
    // Removed when `tmp` drops at the end of this function. These were
    // `wg-zeroize-<pid>` in the system temp directory: one name per run of the
    // test, left behind by a crash, and holding the canary this file exists to
    // hunt for in memory.
    let tmp = tempfile::tempdir().expect("could not create a temporary directory");
    let path = tmp.path().join("credential");
    std::fs::write(&path, &contents).unwrap();
    let size = std::fs::metadata(&path).unwrap().len() as usize;
    let source = CANARY.to_vec();

    // A service account token is a few kilobytes, and a signed AWS header set
    // larger still. Size is the whole question here: a buffer only leaks the
    // sizes it outgrew, and for a payload that fits the first allocation there
    // is nothing to outgrow.
    let big_secret = format!("{}{}", "x".repeat(4096), canary);
    let big_path = tmp.path().join("credential-big");
    std::fs::write(&big_path, &big_secret).unwrap();

    let read_to_string = w.sightings_while(|| {
        drop(Zeroizing::new(std::fs::read_to_string(&path).unwrap()));
    });

    let sized_read = w.sightings_while(|| {
        let mut raw = Zeroizing::new(Vec::<u8>::with_capacity(size + 1));
        std::io::Read::read_to_end(&mut std::fs::File::open(&path).unwrap(), &mut raw).unwrap();
        drop(raw);
    });

    let grown_payload = w.sightings_while(|| {
        let secret = Zeroizing::new(String::from_utf8(source.clone()).unwrap());
        drop(Zeroizing::new(
            serde_json::to_string(&AppRoleLogin {
                role_id: "r",
                secret_id: &secret,
            })
            .unwrap(),
        ));
        drop(secret);
    });

    // The real function, not the pattern rewritten beside it. A test that
    // rebuilds the safe shape inline stays green when the shipped one is
    // reverted, which is the regression it exists to catch — and for two
    // rounds this file did exactly that while its own comments said otherwise.
    let sized_payload = w.sightings_while(|| {
        let secret = Zeroizing::new(String::from_utf8(source.clone()).unwrap());
        drop(
            login_payload(&AppRoleLogin {
                role_id: "r",
                secret_id: &secret,
            })
            .unwrap(),
        );
        drop(secret);
    });

    let big_read = w.sightings_while(|| {
        drop(Zeroizing::new(std::fs::read_to_string(&big_path).unwrap()));
    });

    let big_grown_payload = w.sightings_while(|| {
        let secret = Zeroizing::new(big_secret.clone());
        drop(Zeroizing::new(
            serde_json::to_string(&AppRoleLogin {
                role_id: "r",
                secret_id: &secret,
            })
            .unwrap(),
        ));
        drop(secret);
    });

    let big_sized_payload = w.sightings_while(|| {
        let secret = Zeroizing::new(big_secret.clone());
        drop(
            login_payload(&AppRoleLogin {
                role_id: "r",
                secret_id: &secret,
            })
            .unwrap(),
        );
        drop(secret);
    });

    println!(
        "small: read_to_string {read_to_string}, sized_read {sized_read}, \
grown_payload {grown_payload}, sized_payload {sized_payload}\n\
large: read {big_read}, grown_payload {big_grown_payload}, sized_payload {big_sized_payload}"
    );

    // A buffer that grows leaves behind every size it outgrew.
    assert!(
        big_grown_payload > 0,
        "a growing serialisation buffer no longer leaks"
    );
    // One allocation, made at the size it needs, does not.
    assert_eq!(
        sized_read, 0,
        "reading into a sized buffer leaked {sized_read}"
    );
    assert_eq!(sized_payload, 0, "the sized payload leaked {sized_payload}");
    assert_eq!(
        big_sized_payload, 0,
        "the sized payload leaked {big_sized_payload}"
    );
}
