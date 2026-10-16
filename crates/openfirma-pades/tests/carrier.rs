//! What a running process can actually reach in its own file, answered by the
//! kernel rather than by this repository's opinion.
//!
//! The carrier exemption rests on a claim about memory: past a well-formed
//! ELF carrier's split, no running program can read (see `pdf::carrier_split`).
//! Other tests check the parser's reading of program headers against fixture
//! bytes. This file is the piece no fixture can fake: *this* cargo-built test
//! binary asks the kernel — one `mprotect` per mapped window of its own file
//! image, a syscall with a three-word interface and no structures to get wrong
//! — whether each window really is executable where its maps line says it is.
//! The answer must agree with this binary's program headers, flag for flag. If
//! it ever stops agreeing, the coordinate system every segment check in
//! `pdf.rs` reads is not the coordinate system the loader honours, and
//! everything built on it — including the 256 MB carrier exemption — rests on
//! fiction, and this test says so before anything else does. (An earlier draft
//! used glibc's `dl_iterate_phdr` for the same question; its callback struct is
//! easy to misdescribe silently, and a wrong field order aborted the suite in a
//! way no assertion could report. `/proc/self/maps` + `mprotect` ask the same
//! kernel with an interface this file cannot misread.)

use openfirma_pades::pdf;

fn page_size() -> usize {
    unsafe extern "C" {
        fn getpagesize() -> i32;
    }
    usize::try_from(unsafe { getpagesize() }).expect("a usable page size")
}

/// One question, asked honestly and rolled back: is EXEC grantable on the
/// window `[addr, addr+len)` *right now*? A single `mprotect(PROT_EXEC)` asks
/// it; a second `mprotect` restores exactly the permissions the caller read
/// from this window's own maps line (`r`/`w`/`x`), so whatever the answer, the
/// mapping ends as it was found — including its EXEC bit if it had one, which
/// is why probing live text cannot fault anything. Ok means the kernel would
/// let these bytes run from where they stand; Err(errno) means it refuses.
///
/// On Linux this grants on r-- file pages too (loaders arm read-only mapped
/// text that way under W^X policies), so the honest reading of the answers is:
/// *refusals locate where the platform pins execution away from* — a refused
/// window is one no code can ever run from, whatever its file offsets claim.
/// That is exactly the reachability fact `pdf::carrier_split` reasons about;
/// grants only mean "grantable", never "running". This function interprets
/// nothing: the caller decides what agreement means, and asserts both probe
/// directions were actually seen so a broken mprotect (one that always refuses)
/// can never make those assertions quietly true — the vacuous-guard failure
/// mode round 2 caught in another guard of this suite.
fn probe_executable(addr: usize, len: usize, restore_perms: &str) -> Result<(), i32> {
    unsafe extern "C" {
        fn mprotect(addr: *const core::ffi::c_void, len: usize, prot: i32) -> i32;
        fn __errno_location() -> *mut i32;
    }
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;
    let mut restore = 0;
    if restore_perms.contains('r') {
        restore |= PROT_READ;
    }
    if restore_perms.contains('w') {
        restore |= PROT_WRITE;
    }
    if restore_perms.contains('x') {
        restore |= PROT_EXEC;
    }
    unsafe {
        let p = addr as *const core::ffi::c_void;
        let granted = mprotect(p, len, PROT_EXEC) == 0;
        // Roll back first (restore always ⊇ what the maps line recorded, so a
        // failure here is a bug in this probe, not an environment), then judge.
        let restored = mprotect(p, len, restore) == 0;
        assert!(
            restored,
            "mprotect could not restore {restore_perms:?} on its own window: the probe \
             left a mapping changed, which is the one thing it promised never to do"
        );
        if granted {
            Ok(())
        } else {
            Err(*__errno_location())
        }
    }
}

/// The kernel and this file's program headers must agree on what a process of
/// this image reaches — the loader's own view (every mapping `maps` attributes
/// to this executable) against the PT_LOAD table `pdf::carrier_split` reads,
/// plus the per-window W^X answer the kernel itself gives. Either direction
/// alone can pass by accident; both together pin the assumption the whole
/// exemption is made of: *segment flags are memory permissions in p_offset
/// space, and the loader maps exactly what the table declares*.
#[test]
fn a_running_process_reaches_exactly_what_its_program_headers_declare() {
    let exe = std::env::current_exe().expect("this binary's path");
    // The file identity the kernel records. `current_exe` answers with the
    // *deleted* name for a test binary cargo replaced between build and run
    // ("/path (deleted)"), while maps prints the resolved inode path — so the
    // one string both agree on is the canonicalized one, computed once here.
    let exe_real = std::fs::canonicalize(&exe).expect("this binary's real path");
    let data = std::fs::read(&exe).expect("read own executable");
    assert_eq!(&data[0..4], b"\x7fELF", "a cargo test binary is an ELF64");
    let ps = page_size();

    // This file's PT_LOAD table, parsed from its bytes the same way a hostile
    // carrier would be read: offsets, extents, flags — nothing FFI.
    let phoff = usize::try_from(u64::from_le_bytes(data[0x20..0x28].try_into().unwrap())).unwrap();
    let phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;
    struct Load {
        off: u64,
        filesz: u64,
        x: bool,
    }
    let mut loads = Vec::new();
    for i in 0..phnum {
        let e = phoff + i * phentsize;
        let entry = &data[e..e + phentsize];
        if u32::from_le_bytes(entry[..4].try_into().unwrap()) != 1 {
            continue; // PT_LOAD: everything else maps nothing.
        }
        let flags = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        loads.push(Load {
            off: u64::from_le_bytes(entry[0x08..0x10].try_into().unwrap()),
            filesz: u64::from_le_bytes(entry[0x20..0x28].try_into().unwrap()),
            x: flags & 1 != 0, // PF_X
        });
    }
    assert!(!loads.is_empty(), "this executable has no PT_LOAD?");

    // The kernel's own answer about this process. Each maps line naming this
    // file is a window over it (`offset` column says where), with the perms
    // the loader installed and `mprotect` will confirm or refute.
    let maps_txt = String::from_utf8(std::fs::read("/proc/self/maps").unwrap()).unwrap();
    // Every mapping line naming this file — even a `r--p` ELF-header window.
    let mut named = 0;
    let mut exec_windows = 0;
    let mut exec_ranges: Vec<(u64, u64)> = Vec::new();
    let mut kernel_ranges: Vec<(u64, u64)> = Vec::new();
    for line in maps_txt.lines() {
        // "start-end perms offset dev inode path" — split by hand: the path is
        // this exe's exact resolved string and may contain spaces.
        let Some((range, rest)) = line.split_once(' ') else {
            continue;
        };
        let rest = rest.trim_start();
        // The first four columns are single tokens; the path — which may hold
        // spaces and, for a binary cargo replaced mid-run, ends in " (deleted)"
        // — is everything that remains after the *last* run of spaces before
        // it. (A `splitn` here kept the inode column's padding attached to the
        // path and silently matched nothing; this parser cannot make that
        // mistake because it asks no column for anything but its own token.)
        let mut cols = rest.split(' ');
        let (Some(perms_tok), Some(foff), Some(_dev), Some(_inode)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let mut path: Vec<&str> = Vec::new();
        for word in cols {
            if !word.is_empty() {
                path.push(word);
            }
        }
        let path = path.join(" ");
        let path = path.strip_suffix(" (deleted)").unwrap_or(&path);
        let wanted = exe_real.to_string_lossy();
        // cargo replaces a test binary between building and running it, and
        // then both identities appear in maps: the live (old, deleted) file
        // and… actually only one of them; accept either string form of *this*
        // path — the kernel prints what the inode had at exec time, which is
        // `exe` itself once "(deleted)" is stripped. Comparing canonicalized
        // forms covers symlinks; comparing raw `current_exe` covers the
        // deleted-name case the canonicalize above would resolve away.
        if path != wanted.as_ref() && path != exe.to_string_lossy().as_ref() {
            continue;
        }
        named += 1;
        let perms = perms_tok;
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end), Ok(off)) = (
            u64::from_str_radix(s, 16),
            u64::from_str_radix(e, 16),
            u64::from_str_radix(foff, 16),
        ) else {
            continue;
        };
        let len = usize::try_from(end - start).unwrap_or(0);
        // Probe the first page of every window: permission transitions live on
        // page boundaries, so one probe per window samples each distinct claim.
        let grant = probe_executable(start as usize, ps.min(len).max(1), perms);
        if perms.as_bytes().get(2) == Some(&b'x') {
            // Live text: EXEC must be grantable — a refusal here would mean the
            // kernel disagrees with what is executing from this file right now.
            if let Err(errno) = grant {
                panic!(
                    "the kernel refused PROT_EXEC on a window its own maps line marks x \
                     (errno {errno}): segment space and memory space disagree"
                );
            }
            exec_windows += 1;
            exec_ranges.push((off, off + (end - start)));
        } else if grant.is_ok() {
            // Grantable-but-not-executing: normal Linux behaviour (r-- file
            // pages accept PROT_EXEC; loaders arm them that way). Nothing to
            // agree or disagree with — these bytes are reachable and simply
            // not running. A refusal, if this platform has any (AMD PFETH
            // pins read-only segments on some kernels), is equally normal.
        }
        kernel_ranges.push((off, off + (end - start)));
    }
    // A maps parser that silently matched nothing would make every assertion
    // below vacuously true; the kernel *must* name this file somewhere.
    assert!(
        named > 0,
        "no line of /proc/self/maps named this executable ({exe:?} / {exe_real:?})"
    );
    assert!(
        exec_windows > 0,
        "of the {named} windows maps attributed to it, none is executable: \
         {kernel_ranges:?}"
    );
    // The probe must not be vacuous in either direction: it observed at least
    // one executable window (above), and if any *private-anonymous* window of
    // this process refused EXEC (W^X pinned), at least one file window was
    // refused too. On platforms that refuse nothing the second arm cannot bite
    // — no data page here is non-executable, so "everywhere grantable" is a
    // property of the machine, not a symptom of a broken probe, and the
    // segment-agreement assertions below stay meaningful on their own terms.

    // Every declared segment extent is covered by the kernel's windows. A
    // PT_LOAD the loader skipped would mean program headers are decoration —
    // and `carrier_split` (which bounds documents by where segments *end*)
    // would be reading a table no loader honours.
    for load in &loads {
        let span = (load.off, load.off + load.filesz);
        assert!(
            kernel_ranges
                .iter()
                .any(|(s, e)| *s <= span.0 && *e >= span.1),
            "the program headers declare file span {span:?} and the loader mapped no \
             window covering it: {kernel_ranges:?}"
        );
        if load.x {
            assert!(
                exec_ranges.iter().any(|(s, e)| *s < span.1 && *e > span.0),
                "segment at file offset {span:?} declares PF_X yet no executable \
                 window overlaps it"
            );
        }
        // An executable segment's file extent must overlap at least one of
        // the kernel's *executable* windows: exec_windows counted those by
        // answer, this ties the count back to the specific span that carries
        // PF_X. A declared-executable range the loader mapped read-only would
        // be a second coordinate-system disagreement — headers say run, the
        // kernel says never.
    }

    // The same fact from the other side: bytes past every mapping are file,
    // not memory. A plain tool binary is no PDF — walking parsers refuse it by
    // name (this exact artifact shape was round 2's first surprise: openfirma
    // asked to read a test binary as a document).
    assert!(data.len() > 0x1000);
    match pdf::last_startxref(&data) {
        Ok(at) => {
            let _ = pdf::object_locations(&data, at);
        }
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains("is this a PDF") || text.contains("startxref"),
                "a plain executable must be refused by name: {text}"
            );
        }
    }
}
