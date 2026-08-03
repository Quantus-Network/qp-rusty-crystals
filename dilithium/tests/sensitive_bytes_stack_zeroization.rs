//! Regression test (security review): the `SensitiveBytes{32,64}`
//! constructors must not leave a plaintext copy of the input secret in dead
//! stack memory.
//!
//! `new`/`from` were written as `Self(*bytes)` followed by `bytes.zeroize()`.
//! Because `[u8; N]` is `Copy`, the `*bytes` expression can materialize a
//! by-value temporary that is not owned by the returned wrapper, so the
//! wrapper's `ZeroizeOnDrop` never reaches it and the source wipe does not
//! cover it — its survival depends purely on whether codegen elides the copy.
//!
//! Detection uses the same painted-stack technique as the crate's other
//! stack probes: run the constructor on a sentinel-painted buffer via
//! `psm::on_stack`, then scan the buffer — which we own, so the read is sound
//! — for the input pattern. The source array lives outside the probe (the
//! closure captures it by `&mut`, so the harness never copies the pattern
//! onto the probed stack itself), and the returned wrapper is wiped in place
//! through `as_mut_bytes`. Any surviving match is a copy the constructor
//! failed to clean up.
//!
//! Only compiled for optimized builds (`cargo test --release`): unoptimized
//! codegen materializes additional move temporaries that no source-level fix
//! can wipe.
#![cfg(not(debug_assertions))]

use std::alloc::{alloc, dealloc, Layout};

use qp_rusty_crystals_dilithium::{SensitiveBytes32, SensitiveBytes64};
use zeroize::Zeroize;

const PAINT: u8 = 0xAA;
const STACK_BYTES: usize = 1024 * 1024;
const ALIGN: usize = 4096;

const PATTERN32: [u8; 32] = *b"sensitive-bytes-32-stack-pattern";
const PATTERN64: [u8; 64] = *b"sensitive-bytes-64-stack-residue-probe-pattern-unique-abcdefghij";

/// Run `f` on a freshly painted stack buffer, then scan the buffer for
/// `pattern` and return whether it was found.
fn probe_stack_for<F: FnOnce()>(pattern: &[u8], f: F) -> bool {
	let layout = Layout::from_size_align(STACK_BYTES, ALIGN).unwrap();
	unsafe {
		let base = alloc(layout);
		assert!(!base.is_null(), "probe stack allocation failed");
		std::ptr::write_bytes(base, PAINT, STACK_BYTES);

		psm::on_stack(base, STACK_BYTES, f);

		let region = std::slice::from_raw_parts(base, STACK_BYTES);
		let offsets: Vec<usize> = region
			.windows(pattern.len())
			.enumerate()
			.filter(|(_, w)| *w == pattern)
			.map(|(i, _)| i)
			.collect();
		eprintln!("probe: {} match(es) at offsets {:?}", offsets.len(), offsets);
		let found = !offsets.is_empty();
		dealloc(base, layout);
		found
	}
}

#[test]
fn sensitive_bytes_constructors_leave_no_secret_copies_on_the_stack() {
	// Sanity: the technique detects an unwiped copy.
	assert!(
		probe_stack_for(&PATTERN32, || {
			let leaked = PATTERN32;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// The source arrays live here, outside the probe; the closures capture
	// them by `&mut`, so the harness never places the pattern on the probed
	// stack. Each constructor zeroizes its source, so refill before reuse.
	let mut src32 = PATTERN32;
	let new32_leaked = probe_stack_for(&PATTERN32, || {
		let mut w = SensitiveBytes32::new(&mut src32);
		w.as_mut_bytes().zeroize();
		core::hint::black_box(&w);
	});

	let mut src32 = PATTERN32;
	let from32_leaked = probe_stack_for(&PATTERN32, || {
		let mut w = SensitiveBytes32::from(&mut src32);
		w.as_mut_bytes().zeroize();
		core::hint::black_box(&w);
	});

	let mut src64 = PATTERN64;
	let new64_leaked = probe_stack_for(&PATTERN64, || {
		let mut w = SensitiveBytes64::new(&mut src64);
		w.as_mut_bytes().zeroize();
		core::hint::black_box(&w);
	});

	let mut src64 = PATTERN64;
	let from64_leaked = probe_stack_for(&PATTERN64, || {
		let mut w = SensitiveBytes64::from(&mut src64);
		w.as_mut_bytes().zeroize();
		core::hint::black_box(&w);
	});

	assert!(!new32_leaked, "SensitiveBytes32::new left the secret in stack memory");
	assert!(!from32_leaked, "SensitiveBytes32::from left the secret in stack memory");
	assert!(!new64_leaked, "SensitiveBytes64::new left the secret in stack memory");
	assert!(!from64_leaked, "SensitiveBytes64::from left the secret in stack memory");
}
