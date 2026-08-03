//! Shared helpers for painted-stack zeroization probes.
//!
//! Run an operation on a sentinel-painted stack buffer via `psm::on_stack`,
//! then scan the buffer for secret patterns. Used by the
//! `*_stack_zeroization` integration tests across dilithium, hdwallet, and
//! threshold. Unit-test probes that cannot take a `dev-dependency` keep a
//! local copy.

use std::alloc::{alloc, dealloc, Layout};

const PAINT: u8 = 0xAA;
const ALIGN: usize = 4096;

/// Run `f` on a freshly painted stack of `stack_bytes`, then scan for
/// `pattern`. Returns whether any match was found (and eprints offsets).
pub fn probe_stack_for<F: FnOnce()>(stack_bytes: usize, pattern: &[u8], f: F) -> bool {
	!probe_stack_for_named(stack_bytes, &[("pattern", pattern)], f).is_empty()
}

/// Like [`probe_stack_for`], but scans for several named patterns and returns
/// the names of those found.
pub fn probe_stack_for_named<F: FnOnce()>(
	stack_bytes: usize,
	patterns: &[(&str, &[u8])],
	f: F,
) -> Vec<String> {
	let layout = Layout::from_size_align(stack_bytes, ALIGN).unwrap();
	unsafe {
		let base = alloc(layout);
		assert!(!base.is_null(), "probe stack allocation failed");
		std::ptr::write_bytes(base, PAINT, stack_bytes);

		psm::on_stack(base, stack_bytes, f);

		let region = std::slice::from_raw_parts(base, stack_bytes);
		let mut found = Vec::new();
		for (name, pattern) in patterns {
			let offsets: Vec<usize> = region
				.windows(pattern.len())
				.enumerate()
				.filter(|(_, w)| w == pattern)
				.map(|(i, _)| i)
				.collect();
			if !offsets.is_empty() {
				eprintln!("probe: pattern {name:?} found at offsets {offsets:?}");
				found.push((*name).to_string());
			}
		}
		dealloc(base, layout);
		found
	}
}
