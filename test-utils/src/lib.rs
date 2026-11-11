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

struct PaintedStack {
	base: *mut u8,
	layout: Layout,
}

impl PaintedStack {
	fn new(stack_bytes: usize) -> Self {
		let layout = Layout::from_size_align(stack_bytes, ALIGN).unwrap();
		let base = unsafe { alloc(layout) };
		assert!(!base.is_null(), "probe stack allocation failed");
		Self { base, layout }
	}

	fn run<F: FnOnce()>(&mut self, f: F) -> &[u8] {
		unsafe {
			std::ptr::write_bytes(self.base, PAINT, self.layout.size());
			psm::on_stack(self.base, self.layout.size(), f);
			std::slice::from_raw_parts(self.base, self.layout.size())
		}
	}
}

impl Drop for PaintedStack {
	fn drop(&mut self) {
		unsafe { dealloc(self.base, self.layout) }
	}
}

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
	let mut stack = PaintedStack::new(stack_bytes);
	let region = stack.run(f);
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
	found
}

struct ResidueProbe<'a, T> {
	stack: PaintedStack,
	input: &'a mut T,
	set: &'a mut dyn FnMut(&mut T, usize),
	op: &'a mut dyn FnMut(&mut T),
	run: usize,
	snapshots: [Vec<u8>; 2],
}

// Both runs go through this one call site with every run-specific value behind
// `probe`, so the callee-saved registers that deeper frames spill are the same
// in both runs and only input-dependent data can differ.
#[inline(never)]
fn residue_run<T>(probe: &mut ResidueProbe<T>) {
	(probe.set)(probe.input, unsafe { std::ptr::read_volatile(&probe.run) });
	let (op, input) = (&mut *probe.op, &mut *probe.input);
	let region = probe.stack.run(|| op(input));
	let run = unsafe { std::ptr::read_volatile(&probe.run) };
	probe.snapshots[run].copy_from_slice(region);
	probe.run = run + 1;
}

/// Run `op(input)` twice on the same repainted stack of `stack_bytes`, calling
/// `set(input, run)` before each run, and return how many stack bytes differ
/// between the two runs. When the two inputs differ only in secret values,
/// every differing byte is secret-dependent data `op` left in dead stack
/// memory, whatever its representation.
pub fn stack_residue_diff<T>(
	stack_bytes: usize,
	input: &mut T,
	mut set: impl FnMut(&mut T, usize),
	mut op: impl FnMut(&mut T),
) -> usize {
	let mut probe = ResidueProbe {
		stack: PaintedStack::new(stack_bytes),
		input,
		set: &mut set,
		op: &mut op,
		run: 0,
		snapshots: [vec![0; stack_bytes], vec![0; stack_bytes]],
	};
	residue_run(&mut probe);
	residue_run(&mut probe);
	let [first, second] = &probe.snapshots;
	let differing: Vec<usize> = (0..stack_bytes).filter(|&i| first[i] != second[i]).collect();
	if let (Some(lowest), Some(highest)) = (differing.first(), differing.last()) {
		eprintln!(
			"probe: {} stack bytes differ, {} to {} bytes below the stack top",
			differing.len(),
			stack_bytes - highest,
			stack_bytes - lowest
		);
	}
	differing.len()
}
