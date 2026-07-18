//! Reliable peak-stack measurement for ML-DSA-87 keygen / sign / verify.
//!
//! Thread-stack-size probing (see `stack_usage_demo`) is unreliable: the OS rounds requested
//! thread stacks up and small overruns don't always fault, so it under-reports. This probe
//! instead paints a dedicated stack buffer with a sentinel byte, runs the operation on it via
//! `psm::on_stack`, then scans for the high-water mark. The number reported is the actual peak
//! stack the routine touched on the host architecture.
//!
//! Run: `cargo run --release --example stack_probe -p qp-rusty-crystals-dilithium`

use qp_rusty_crystals_dilithium::ml_dsa_87;
use std::alloc::{alloc, dealloc, Layout};

const PAINT: u8 = 0xAA;
const STACK_BYTES: usize = 1024 * 1024; // 1 MiB scratch, far above any expected usage
const ALIGN: usize = 4096;

/// Run `f` on a freshly painted stack and return its peak stack usage in bytes.
fn peak_stack<F: FnOnce()>(f: F) -> usize {
	let layout = Layout::from_size_align(STACK_BYTES, ALIGN).unwrap();
	unsafe {
		let base = alloc(layout);
		assert!(!base.is_null(), "stack allocation failed");
		std::ptr::write_bytes(base, PAINT, STACK_BYTES);

		psm::on_stack(base, STACK_BYTES, f);

		let region = std::slice::from_raw_parts(base, STACK_BYTES);
		let used = match psm::StackDirection::new() {
			// Grows toward lower addresses: untouched sentinel bytes remain at the low end.
			psm::StackDirection::Descending =>
				STACK_BYTES - region.iter().take_while(|&&b| b == PAINT).count(),
			// Grows toward higher addresses: untouched sentinel bytes remain at the high end.
			psm::StackDirection::Ascending =>
				STACK_BYTES - region.iter().rev().take_while(|&&b| b == PAINT).count(),
		};
		dealloc(base, layout);
		used
	}
}

fn kb(bytes: usize) -> String {
	format!("{:.1} KB", bytes as f64 / 1024.0)
}

fn main() {
	// Prepare inputs on the normal stack.
	let kp = ml_dsa_87::Keypair::generate((&mut [7u8; 32]).into());
	let kp_bytes = kp.to_bytes();
	let msg: &[u8] = b"stack probe message";
	let sig = kp.sign(msg, None, None).expect("sign");

	let keygen = peak_stack(|| {
		let _ = ml_dsa_87::Keypair::generate((&mut [1u8; 32]).into());
	});

	let sign = peak_stack(move || {
		let kp = ml_dsa_87::Keypair::from_bytes(&kp_bytes).expect("from_bytes");
		let _ = kp.sign(msg, None, None);
	});

	let verify = peak_stack(move || {
		let kp = ml_dsa_87::Keypair::from_bytes(&kp_bytes).expect("from_bytes");
		let _ = kp.verify(msg, &sig, None);
	});

	println!(
		"=== ML-DSA-87 peak stack (painted-stack probe, host arch: {}) ===",
		std::env::consts::ARCH
	);
	println!("  keygen: {}", kb(keygen));
	println!("  sign  : {}", kb(sign));
	println!("  verify: {}", kb(verify));
	println!("  worst : {}", kb(keygen.max(sign).max(verify)));
}
