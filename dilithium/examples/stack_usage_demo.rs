//! Stack Usage Demonstration for ML-DSA 87
//!
//! This example demonstrates that the current ML-DSA implementations
//! work with very small stack sizes, making them suitable for embedded
//! systems, blockchain VMs, and other constrained environments.

use qp_rusty_crystals_dilithium::ml_dsa_87;
use std::{panic, sync::mpsc, thread, time::Duration};

use rand::Rng;

fn get_random_bytes() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    bytes
}


/// Test ML-DSA key generation with a specific stack size
fn test_keygen_with_stack_size<T>(stack_kb: usize, variant_name: &str, keygen_fn: T) -> bool
where
	T: FnOnce() -> bool + Send + 'static,
{
	let stack_bytes = stack_kb * 1024;
	let (tx, rx) = mpsc::channel();

	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let tx_clone = tx.clone();
		let handle = thread::Builder::new()
			.name(format!("{}-keygen-{}kb", variant_name, stack_kb))
			.stack_size(stack_bytes)
			.spawn(move || {
				let result = panic::catch_unwind(panic::AssertUnwindSafe(keygen_fn));
				let _ = tx_clone.send(result.is_ok() && result.unwrap_or(false));
			});

		match handle {
			Ok(thread_handle) => {
				// Wait for result with timeout
				match rx.recv_timeout(Duration::from_secs(1)) {
					Ok(success) => {
						let _ = thread_handle.join();
						success
					},
					Err(_) => {
						// Timeout or channel error - likely stack overflow
						false
					},
				}
			},
			Err(_) => false, // Failed to spawn thread
		}
	}));

	result.unwrap_or(false)
}

/// Test ML-DSA signing with a specific stack size
fn test_sign_with_stack_size<T>(stack_kb: usize, variant_name: &str, sign_fn: T) -> bool
where
	T: FnOnce() -> bool + Send + 'static,
{
	let stack_bytes = stack_kb * 1024;
	let (tx, rx) = mpsc::channel();

	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let tx_clone = tx.clone();
		let handle = thread::Builder::new()
			.name(format!("{}-sign-{}kb", variant_name, stack_kb))
			.stack_size(stack_bytes)
			.spawn(move || {
				let result = panic::catch_unwind(panic::AssertUnwindSafe(sign_fn));
				let _ = tx_clone.send(result.is_ok() && result.unwrap_or(false));
			});

		match handle {
			Ok(thread_handle) => {
				// Wait for result with timeout
				match rx.recv_timeout(Duration::from_secs(1)) {
					Ok(success) => {
						let _ = thread_handle.join();
						success
					},
					Err(_) => {
						// Timeout or channel error - likely stack overflow
						false
					},
				}
			},
			Err(_) => false, // Failed to spawn thread
		}
	}));

	result.unwrap_or(false)
}

/// Test ML-DSA verification with a specific stack size
fn test_verify_with_stack_size<T>(stack_kb: usize, variant_name: &str, verify_fn: T) -> bool
where
	T: FnOnce() -> bool + Send + 'static,
{
	let stack_bytes = stack_kb * 1024;
	let (tx, rx) = mpsc::channel();

	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let tx_clone = tx.clone();
		let handle = thread::Builder::new()
			.name(format!("{}-verify-{}kb", variant_name, stack_kb))
			.stack_size(stack_bytes)
			.spawn(move || {
				let result = panic::catch_unwind(panic::AssertUnwindSafe(verify_fn));
				let _ = tx_clone.send(result.is_ok() && result.unwrap_or(false));
			});

		match handle {
			Ok(thread_handle) => {
				// Wait for result with timeout
				match rx.recv_timeout(Duration::from_secs(1)) {
					Ok(success) => {
						let _ = thread_handle.join();
						success
					},
					Err(_) => {
						// Timeout or channel error - likely stack overflow
						false
					},
				}
			},
			Err(_) => false, // Failed to spawn thread
		}
	}));

	result.unwrap_or(false)
}

fn main() {
	println!("=== ML-DSA Stack Usage Analysis ===\n");

	// Pre-generate test data for all variants
	let entropy = get_random_bytes();
	let ml87_keypair = ml_dsa_87::Keypair::generate(&entropy);

	let test_msg = b"stack usage test message";

	let ml87_sig = ml87_keypair.sign(test_msg, None, None);

	// Test with progressively smaller stack sizes
	let stack_sizes = [
		512, // 512KB - should definitely work
		256, // 256KB - typical small embedded system
		200, 160, 150, 140, 128, // 128KB - typical small embedded system
		100, 88, 64, // 64KB - large microcontroller
		50, 40, 36, 34, 33, 32, // 32KB - medium microcontroller
		16, // 16KB - small microcontroller
	];

	println!(
		"{:>17} | {:>17} | {:>15} | {:>17}",
		"Stack Size", "ML-DSA-87 KeyGen", "ML-DSA-87 Sign", "ML-DSA-87 Verify"
	);
	println!("{:->17}-+-{:->17}-+-{:->15}-+-{:->17}", "", "", "", "");

	let mut min_sizes = [None; 3]; // [ml87_keygen, ml87_sign, ml87_verify]

	for &size_kb in &stack_sizes {
		// Test ML-DSA-87
		let ml87_keygen = test_keygen_with_stack_size(size_kb, "ml-dsa-87", move || {
			let _kp = ml_dsa_87::Keypair::generate(&[1u8; 32]);
			true
		});

		let ml87_keypair_clone = ml87_keypair.clone();
		let ml87_sign = test_sign_with_stack_size(size_kb, "ml-dsa-87", move || {
			let _sig = ml87_keypair_clone.sign(test_msg, None, None);
			true
		});

		let ml87_keypair_clone2 = ml87_keypair.clone();
		let ml87_sig_clone = ml87_sig;
		let ml87_verify = test_verify_with_stack_size(size_kb, "ml-dsa-87", move || {
			ml87_keypair_clone2.verify(test_msg, &ml87_sig_clone, None)
		});

		println!(
			"{:>17} | {:>17} | {:>15} | {:>17}",
			format!("{} KB", size_kb),
			if ml87_keygen { "✅ Works" } else { "❌ Fails" },
			if ml87_sign { "✅ Works" } else { "❌ Fails" },
			if ml87_verify { "✅ Works" } else { "❌ Fails" }
		);

		// Track minimum working stack sizes
		let results = [ml87_keygen, ml87_sign, ml87_verify];
		for (i, &works) in results.iter().enumerate() {
			if works {
				min_sizes[i] = Some(size_kb);
			}
		}
	}

	println!("\n=== Results ===");

	let operation_names =
		["ML-DSA-87 Key Generation", "ML-DSA-87 Signing", "ML-DSA-87 Verification"];

	println!("Minimum stack requirements:");
	for (i, &min_size) in min_sizes.iter().enumerate() {
		println!(
			"• {}: {}KB",
			operation_names[i],
			min_size.map_or("Unknown".to_string(), |kb| format!("≤{}", kb))
		);
	}

	let min_overall = min_sizes.iter().filter_map(|&x| x).max().unwrap_or(128);

	println!("\nOverall minimum stack requirement: ≤{}KB", min_overall);

	if min_overall <= 8 {
		println!(
			"🎯 All ML-DSA variants work with ≤8KB stack - excellent for constrained environments!"
		);
	} else if min_overall <= 32 {
		println!(
			"✅ All ML-DSA variants work with ≤{}KB stack - suitable for embedded systems",
			min_overall
		);
	} else {
		println!("⚠️  ML-DSA variants require ≤{}KB stack", min_overall);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_all_variants_4kb_stack() {
		assert!(
			test_keygen_with_stack_size(4, "ml-dsa-87", || {
				let _kp = ml_dsa_87::Keypair::generate(Some(&[1u8; 32]));
				true
			}),
			"ML-DSA-87 key generation should work with 4KB stack"
		);
	}
}
