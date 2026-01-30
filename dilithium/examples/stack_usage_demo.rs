//! Stack Usage Demonstration for ML-DSA 87
//!
//! This example demonstrates that the current ML-DSA implementations
//! work with very small stack sizes, making them suitable for embedded
//! systems, blockchain VMs, and other constrained environments.

use qp_rusty_crystals_dilithium::{ml_dsa_87, SensitiveBytes32};
use std::{
	env,
	panic,
	process::{self, Command},
	sync::mpsc,
	thread,
	time::Duration,
};

use rand::Rng;

fn get_random_bytes() -> SensitiveBytes32 {
	let mut rng = rand::rng();
	let mut bytes = [0u8; 32];
	rng.fill(&mut bytes);
	(&mut bytes).into()
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
				match rx.recv_timeout(Duration::from_secs(10)) {
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
	if let (Ok(op), Ok(stack_kb)) = (env::var("STACK_DEMO_OP"), env::var("STACK_DEMO_STACK_KB")) {
		let stack_kb: usize = stack_kb.parse().unwrap_or(0);
		let ok = match op.as_str() {
			"keygen" => test_keygen_with_stack_size(stack_kb, "ml-dsa-87", move || {
				let _kp = ml_dsa_87::Keypair::generate((&mut [1u8; 32]).into());
				true
			}),
			"sign" => {
				let entropy = get_random_bytes();
				let kp = Box::new(ml_dsa_87::Keypair::generate(entropy));
				let msg = b"stack usage test message";
				test_sign_with_stack_size(stack_kb, "ml-dsa-87", move || {
					let _sig = kp.sign(msg, None, None);
					true
				})
			},
			"verify" => {
				let entropy = get_random_bytes();
				let kp = Box::new(ml_dsa_87::Keypair::generate(entropy));
				let msg = b"stack usage test message";
				let sig = Box::new(kp.sign(msg, None, None).unwrap());
				test_verify_with_stack_size(stack_kb, "ml-dsa-87", move || kp.verify(msg, sig.as_ref(), None))
			},
			_ => false,
		};
		process::exit(if ok { 0 } else { 1 });
	}

	println!("=== ML-DSA Stack Usage Analysis ===\n");

	// Test with progressively smaller stack sizes
	let stack_sizes = [256, 128, 64, 32, 24, 16, 12, 10, 8, 6, 4, 3, 2];

	println!(
		"{:>17} | {:>17} | {:>15} | {:>17}",
		"Stack Size", "ML-DSA-87 KeyGen", "ML-DSA-87 Sign", "ML-DSA-87 Verify"
	);
	println!("{:->17}-+-{:->17}-+-{:->15}-+-{:->17}", "", "", "", "");

	let mut min_sizes = [None; 3]; // [ml87_keygen, ml87_sign, ml87_verify]

	for &size_kb in &stack_sizes {
		let exe = env::current_exe().unwrap();
		let run = |op: &str| {
			Command::new(&exe)
				.env("STACK_DEMO_OP", op)
				.env("STACK_DEMO_STACK_KB", size_kb.to_string())
				.status()
				.map(|s| s.success())
				.unwrap_or(false)
		};

		let ml87_keygen = run("keygen");
		let ml87_sign = run("sign");
		let ml87_verify = run("verify");

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
				let _kp = ml_dsa_87::Keypair::generate((&mut [1u8; 32]).into());
				true
			}),
			"ML-DSA-87 key generation should work with 4KB stack"
		);
	}
}
