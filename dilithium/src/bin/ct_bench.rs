//! Constant-time testing for Dilithium implementation using dudect-bencher
//!
//! This module tests that cryptographic operations in the Dilithium digital signature scheme
//! execute in constant time, preventing timing side-channel attacks.
//!
//! Tests are organized by fixed input sizes with statistically distinguishable input classes:
//! - Class A: Fixed pattern (all 0x00 or deterministic seed)
//! - Class B: Random data
//!
//! This ensures the two classes are distinguishable before timing analysis begins.

#[cfg(feature = "dudect-bencher")]
use dudect_bencher::rand::{Rng, RngCore};
#[cfg(feature = "dudect-bencher")]
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;

// Test message sizes in bytes
const SMALL_MSG_SIZE: usize = 32;
const MEDIUM_MSG_SIZE: usize = 256;
const LARGE_MSG_SIZE: usize = 1024;
const EXTRA_LARGE_MSG_SIZE: usize = 4096;

// Seed size for keypair generation
const SEED_SIZE: usize = 32;

/// Generate a fixed seed for Left class (same for all samples)
fn generate_fixed_seed(rng: &mut BenchRng) -> Vec<u8> {
	// Use a fixed pattern for Left class
	let byte = rng.gen::<u8>();
	vec![byte; SEED_SIZE]
}

/// Generate a random seed for Right class
fn generate_random_seed(rng: &mut BenchRng) -> Vec<u8> {
	let mut seed = vec![0u8; SEED_SIZE];
	rng.fill_bytes(&mut seed);
	seed
}

/// Generate a fixed message for Left class
fn generate_fixed_message(size: usize, rng: &mut BenchRng) -> Vec<u8> {
	let byte = rng.gen::<u8>();
	vec![byte; size]
}

/// Generate a random message for Right class
fn generate_random_message(size: usize, rng: &mut BenchRng) -> Vec<u8> {
	let mut message = vec![0u8; size];
	rng.fill_bytes(&mut message);
	message
}

/// Disrupt cache and microarchitectural state between samples
fn disrupt_cache(rng: &mut BenchRng) {
	// Large memory access to evict cache lines
	let dummy = vec![0u8; 8 * 1024 * 1024]; // 8MB
	let mut sum = 0u64;

	// Access every cache line (64 bytes) to force eviction
	for i in (0..dummy.len()).step_by(64) {
		sum = sum.wrapping_add(dummy[i] as u64);
	}

	// Random access pattern to disrupt prefetcher
	for _ in 0..50 {
		let idx = rng.gen_range(0..dummy.len());
		sum = sum.wrapping_add(dummy[idx] as u64);
	}

	// Memory barrier and dummy computation
	std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
	for i in 0..500 {
		sum = sum.wrapping_mul(i).wrapping_add(0xDEADBEEF);
	}

	// Prevent compiler optimization
	std::hint::black_box(sum);
}

/// Test keypair generation for constant time
#[cfg(feature = "dudect-bencher")]
fn test_keypair_generation_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running keypair generation constant-time test...");

	// Generate seeds and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed seed once for all Left class samples
	let fixed_seed = generate_fixed_seed(rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let seed = match class {
			Class::Left => fixed_seed.clone(),
			Class::Right => generate_random_seed(rng),
		};

		inputs.push(seed);
		classes.push(class);
	}

	for (class, seed) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _keypair = Keypair::generate(Some(&seed));
		});
	}
}

/// Test signing with small messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running small message signing constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(Some(&[0x42; SEED_SIZE]));

	// Generate messages and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all Left class samples
	let fixed_message = generate_fixed_message(SMALL_MSG_SIZE, rng);

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let message = match class {
			Class::Left => fixed_message.clone(),
			Class::Right => generate_random_message(SMALL_MSG_SIZE, rng),
		};

		inputs.push(message);
		classes.push(class);
	}

	for (class, message) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&message, None, false);
		});
	}
}

/// Test signing with medium messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running medium message signing constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(Some(&[0x42; SEED_SIZE]));

	// Generate messages and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all Left class samples
	let fixed_message = generate_fixed_message(MEDIUM_MSG_SIZE, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let message = match class {
			Class::Left => fixed_message.clone(),
			Class::Right => generate_random_message(MEDIUM_MSG_SIZE, rng),
		};

		inputs.push(message);
		classes.push(class);
	}

	for (class, message) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&message, None, false);
		});
	}
}

/// Test signing with large messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running large message signing constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(Some(&[0x42; SEED_SIZE]));

	// Generate messages and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all Left class samples
	let fixed_message = generate_fixed_message(LARGE_MSG_SIZE, rng);

	for _ in 0..3_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let message = match class {
			Class::Left => fixed_message.clone(),
			Class::Right => generate_random_message(LARGE_MSG_SIZE, rng),
		};

		inputs.push(message);
		classes.push(class);
	}

	for (class, message) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&message, None, false);
		});
	}
}

/// Test signing with extra large messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_xlarge_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running extra large message signing constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(Some(&[0x42; SEED_SIZE]));

	// Generate messages and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all Left class samples
	let fixed_message = generate_fixed_message(EXTRA_LARGE_MSG_SIZE, rng);

	for _ in 0..2_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let message = match class {
			Class::Left => fixed_message.clone(),
			Class::Right => generate_random_message(EXTRA_LARGE_MSG_SIZE, rng),
		};

		inputs.push(message);
		classes.push(class);
	}

	for (class, message) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&message, None, false);
		});
	}
}

/// Test hedged signing (randomized) with small messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_hedged_signing_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running hedged signing constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(Some(&[0x42; SEED_SIZE]));

	// Generate messages and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all Left class samples
	let fixed_message = generate_fixed_message(SMALL_MSG_SIZE, rng);

	for _ in 0..6_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let message = match class {
			Class::Left => fixed_message.clone(),
			Class::Right => generate_random_message(SMALL_MSG_SIZE, rng),
		};

		inputs.push(message);
		classes.push(class);
	}

	for (class, message) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&message, None, true); // hedged = true
		});
	}
}

/// Test signing with context strings for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_with_context_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running context signing constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(Some(&[0x42; SEED_SIZE]));

	// Generate messages and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message and context once for all Left class samples
	let fixed_message = generate_fixed_message(MEDIUM_MSG_SIZE, rng);
	let fixed_context = b"test_context_string_for_constant_time_testing".to_vec();

	for _ in 0..4_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let (message, context) = match class {
			Class::Left => (fixed_message.clone(), fixed_context.clone()),
			Class::Right => {
				let msg = generate_random_message(MEDIUM_MSG_SIZE, rng);
				let ctx_len = rng.gen_range(10..100);
				let mut ctx = vec![0u8; ctx_len];
				rng.fill_bytes(&mut ctx);
				(msg, ctx)
			},
		};

		inputs.push((message, context));
		classes.push(class);
	}

	for (class, (message, context)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&message, Some(&context), false);
		});
	}
}

/// Test edge cases with single-byte and small messages
#[cfg(feature = "dudect-bencher")]
fn test_edge_cases_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running edge cases constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(Some(&[0x42; SEED_SIZE]));

	// Generate messages and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	let fixed_byte = rng.gen::<u8>();

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let message = match class {
			Class::Left => vec![fixed_byte], // Single fixed byte
			Class::Right => {
				let len = rng.gen_range(1..4); // 1-3 bytes
				let mut msg = vec![0u8; len];
				rng.fill_bytes(&mut msg);
				msg
			},
		};

		inputs.push(message);
		classes.push(class);
	}

	for (class, message) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&message, None, false);
		});
	}
}

/// Test uniform_eta function for constant time
#[cfg(feature = "dudect-bencher")]
fn test_uniform_eta_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running uniform_eta constant-time test...");

	// Generate seeds and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Use fixed seed size matching CRHBYTES = 64 (what uniform_eta expects)
	let fixed_seed = [42u8; 64];

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let seed = match class {
			Class::Left => fixed_seed.to_vec(),
			Class::Right => {
				let mut random_seed = vec![0u8; 64];
				rng.fill_bytes(&mut random_seed);
				random_seed
			},
		};

		inputs.push(seed);
		classes.push(class);
	}

	for (class, seed) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut poly = qp_rusty_crystals_dilithium::poly::Poly::default();
			qp_rusty_crystals_dilithium::poly::lvl5::uniform_eta(&mut poly, &seed, 0);
		});
	}
}

/// Test rej_eta function for constant time with different buffer contents
#[cfg(feature = "dudect-bencher")]
fn test_rej_eta_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running rej_eta constant-time test...");

	// Generate buffers and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Buffer with many rejections (values >= 15)
	let reject_heavy_buf = vec![15u8; 168]; // Mostly rejections

	// Buffer with few rejections (values < 15)
	let mut accept_heavy_buf = vec![0u8; 168];
	for i in 0..168 {
		accept_heavy_buf[i] = (i % 15) as u8; // Values 0-14, all accepted
	}

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let buffer = match class {
			Class::Left => reject_heavy_buf.clone(), // Many rejections (slow case)
			Class::Right => accept_heavy_buf.clone(), // Few rejections (fast case)
		};
		
		inputs.push(buffer);
		classes.push(class);
	}

	for (class, buffer) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut coeffs = [0i32; 256];
			let _count = qp_rusty_crystals_dilithium::poly::lvl5::rej_eta(
				&mut coeffs,
				256,
				&buffer,
				buffer.len(),
			);
		});
	}
}

/// Test uniform_eta with different nonce values to check for timing differences
#[cfg(feature = "dudect-bencher")]
fn test_uniform_eta_nonce_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running uniform_eta nonce constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	let fixed_seed = [42u8; 64].to_vec();

	for _ in 0..6_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let nonce = match class {
			Class::Left => 0u16,              // Fixed nonce
			Class::Right => rng.gen::<u16>(), // Random nonce
		};

		inputs.push((fixed_seed.clone(), nonce));
		classes.push(class);
	}

	for (class, (seed, nonce)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut poly = qp_rusty_crystals_dilithium::poly::Poly::default();
			qp_rusty_crystals_dilithium::poly::lvl5::uniform_eta(&mut poly, &seed, nonce);
		});
	}
}

#[cfg(feature = "dudect-bencher")]
ctbench_main!(
	test_keypair_generation_ct,
	test_signing_small_ct,
	test_signing_medium_ct,
	test_signing_large_ct,
	test_signing_xlarge_ct,
	test_hedged_signing_small_ct,
	test_signing_with_context_ct,
	test_edge_cases_ct,
	test_uniform_eta_ct,
	test_rej_eta_ct,
	test_uniform_eta_nonce_ct
);

#[cfg(not(feature = "dudect-bencher"))]
fn main() {
	println!("Constant-time testing requires the 'ct-testing' feature.");
	println!("Run with: cargo run --release --features ct-testing --bin ct_bench");
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_input_generation_distinguishable() {
		#[cfg(feature = "dudect-bencher")]
		{
			use dudect_bencher::rand::SeedableRng;
			let mut rng = BenchRng::seed_from_u64(42);

			// Test that fixed and random seeds are different
			let fixed_seed1 = generate_fixed_seed(&mut rng);
			let mut rng2 = BenchRng::seed_from_u64(42);
			let fixed_seed2 = generate_fixed_seed(&mut rng2);
			// Fixed seeds from same RNG state should be identical
			assert_eq!(fixed_seed1, fixed_seed2);

			let random_seed1 = generate_random_seed(&mut rng);
			let random_seed2 = generate_random_seed(&mut rng);
			// Random seeds should be different (with very high probability)
			assert_ne!(random_seed1, random_seed2);

			// Test that fixed and random messages are distinguishable
			let fixed_msg = generate_fixed_message(32, &mut rng);
			let random_msg = generate_random_message(32, &mut rng);
			// They should be different (with very high probability)
			assert_ne!(fixed_msg, random_msg);
		}
	}
}
