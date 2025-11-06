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

fn generate_random_polyvecl(rng: &mut BenchRng) -> qp_rusty_crystals_dilithium::polyvec::Polyvecl {
	let mut z = qp_rusty_crystals_dilithium::polyvec::Polyvecl::default();
	for i in 0..qp_rusty_crystals_dilithium::params::L {
		for j in 0..qp_rusty_crystals_dilithium::params::N {
			z.vec[i].coeffs[j as usize] = rng.gen_range(-100000..100000);
		}
	}
	z
}

fn generate_random_hint_polyveck(
	rng: &mut BenchRng,
) -> qp_rusty_crystals_dilithium::polyvec::Polyveck {
	let mut h = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
	let mut hint_count = 0;
	for i in 0..qp_rusty_crystals_dilithium::params::K {
		for j in 0..qp_rusty_crystals_dilithium::params::N {
			if hint_count < qp_rusty_crystals_dilithium::params::OMEGA && rng.gen_bool(0.01) {
				h.vec[i].coeffs[j as usize] = 1;
				hint_count += 1;
			}
		}
	}
	h
}

fn generate_fixed_polyvecl() -> qp_rusty_crystals_dilithium::polyvec::Polyvecl {
	let mut z = qp_rusty_crystals_dilithium::polyvec::Polyvecl::default();
	for i in 0..qp_rusty_crystals_dilithium::params::L {
		for j in 0..qp_rusty_crystals_dilithium::params::N {
			z.vec[i].coeffs[j as usize] = (i as i32 * 1000 + j) % 200000 - 100000;
		}
	}
	z
}

fn generate_fixed_hint_polyveck() -> qp_rusty_crystals_dilithium::polyvec::Polyveck {
	let mut h = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
	let mut hint_count = 0;
	for i in 0..qp_rusty_crystals_dilithium::params::K {
		for j in 0..qp_rusty_crystals_dilithium::params::N {
			if hint_count < qp_rusty_crystals_dilithium::params::OMEGA &&
				(i * qp_rusty_crystals_dilithium::params::N as usize + j as usize) % 37 == 0
			{
				h.vec[i].coeffs[j as usize] = 1;
				hint_count += 1;
			}
		}
	}
	h
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
			let _keypair = Keypair::generate(&seed);
		});
	}
}

/// Test signing with small messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running small message signing constant-time test...");

	// Generate keypairs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all samples
	let fixed_message = generate_fixed_message(SMALL_MSG_SIZE, rng);
	let fixed_seed = generate_fixed_seed(rng);

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let keypair = match class {
			Class::Left => Keypair::generate(&fixed_seed),
			Class::Right => Keypair::generate(&generate_random_seed(rng)),
		};

		inputs.push(keypair);
		classes.push(class);
	}

	for (class, keypair) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&fixed_message, None, None);
		});
	}
}

/// Test signing with medium messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running medium message signing constant-time test...");

	// Generate keypairs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all samples
	let fixed_message = generate_fixed_message(MEDIUM_MSG_SIZE, rng);
	let fixed_seed = generate_fixed_seed(rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let keypair = match class {
			Class::Left => Keypair::generate(&fixed_seed),
			Class::Right => Keypair::generate(&generate_random_seed(rng)),
		};

		inputs.push(keypair);
		classes.push(class);
	}

	for (class, keypair) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&fixed_message, None, None);
		});
	}
}

/// Test signing with large messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running large message signing constant-time test...");

	// Generate keypairs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all samples
	let fixed_message = generate_fixed_message(LARGE_MSG_SIZE, rng);
	let fixed_seed = generate_fixed_seed(rng);

	for _ in 0..3_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let keypair = match class {
			Class::Left => Keypair::generate(&fixed_seed),
			Class::Right => Keypair::generate(&generate_random_seed(rng)),
		};

		inputs.push(keypair);
		classes.push(class);
	}

	for (class, keypair) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&fixed_message, None, None);
		});
	}
}

/// Test signing with extra large messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_xlarge_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running extra large message signing constant-time test...");

	// Generate keypairs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all samples
	let fixed_message = generate_fixed_message(EXTRA_LARGE_MSG_SIZE, rng);
	let fixed_seed = generate_fixed_seed(rng);

	for _ in 0..2_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let keypair = match class {
			Class::Left => Keypair::generate(&fixed_seed),
			Class::Right => Keypair::generate(&generate_random_seed(rng)),
		};

		inputs.push(keypair);
		classes.push(class);
	}

	for (class, keypair) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&fixed_message, None, None);
		});
	}
}

/// Test hedged signing (randomized) with small messages for constant time
#[cfg(feature = "dudect-bencher")]
fn test_hedged_signing_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running hedged signing constant-time test...");

	// Generate keypairs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message once for all samples
	let fixed_message = generate_fixed_message(SMALL_MSG_SIZE, rng);
	let fixed_seed = generate_fixed_seed(rng);

	for _ in 0..6_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let keypair = match class {
			Class::Left => Keypair::generate(&fixed_seed),
			Class::Right => Keypair::generate(&generate_random_seed(rng)),
		};

		inputs.push(keypair);
		classes.push(class);
	}

	for (class, keypair) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&fixed_message, None, None); // hedged = true
		});
	}
}

/// Test signing with context strings for constant time
#[cfg(feature = "dudect-bencher")]
fn test_signing_with_context_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running context signing constant-time test...");

	// Generate keypairs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed message and context once for all samples
	let fixed_message = generate_fixed_message(SMALL_MSG_SIZE, rng);
	let fixed_context = b"test context";
	let fixed_seed = generate_fixed_seed(rng);

	for _ in 0..4_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let keypair = match class {
			Class::Left => Keypair::generate(&fixed_seed),
			Class::Right => Keypair::generate(&generate_random_seed(rng)),
		};

		inputs.push(keypair);
		classes.push(class);
	}

	for (class, keypair) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _signature = keypair.sign(&fixed_message, Some(fixed_context), None);
		});
	}
}

/// Test edge cases with single-byte and small messages
#[cfg(feature = "dudect-bencher")]
fn test_edge_cases_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running edge cases constant-time test...");

	// Pre-generate a keypair for signing
	let keypair = Keypair::generate(&[0x42; SEED_SIZE]);

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
			let _signature = keypair.sign(&message, None, None);
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
	let fixed_seed = generate_fixed_message(64, rng);

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let seed = match class {
			Class::Left => fixed_seed.to_vec(),
			Class::Right => generate_random_message(64, rng),
		};

		inputs.push(seed);
		classes.push(class);
	}

	for (class, seed) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut poly = qp_rusty_crystals_dilithium::poly::Poly::default();
			qp_rusty_crystals_dilithium::poly::uniform_eta(&mut poly, &seed, 0);
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

	let fixed = generate_fixed_message(168, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let buffer = match class {
			Class::Left => fixed.clone(),
			Class::Right => generate_random_message(168, rng),
		};

		inputs.push(buffer);
		classes.push(class);
	}

	for (class, buffer) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut coeffs = [0i32; 256];
			let _count =
				qp_rusty_crystals_dilithium::poly::rej_eta(&mut coeffs, 256, &buffer, buffer.len());
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

	let fixed_seed = generate_fixed_message(64, rng);
	let fixed_nonce = generate_fixed_message(2, rng);

	for _ in 0..6_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let nonce = match class {
			Class::Left => fixed_nonce.clone(),              // Fixed nonce
			Class::Right => generate_random_message(2, rng), // Random nonce
		};
		let seed = match class {
			Class::Left => fixed_seed.clone(),                // Fixed seed
			Class::Right => generate_random_message(64, rng), // Random seed
		};
		inputs.push((seed, nonce));
		classes.push(class);
	}

	for (class, (seed, nonce)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut poly = qp_rusty_crystals_dilithium::poly::Poly::default();
			qp_rusty_crystals_dilithium::poly::uniform_eta(
				&mut poly,
				&seed,
				u16::from_be_bytes(nonce.clone().try_into().expect("Nonce conversion failed")),
			);
		});
	}
}

/// Test l_uniform_gamma1 function for constant time
#[cfg(feature = "dudect-bencher")]
fn test_l_uniform_gamma1_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running l_uniform_gamma1 constant-time test...");

	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	let fixed_seed = generate_fixed_message(64, rng);
	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let seed = match class {
			Class::Left => fixed_seed.clone(),
			Class::Right => generate_random_message(64, rng),
		};
		inputs.push(seed);
		classes.push(class);
	}

	for (class, seed) in classes.into_iter().zip(inputs.into_iter()) {
		disrupt_cache(rng);
		runner.run_one(class, || {
			let mut y = qp_rusty_crystals_dilithium::polyvec::Polyvecl::default();
			qp_rusty_crystals_dilithium::polyvec::l_uniform_gamma1(&mut y, &seed, 0);
		});
	}
}

/// Test polyvecl_is_norm_within_bound function for constant time
#[cfg(feature = "dudect-bencher")]
fn test_polyvecl_norm_check_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running polyvecl norm check constant-time test...");

	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	let fixed_polyvec = qp_rusty_crystals_dilithium::polyvec::Polyvecl::default();
	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let poly = match class {
			Class::Left => fixed_polyvec,
			Class::Right => {
				let mut p = qp_rusty_crystals_dilithium::polyvec::Polyvecl::default();
				for i in 0..7 {
					for j in 0..256 {
						p.vec[i].coeffs[j] = rng.gen::<i32>() % 1000;
					}
				}
				p
			},
		};
		inputs.push(poly);
		classes.push(class);
	}

	for (class, poly) in classes.into_iter().zip(inputs.into_iter()) {
		disrupt_cache(rng);
		runner.run_one(class, || {
			let _result =
				qp_rusty_crystals_dilithium::polyvec::polyvecl_is_norm_within_bound(&poly, 500000);
		});
	}
}

/// Test polyveck_is_norm_within_bound function for constant time
#[cfg(feature = "dudect-bencher")]
fn test_polyveck_norm_check_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running polyveck norm check constant-time test...");

	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	let fixed_polyvec = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let poly = match class {
			Class::Left => fixed_polyvec,
			Class::Right => {
				let mut p = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
				for i in 0..8 {
					for j in 0..256 {
						p.vec[i].coeffs[j] = rng.gen::<i32>() % 1000;
					}
				}
				p
			},
		};
		inputs.push(poly);
		classes.push(class);
	}

	for (class, poly) in classes.into_iter().zip(inputs.into_iter()) {
		disrupt_cache(rng);
		runner.run_one(class, || {
			let _result =
				qp_rusty_crystals_dilithium::polyvec::polyveck_is_norm_within_bound(&poly, 500000);
		});
	}
}

fn test_challenge_generation_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running challenge generation constant-time test...");

	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };

		let w1 = match class {
			Class::Left => qp_rusty_crystals_dilithium::polyvec::Polyveck::default(),
			Class::Right => {
				let mut w1 = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
				// Fill w1 with random data
				for i in 0..qp_rusty_crystals_dilithium::params::K {
					for j in 0..qp_rusty_crystals_dilithium::params::N {
						w1.vec[i].coeffs[j as usize] = rng.gen_range(0..16);
					}
				}
				w1
			},
		};

		inputs.push(w1);
		classes.push(class);
	}

	for (class, w1) in classes.into_iter().zip(inputs.into_iter()) {
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut output_buffer = [0u8; qp_rusty_crystals_dilithium::params::SIGNBYTES];
			// Test the packing operation which is part of challenge generation
			qp_rusty_crystals_dilithium::polyvec::k_pack_w1(&mut output_buffer, &w1);
		});
	}
}

fn test_packing_operations_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running packing operations constant-time test...");

	// Generate fixed signature components upfront
	let fixed_z = generate_fixed_polyvecl();
	let fixed_h = generate_fixed_hint_polyveck();

	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };

		let (z_vec, h_vec) = match class {
			Class::Left => {
				// Use the fixed signature components
				(fixed_z, fixed_h)
			},
			Class::Right => {
				// Generate random signature components
				let z = generate_random_polyvecl(rng);
				let h = generate_random_hint_polyveck(rng);
				(z, h)
			},
		};

		inputs.push((z_vec, h_vec));
		classes.push(class);
	}

	for (class, (z_vec, h_vec)) in classes.into_iter().zip(inputs.into_iter()) {
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut sig_buffer = [0u8; qp_rusty_crystals_dilithium::params::SIGNBYTES];
			qp_rusty_crystals_dilithium::packing::pack_sig(&mut sig_buffer, None, &z_vec, &h_vec);
		});
	}
}

fn test_k_make_hint_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running k_make_hint constant-time test...");

	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	let fixed_w0 = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
	let fixed_w1 = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();

	for _ in 0..6_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let (w0, w1) = match class {
			Class::Left => (fixed_w0, fixed_w1),
			Class::Right => {
				let mut w0 = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
				let mut w1 = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
				for i in 0..8 {
					for j in 0..256 {
						w0.vec[i].coeffs[j] = rng.gen::<i32>() % 10000;
						w1.vec[i].coeffs[j] = rng.gen::<i32>() % 10000;
					}
				}
				(w0, w1)
			},
		};
		inputs.push((w0, w1));
		classes.push(class);
	}

	for (class, (w0, w1)) in classes.into_iter().zip(inputs.into_iter()) {
		disrupt_cache(rng);
		runner.run_one(class, || {
			let mut hint = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
			let _weight = qp_rusty_crystals_dilithium::polyvec::k_make_hint(&mut hint, &w0, &w1);
		});
	}
}

/// Test NTT (Number Theoretic Transform) for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_ntt_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running NTT constant-time test...");

	// Generate arrays and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed array once for all Left class samples
	let fixed_array = generate_fixed_polynomial_array(rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let array = match class {
			Class::Left => fixed_array.clone(),
			Class::Right => generate_random_polynomial_array(rng),
		};

		inputs.push(array);
		classes.push(class);
	}

	for (class, array) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut array_copy = array.clone();
			qp_rusty_crystals_dilithium::ntt::ntt(&mut array_copy);
		});
	}
}

/// Generate a fixed polynomial array for Left class (deterministic pattern)
#[cfg(feature = "dudect-bencher")]
fn generate_fixed_polynomial_array(rng: &mut BenchRng) -> Vec<i32> {
	// Use a deterministic pattern based on a single random byte
	let pattern = rng.gen::<u8>() as i32;
	let mut array = Vec::with_capacity(qp_rusty_crystals_dilithium::params::N as usize);

	for i in 0..qp_rusty_crystals_dilithium::params::N as usize {
		// Create a simple deterministic pattern that varies by position
		array.push(pattern.wrapping_add(i as i32) & 0x7FFFFF); // Keep within reasonable range
	}
	array
}

/// Generate a random polynomial array for Right class
#[cfg(feature = "dudect-bencher")]
fn generate_random_polynomial_array(rng: &mut BenchRng) -> Vec<i32> {
	let mut array = Vec::with_capacity(qp_rusty_crystals_dilithium::params::N as usize);

	for _ in 0..qp_rusty_crystals_dilithium::params::N as usize {
		// Generate random coefficients within a reasonable range
		array.push(rng.gen::<i32>() & 0x7FFFFF);
	}
	array
}

/// Test inverse NTT for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_invntt_tomont_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running inverse NTT constant-time test...");

	// Generate arrays and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed array once for all Left class samples
	let fixed_array = generate_fixed_polynomial_array(rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let array = match class {
			Class::Left => fixed_array.clone(),
			Class::Right => generate_random_polynomial_array(rng),
		};

		inputs.push(array);
		classes.push(class);
	}

	for (class, array) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut array_copy = array.clone();
			qp_rusty_crystals_dilithium::ntt::invntt_tomont(&mut array_copy);
		});
	}
}

/// Test check_norm function for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_check_norm_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running check_norm constant-time test...");

	// Generate polynomials and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate the fixed polynomial once for all Left class samples
	let fixed_poly = generate_fixed_polynomial(rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let poly = match class {
			Class::Left => fixed_poly,
			Class::Right => generate_random_polynomial(rng),
		};

		inputs.push(poly);
		classes.push(class);
	}

	// Use a fixed bound for the test
	let bound = 100_000i32;

	for (class, poly) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _result = qp_rusty_crystals_dilithium::poly::check_norm(&poly, bound);
		});
	}
}

/// Generate a fixed polynomial for Left class (deterministic pattern)
#[cfg(feature = "dudect-bencher")]
fn generate_fixed_polynomial(rng: &mut BenchRng) -> qp_rusty_crystals_dilithium::poly::Poly {
	use qp_rusty_crystals_dilithium::poly::Poly;

	let pattern = rng.gen::<u8>() as i32;
	let mut poly = Poly::default();

	for i in 0..qp_rusty_crystals_dilithium::params::N as usize {
		// Create a deterministic pattern that varies by position
		poly.coeffs[i] = pattern.wrapping_add(i as i32) & 0x7FFFFF;
	}
	poly
}

/// Generate a random polynomial for Right class
#[cfg(feature = "dudect-bencher")]
fn generate_random_polynomial(rng: &mut BenchRng) -> qp_rusty_crystals_dilithium::poly::Poly {
	use qp_rusty_crystals_dilithium::poly::Poly;

	let mut poly = Poly::default();

	for i in 0..qp_rusty_crystals_dilithium::params::N as usize {
		// Generate random coefficients within a reasonable range
		poly.coeffs[i] = rng.gen::<i32>() & 0x7FFFFF;
	}
	poly
}

/// Test make_hint function for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_make_hint_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running make_hint constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate fixed values for Left class
	let fixed_a0 = rng.gen::<i32>() % 1000000;
	let fixed_a1 = rng.gen::<i32>() % 1000000;

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let (a0, a1) = match class {
			Class::Left => (fixed_a0, fixed_a1),
			Class::Right => (rng.gen::<i32>() % 1000000, rng.gen::<i32>() % 1000000),
		};

		inputs.push((a0, a1));
		classes.push(class);
	}

	for (class, (a0, a1)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _result = qp_rusty_crystals_dilithium::rounding::make_hint(a0, a1);
		});
	}
}

/// Test use_hint function for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_use_hint_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running use_hint constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate fixed values for Left class
	let fixed_a = rng.gen::<i32>() % 1000000;
	let fixed_hint = rng.gen::<i32>() % 2;

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let (a, hint) = match class {
			Class::Left => (fixed_a, fixed_hint),
			Class::Right => (rng.gen::<i32>() % 1000000, rng.gen::<i32>() % 2),
		};

		inputs.push((a, hint));
		classes.push(class);
	}

	for (class, (a, hint)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let _result = qp_rusty_crystals_dilithium::rounding::use_hint(a, hint);
		});
	}
}

/// Test signing with fixed keypair but different messages for constant-time
#[cfg(feature = "dudect-bencher")]
fn test_signing_fixed_key_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running signing with fixed key constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate single fixed keypair for all tests
	let fixed_seed = generate_fixed_seed(rng);
	let keypair = Keypair::generate(&fixed_seed);

	// Generate the fixed message once for all Left class samples
	let fixed_message = generate_fixed_message(SMALL_MSG_SIZE, rng);

	for _ in 0..5_000 {
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
			let _signature = keypair.sign(&message, None, None);
		});
	}
}

/// Test message hashing specifically for constant-time
#[cfg(feature = "dudect-bencher")]
fn test_message_hashing_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running message hashing constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate fixed values for Left class
	let fixed_tr = {
		let mut tr = [0u8; qp_rusty_crystals_dilithium::params::TR_BYTES];
		rng.fill_bytes(&mut tr);
		tr
	};
	let fixed_message = generate_fixed_message(MEDIUM_MSG_SIZE, rng);

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let (tr, message) = match class {
			Class::Left => (fixed_tr, fixed_message.clone()),
			Class::Right => {
				let mut tr = [0u8; qp_rusty_crystals_dilithium::params::TR_BYTES];
				rng.fill_bytes(&mut tr);
				(tr, generate_random_message(MEDIUM_MSG_SIZE, rng))
			},
		};

		inputs.push((tr, message));
		classes.push(class);
	}

	for (class, (tr, message)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			// Simulate the message hashing operation from signing
			use qp_rusty_crystals_dilithium::fips202;
			let mut keccak_state = fips202::KeccakState::default();
			fips202::shake256_absorb(
				&mut keccak_state,
				&tr,
				qp_rusty_crystals_dilithium::params::TR_BYTES,
			);
			let context_prefix = [0u8, 0u8];
			fips202::shake256_absorb(&mut keccak_state, &context_prefix, 2);
			fips202::shake256_absorb(&mut keccak_state, &message, message.len());
			fips202::shake256_finalize(&mut keccak_state);
			let mut message_hash_mu = [0u8; qp_rusty_crystals_dilithium::params::CRHBYTES];
			fips202::shake256_squeeze(
				&mut message_hash_mu,
				qp_rusty_crystals_dilithium::params::CRHBYTES,
				&mut keccak_state,
			);
		});
	}
}

/// Test challenge polynomial generation for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_challenge_generation_detailed_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running detailed challenge generation constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate fixed values for Left class
	let fixed_mu = {
		let mut mu = [0u8; qp_rusty_crystals_dilithium::params::CRHBYTES];
		rng.fill_bytes(&mut mu);
		mu
	};
	let fixed_w1 = {
		let mut w1 = Box::new(qp_rusty_crystals_dilithium::polyvec::Polyveck::default());
		for i in 0..qp_rusty_crystals_dilithium::params::K {
			for j in 0..qp_rusty_crystals_dilithium::params::N as usize {
				w1.vec[i].coeffs[j] = rng.gen::<i32>() % 16; // w1 coefficients are in [0, 15]
			}
		}
		w1
	};

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let (mu, w1) = match class {
			Class::Left => {
				let mut mu = [0u8; qp_rusty_crystals_dilithium::params::CRHBYTES];
				mu.copy_from_slice(&fixed_mu);
				(mu, *fixed_w1)
			},
			Class::Right => {
				let mut mu = [0u8; qp_rusty_crystals_dilithium::params::CRHBYTES];
				rng.fill_bytes(&mut mu);
				let mut w1 = Box::new(qp_rusty_crystals_dilithium::polyvec::Polyveck::default());
				for i in 0..qp_rusty_crystals_dilithium::params::K {
					for j in 0..qp_rusty_crystals_dilithium::params::N as usize {
						w1.vec[i].coeffs[j] = rng.gen::<i32>() % 16;
					}
				}
				(mu, *w1)
			},
		};

		inputs.push((mu, w1));
		classes.push(class);
	}

	for (class, (mu, w1)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut signature_buffer = [0u8; qp_rusty_crystals_dilithium::params::SIGNBYTES];

			// Pack w1 into signature buffer
			qp_rusty_crystals_dilithium::polyvec::k_pack_w1(&mut signature_buffer, &w1);

			// Generate challenge
			use qp_rusty_crystals_dilithium::fips202;
			let mut keccak_state = fips202::KeccakState::default();
			fips202::shake256_absorb(
				&mut keccak_state,
				&mu,
				qp_rusty_crystals_dilithium::params::CRHBYTES,
			);
			fips202::shake256_absorb(
				&mut keccak_state,
				&signature_buffer,
				qp_rusty_crystals_dilithium::params::K *
					qp_rusty_crystals_dilithium::params::POLYW1_PACKEDBYTES,
			);
			fips202::shake256_finalize(&mut keccak_state);
			fips202::shake256_squeeze(
				&mut signature_buffer,
				qp_rusty_crystals_dilithium::params::C_DASH_BYTES,
				&mut keccak_state,
			);

			let mut challenge_poly_c = qp_rusty_crystals_dilithium::poly::Poly::default();
			qp_rusty_crystals_dilithium::poly::challenge(&mut challenge_poly_c, &signature_buffer);
			qp_rusty_crystals_dilithium::poly::ntt(&mut challenge_poly_c);
		});
	}
}

/// Test polynomial arithmetic operations for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_polynomial_arithmetic_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running polynomial arithmetic constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate fixed polynomials for Left class
	let fixed_poly1 = generate_fixed_polynomial(rng);
	let fixed_poly2 = generate_fixed_polynomial(rng);

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let (poly1, poly2) = match class {
			Class::Left => (fixed_poly1, fixed_poly2),
			Class::Right => (generate_random_polynomial(rng), generate_random_polynomial(rng)),
		};

		inputs.push((poly1, poly2));
		classes.push(class);
	}

	for (class, (poly1, poly2)) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			// Test various polynomial operations that happen during signing
			let mut poly1_copy = poly1;
			qp_rusty_crystals_dilithium::poly::ntt(&mut poly1_copy);
			let mut result = qp_rusty_crystals_dilithium::poly::Poly::default();
			qp_rusty_crystals_dilithium::poly::pointwise_montgomery(
				&mut result,
				&poly1_copy,
				&poly2,
			);
		});
	}
}

/// Test k_pack_w1 operation for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_k_pack_w1_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running k_pack_w1 constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate fixed w1 for Left class
	let fixed_w1 = {
		let mut w1 = Box::new(qp_rusty_crystals_dilithium::polyvec::Polyveck::default());
		for i in 0..qp_rusty_crystals_dilithium::params::K {
			for j in 0..qp_rusty_crystals_dilithium::params::N as usize {
				w1.vec[i].coeffs[j] = rng.gen::<i32>() % 16; // w1 coefficients are in [0, 15]
			}
		}
		w1
	};

	for _ in 0..8_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let w1 = match class {
			Class::Left => *fixed_w1,
			Class::Right => {
				let mut w1 = Box::new(qp_rusty_crystals_dilithium::polyvec::Polyveck::default());
				for i in 0..qp_rusty_crystals_dilithium::params::K {
					for j in 0..qp_rusty_crystals_dilithium::params::N as usize {
						w1.vec[i].coeffs[j] = rng.gen::<i32>() % 16;
					}
				}
				*w1
			},
		};

		inputs.push(w1);
		classes.push(class);
	}

	for (class, w1) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut signature_buffer = [0u8; qp_rusty_crystals_dilithium::params::SIGNBYTES];
			qp_rusty_crystals_dilithium::polyvec::k_pack_w1(&mut signature_buffer, &w1);
		});
	}
}

/// Test poly::challenge function for constant-time execution
#[cfg(feature = "dudect-bencher")]
fn test_poly_challenge_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	println!("Running poly::challenge constant-time test...");

	// Generate inputs and classes upfront
	let mut inputs = Vec::new();
	let mut classes = Vec::new();

	// Generate fixed seed for Left class
	let fixed_seed = {
		let mut seed = [0u8; qp_rusty_crystals_dilithium::params::C_DASH_BYTES];
		rng.fill_bytes(&mut seed);
		seed
	};

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let seed = match class {
			Class::Left => fixed_seed,
			Class::Right => {
				let mut seed = [0u8; qp_rusty_crystals_dilithium::params::C_DASH_BYTES];
				rng.fill_bytes(&mut seed);
				seed
			},
		};

		inputs.push(seed);
		classes.push(class);
	}

	for (class, seed) in classes.into_iter().zip(inputs.into_iter()) {
		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut challenge_poly = qp_rusty_crystals_dilithium::poly::Poly::default();
			qp_rusty_crystals_dilithium::poly::challenge(&mut challenge_poly, &seed);
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
	test_uniform_eta_nonce_ct,
	test_l_uniform_gamma1_ct,
	test_polyvecl_norm_check_ct,
	test_polyveck_norm_check_ct,
	test_k_make_hint_ct,
	test_challenge_generation_ct,
	test_packing_operations_ct,
	test_ntt_ct,
	test_invntt_tomont_ct,
	test_check_norm_ct,
	test_make_hint_ct,
	test_use_hint_ct,
	test_signing_fixed_key_ct,
	test_message_hashing_ct,
	test_challenge_generation_detailed_ct,
	test_polynomial_arithmetic_ct,
	test_k_pack_w1_ct,
	test_poly_challenge_ct
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
