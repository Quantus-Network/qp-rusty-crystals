//! Benchmarks for threshold ML-DSA-87 implementation.
//!
//! Run with: `cargo bench`
//! Run specific benchmark: `cargo bench -- dealer_keygen`
//! Generate HTML report: `cargo bench -- --save-baseline main`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use qp_rusty_crystals_threshold::{
	generate_with_dealer,
	keygen::dkg::{run_local_mithril_dkg, TranscriptSigner},
	signing_protocol::run_local_signing,
	verify_signature, ThresholdConfig, ThresholdSigner,
};

/// Simple test signer for DKG benchmarks.
/// Uses a trivial signature scheme (just ID + hash) for benchmarking purposes.
#[derive(Clone, Debug)]
struct BenchSigner {
	id: u32,
}

impl TranscriptSigner for BenchSigner {
	type Signature = Vec<u8>;
	type PublicKey = u32;

	fn sign(&self, hash: &[u8; 32]) -> Self::Signature {
		let mut sig = vec![0u8; 36];
		sig[..4].copy_from_slice(&self.id.to_le_bytes());
		sig[4..36].copy_from_slice(hash);
		sig
	}

	fn verify(pk: &Self::PublicKey, hash: &[u8; 32], sig: &Self::Signature) -> bool {
		Self::verify_bytes(pk, hash, sig)
	}

	fn verify_bytes(pk: &Self::PublicKey, hash: &[u8; 32], sig: &[u8]) -> bool {
		if sig.len() < 36 {
			return false;
		}
		let sig_id = u32::from_le_bytes(sig[..4].try_into().unwrap());
		sig_id == *pk && &sig[4..36] == hash
	}

	fn public_key(&self) -> Self::PublicKey {
		self.id
	}
}

/// All supported threshold configurations for benchmarking.
/// Note: n=7 is not supported (MAX_PARTIES = 6) due to impractical K values.
const ALL_CONFIGS: [(u32, u32); 15] = [
	// n = 2
	(2, 2),
	// n = 3
	(2, 3),
	(3, 3),
	// n = 4
	(2, 4),
	(3, 4),
	(4, 4),
	// n = 5
	(2, 5),
	(3, 5),
	(4, 5),
	(5, 5),
	// n = 6
	(2, 6),
	(3, 6),
	(4, 6),
	(5, 6),
	(6, 6),
];

/// Subset of configurations for expensive benchmarks.
const QUICK_CONFIGS: [(u32, u32); 8] =
	[(2, 2), (2, 3), (3, 3), (3, 4), (4, 4), (3, 5), (5, 5), (6, 6)];

/// Helper to create signers from shares for a given configuration.
fn create_signers(
	seed: &[u8; 32],
	t: u32,
	n: u32,
) -> (
	qp_rusty_crystals_threshold::PublicKey,
	Vec<qp_rusty_crystals_threshold::PrivateKeyShare>,
	ThresholdConfig,
) {
	let config = ThresholdConfig::new(t, n).unwrap();
	let (public_key, shares) = generate_with_dealer(seed, config).unwrap();
	(public_key, shares, config)
}

/// Benchmark dealer-based key generation for all configurations.
fn bench_dealer_keygen(c: &mut Criterion) {
	let mut group = c.benchmark_group("dealer_keygen");
	group.measurement_time(Duration::from_secs(10));

	let seed = [42u8; 32];

	for (t, n) in ALL_CONFIGS {
		let config = ThresholdConfig::new(t, n).unwrap();

		group.bench_with_input(
			BenchmarkId::new("config", format!("{}_of_{}", t, n)),
			&(t, n),
			|b, _| {
				b.iter(|| generate_with_dealer(&seed, config).unwrap());
			},
		);
	}

	group.finish();
}

/// Benchmark distributed key generation (DKG) for quick configurations.
fn bench_dkg(c: &mut Criterion) {
	use rand::SeedableRng;

	let mut group = c.benchmark_group("dkg");
	group.sample_size(10); // DKG is slow, use fewer samples
	group.measurement_time(Duration::from_secs(30));

	for &(t, n) in &QUICK_CONFIGS {
		group.bench_with_input(
			BenchmarkId::new("config", format!("{}_of_{}", t, n)),
			&(t, n),
			|b, &(t, n)| {
				b.iter(|| {
					let signers: Vec<BenchSigner> = (0..n).map(|id| BenchSigner { id }).collect();
					let public_keys: Vec<u32> = (0..n).collect();
					let rng = rand::rngs::StdRng::seed_from_u64(42);
					run_local_mithril_dkg(t, n, signers, public_keys, rng).unwrap()
				});
			},
		);
	}

	group.finish()
}

/// Benchmark the complete 4-round signing protocol.
fn bench_signing_4round(c: &mut Criterion) {
	let mut group = c.benchmark_group("signing_4round");
	group.sample_size(10); // Signing can be slow, use fewer samples
	group.measurement_time(Duration::from_secs(30));

	let seed = [42u8; 32];
	let message = b"benchmark message for threshold signing";
	let context: &[u8] = b"";

	for (t, n) in QUICK_CONFIGS {
		let (public_key, shares, config) = create_signers(&seed, t, n);

		group.bench_with_input(
			BenchmarkId::new("config", format!("{}_of_{}", t, n)),
			&(public_key, shares, config),
			|b, (public_key, shares, config)| {
				b.iter(|| {
					// Create fresh signers for each iteration (signers have state)
					let signers: Vec<ThresholdSigner> = shares
						.iter()
						.take(t as usize)
						.map(|s| {
							ThresholdSigner::new(s.clone(), public_key.clone(), *config).unwrap()
						})
						.collect();
					run_local_signing(signers, message, context).unwrap()
				});
			},
		);
	}

	group.finish();
}

/// Benchmark signature verification (should match standard Dilithium).
fn bench_verify(c: &mut Criterion) {
	let mut group = c.benchmark_group("verify_signature");
	group.measurement_time(Duration::from_secs(10));

	let seed = [42u8; 32];
	let message = b"message to verify";
	let context: &[u8] = b"";

	// Generate a signature to verify (use 2-of-2 for speed)
	let (public_key, shares, config) = create_signers(&seed, 2, 2);

	let signers: Vec<ThresholdSigner> = shares
		.iter()
		.take(2)
		.map(|s| ThresholdSigner::new(s.clone(), public_key.clone(), config).unwrap())
		.collect();

	let signature = run_local_signing(signers, message, context).unwrap();

	group.throughput(Throughput::Elements(1));
	group.bench_function("dilithium_threshold", |b| {
		b.iter(|| verify_signature(&public_key, message, context, &signature));
	});

	group.finish();
}

/// Benchmark individual signing rounds (Round 1 commitment).
fn bench_round1(c: &mut Criterion) {
	let mut group = c.benchmark_group("round1_commit");
	group.measurement_time(Duration::from_secs(10));

	let seed = [42u8; 32];

	for (t, n) in QUICK_CONFIGS {
		let (public_key, shares, config) = create_signers(&seed, t, n);

		group.bench_with_input(
			BenchmarkId::new("config", format!("{}_of_{}", t, n)),
			&(public_key, shares, config),
			|b, (public_key, shares, config)| {
				let mut rng = rand::thread_rng();
				b.iter(|| {
					let mut signer =
						ThresholdSigner::new(shares[0].clone(), public_key.clone(), *config)
							.unwrap();
					signer.round1_commit(&mut rng).unwrap()
				});
			},
		);
	}

	group.finish();
}

/// Benchmark comparison: threshold vs standard Dilithium.
fn bench_comparison(c: &mut Criterion) {
	use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;

	let mut group = c.benchmark_group("comparison");
	group.measurement_time(Duration::from_secs(10));

	let mut seed = [42u8; 32];
	let message = b"comparison benchmark message";
	let context: &[u8] = b"";

	// Standard Dilithium
	let keypair = Keypair::generate((&mut seed).into());

	group.bench_function("standard_dilithium_sign", |b| {
		b.iter(|| keypair.sign(message, None, None).unwrap());
	});

	let std_sig = keypair.sign(message, None, None).unwrap();
	group.bench_function("standard_dilithium_verify", |b| {
		b.iter(|| keypair.verify(message, &std_sig, None));
	});

	// Threshold 2-of-2 (minimum overhead)
	let (pk_2_2, shares_2_2, config_2_2) = create_signers(&seed, 2, 2);

	group.bench_function("threshold_2_of_2_sign", |b| {
		b.iter(|| {
			let signers: Vec<ThresholdSigner> = shares_2_2
				.iter()
				.take(2)
				.map(|s| ThresholdSigner::new(s.clone(), pk_2_2.clone(), config_2_2).unwrap())
				.collect();
			run_local_signing(signers, message, context).unwrap()
		});
	});

	// Threshold 3-of-5 (typical configuration)
	let (pk_3_5, shares_3_5, config_3_5) = create_signers(&seed, 3, 5);

	group.bench_function("threshold_3_of_5_sign", |b| {
		b.iter(|| {
			let signers: Vec<ThresholdSigner> = shares_3_5
				.iter()
				.take(3)
				.map(|s| ThresholdSigner::new(s.clone(), pk_3_5.clone(), config_3_5).unwrap())
				.collect();
			run_local_signing(signers, message, context).unwrap()
		});
	});

	group.finish();
}

// Register benchmark groups
criterion_group! {
	name = keygen_benches;
	config = Criterion::default();
	targets = bench_dealer_keygen, bench_dkg
}

criterion_group! {
	name = signing_benches;
	config = Criterion::default();
	targets = bench_signing_4round, bench_round1
}

criterion_group! {
	name = verify_benches;
	config = Criterion::default();
	targets = bench_verify
}

criterion_group! {
	name = comparison_benches;
	config = Criterion::default();
	targets = bench_comparison
}

criterion_main!(keygen_benches, signing_benches, verify_benches, comparison_benches);
