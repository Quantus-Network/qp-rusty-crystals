// -*- mode: rust; -*-

use criterion::{criterion_group, Criterion};

mod dilithium_benches {
	use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;

	use super::*;

	fn key_generation(c: &mut Criterion) {
		c.bench_function("Dilithium keypair generation", move |b| {
			b.iter(|| Keypair::generate((&mut [1u8; 32]).into()));
		});
	}

	fn sign(c: &mut Criterion) {
		let keypair = Keypair::generate((&mut [2u8; 32]).into());
		let msg = b"";

		c.bench_function("Dilithium signing", move |b| b.iter(|| keypair.sign(msg, None, None)));
	}

	fn verify(c: &mut Criterion) {
		let keypair = Keypair::generate((&mut [3u8; 32]).into());
		let msg = b"";
		let sig = keypair.sign(msg, None, None).expect("Signing should succeed");

		c.bench_function("Dilithium signature verification", move |b| {
			b.iter(|| keypair.verify(msg, sig.as_slice(), None))
		});
	}

	criterion_group! {
		name = dilithium_benches;
		config = Criterion::default();
		targets =
			sign,
			verify,
			key_generation,
	}
}

criterion::criterion_main!(dilithium_benches::dilithium_benches);
