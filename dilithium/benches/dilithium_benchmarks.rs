// -*- mode: rust; -*-

use criterion::Criterion;

fn bench_variant<FKey, FSign, FVerify>(
	c: &mut Criterion,
	label: &str,
	mut keygen: FKey,
	mut sign: FSign,
	mut verify: FVerify,
) where
	FKey: FnMut(),
	FSign: FnMut(),
	FVerify: FnMut(),
{
	c.bench_function(&format!("{label} keypair generation"), |b| b.iter(&mut keygen));
	c.bench_function(&format!("{label} signing"), |b| b.iter(&mut sign));
	c.bench_function(&format!("{label} signature verification"), |b| b.iter(&mut verify));
}

fn main() {
	let mut c = Criterion::default().configure_from_args();

	#[cfg(feature = "ml-dsa-44")]
	{
		use qp_rusty_crystals_dilithium::ml_dsa_44::Keypair;
		let keypair = Keypair::generate((&mut [2u8; 32]).into());
		let msg = b"";
		let sig = keypair.sign(msg, None, None).expect("Signing should succeed");
		bench_variant(
			&mut c,
			"ML-DSA-44",
			|| {
				let _ = Keypair::generate((&mut [1u8; 32]).into());
			},
			|| {
				let _ = keypair.sign(msg, None, None);
			},
			|| {
				let _ = keypair.verify(msg, sig.as_slice(), None);
			},
		);
	}

	#[cfg(feature = "ml-dsa-65")]
	{
		use qp_rusty_crystals_dilithium::ml_dsa_65::Keypair;
		let keypair = Keypair::generate((&mut [2u8; 32]).into());
		let msg = b"";
		let sig = keypair.sign(msg, None, None).expect("Signing should succeed");
		bench_variant(
			&mut c,
			"ML-DSA-65",
			|| {
				let _ = Keypair::generate((&mut [1u8; 32]).into());
			},
			|| {
				let _ = keypair.sign(msg, None, None);
			},
			|| {
				let _ = keypair.verify(msg, sig.as_slice(), None);
			},
		);
	}

	#[cfg(feature = "ml-dsa-87")]
	{
		use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
		let keypair = Keypair::generate((&mut [2u8; 32]).into());
		let msg = b"";
		let sig = keypair.sign(msg, None, None).expect("Signing should succeed");
		bench_variant(
			&mut c,
			"ML-DSA-87",
			|| {
				let _ = Keypair::generate((&mut [1u8; 32]).into());
			},
			|| {
				let _ = keypair.sign(msg, None, None);
			},
			|| {
				let _ = keypair.verify(msg, sig.as_slice(), None);
			},
		);
	}

	c.final_summary();
}
