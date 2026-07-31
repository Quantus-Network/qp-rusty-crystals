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

/// Run the keygen/sign/verify trio for one variant module; expands to nothing
/// when the corresponding feature is disabled.
macro_rules! bench_ml_dsa {
	($c:expr, $mod_name:ident, $label:literal, $feature:literal) => {
		#[cfg(feature = $feature)]
		{
			use qp_rusty_crystals_dilithium::$mod_name::Keypair;
			let keypair = Keypair::generate(&mut (&mut [2u8; 32]).into());
			let msg = b"";
			let sig = keypair.sign(msg, None, None).expect("Signing should succeed");
			bench_variant(
				$c,
				$label,
				|| {
					let _ = Keypair::generate(&mut (&mut [1u8; 32]).into());
				},
				|| {
					let _ = keypair.sign(msg, None, None);
				},
				|| {
					let _ = keypair.verify(msg, sig.as_slice(), None);
				},
			);
		}
	};
}

fn main() {
	let mut c = Criterion::default().configure_from_args();

	bench_ml_dsa!(&mut c, ml_dsa_44, "ML-DSA-44", "ml-dsa-44");
	bench_ml_dsa!(&mut c, ml_dsa_65, "ML-DSA-65", "ml-dsa-65");
	bench_ml_dsa!(&mut c, ml_dsa_87, "ML-DSA-87", "ml-dsa-87");

	c.final_summary();
}
