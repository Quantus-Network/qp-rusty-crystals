use qp_rusty_crystals_threshold::ml_dsa_87::{self, ThresholdConfig};

#[test]
fn test_debug_trace() {
	println!("🔍 DEBUG TRACE START");

	// 1. Setup deterministic parameters
	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}
	print!("SEED: ");
	for b in &seed {
		print!("{:02x}", b);
	}
	println!();

	// 2. Generate Keys
	let config = ThresholdConfig::new(2, 3).unwrap();

	// Get the original secrets for debugging
	let (s1_total, s2_total) = ml_dsa_87::get_original_secrets_from_seed(&seed, &config).unwrap();

	let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config).unwrap();

	println!("\n--- KEY GENERATION ---");

	// Dump A matrix (first row, first poly, first 5 coeffs)
	let poly_a = pk.a_ntt.get(0, 0);
	print!("A[0][0][0..5]: [");
	for k in 0..5 {
		if k > 0 {
			print!(" ");
		}
		print!("{}", poly_a.get(k).value());
	}
	println!("]");

	// Dump s1 share of party 0
	let sk = &sks[0];
	println!("Party ID: {}", sk.id);

	for (subset_id, share) in &sk.shares {
		print!("Party 0 s1 share (subset {}): [", subset_id);
		for k in 0..5 {
			if k > 0 {
				print!(" ");
			}
			// Display the coefficient as-is (already in unnormalized form [Q-η, Q+η])
			print!("{}", share.s1_share.vec[0].coeffs[k]);
		}
		println!("]");
	}

	// Dump s1_total and s2_total after normalization
	print!("s1_total[0][0..5]: [");
	for k in 0..5 {
		if k > 0 {
			print!(" ");
		}
		print!("{}", s1_total.vec[0].coeffs[k]);
	}
	println!("]");

	print!("s2_total[0][0..5]: [");
	for k in 0..5 {
		if k > 0 {
			print!(" ");
		}
		print!("{}", s2_total.vec[0].coeffs[k]);
	}
	println!("]");

	// Dump PK t1
	let poly_t1 = pk.t1.get(0);
	print!("PK t1[0][0..5]: [");
	for k in 0..5 {
		if k > 0 {
			print!(" ");
		}
		print!("{}", poly_t1.get(k).value());
	}
	println!("]");

	print!("PK rho: ");
	for b in &pk.rho {
		print!("{:02x}", b);
	}
	println!();

	print!("PK tr: ");
	for b in &pk.tr {
		print!("{:02x}", b);
	}
	println!();
}
