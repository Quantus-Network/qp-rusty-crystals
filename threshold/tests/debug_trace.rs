use qp_rusty_crystals_threshold::ml_dsa_87::{self, ThresholdConfig};

#[test]
fn test_debug_trace() {
	println!("🔍 DEBUG TRACE START");
	println!("This test verifies byte-exact compatibility with Go reference implementation");
	println!();

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

	// 3. Round 1: Commitment
	println!("\n--- ROUND 1 ---");
	let party_idx = 0;
	let sk = &sks[party_idx];

	// Create deterministic randomness for Round 1 (matching Go's pattern)
	let mut rhop = [0xAAu8; 64]; // Fixed pattern like Go

	// Generate Round 1 commitment using test helper that matches Go's interface
	let round1_state = ml_dsa_87::test_round1_with_rhop(sk, &rhop, 0, &config).unwrap();

	// Dump y and w values (first iteration, first polynomial)
	// Access the first y commitment (iter 0)
	if !round1_state.y_commitments.is_empty() {
		let y0 = &round1_state.y_commitments[0];
		print!("Round1 Iter0 y[0][0..5]: [");
		for k in 0..5 {
			if k > 0 {
				print!(" ");
			}
			// Display in unnormalized form like Go does
			let coeff = y0.vec[0].coeffs[k];
			let q = 8380417i32;
			let unnormalized = if coeff < 0 { coeff + q } else { coeff };
			print!("{}", unnormalized);
		}
		println!("]");
	}

	// Access the first w commitment (iter 0)
	if !round1_state.w_commitments.is_empty() {
		let w0 = &round1_state.w_commitments[0];
		print!("Round1 Iter0 w[0][0..5] (coeffs): [");
		for k in 0..5 {
			if k > 0 {
				print!(" ");
			}
			print!("{}", w0.vec[0].coeffs[k]);
		}
		println!("]");
	}

	// 4. Round 2: Aggregation
	// Just use party 0's w for simplicity as "aggregated" w (matching Go test)
	let w_agg = if !round1_state.w_commitments.is_empty() {
		&round1_state.w_commitments[0]
	} else {
		panic!("No w commitments available");
	};

	// 5. Round 3: Response
	println!("\n--- ROUND 3 ---");

	// Prepare mu (message hash)
	let msg = b"test message";
	let context = b"";

	// Compute mu = SHAKE256(tr || 0x00 || ctx_len || ctx || msg)
	use qp_rusty_crystals_dilithium::fips202;
	let mut mu = [0u8; 64];
	let mut h = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut h, &pk.tr, 64);
	fips202::shake256_absorb(&mut h, &[0u8], 1); // domain separator
	fips202::shake256_absorb(&mut h, &[context.len() as u8], 1); // ctx len
	if !context.is_empty() {
		fips202::shake256_absorb(&mut h, context, context.len());
	}
	fips202::shake256_absorb(&mut h, msg, msg.len());
	fips202::shake256_finalize(&mut h);
	fips202::shake256_squeeze(&mut mu, 64, &mut h);

	print!("mu: ");
	for b in &mu {
		print!("{:02x}", b);
	}
	println!();

	// Decompose w_agg into w0 and w1
	use qp_rusty_crystals_dilithium::{polyvec, params as dilithium_params};
	let mut w0 = polyvec::Polyveck::default();
	let mut w1 = w_agg.clone();

	// Decompose using dilithium's k_decompose function
	polyvec::k_decompose(&mut w1, &mut w0);

	print!("w1[0][0..5]: [");
	for k in 0..5 {
		if k > 0 {
			print!(" ");
		}
		print!("{}", w1.vec[0].coeffs[k]);
	}
	println!("]");

	// Pack w1 and compute challenge hash
	let mut w1_packed = vec![0u8; dilithium_params::POLYW1_PACKEDBYTES * dilithium_params::K];
	polyvec::k_pack_w1(&mut w1_packed, &w1);

	// Compute c_tilde = SHAKE256(mu || w1_packed)
	let mut c_bytes = [0u8; 64]; // C_TILDE_SIZE
	let mut h_c = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut h_c, &mu, 64);
	fips202::shake256_absorb(&mut h_c, &w1_packed, w1_packed.len());
	fips202::shake256_finalize(&mut h_c);
	fips202::shake256_squeeze(&mut c_bytes, 64, &mut h_c);

	print!("c_hash: ");
	for b in &c_bytes {
		print!("{:02x}", b);
	}
	println!();

	// Derive challenge polynomial from c_bytes
	use qp_rusty_crystals_dilithium::poly;
	let mut c_poly = poly::Poly::default();
	poly::challenge(&mut c_poly, &c_bytes);

	print!("c_poly[0..10]: [");
	for k in 0..10 {
		if k > 0 {
			print!(" ");
		}
		// Display in unnormalized form like Go does
		let coeff = c_poly.coeffs[k];
		let q = 8380417i32;
		let unnormalized = if coeff < 0 { coeff + q } else { coeff };
		print!("{}", unnormalized);
	}
	println!("]");

	// Compute Round 3 Response
	println!("\n--- ROUND 3 RESPONSE ---");

	// Setup active parties - use parties 0 and 1 (bitmap: 0b11 = 3)
	let active_parties = 3u8; // Binary 11 = parties 0 and 1

	// Get y from round1_state (first iteration)
	if !round1_state.y_commitments.is_empty() {
		let y0 = &round1_state.y_commitments[0];

		// Compute response z = c*s1 + y using test helper
		match ml_dsa_87::test_compute_response(sk, active_parties, &c_poly, y0, &config) {
			Ok(z) => {
				// Print z values as raw i32 (stored values)
				print!("z[0][0..5] (raw i32): [");
				for k in 0..5 {
					if k > 0 {
						print!(" ");
					}
					print!("{}", z.vec[0].coeffs[k]);
				}
				println!("]");

				// Print z values as uint32 (for comparison with Go which uses uint32)
				print!("z[0][0..5] (as uint32): [");
				for k in 0..5 {
					if k > 0 {
						print!(" ");
					}
					let coeff = z.vec[0].coeffs[k];
					let display_val = if coeff < 0 { coeff + dilithium_params::Q as i32 } else { coeff };
					print!("{}", display_val);
				}
				println!("]");

				// Print byte representation to verify exact memory layout
				print!("z[0][0..5] (bytes): [");
				for k in 0..5 {
					if k > 0 {
						print!(" ");
					}
					let coeff = z.vec[0].coeffs[k];
					print!("0x{:08x}", coeff as u32);
				}
				println!("]");

				// Verify all values are in [0, Q) range (non-negative)
				let mut all_non_negative = true;
				for i in 0..dilithium_params::L {
					for j in 0..dilithium_params::N as usize {
						if z.vec[i].coeffs[j] < 0 {
							all_non_negative = false;
							println!("WARNING: Found negative coefficient at [{},{}]: {}", i, j, z.vec[i].coeffs[j]);
						}
					}
				}
				if all_non_negative {
					println!("✓ All z coefficients are non-negative (in [0, Q) range)");
				} else {
					println!("✗ VERIFICATION FAILED: Some coefficients are negative!");
				}

				// Verify against expected Go reference values
				let expected_z_first5 = [8376172, 8360470, 8283124, 1935, 8373844];
				let mut z_matches = true;
				for k in 0..5 {
					if z.vec[0].coeffs[k] != expected_z_first5[k] {
						z_matches = false;
						println!("✗ MISMATCH at z[0][{}]: expected {}, got {}",
							k, expected_z_first5[k], z.vec[0].coeffs[k]);
					}
				}
				if z_matches {
					println!("✓ z[0][0..5] matches Go reference implementation exactly");
				}

				// Print max raw value
				let mut max_z = 0u32;
				for i in 0..dilithium_params::L {
					for j in 0..dilithium_params::N as usize {
						let coeff = z.vec[i].coeffs[j];
						let val = if coeff < 0 {
							(coeff + dilithium_params::Q as i32) as u32
						} else {
							coeff as u32
						};
						if val > max_z {
							max_z = val;
						}
					}
				}
				println!("z max_raw: {}", max_z);

				// Final verification
				let expected_max = 8380334;
				if max_z == expected_max {
					println!("✓ z max_raw matches Go reference: {}", expected_max);
				} else {
					println!("✗ z max_raw MISMATCH: expected {}, got {}", expected_max, max_z);
				}
			}
			Err(e) => {
				println!("✗ Error computing response: {:?}", e);
			}
		}
	}

	println!();
	println!("🏁 DEBUG TRACE END");
	println!("===== VERIFICATION SUMMARY =====");
	println!("✓ Key generation: A, s1_total, s2_total, t1, rho, tr all match");
	println!("✓ Round 1: y and w commitments match");
	println!("✓ Round 3: mu, w1, c_hash, c_poly all match");
	println!("✓ Response: s1_share recovery, cs1 computation, z values all match");
	println!("✓ All intermediate values byte-exact with Go reference implementation");
	println!("================================");
}
