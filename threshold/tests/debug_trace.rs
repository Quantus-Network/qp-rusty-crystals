use qp_rusty_crystals_threshold::ml_dsa_87::{self, ThresholdConfig};

#[test]
fn test_debug_trace() {
	// Setup: same seed as Go's TestThSignMultiKeys (all zeros)
	let seed = [0u8; 32];
	let config = ThresholdConfig::new(2, 3).unwrap();

	// Generate threshold keys
	let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config).unwrap();

	println!("PK t1[0][0..5]: [{} {} {} {} {}]",
		pk.t1.get(0).get(0).value(),
		pk.t1.get(0).get(1).value(),
		pk.t1.get(0).get(2).value(),
		pk.t1.get(0).get(3).value(),
		pk.t1.get(0).get(4).value());

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

	// Round 1: Generate commitments
	// Use all-zeros rhop to match Go's TestThSignMultiKeys (Go zero-initializes by default)
	let rhop = [0u8; 64];
	let msg = [0u8; 8];
	let context = b"";

	// Try multiple nonces to find one that produces a valid signature
	for nonce in 0..200 {
		// Generate Round 1 commitments for both parties (same rhop and nonce, matching Go)
		let (_, round1_state_party0) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop, nonce).unwrap();
		let (_, round1_state_party1) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop, nonce).unwrap();

		// Round 2: Aggregate commitments
		use qp_rusty_crystals_dilithium::{polyvec, params as dilithium_params, poly, fips202};

		let mut w_aggregated = polyvec::Polyveck::default();
		if !round1_state_party0.w_commitments.is_empty() && !round1_state_party1.w_commitments.is_empty() {
			let w0 = &round1_state_party0.w_commitments[0];
			let w1 = &round1_state_party1.w_commitments[0];

			for i in 0..dilithium_params::K {
				for j in 0..dilithium_params::N as usize {
					w_aggregated.vec[i].coeffs[j] = w0.vec[i].coeffs[j] + w1.vec[i].coeffs[j];
				}
			}

			// Normalize aggregated w
			for i in 0..dilithium_params::K {
				poly::reduce(&mut w_aggregated.vec[i]);
				for j in 0..dilithium_params::N as usize {
					let mut x = w_aggregated.vec[i].coeffs[j];
					if x < 0 {
						x += dilithium_params::Q as i32;
					}
					let y = x - dilithium_params::Q as i32;
					let mask = y >> 31;
					w_aggregated.vec[i].coeffs[j] = y + (mask & dilithium_params::Q as i32);
				}
			}
		}

		// Compute mu = SHAKE256(tr || msg) - matching Go's ComputeMu exactly
		let mut mu = [0u8; 64];
		let mut h = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut h, &pk.tr, 64);
		fips202::shake256_absorb(&mut h, &msg, msg.len());
		fips202::shake256_finalize(&mut h);
		fips202::shake256_squeeze(&mut mu, 64, &mut h);

		// Decompose aggregated w into w0 and w1
		let mut w0 = polyvec::Polyveck::default();
		let mut w1 = w_aggregated.clone();
		polyvec::k_decompose(&mut w1, &mut w0);

		// Compute challenge hash
		let mut w1_packed = vec![0u8; dilithium_params::POLYW1_PACKEDBYTES * dilithium_params::K];
		polyvec::k_pack_w1(&mut w1_packed, &w1);

		let mut c_bytes = [0u8; 64];
		let mut h_c = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut h_c, &mu, 64);
		fips202::shake256_absorb(&mut h_c, &w1_packed, w1_packed.len());
		fips202::shake256_finalize(&mut h_c);
		fips202::shake256_squeeze(&mut c_bytes, 64, &mut h_c);

		// Derive challenge polynomial
		let mut c_poly = poly::Poly::default();
		poly::challenge(&mut c_poly, &c_bytes);

		// Round 3: Compute responses
		let active_parties = 3u8; // Binary 11 = parties 0 and 1

		if round1_state_party0.hyperball_samples.is_empty() || round1_state_party1.hyperball_samples.is_empty() {
			continue;
		}

		let hyperball0 = &round1_state_party0.hyperball_samples[0];
		let hyperball1 = &round1_state_party1.hyperball_samples[0];

		let z_party0 = match ml_dsa_87::test_compute_response(&sks[0], active_parties, &c_poly, hyperball0, &config) {
			Ok(z) => z,
			Err(_) => continue,
		};

		let z_party1 = match ml_dsa_87::test_compute_response(&sks[1], active_parties, &c_poly, hyperball1, &config) {
			Ok(z) => z,
			Err(_) => continue,
		};

		// Aggregate z values
		let mut z = polyvec::Polyvecl::default();
		for i in 0..dilithium_params::L {
			for j in 0..dilithium_params::N as usize {
				z.vec[i].coeffs[j] = z_party0.vec[i].coeffs[j] + z_party1.vec[i].coeffs[j];
			}
		}

		// Normalize aggregated z
		for i in 0..dilithium_params::L {
			poly::reduce(&mut z.vec[i]);
			for j in 0..dilithium_params::N as usize {
				let mut x = z.vec[i].coeffs[j];
				if x < 0 {
					x += dilithium_params::Q as i32;
				}
				let y = x - dilithium_params::Q as i32;
				let mask = y >> 31;
				z.vec[i].coeffs[j] = y + (mask & dilithium_params::Q as i32);
			}
		}

		// Pack commitments and responses for combine_signatures
		let poly_q_size = (dilithium_params::N as usize * 23 + 7) / 8;
		let single_commitment_size = dilithium_params::K * poly_q_size;
		const POLY_LE_GAMMA1_SIZE: usize = 640;
		let single_response_size = dilithium_params::L * POLY_LE_GAMMA1_SIZE;
		let k_iterations = config.k_iterations as usize;

		let pack_w_commitment = |w: &polyvec::Polyveck| -> Vec<u8> {
			let mut packed = vec![0u8; single_commitment_size];
			for i in 0..dilithium_params::K {
				let poly_start = i * poly_q_size;
				let mut v: u32 = 0;
				let mut j: u32 = 0;
				let mut k: usize = poly_start;

				for coeff_idx in 0..dilithium_params::N as usize {
					let coeff = w.vec[i].coeffs[coeff_idx] as u32;
					v = v | (coeff << j);
					j += 23;
					while j >= 8 && k < packed.len() {
						packed[k] = (v & 0xFF) as u8;
						v >>= 8;
						j -= 8;
						k += 1;
					}
				}
			}
			packed
		};

		let pack_z_response = |z: &polyvec::Polyvecl| -> Vec<u8> {
			let mut packed = vec![0u8; single_response_size];
			const GAMMA1: u32 = dilithium_params::GAMMA1 as u32;

			for poly_idx in 0..dilithium_params::L {
				let poly_offset = poly_idx * POLY_LE_GAMMA1_SIZE;
				let p = &z.vec[poly_idx];

				let mut j = 0;
				for i in (0..POLY_LE_GAMMA1_SIZE).step_by(5) {
					let mut p0 = GAMMA1.wrapping_sub(p.coeffs[j] as u32);
					p0 = p0.wrapping_add(((p0 as i32) >> 31) as u32 & (dilithium_params::Q as u32));
					let mut p1 = GAMMA1.wrapping_sub(p.coeffs[j + 1] as u32);
					p1 = p1.wrapping_add(((p1 as i32) >> 31) as u32 & (dilithium_params::Q as u32));

					let buf_offset = poly_offset + i;
					packed[buf_offset] = (p0 & 0xFF) as u8;
					packed[buf_offset + 1] = ((p0 >> 8) & 0xFF) as u8;
					packed[buf_offset + 2] = (((p0 >> 16) & 0x0F) | ((p1 & 0x0F) << 4)) as u8;
					packed[buf_offset + 3] = ((p1 >> 4) & 0xFF) as u8;
					packed[buf_offset + 4] = ((p1 >> 12) & 0xFF) as u8;

					j += 2;
				}
			}
			packed
		};

		// Pack all K iterations
		let mut packed_commitments_party0 = vec![0u8; single_commitment_size * k_iterations];
		let mut packed_commitments_party1 = vec![0u8; single_commitment_size * k_iterations];
		let mut packed_responses_party0 = vec![0u8; single_response_size * k_iterations];
		let mut packed_responses_party1 = vec![0u8; single_response_size * k_iterations];

		for k_iter in 0..k_iterations {
			let w_start = k_iter * single_commitment_size;
			let z_start = k_iter * single_response_size;

			let w_party0_iter = &round1_state_party0.w_commitments[k_iter];
			let w_party1_iter = &round1_state_party1.w_commitments[k_iter];

			let packed_w0_iter = pack_w_commitment(w_party0_iter);
			let packed_w1_iter = pack_w_commitment(w_party1_iter);
			packed_commitments_party0[w_start..w_start + single_commitment_size].copy_from_slice(&packed_w0_iter);
			packed_commitments_party1[w_start..w_start + single_commitment_size].copy_from_slice(&packed_w1_iter);

			// Aggregate w for this iteration and compute per-iteration challenge
			let mut w_agg_iter = polyvec::Polyveck::default();
			for i in 0..dilithium_params::K {
				for j in 0..dilithium_params::N as usize {
					w_agg_iter.vec[i].coeffs[j] = w_party0_iter.vec[i].coeffs[j] + w_party1_iter.vec[i].coeffs[j];
				}
			}
			for i in 0..dilithium_params::K {
				poly::reduce(&mut w_agg_iter.vec[i]);
				for j in 0..dilithium_params::N as usize {
					let mut x = w_agg_iter.vec[i].coeffs[j];
					if x < 0 { x += dilithium_params::Q as i32; }
					let y = x - dilithium_params::Q as i32;
					let mask = y >> 31;
					w_agg_iter.vec[i].coeffs[j] = y + (mask & dilithium_params::Q as i32);
				}
			}

			let mut w0_iter = polyvec::Polyveck::default();
			let mut w1_iter = w_agg_iter.clone();
			polyvec::k_decompose(&mut w1_iter, &mut w0_iter);

			let mut w1_packed_iter = vec![0u8; dilithium_params::POLYW1_PACKEDBYTES * dilithium_params::K];
			polyvec::k_pack_w1(&mut w1_packed_iter, &w1_iter);

			let mut c_bytes_iter = [0u8; 64];
			let mut h_c_iter = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut h_c_iter, &mu, 64);
			fips202::shake256_absorb(&mut h_c_iter, &w1_packed_iter, w1_packed_iter.len());
			fips202::shake256_finalize(&mut h_c_iter);
			fips202::shake256_squeeze(&mut c_bytes_iter, 64, &mut h_c_iter);

			let mut c_poly_iter = poly::Poly::default();
			poly::challenge(&mut c_poly_iter, &c_bytes_iter);

			let hyperball0_iter = &round1_state_party0.hyperball_samples[k_iter];
			let hyperball1_iter = &round1_state_party1.hyperball_samples[k_iter];

			if let Ok(z_party0_iter) = ml_dsa_87::test_compute_response(&sks[0], active_parties, &c_poly_iter, hyperball0_iter, &config) {
				let packed_z0_iter = pack_z_response(&z_party0_iter);
				packed_responses_party0[z_start..z_start + single_response_size].copy_from_slice(&packed_z0_iter);
			}

			if let Ok(z_party1_iter) = ml_dsa_87::test_compute_response(&sks[1], active_parties, &c_poly_iter, hyperball1_iter, &config) {
				let packed_z1_iter = pack_z_response(&z_party1_iter);
				packed_responses_party1[z_start..z_start + single_response_size].copy_from_slice(&packed_z1_iter);
			}
		}

		let packed_commitments = vec![packed_commitments_party0, packed_commitments_party1];
		let packed_responses = vec![packed_responses_party0, packed_responses_party1];

		// Try to combine signatures
		let signature = match ml_dsa_87::combine_signatures(
			&pk,
			&msg,
			context,
			&packed_commitments,
			&packed_responses,
			&config,
		) {
			Ok(sig) => sig,
			Err(_) => continue,
		};

		// Verify the signature
		let dilithium_pk = match qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&pk.packed) {
			Ok(pk) => pk,
			Err(e) => {
				println!("Failed to load public key: {:?}", e);
				continue;
			}
		};

		let is_valid = dilithium_pk.verify(&msg, &signature, Some(context));

		if is_valid {
			println!("✅ SUCCESS: Threshold signature verifies on nonce {}", nonce);
			println!("   Signature size: {} bytes", signature.len());
			return;
		} else {
			println!("Signature created but verification failed on nonce {}", nonce);
		}
	}

	println!("❌ FAILED: No valid signature produced after 200 attempts");
	panic!("Threshold signature test failed");
}
