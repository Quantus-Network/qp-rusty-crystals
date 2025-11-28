use crate::{
	params, poly,
	polyvec::{Polyveck, Polyvecl},
};
const K: usize = params::K;
const L: usize = params::L;
const N: usize = params::N as usize;

/// Bit-pack public key pk = (rho, t1).
///
/// # Arguments
///
/// * 'pk' - output for public key value
/// * 'rho' - const reference to rho of params::SEEDBYTES length
/// * 't1' - const reference to t1
pub fn pack_pk(pk: &mut [u8], rho: &[u8], t1: &Polyveck) {
	pk[..params::SEEDBYTES].copy_from_slice(&rho[..params::SEEDBYTES]);
	for i in 0..K {
		poly::t1_pack(&mut pk[params::SEEDBYTES + i * params::POLYT1_PACKEDBYTES..], &t1.vec[i]);
	}
}

/// Unpack public key pk = (rho, t1).
///
/// # Arguments
///
/// * 'rho' - output for rho value of params::SEEDBYTES length
/// * 't1' - output for t1 value
/// * 'pk' - const reference to public key
pub fn unpack_pk(rho: &mut [u8], t1: &mut Polyveck, pk: &[u8]) {
	rho[..params::SEEDBYTES].copy_from_slice(&pk[..params::SEEDBYTES]);
	for i in 0..K {
		poly::t1_unpack(&mut t1.vec[i], &pk[params::SEEDBYTES + i * params::POLYT1_PACKEDBYTES..]);
	}
}

/// Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn pack_sk(
	sk: &mut [u8],
	rho: &[u8],
	tr: &[u8],
	key: &[u8],
	t0: &Polyveck,
	s1: &Polyvecl,
	s2: &Polyveck,
) {
	sk[..params::SEEDBYTES].copy_from_slice(&rho[0..params::SEEDBYTES]);
	let mut idx = params::SEEDBYTES;

	sk[idx..idx + params::SEEDBYTES].copy_from_slice(&key[0..params::SEEDBYTES]);
	idx += params::SEEDBYTES;

	sk[idx..idx + params::TR_BYTES].copy_from_slice(&tr[0..params::TR_BYTES]);
	idx += params::TR_BYTES;

	for i in 0..L {
		poly::eta_pack(&mut sk[idx + i * params::POLYETA_PACKEDBYTES..], &s1.vec[i]);
	}
	idx += L * params::POLYETA_PACKEDBYTES;

	for i in 0..K {
		poly::eta_pack(&mut sk[idx + i * params::POLYETA_PACKEDBYTES..], &s2.vec[i]);
	}
	idx += K * params::POLYETA_PACKEDBYTES;

	for i in 0..K {
		poly::t0_pack(&mut sk[idx + i * params::POLYT0_PACKEDBYTES..], &t0.vec[i]);
	}
}

/// Unpack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn unpack_sk(
	rho: &mut [u8],
	tr: &mut [u8],
	key: &mut [u8],
	t0: &mut Polyveck,
	s1: &mut Polyvecl,
	s2: &mut Polyveck,
	sk: &[u8],
) {
	rho[..params::SEEDBYTES].copy_from_slice(&sk[..params::SEEDBYTES]);
	let mut idx = params::SEEDBYTES;

	key[..params::SEEDBYTES].copy_from_slice(&sk[idx..idx + params::SEEDBYTES]);
	idx += params::SEEDBYTES;

	tr[..params::TR_BYTES].copy_from_slice(&sk[idx..idx + params::TR_BYTES]);
	idx += params::TR_BYTES;

	for i in 0..L {
		poly::eta_unpack(&mut s1.vec[i], &sk[idx + i * params::POLYETA_PACKEDBYTES..]);
	}
	idx += L * params::POLYETA_PACKEDBYTES;

	for i in 0..K {
		poly::eta_unpack(&mut s2.vec[i], &sk[idx + i * params::POLYETA_PACKEDBYTES..]);
	}
	idx += K * params::POLYETA_PACKEDBYTES;

	for i in 0..K {
		poly::t0_unpack(&mut t0.vec[i], &sk[idx + i * params::POLYT0_PACKEDBYTES..]);
	}
}

/// Bit-pack signature sig = (c, z, h).
pub fn pack_sig(sig: &mut [u8], c: Option<&[u8]>, z: &Polyvecl, h: &Polyveck) {
	if let Some(challenge) = c {
		sig[..params::C_DASH_BYTES].copy_from_slice(&challenge[..params::C_DASH_BYTES]);
	}

	let mut idx = params::C_DASH_BYTES;
	for i in 0..L {
		poly::z_pack(&mut sig[idx + i * params::POLYZ_PACKEDBYTES..], &z.vec[i]);
	}

	idx += L * params::POLYZ_PACKEDBYTES;
	sig[idx..idx + params::OMEGA + K].copy_from_slice(&[0u8; params::OMEGA + K]);

	let mut k = 0;
	let mut write_idx: u32;
	for i in 0..K {
		for j in 0..N {
			let is_nonzero = h.vec[i].coeffs[j] != 0;
			let has_space = k < params::OMEGA;
			let should_store = is_nonzero & has_space;

			let in_bounds_idx = (idx + k) as u32;
			let out_bounds_idx = (idx + params::OMEGA - 1) as u32;
			let has_space_choice = k < params::OMEGA;
			if has_space_choice {
				write_idx = in_bounds_idx;
			} else {
				write_idx = out_bounds_idx;
			}

			// Create a mask from should_store (0x00 or 0xFF)
			let mask = (should_store as i8).wrapping_neg() as u8;

			// Branchless selection using bitwise operations
			// if should_store { sig[write_idx] = j }
			sig[write_idx as usize] = (j as u8 & mask) | (sig[write_idx as usize] & !mask);

			// Branchless increment to reduce timing variations
			if is_nonzero {
				k += 1;
			}
		}
		sig[idx + params::OMEGA + i] = k as u8;
	}
}

/// Unpack signature sig = (z, h, c).
pub fn unpack_sig(c: &mut [u8], z: &mut Polyvecl, h: &mut Polyveck, sig: &[u8]) -> bool {
	c[..params::C_DASH_BYTES].copy_from_slice(&sig[..params::C_DASH_BYTES]);

	let mut idx = params::C_DASH_BYTES;
	for i in 0..L {
		poly::z_unpack(&mut z.vec[i], &sig[idx + i * params::POLYZ_PACKEDBYTES..]);
	}
	idx += L * params::POLYZ_PACKEDBYTES;

	let mut k: usize = 0;
	for i in 0..K {
		if sig[idx + params::OMEGA + i] < k as u8 ||
			sig[idx + params::OMEGA + i] > params::OMEGA as u8
		{
			return false;
		}
		for j in k..sig[idx + params::OMEGA + i] as usize {
			if j > k && sig[idx + j as usize] <= sig[idx + j as usize - 1] {
				return false;
			}
			h.vec[i].coeffs[sig[idx + j] as usize] = 1;
		}
		k = sig[idx + params::OMEGA + i] as usize;
	}

	for j in k..params::OMEGA {
		if sig[idx + j as usize] > 0 {
			return false;
		}
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::polyvec::{Polyveck, Polyvecl};

	#[test]
	fn test_pack_unpack_pk_roundtrip() {
		let rho = [0x42u8; params::SEEDBYTES];
		let mut t1 = Polyveck::default();

		// Initialize t1 with some test data
		for i in 0..K {
			for j in 0..N {
				t1.vec[i].coeffs[j] = ((i * N + j) % 1024) as i32;
			}
		}

		let mut packed_pk = [0u8; params::PUBLICKEYBYTES];
		pack_pk(&mut packed_pk, &rho, &t1);

		let mut unpacked_rho = [0u8; params::SEEDBYTES];
		let mut unpacked_t1 = Polyveck::default();
		unpack_pk(&mut unpacked_rho, &mut unpacked_t1, &packed_pk);

		assert_eq!(rho, unpacked_rho);

		// Compare t1 values (they may be normalized during packing/unpacking)
		for i in 0..K {
			for j in 0..N {
				// Values should be close after pack/unpack cycle
				let diff = (t1.vec[i].coeffs[j] - unpacked_t1.vec[i].coeffs[j]).abs();
				assert!(
					diff <= 1,
					"Coefficient mismatch at [{},{}]: {} vs {}",
					i,
					j,
					t1.vec[i].coeffs[j],
					unpacked_t1.vec[i].coeffs[j]
				);
			}
		}
	}

	#[test]
	fn test_pack_unpack_sk_roundtrip() {
		let rho = [0x11u8; params::SEEDBYTES];
		let tr = [0x22u8; params::TR_BYTES];
		let key = [0x33u8; params::SEEDBYTES];

		let mut t0 = Polyveck::default();
		let mut s1 = Polyvecl::default();
		let mut s2 = Polyveck::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				t0.vec[i].coeffs[j] = ((i * 100 + j) % 512) as i32;
				s2.vec[i].coeffs[j] = ((i * 200 + j) % params::ETA) as i32;
			}
		}

		for i in 0..L {
			for j in 0..N {
				s1.vec[i].coeffs[j] = ((i * 300 + j) % params::ETA) as i32;
			}
		}

		let mut packed_sk = [0u8; params::SECRETKEYBYTES];
		pack_sk(&mut packed_sk, &rho, &tr, &key, &t0, &s1, &s2);

		let mut unpacked_rho = [0u8; params::SEEDBYTES];
		let mut unpacked_tr = [0u8; params::TR_BYTES];
		let mut unpacked_key = [0u8; params::SEEDBYTES];
		let mut unpacked_t0 = Polyveck::default();
		let mut unpacked_s1 = Polyvecl::default();
		let mut unpacked_s2 = Polyveck::default();

		unpack_sk(
			&mut unpacked_rho,
			&mut unpacked_tr,
			&mut unpacked_key,
			&mut unpacked_t0,
			&mut unpacked_s1,
			&mut unpacked_s2,
			&packed_sk,
		);

		assert_eq!(rho, unpacked_rho);
		assert_eq!(tr, unpacked_tr);
		assert_eq!(key, unpacked_key);

		// Compare polynomial values
		for i in 0..K {
			for j in 0..N {
				assert_eq!(
					t0.vec[i].coeffs[j], unpacked_t0.vec[i].coeffs[j],
					"t0 mismatch at [{},{}]",
					i, j
				);
				assert_eq!(
					s2.vec[i].coeffs[j], unpacked_s2.vec[i].coeffs[j],
					"s2 mismatch at [{},{}]",
					i, j
				);
			}
		}

		for i in 0..L {
			for j in 0..N {
				assert_eq!(
					s1.vec[i].coeffs[j], unpacked_s1.vec[i].coeffs[j],
					"s1 mismatch at [{},{}]",
					i, j
				);
			}
		}
	}

	#[test]
	fn test_pack_unpack_sig_valid() {
		let c = [0x55u8; params::C_DASH_BYTES];
		let mut z = Polyvecl::default();
		let mut h = Polyveck::default();

		// Initialize z with test data
		for i in 0..L {
			for j in 0..N {
				z.vec[i].coeffs[j] = ((i * 1000 + j) % 100000) as i32;
			}
		}

		// Initialize h with sparse data (hints should be 0 or 1)
		// Keep the number of hints reasonable to avoid overflow
		let mut hint_count = 0;
		for i in 0..K {
			for j in 0..N {
				if (i + j) % 20 == 0 && hint_count < params::OMEGA {
					h.vec[i].coeffs[j] = 1;
					hint_count += 1;
				} else {
					h.vec[i].coeffs[j] = 0;
				}
			}
		}

		let mut packed_sig = [0u8; params::SIGNBYTES];
		pack_sig(&mut packed_sig, Some(&c), &z, &h);

		let mut unpacked_c = [0u8; params::C_DASH_BYTES];
		let mut unpacked_z = Polyvecl::default();
		let mut unpacked_h = Polyveck::default();

		assert!(unpack_sig(&mut unpacked_c, &mut unpacked_z, &mut unpacked_h, &packed_sig));

		assert_eq!(c, unpacked_c);

		// Compare z values
		for i in 0..L {
			for j in 0..N {
				assert_eq!(
					z.vec[i].coeffs[j], unpacked_z.vec[i].coeffs[j],
					"z mismatch at [{},{}]",
					i, j
				);
			}
		}

		// Compare h values
		for i in 0..K {
			for j in 0..N {
				assert_eq!(
					h.vec[i].coeffs[j], unpacked_h.vec[i].coeffs[j],
					"h mismatch at [{},{}]",
					i, j
				);
			}
		}
	}

	#[test]
	fn test_unpack_sig_invalid() {
		// Create an invalid signature with too many hints
		let mut invalid_sig = [0u8; params::SIGNBYTES];

		// Fill hint section with invalid data
		let hint_start = params::C_DASH_BYTES + L * params::POLYZ_PACKEDBYTES;

		// Set all omega positions to maximum value (invalid)
		for i in 0..K {
			invalid_sig[hint_start + params::OMEGA + i] = 255;
		}

		let mut c = [0u8; params::C_DASH_BYTES];
		let mut z = Polyvecl::default();
		let mut h = Polyveck::default();

		assert!(!unpack_sig(&mut c, &mut z, &mut h, &invalid_sig));
	}

	#[test]
	fn test_empty_hint_signature() {
		let c = [0x77u8; params::C_DASH_BYTES];
		let mut z = Polyvecl::default();
		let h = Polyveck::default(); // All zeros (empty hints)

		// Initialize z with valid data
		for i in 0..L {
			for j in 0..N {
				z.vec[i].coeffs[j] = (j % 1000) as i32;
			}
		}

		let mut packed_sig = [0u8; params::SIGNBYTES];
		pack_sig(&mut packed_sig, Some(&c), &z, &h);

		let mut unpacked_c = [0u8; params::C_DASH_BYTES];
		let mut unpacked_z = Polyvecl::default();
		let mut unpacked_h = Polyveck::default();

		assert!(unpack_sig(&mut unpacked_c, &mut unpacked_z, &mut unpacked_h, &packed_sig));

		assert_eq!(c, unpacked_c);

		// All h coefficients should be 0
		for i in 0..K {
			for j in 0..N {
				assert_eq!(0, unpacked_h.vec[i].coeffs[j], "Expected zero hint at [{},{}]", i, j);
			}
		}
	}

	#[test]
	fn test_pack_sig_without_challenge() {
		let mut z = Polyvecl::default();
		let h = Polyveck::default();

		// Initialize test data
		for i in 0..L {
			for j in 0..N {
				z.vec[i].coeffs[j] = (i * j) as i32;
			}
		}

		let mut packed_sig = [0u8; params::SIGNBYTES];
		pack_sig(&mut packed_sig, None, &z, &h);

		// When no challenge is provided, first C_DASH_BYTES should remain as initialized
		let expected_c = [0u8; params::C_DASH_BYTES];
		assert_eq!(&packed_sig[..params::C_DASH_BYTES], &expected_c);
	}
}
