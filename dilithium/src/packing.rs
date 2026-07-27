use crate::{params, poly, polyvec::Polyvec};

const N: usize = params::N as usize;

/// Bit-pack public key pk = (rho, t1).
///
/// Generic over the variant's row count `K`; `PK` is the packed public key
/// size, checked against `K` at compile time.
///
/// # Arguments
///
/// * 'pk' - output buffer for public key (PUBLICKEYBYTES)
/// * 'rho' - const reference to rho of SEEDBYTES length
/// * 't1' - const reference to t1
pub fn pack_pk<const K: usize, const PK: usize>(
	pk: &mut [u8; PK],
	rho: &[u8; params::SEEDBYTES],
	t1: &Polyvec<K>,
) {
	const {
		assert!(PK == params::publickeybytes(K));
	}
	pk[..params::SEEDBYTES].copy_from_slice(rho);
	for i in 0..K {
		poly::t1_pack(&mut pk[params::SEEDBYTES + i * params::POLYT1_PACKEDBYTES..], &t1.vec[i]);
	}
}

/// Unpack public key pk = (rho, t1).
///
/// # Arguments
///
/// * 'rho' - output for rho value of SEEDBYTES length
/// * 't1' - output for t1 value
/// * 'pk' - const reference to public key
pub fn unpack_pk<const K: usize, const PK: usize>(
	rho: &mut [u8; params::SEEDBYTES],
	t1: &mut Polyvec<K>,
	pk: &[u8; PK],
) {
	const {
		assert!(PK == params::publickeybytes(K));
	}
	rho.copy_from_slice(&pk[..params::SEEDBYTES]);
	for i in 0..K {
		poly::t1_unpack(&mut t1.vec[i], &pk[params::SEEDBYTES + i * params::POLYT1_PACKEDBYTES..]);
	}
}

/// Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
///
/// Generic over the variant's `K`/`L`/`ETA`; `SK` is the packed secret key
/// size, checked for consistency at compile time.
pub fn pack_sk<const K: usize, const L: usize, const ETA: usize, const SK: usize>(
	sk: &mut [u8; SK],
	rho: &[u8; params::SEEDBYTES],
	tr: &[u8; params::TR_BYTES],
	key: &[u8; params::SEEDBYTES],
	t0: &Polyvec<K>,
	s1: &Polyvec<L>,
	s2: &Polyvec<K>,
) {
	const {
		assert!(SK == params::secretkeybytes(K, L, ETA));
	}
	let peta = params::polyeta_packedbytes(ETA);

	sk[..params::SEEDBYTES].copy_from_slice(rho);
	let mut idx = params::SEEDBYTES;

	sk[idx..idx + params::SEEDBYTES].copy_from_slice(key);
	idx += params::SEEDBYTES;

	sk[idx..idx + params::TR_BYTES].copy_from_slice(tr);
	idx += params::TR_BYTES;

	for i in 0..L {
		poly::eta_pack::<ETA>(&mut sk[idx + i * peta..], &s1.vec[i]);
	}
	idx += L * peta;

	for i in 0..K {
		poly::eta_pack::<ETA>(&mut sk[idx + i * peta..], &s2.vec[i]);
	}
	idx += K * peta;

	for i in 0..K {
		poly::t0_pack(&mut sk[idx + i * params::POLYT0_PACKEDBYTES..], &t0.vec[i]);
	}
}

/// Unpack secret key sk = (rho, key, tr, s1, s2, t0).
///
/// Returns `false` if the packed `s1`/`s2` regions contain a non-canonical
/// eta slot — an encoding that would decode to a coefficient outside
/// `[-ETA, ETA]`, which key generation never emits and which lies outside
/// the key distribution the signing rejection margin (`BETA = TAU * ETA`)
/// is sized for. All output buffers are fully written either way; callers
/// must treat the unpacked values as invalid when `false` is returned.
#[must_use]
pub fn unpack_sk<const K: usize, const L: usize, const ETA: usize, const SK: usize>(
	rho: &mut [u8; params::SEEDBYTES],
	tr: &mut [u8; params::TR_BYTES],
	key: &mut [u8; params::SEEDBYTES],
	t0: &mut Polyvec<K>,
	s1: &mut Polyvec<L>,
	s2: &mut Polyvec<K>,
	sk: &[u8; SK],
) -> bool {
	const {
		assert!(SK == params::secretkeybytes(K, L, ETA));
	}
	let peta = params::polyeta_packedbytes(ETA);

	rho.copy_from_slice(&sk[..params::SEEDBYTES]);
	let mut idx = params::SEEDBYTES;

	key.copy_from_slice(&sk[idx..idx + params::SEEDBYTES]);
	idx += params::SEEDBYTES;

	tr.copy_from_slice(&sk[idx..idx + params::TR_BYTES]);
	idx += params::TR_BYTES;

	// Accumulate with `&` rather than short-circuiting so every polynomial is
	// unpacked and checked regardless of earlier results (data-independent
	// control flow; honest keys always pass anyway).
	let mut canonical = true;
	for i in 0..L {
		canonical &= poly::eta_unpack::<ETA>(&mut s1.vec[i], &sk[idx + i * peta..]);
	}
	idx += L * peta;

	for i in 0..K {
		canonical &= poly::eta_unpack::<ETA>(&mut s2.vec[i], &sk[idx + i * peta..]);
	}
	idx += K * peta;

	for i in 0..K {
		poly::t0_unpack(&mut t0.vec[i], &sk[idx + i * params::POLYT0_PACKEDBYTES..]);
	}

	canonical
}

/// Bit-pack signature sig = (c, z, h).
///
/// Generic over the variant's `K`/`L`/`GAMMA1`/`OMEGA`; `CD` is the challenge
/// size (lambda/4), `PZ` the packed size of one `z` polynomial, and `SIG` the
/// total signature size, all checked for consistency at compile time.
pub fn pack_sig<
	const K: usize,
	const L: usize,
	const GAMMA1: usize,
	const OMEGA: usize,
	const CD: usize,
	const PZ: usize,
	const SIG: usize,
>(
	sig: &mut [u8; SIG],
	c: Option<&[u8; CD]>,
	z: &Polyvec<L>,
	h: &Polyvec<K>,
) {
	const {
		assert!(PZ == params::polyz_packedbytes(GAMMA1));
		assert!(SIG == params::signbytes(K, L, GAMMA1, OMEGA, CD));
	}
	if let Some(challenge) = c {
		sig[..CD].copy_from_slice(challenge);
	}

	let mut idx = CD;
	// `as_chunks_mut` splits the buffer into exact-size `&mut [u8; PZ]`
	// arrays, so no per-polynomial length check or fallible conversion is needed.
	let (z_chunks, _) = sig[idx..].as_chunks_mut::<PZ>();
	for (chunk, zi) in z_chunks.iter_mut().zip(z.vec.iter()).take(L) {
		poly::z_pack::<GAMMA1, PZ>(chunk, zi);
	}

	idx += L * PZ;
	sig[idx..idx + OMEGA + K].fill(0);

	// Branchless hint packing: the hint pattern is secret on rejected attempts, so no
	// data-dependent branches. The write index is clamped with `min` (conditional move) and
	// the store is masked; the counter advances with arithmetic instead of a branch.
	let mut k: usize = 0;
	for i in 0..K {
		for j in 0..N {
			let is_nonzero = h.vec[i].coeffs[j] != 0;
			let has_space = k < OMEGA;
			let should_store = is_nonzero & has_space;

			let write_idx = idx + k.min(OMEGA - 1);

			// Create a mask from should_store (0x00 or 0xFF)
			let mask = (should_store as i8).wrapping_neg() as u8;

			// if should_store { sig[write_idx] = j }
			sig[write_idx] = (j as u8 & mask) | (sig[write_idx] & !mask);

			k += is_nonzero as usize;
		}
		sig[idx + OMEGA + i] = k as u8;
	}
}

/// Unpack signature sig = (z, h, c).
///
/// The hint vector is sparse: only the coefficients listed in the encoded hint
/// section are set to 1. `h` is therefore zeroed on entry so the output represents
/// only the current signature — otherwise a reused (or attacker-poisoned) `h`
/// buffer would retain stale hint bits from a previous parse, letting a signature
/// that encodes fewer/zero hints verify or canonicalize against hidden data.
pub fn unpack_sig<
	const K: usize,
	const L: usize,
	const GAMMA1: usize,
	const OMEGA: usize,
	const CD: usize,
	const PZ: usize,
	const SIG: usize,
>(
	c: &mut [u8; CD],
	z: &mut Polyvec<L>,
	h: &mut Polyvec<K>,
	sig: &[u8; SIG],
) -> bool {
	const {
		assert!(PZ == params::polyz_packedbytes(GAMMA1));
		assert!(SIG == params::signbytes(K, L, GAMMA1, OMEGA, CD));
	}
	// Overwrite, don't merge: clear any prior hint bits before decoding this signature.
	*h = Polyvec::<K>::default();

	c.copy_from_slice(&sig[..CD]);

	let mut idx = CD;
	// Exact-size chunks: each `&[u8; PZ]` is produced by the split,
	// so a truncated per-polynomial slice can't reach `z_unpack`.
	let (z_chunks, _) = sig[idx..].as_chunks::<PZ>();
	for (chunk, zi) in z_chunks.iter().zip(z.vec.iter_mut()).take(L) {
		poly::z_unpack::<GAMMA1, PZ>(zi, chunk);
	}
	idx += L * PZ;

	let mut k: usize = 0;
	for i in 0..K {
		if sig[idx + OMEGA + i] < k as u8 || sig[idx + OMEGA + i] > OMEGA as u8 {
			return false;
		}
		for j in k..sig[idx + OMEGA + i] as usize {
			if j > k && sig[idx + j as usize] <= sig[idx + j as usize - 1] {
				return false;
			}
			h.vec[i].coeffs[sig[idx + j] as usize] = 1;
		}
		k = sig[idx + OMEGA + i] as usize;
	}

	for j in k..OMEGA {
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

	const K: usize = params::K;
	const L: usize = params::L;

	// The generic pack/unpack functions pinned to the ML-DSA-87 parameters.
	// These shadow the glob-imported generics so the test bodies below read
	// exactly as they did when the module was single-variant.
	fn pack_sk(
		sk: &mut [u8; params::SECRETKEYBYTES],
		rho: &[u8; params::SEEDBYTES],
		tr: &[u8; params::TR_BYTES],
		key: &[u8; params::SEEDBYTES],
		t0: &Polyveck,
		s1: &Polyvecl,
		s2: &Polyveck,
	) {
		super::pack_sk::<K, L, { params::ETA }, { params::SECRETKEYBYTES }>(
			sk, rho, tr, key, t0, s1, s2,
		)
	}

	#[must_use]
	fn unpack_sk(
		rho: &mut [u8; params::SEEDBYTES],
		tr: &mut [u8; params::TR_BYTES],
		key: &mut [u8; params::SEEDBYTES],
		t0: &mut Polyveck,
		s1: &mut Polyvecl,
		s2: &mut Polyveck,
		sk: &[u8; params::SECRETKEYBYTES],
	) -> bool {
		super::unpack_sk::<K, L, { params::ETA }, { params::SECRETKEYBYTES }>(
			rho, tr, key, t0, s1, s2, sk,
		)
	}

	fn pack_sig(
		sig: &mut [u8; params::SIGNBYTES],
		c: Option<&[u8; params::C_DASH_BYTES]>,
		z: &Polyvecl,
		h: &Polyveck,
	) {
		super::pack_sig::<
			K,
			L,
			{ params::GAMMA1 },
			{ params::OMEGA },
			{ params::C_DASH_BYTES },
			{ params::POLYZ_PACKEDBYTES },
			{ params::SIGNBYTES },
		>(sig, c, z, h)
	}

	fn unpack_sig(
		c: &mut [u8; params::C_DASH_BYTES],
		z: &mut Polyvecl,
		h: &mut Polyveck,
		sig: &[u8; params::SIGNBYTES],
	) -> bool {
		super::unpack_sig::<
			K,
			L,
			{ params::GAMMA1 },
			{ params::OMEGA },
			{ params::C_DASH_BYTES },
			{ params::POLYZ_PACKEDBYTES },
			{ params::SIGNBYTES },
		>(c, z, h, sig)
	}

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

		assert!(
			unpack_sk(
				&mut unpacked_rho,
				&mut unpacked_tr,
				&mut unpacked_key,
				&mut unpacked_t0,
				&mut unpacked_s1,
				&mut unpacked_s2,
				&packed_sk,
			),
			"canonically packed secret key must unpack cleanly"
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

	// unpack_sig must overwrite the destination hint vector, not merge into it. A
	// reused (or attacker-poisoned) `h` buffer must not leak stale hint bits from a
	// previous parse into a later signature that encodes fewer/zero hints. Otherwise
	// direct users of the public packing API could verify or canonicalize bytes
	// against hidden hint data that is not present in the supplied signature.
	#[test]
	fn unpack_sig_clears_stale_hints_from_reused_buffer() {
		// A syntactically valid signature with an empty hint vector.
		let c = [0x99u8; params::C_DASH_BYTES];
		let z = Polyvecl::default();
		let h = Polyveck::default();
		let mut packed_sig = [0u8; params::SIGNBYTES];
		pack_sig(&mut packed_sig, Some(&c), &z, &h);

		// Reuse output buffers that already hold hint bits from a "previous" parse.
		let mut unpacked_c = [0u8; params::C_DASH_BYTES];
		let mut unpacked_z = Polyvecl::default();
		let mut unpacked_h = Polyveck::default();
		unpacked_h.vec[0].coeffs[5] = 1;
		unpacked_h.vec[K - 1].coeffs[N - 1] = 1;

		assert!(unpack_sig(&mut unpacked_c, &mut unpacked_z, &mut unpacked_h, &packed_sig));

		// The empty-hint signature must yield an all-zero hint vector: the stale bits
		// must have been cleared, not preserved.
		for i in 0..K {
			for j in 0..N {
				assert_eq!(
					0, unpacked_h.vec[i].coeffs[j],
					"stale hint survived unpack_sig at [{},{}]",
					i, j
				);
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
