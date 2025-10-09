//! Stack-optimized ML-DSA-87 implementation
//!
//! This module provides ML-DSA-87 operations optimized for minimal stack usage
//! by moving large polynomial structures to the heap using Box<T>.
//! This enables deployment in embedded devices and blockchain applications
//! where stack space is limited.

use crate::{
	errors::{KeyParsingError, KeyParsingError::BadSecretKey},
	fips202, packing, params, poly,
	poly::Poly,
	polyvec,
	polyvec::lvl5::{Polyveck, Polyvecl},
};
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "no_std")]
extern crate alloc;
#[cfg(feature = "no_std")]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(not(feature = "no_std"))]
use std::boxed::Box;

use core::fmt;

const K: usize = params::ml_dsa_87::K;
const L: usize = params::ml_dsa_87::L;

pub const SECRETKEYBYTES: usize = params::ml_dsa_87::SECRETKEYBYTES;
pub const PUBLICKEYBYTES: usize = params::ml_dsa_87::PUBLICKEYBYTES;
pub const SIGNBYTES: usize = params::ml_dsa_87::SIGNBYTES;
pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

pub type Signature = [u8; SIGNBYTES];

/// Stack-optimized workspace for cryptographic operations
/// This structure holds all the large polynomial vectors on the heap
/// to avoid stack overflow issues.
struct CryptoWorkspace {
	// Matrix A (K x L polynomial vectors)
	mat: Box<[Polyvecl; K]>,
	// Polynomial vectors for various operations
	s1: Box<Polyvecl>,
	s2: Box<Polyveck>,
	t0: Box<Polyveck>,
	t1: Box<Polyveck>,
	y: Box<Polyvecl>,
	z: Box<Polyvecl>,
	w0: Box<Polyveck>,
	w1: Box<Polyveck>,
	h: Box<Polyveck>,
	// Single polynomial for challenges
	cp: Box<Poly>,
	// Temporary polynomials to avoid stack allocations
	temp_poly1: Box<Poly>,
}

impl CryptoWorkspace {
	fn new() -> Self {
		Self {
			mat: Box::new([Polyvecl::default(); K]),
			s1: Box::new(Polyvecl::default()),
			s2: Box::new(Polyveck::default()),
			t0: Box::new(Polyveck::default()),
			t1: Box::new(Polyveck::default()),
			y: Box::new(Polyvecl::default()),
			z: Box::new(Polyvecl::default()),
			w0: Box::new(Polyveck::default()),
			w1: Box::new(Polyveck::default()),
			h: Box::new(Polyveck::default()),
			cp: Box::new(Poly::default()),
			temp_poly1: Box::new(Poly::default()),
		}
	}
}

/// A pair of private and public keys.
#[derive(Clone)]
pub struct Keypair {
	pub secret: SecretKey,
	pub public: PublicKey,
}

impl Keypair {
	/// Generate a Keypair instance with minimal stack usage.
	pub fn generate(entropy: Option<&[u8]>) -> Keypair {
		let mut pk = [0u8; PUBLICKEYBYTES];
		let mut sk = [0u8; SECRETKEYBYTES];
		keypair(&mut pk, &mut sk, entropy);
		Keypair {
			secret: SecretKey::from_bytes(&sk).expect("Should never fail"),
			public: PublicKey::from_bytes(&pk).expect("Should never fail"),
		}
	}

	/// Convert a Keypair to a bytes array.
	pub fn to_bytes(&self) -> [u8; KEYPAIRBYTES] {
		let mut result = [0u8; KEYPAIRBYTES];
		result[..SECRETKEYBYTES].copy_from_slice(&self.secret.to_bytes());
		result[SECRETKEYBYTES..].copy_from_slice(&self.public.to_bytes());
		result
	}

	/// Create a Keypair from bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, KeyParsingError> {
		if bytes.len() != SECRETKEYBYTES + PUBLICKEYBYTES {
			return Err(KeyParsingError::BadKeypair);
		}
		let (secret_bytes, public_bytes) = bytes.split_at(SECRETKEYBYTES);
		let secret =
			SecretKey::from_bytes(secret_bytes).map_err(|_| KeyParsingError::BadKeypair)?;
		let public =
			PublicKey::from_bytes(public_bytes).map_err(|_| KeyParsingError::BadKeypair)?;
		Ok(Keypair { secret, public })
	}

	/// Compute a signature for a given message with minimal stack usage.
	pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Signature {
		self.secret.sign(msg, ctx, hedged)
	}

	/// Verify a signature for a given message with a public key.
	pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
		self.public.verify(msg, sig, ctx)
	}

	/// Compute a signature for a given message (prehash version).
	#[cfg(not(feature = "no_std"))]
	pub fn prehash_sign(
		&self,
		msg: &[u8],
		ctx: Option<&[u8]>,
		hedged: bool,
		ph: crate::PH,
	) -> Option<Signature> {
		self.secret.prehash_sign(msg, ctx, hedged, ph)
	}

	/// Verify a signature for a given message with a public key (prehash version).
	pub fn prehash_verify(
		&self,
		msg: &[u8],
		sig: &[u8],
		ctx: Option<&[u8]>,
		ph: crate::PH,
	) -> bool {
		self.public.prehash_verify(msg, sig, ctx, ph)
	}
}

impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair").field("public", &self.public).finish()
	}
}

/// Private key.
#[derive(Clone)]
pub struct SecretKey {
	pub bytes: [u8; SECRETKEYBYTES],
}

impl SecretKey {
	/// Returns a copy of underlying bytes.
	pub fn to_bytes(&self) -> [u8; SECRETKEYBYTES] {
		self.bytes
	}

	/// Create a SecretKey from bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, KeyParsingError> {
		let result = bytes.try_into();
		match result {
			Ok(bytes) => Ok(SecretKey { bytes }),
			Err(_) => Err(BadSecretKey),
		}
	}

	/// Compute a signature for a given message with minimal stack usage.
	pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedged: bool) -> Signature {
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					panic!("ctx length must not be larger than 255");
				}
				let x_len = x.len();
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2 + x_len];
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..].copy_from_slice(msg);
				let mut sig: Signature = [0u8; SIGNBYTES];
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				sig
			},
			None => {
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2];
				m[2..].copy_from_slice(msg);
				let mut sig: Signature = [0u8; SIGNBYTES];
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				sig
			},
		}
	}

	/// Compute a signature for a given message (prehash version).
	#[cfg(not(feature = "no_std"))]
	pub fn prehash_sign(
		&self,
		msg: &[u8],
		ctx: Option<&[u8]>,
		hedged: bool,
		ph: crate::PH,
	) -> Option<Signature> {
		let mut oid = [0u8; 11];
		let mut phm: Vec<u8> = Vec::new();
		match ph {
			crate::PH::SHA256 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
				]);
				phm.extend_from_slice(Sha256::digest(msg).as_slice());
			},
			crate::PH::SHA512 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
				]);
				phm.extend_from_slice(Sha512::digest(msg).as_slice());
			},
		}
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return None;
				}
				let x_len = x.len();
				let phm_len = phm.len();
				let mut m = vec![0; 2 + x_len + 11 + phm_len];
				m[0] = 1;
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..2 + x_len + 11].copy_from_slice(&oid);
				m[2 + x_len + 11..].copy_from_slice(phm.as_slice());
				let mut sig: Signature = [0u8; SIGNBYTES];
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
			},
			None => {
				let phm_len = phm.len();
				let mut m = vec![0; 2 + 11 + phm_len];
				m[0] = 1;
				m[2..2 + 11].copy_from_slice(&oid);
				m[2 + 11..].copy_from_slice(phm.as_slice());
				let mut sig: Signature = [0u8; SIGNBYTES];
				signature(&mut sig, m.as_slice(), &self.bytes, hedged);
				Some(sig)
			},
		}
	}
}

#[derive(Eq, Clone, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub struct PublicKey {
	pub bytes: [u8; PUBLICKEYBYTES],
}

impl PublicKey {
	/// Returns a copy of underlying bytes.
	pub fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
		self.bytes
	}

	/// Create a PublicKey from bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, KeyParsingError> {
		let result = bytes.try_into();
		match result {
			Ok(bytes) => Ok(PublicKey { bytes }),
			Err(_) => Err(KeyParsingError::BadPublicKey),
		}
	}

	/// Verify a signature for a given message with a public key.
	pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
		if sig.len() != SIGNBYTES {
			return false;
		}
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return false;
				}
				let x_len = x.len();
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2 + x_len];
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..].copy_from_slice(msg);
				verify(sig, m.as_slice(), &self.bytes)
			},
			None => {
				let msg_len = msg.len();
				let mut m = vec![0; msg_len + 2];
				m[2..].copy_from_slice(msg);
				verify(sig, m.as_slice(), &self.bytes)
			},
		}
	}

	/// Verify a signature for a given message with a public key (prehash version).
	pub fn prehash_verify(
		&self,
		msg: &[u8],
		sig: &[u8],
		ctx: Option<&[u8]>,
		ph: crate::PH,
	) -> bool {
		if sig.len() != SIGNBYTES {
			return false;
		}
		let mut oid = [0u8; 11];
		let mut phm: Vec<u8> = Vec::new();
		match ph {
			crate::PH::SHA256 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
				]);
				phm.extend_from_slice(Sha256::digest(msg).as_slice());
			},
			crate::PH::SHA512 => {
				oid.copy_from_slice(&[
					0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
				]);
				phm.extend_from_slice(Sha512::digest(msg).as_slice());
			},
		}
		match ctx {
			Some(x) => {
				if x.len() > 255 {
					return false;
				}
				let x_len = x.len();
				let phm_len = phm.len();
				let mut m = vec![0; 2 + x_len + 11 + phm_len];
				m[0] = 1;
				m[1] = x_len as u8;
				m[2..2 + x_len].copy_from_slice(x);
				m[2 + x_len..2 + x_len + 11].copy_from_slice(&oid);
				m[2 + x_len + 11..].copy_from_slice(phm.as_slice());
				verify(sig, m.as_slice(), &self.bytes)
			},
			None => {
				let phm_len = phm.len();
				let mut m = vec![0; 2 + 11 + phm_len];
				m[0] = 1;
				m[2..2 + 11].copy_from_slice(&oid);
				m[2 + 11..].copy_from_slice(phm.as_slice());
				verify(sig, m.as_slice(), &self.bytes)
			},
		}
	}
}

/// Stack-optimized key pair generation
pub fn keypair(pk: &mut [u8], sk: &mut [u8], seed: Option<&[u8]>) {
	let mut workspace = CryptoWorkspace::new();

	let mut init_seed: Vec<u8>;
	match seed {
		Some(x) => init_seed = x.to_vec(),
		None => {
			#[cfg(feature = "no_std")]
			unimplemented!("must provide entropy in verifier only mode");
			#[cfg(not(feature = "no_std"))]
			{
				init_seed = vec![0u8; params::SEEDBYTES];
				crate::random_bytes(&mut init_seed, params::SEEDBYTES)
			}
		},
	};

	const SEEDBUF_LEN: usize = 2 * params::SEEDBYTES + params::CRHBYTES;
	let mut seedbuf = [0u8; SEEDBUF_LEN];
	fips202::shake256(&mut seedbuf, SEEDBUF_LEN, &init_seed, params::SEEDBYTES);

	let mut rho = [0u8; params::SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

	let mut rhoprime = [0u8; params::CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

	let mut key = [0u8; params::SEEDBYTES];
	key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

	polyvec::lvl5::matrix_expand(&mut *workspace.mat, &rho);

	polyvec::lvl5::l_uniform_eta(&mut workspace.s1, &rhoprime, 0);
	polyvec::lvl5::k_uniform_eta(&mut workspace.s2, &rhoprime, L as u16);

	*workspace.z = *workspace.s1; // s1hat = s1
	polyvec::lvl5::l_ntt(&mut workspace.z); // s1hat

	polyvec::lvl5::matrix_pointwise_montgomery(&mut workspace.t1, &*workspace.mat, &workspace.z, &mut workspace.temp_poly1);
	polyvec::lvl5::k_reduce(&mut workspace.t1);
	polyvec::lvl5::k_invntt_tomont(&mut workspace.t1);
	polyvec::lvl5::k_add(&mut workspace.t1, &workspace.s2);
	polyvec::lvl5::k_caddq(&mut workspace.t1);

	polyvec::lvl5::k_power2round(&mut workspace.t1, &mut workspace.t0);

	packing::ml_dsa_87::pack_pk(pk, &rho, &workspace.t1);

	let mut tr = [0u8; params::TR_BYTES];
	fips202::shake256(&mut tr, params::TR_BYTES, pk, params::ml_dsa_87::PUBLICKEYBYTES);

	packing::ml_dsa_87::pack_sk(sk, &rho, &tr, &key, &workspace.t0, &workspace.s1, &workspace.s2);
}

/// Stack-optimized signature generation
pub fn signature(sig: &mut [u8], msg: &[u8], sk: &[u8], hedged: bool) {
	let mut workspace = CryptoWorkspace::new();

	let mut rho = [0u8; params::SEEDBYTES];
	let mut tr = [0u8; params::TR_BYTES];
	let mut keymu = [0u8; params::SEEDBYTES + params::CRHBYTES];

	packing::ml_dsa_87::unpack_sk(
		&mut rho,
		&mut tr,
		&mut keymu[..params::SEEDBYTES],
		&mut workspace.t0,
		&mut workspace.s1,
		&mut workspace.s2,
		sk,
	);

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, &tr, params::TR_BYTES);
	fips202::shake256_absorb(&mut state, msg, msg.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut keymu[params::SEEDBYTES..], params::CRHBYTES, &mut state);

	let mut rnd = [0u8; params::SEEDBYTES];
	if hedged {
		#[cfg(not(feature = "no_std"))]
		crate::random_bytes(&mut rnd, params::SEEDBYTES);
		#[cfg(feature = "no_std")]
		unimplemented!("hedged mode doesn't work in verifier only mode");
	}
	state.init();
	fips202::shake256_absorb(&mut state, &keymu[..params::SEEDBYTES], params::SEEDBYTES);
	fips202::shake256_absorb(&mut state, &rnd, params::SEEDBYTES);
	fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
	fips202::shake256_finalize(&mut state);
	let mut rhoprime = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut rhoprime, params::CRHBYTES, &mut state);

	polyvec::lvl5::matrix_expand(&mut *workspace.mat, &rho);
	polyvec::lvl5::l_ntt(&mut workspace.s1);
	polyvec::lvl5::k_ntt(&mut workspace.s2);
	polyvec::lvl5::k_ntt(&mut workspace.t0);

	let mut nonce: u16 = 0;
	loop {
		polyvec::lvl5::l_uniform_gamma1(&mut workspace.y, &rhoprime, nonce);
		nonce += 1;

		// Reuse z workspace for NTT version of y
		*workspace.z = *workspace.y;

		polyvec::lvl5::l_ntt(&mut workspace.z);
		polyvec::lvl5::matrix_pointwise_montgomery(
			&mut workspace.w1,
			&*workspace.mat,
			&workspace.z,
			&mut workspace.temp_poly1,
		);
		polyvec::lvl5::k_reduce(&mut workspace.w1);
		polyvec::lvl5::k_invntt_tomont(&mut workspace.w1);
		polyvec::lvl5::k_caddq(&mut workspace.w1);

		polyvec::lvl5::k_decompose(&mut workspace.w1, &mut workspace.w0);
		polyvec::lvl5::k_pack_w1(sig, &workspace.w1);

		state.init();
		fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
		fips202::shake256_absorb(&mut state, sig, K * params::ml_dsa_87::POLYW1_PACKEDBYTES);
		fips202::shake256_finalize(&mut state);
		fips202::shake256_squeeze(sig, params::ml_dsa_87::C_DASH_BYTES, &mut state);

		poly::ml_dsa_87::challenge(&mut workspace.cp, sig);
		poly::ntt(&mut workspace.cp);

		polyvec::lvl5::l_pointwise_poly_montgomery(&mut workspace.z, &workspace.cp, &workspace.s1);
		polyvec::lvl5::l_invntt_tomont(&mut workspace.z);
		polyvec::lvl5::l_add(&mut workspace.z, &workspace.y);
		polyvec::lvl5::l_reduce(&mut workspace.z);

		if polyvec::lvl5::l_chknorm(
			&workspace.z,
			(params::ml_dsa_87::GAMMA1 - params::ml_dsa_87::BETA) as i32,
		) > 0
		{
			continue;
		}

		polyvec::lvl5::k_pointwise_poly_montgomery(&mut workspace.h, &workspace.cp, &workspace.s2);
		polyvec::lvl5::k_invntt_tomont(&mut workspace.h);
		polyvec::lvl5::k_sub(&mut workspace.w0, &workspace.h);
		polyvec::lvl5::k_reduce(&mut workspace.w0);

		if polyvec::lvl5::k_chknorm(
			&workspace.w0,
			(params::ml_dsa_87::GAMMA2 - params::ml_dsa_87::BETA) as i32,
		) > 0
		{
			continue;
		}

		polyvec::lvl5::k_pointwise_poly_montgomery(&mut workspace.h, &workspace.cp, &workspace.t0);
		polyvec::lvl5::k_invntt_tomont(&mut workspace.h);
		polyvec::lvl5::k_reduce(&mut workspace.h);

		if polyvec::lvl5::k_chknorm(&workspace.h, params::ml_dsa_87::GAMMA2 as i32) > 0 {
			continue;
		}

		polyvec::lvl5::k_add(&mut workspace.w0, &workspace.h);

		let n = polyvec::lvl5::k_make_hint(&mut workspace.h, &workspace.w0, &workspace.w1);

		if n > params::ml_dsa_87::OMEGA as i32 {
			continue;
		}

		packing::ml_dsa_87::pack_sig(sig, None, &workspace.z, &workspace.h);

		return;
	}
}

/// Stack-optimized signature verification
pub fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
	if sig.len() != params::ml_dsa_87::SIGNBYTES {
		return false;
	}

	// Use boxed allocations for large structures
	let mut workspace = CryptoWorkspace::new();
	let mut buf = Box::new([0u8; K * params::ml_dsa_87::POLYW1_PACKEDBYTES]);

	let mut rho = [0u8; params::SEEDBYTES];
	let mut mu = [0u8; params::CRHBYTES];
	let mut c = [0u8; params::ml_dsa_87::C_DASH_BYTES];
	let mut c2 = [0u8; params::ml_dsa_87::C_DASH_BYTES];
	let mut state = fips202::KeccakState::default();

	packing::ml_dsa_87::unpack_pk(&mut rho, &mut workspace.t1, pk);
	if !packing::ml_dsa_87::unpack_sig(&mut c, &mut workspace.z, &mut workspace.h, sig) {
		return false;
	}
	if polyvec::lvl5::l_chknorm(
		&workspace.z,
		(params::ml_dsa_87::GAMMA1 - params::ml_dsa_87::BETA) as i32,
	) > 0
	{
		return false;
	}

	// Compute CRH(CRH(rho, t1), msg)
	fips202::shake256(&mut mu, params::CRHBYTES, pk, params::ml_dsa_87::PUBLICKEYBYTES);
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, m, m.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

	// Matrix-vector multiplication; compute Az - c2^dt1
	poly::ml_dsa_87::challenge(&mut workspace.cp, &c);
	polyvec::lvl5::matrix_expand(&mut *workspace.mat, &rho);

	polyvec::lvl5::l_ntt(&mut workspace.z);
	polyvec::lvl5::matrix_pointwise_montgomery(&mut workspace.w1, &*workspace.mat, &workspace.z, &mut workspace.temp_poly1);

	poly::ntt(&mut workspace.cp);
	polyvec::lvl5::k_shiftl(&mut workspace.t1);
	polyvec::lvl5::k_ntt(&mut workspace.t1);

	// Use t0 as temporary for t1 copy to avoid extra allocation
	*workspace.t0 = *workspace.t1;
	polyvec::lvl5::k_pointwise_poly_montgomery(&mut workspace.t1, &workspace.cp, &workspace.t0);

	polyvec::lvl5::k_sub(&mut workspace.w1, &workspace.t1);
	polyvec::lvl5::k_reduce(&mut workspace.w1);
	polyvec::lvl5::k_invntt_tomont(&mut workspace.w1);

	// Reconstruct w1
	polyvec::lvl5::k_caddq(&mut workspace.w1);
	polyvec::lvl5::k_use_hint(&mut workspace.w1, &workspace.h);
	polyvec::lvl5::k_pack_w1(&mut *buf, &workspace.w1);

	// Call random oracle and verify challenge
	state.init();
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, &*buf, K * params::ml_dsa_87::POLYW1_PACKEDBYTES);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut c2, params::ml_dsa_87::C_DASH_BYTES, &mut state);

	// Constant time equality check
	c == c2
}

#[cfg(test)]
#[cfg(not(feature = "no_std"))]
mod tests {
	use super::*;

	#[test]
	fn self_verify_hedged() {
		let mut pk = [0u8; PUBLICKEYBYTES];
		let mut sk = [0u8; SECRETKEYBYTES];
		keypair(&mut pk, &mut sk, None);

		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let mut sig = [0u8; SIGNBYTES];
		signature(&mut sig, &msg, &sk, true);
		assert!(verify(&sig, &msg, &pk));
	}

	#[test]
	fn self_verify() {
		let mut pk = [0u8; PUBLICKEYBYTES];
		let mut sk = [0u8; SECRETKEYBYTES];
		keypair(&mut pk, &mut sk, None);

		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let mut sig = [0u8; SIGNBYTES];
		signature(&mut sig, &msg, &sk, false);
		assert!(verify(&sig, &msg, &pk));
	}

	#[test]
	fn test_keypair_api_compatibility() {
		let keys1 = Keypair::generate(None);
		let keys2 = Keypair::generate(None);

		// Test serialization
		let bytes1 = keys1.to_bytes();
		let keys1_restored = Keypair::from_bytes(&bytes1).unwrap();

		let msg = b"test message";
		let sig1 = keys1.sign(msg, None, false);
		let sig1_restored = keys1_restored.sign(msg, None, false);

		assert!(keys1.verify(msg, &sig1, None));
		assert!(keys1_restored.verify(msg, &sig1_restored, None));

		// Different keys should produce different signatures
		let sig2 = keys2.sign(msg, None, false);
		assert_ne!(sig1, sig2);
	}

	#[test]
	fn test_context_signing() {
		let keys = Keypair::generate(None);
		let msg = b"test message";
		let ctx = b"test context";

		let sig_with_ctx = keys.sign(msg, Some(ctx), false);
		let sig_without_ctx = keys.sign(msg, None, false);

		// Signatures should be different
		assert_ne!(sig_with_ctx, sig_without_ctx);

		// Verify with correct context
		assert!(keys.verify(msg, &sig_with_ctx, Some(ctx)));
		assert!(keys.verify(msg, &sig_without_ctx, None));

		// Verify with wrong context should fail
		assert!(!keys.verify(msg, &sig_with_ctx, None));
		assert!(!keys.verify(msg, &sig_without_ctx, Some(ctx)));
	}

	#[test]
	fn test_workspace_reuse() {
		// Test that workspace can be reused multiple times
		let keys = Keypair::generate(None);
		let msg = b"test message";

		for i in 0..10 {
			let test_msg = format!("test message {}", i);
			let sig = keys.sign(test_msg.as_bytes(), None, false);
			assert!(keys.verify(test_msg.as_bytes(), &sig, None));
		}
	}

	#[test]
	fn self_verify_prehash_hedged() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.prehash_sign(&msg, None, true, crate::PH::SHA256);
		assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
	}

	#[test]
	fn self_verify_prehash() {
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let keys = Keypair::generate(None);
		let sig = keys.prehash_sign(&msg, None, false, crate::PH::SHA256);
		assert!(keys.prehash_verify(&msg, &sig.unwrap(), None, crate::PH::SHA256));
	}
}
