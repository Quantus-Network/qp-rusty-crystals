//! SHAKE128/SHAKE256 XOFs with the sponge rate encoded in the type.
//!
//! A Keccak sponge is only well-defined when every operation agrees on the
//! rate (168 for SHAKE128, 136 for SHAKE256) and on the phase (absorbing vs
//! squeezing): the byte position stored in the state is meaningless without
//! both. This module enforces the rate at compile time and the phase at
//! runtime:
//!
//! - [`KeccakState`] carries its rate as a const generic parameter ([`Shake128State`] vs
//!   [`Shake256State`]), so a state built by SHAKE128 operations cannot reach a SHAKE256 function
//!   at all. Mixing rates used to underflow `rate - pos` and panic; now it does not compile:
//!
//! ```compile_fail
//! use qp_rusty_crystals_dilithium::fips202::*;
//!
//! let mut state = KeccakState::default();
//! shake128_absorb(&mut state, b"seed");
//! shake128_finalize(&mut state);
//! // error[E0308]: `state` is a SHAKE128-rate state, not a SHAKE256 one
//! shake256_absorb(&mut state, b"more");
//! ```
//!
//! - The absorb→squeeze phase is tracked in the state and checked with debug assertions: absorbing
//!   into a finalized state or squeezing an unfinalized one is a caller bug that panics in debug
//!   builds. In release builds these misuses stay deterministic and panic-free (they yield a
//!   well-defined but non-standard stream), matching the crate's policy of not panicking in
//!   production for domain violations.
//!
//! Squeezing (both [`shake256_squeeze`] and the block-sized
//! `shake{128,256}_squeezeblocks`) reads one canonical output stream: the
//! result is the same no matter how reads are chunked.

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;

const NROUNDS: usize = 24;

/// 1600-bit state of the Keccak algorithm for sponge rate `R`, with an index
/// of the current position and the absorb/squeeze phase (see module docs).
///
/// `KeccakState::default()` is the initialized empty (absorbing) state; the
/// rate parameter is normally inferred from the first `shake128_*` /
/// `shake256_*` call.
///
/// # Security
///
/// This struct implements `Zeroize` and `ZeroizeOnDrop` to ensure sensitive
/// state is cleared from memory when no longer needed. The `Copy` trait is
/// intentionally NOT implemented to prevent accidental copies that could
/// leave sensitive data in memory (HQ8).
///
/// The fields are private. This is deliberate: `pos` must satisfy the
/// invariant `pos <= R`, and the squeeze/absorb routines rely on it to make
/// forward progress; `squeezing` must only flip on finalize. Exposing the
/// fields would let a caller (for example one that restores a state from
/// untrusted bytes) construct a state with `pos > R`, which previously caused
/// `keccak_squeeze` to loop forever.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct KeccakState<const R: usize> {
	s: [u64; 25],
	pos: usize,
	squeezing: bool,
}

/// A SHAKE128 sponge state (rate 168).
pub type Shake128State = KeccakState<SHAKE128_RATE>;
/// A SHAKE256 sponge state (rate 136).
pub type Shake256State = KeccakState<SHAKE256_RATE>;

impl<const R: usize> KeccakState<R> {
	/// Set the state to the initial (absorbing) form.
	pub fn init(&mut self) {
		self.s.fill(0);
		self.pos = 0;
		self.squeezing = false;
	}
}

/// No rolling defined in the language so got to do it ourselfs :(
///
/// # Arguments
///
/// * 'a' - number to rotate right
/// * 'offset' - how many places to rotate
///
/// Returns the rotated number
fn rol(a: u64, offset: u64) -> u64 {
	(a << offset) ^ (a >> (64 - offset))
}

/// Load 8 bytes into uint64_t in little-endian order
#[inline]
fn load64(x: &[u8; 8]) -> u64 {
	u64::from_le_bytes(*x)
}

/// Keccak round constants
const KECCAKF_ROUNDCONSTANTS: [u64; NROUNDS] = [
	0x0000000000000001u64,
	0x0000000000008082u64,
	0x800000000000808au64,
	0x8000000080008000u64,
	0x000000000000808bu64,
	0x0000000080000001u64,
	0x8000000080008081u64,
	0x8000000000008009u64,
	0x000000000000008au64,
	0x0000000000000088u64,
	0x0000000080008009u64,
	0x000000008000000au64,
	0x000000008000808bu64,
	0x800000000000008bu64,
	0x8000000000008089u64,
	0x8000000000008003u64,
	0x8000000000008002u64,
	0x8000000000000080u64,
	0x000000000000800au64,
	0x800000008000000au64,
	0x8000000080008081u64,
	0x8000000000008080u64,
	0x0000000080000001u64,
	0x8000000080008008u64,
];

/// The Keccak F1600 Permutation
fn keccakf1600_statepermute(state: &mut [u64; 25]) {
	let mut aba = state[0];
	let mut abe = state[1];
	let mut abi = state[2];
	let mut abo = state[3];
	let mut abu = state[4];
	let mut aga = state[5];
	let mut age = state[6];
	let mut agi = state[7];
	let mut ago = state[8];
	let mut agu = state[9];
	let mut aka = state[10];
	let mut ake = state[11];
	let mut aki = state[12];
	let mut ako = state[13];
	let mut aku = state[14];
	let mut ama = state[15];
	let mut ame = state[16];
	let mut ami = state[17];
	let mut amo = state[18];
	let mut amu = state[19];
	let mut asa = state[20];
	let mut ase = state[21];
	let mut asi = state[22];
	let mut aso = state[23];
	let mut asu = state[24];

	for round in (0..NROUNDS).step_by(2) {
		let mut bca = aba ^ aga ^ aka ^ ama ^ asa;
		let mut bce = abe ^ age ^ ake ^ ame ^ ase;
		let mut bci = abi ^ agi ^ aki ^ ami ^ asi;
		let mut bco = abo ^ ago ^ ako ^ amo ^ aso;
		let mut bcu = abu ^ agu ^ aku ^ amu ^ asu;

		let mut da = bcu ^ rol(bce, 1);
		let mut de = bca ^ rol(bci, 1);
		let mut di = bce ^ rol(bco, 1);
		let mut d_o = bci ^ rol(bcu, 1);
		let mut du = bco ^ rol(bca, 1);

		aba ^= da;
		bca = aba;
		age ^= de;
		bce = rol(age, 44);
		aki ^= di;
		bci = rol(aki, 43);
		amo ^= d_o;
		bco = rol(amo, 21);
		asu ^= du;
		bcu = rol(asu, 14);
		let mut eba = bca ^ ((!bce) & bci);
		eba ^= KECCAKF_ROUNDCONSTANTS[round];
		let mut ebe = bce ^ ((!bci) & bco);
		let mut ebi = bci ^ ((!bco) & bcu);
		let mut ebo = bco ^ ((!bcu) & bca);
		let mut ebu = bcu ^ ((!bca) & bce);

		abo ^= d_o;
		bca = rol(abo, 28);
		agu ^= du;
		bce = rol(agu, 20);
		aka ^= da;
		bci = rol(aka, 3);
		ame ^= de;
		bco = rol(ame, 45);
		asi ^= di;
		bcu = rol(asi, 61);
		let mut ega = bca ^ ((!bce) & bci);
		let mut ege = bce ^ ((!bci) & bco);
		let mut egi = bci ^ ((!bco) & bcu);
		let mut ego = bco ^ ((!bcu) & bca);
		let mut egu = bcu ^ ((!bca) & bce);

		abe ^= de;
		bca = rol(abe, 1);
		agi ^= di;
		bce = rol(agi, 6);
		ako ^= d_o;
		bci = rol(ako, 25);
		amu ^= du;
		bco = rol(amu, 8);
		asa ^= da;
		bcu = rol(asa, 18);
		let mut eka = bca ^ ((!bce) & bci);
		let mut eke = bce ^ ((!bci) & bco);
		let mut eki = bci ^ ((!bco) & bcu);
		let mut eko = bco ^ ((!bcu) & bca);
		let mut eku = bcu ^ ((!bca) & bce);

		abu ^= du;
		bca = rol(abu, 27);
		aga ^= da;
		bce = rol(aga, 36);
		ake ^= de;
		bci = rol(ake, 10);
		ami ^= di;
		bco = rol(ami, 15);
		aso ^= d_o;
		bcu = rol(aso, 56);
		let mut ema = bca ^ ((!bce) & bci);
		let mut eme = bce ^ ((!bci) & bco);
		let mut emi = bci ^ ((!bco) & bcu);
		let mut emo = bco ^ ((!bcu) & bca);
		let mut emu = bcu ^ ((!bca) & bce);

		abi ^= di;
		bca = rol(abi, 62);
		ago ^= d_o;
		bce = rol(ago, 55);
		aku ^= du;
		bci = rol(aku, 39);
		ama ^= da;
		bco = rol(ama, 41);
		ase ^= de;
		bcu = rol(ase, 2);
		let mut esa = bca ^ ((!bce) & bci);
		let mut ese = bce ^ ((!bci) & bco);
		let mut esi = bci ^ ((!bco) & bcu);
		let mut eso = bco ^ ((!bcu) & bca);
		let mut esu = bcu ^ ((!bca) & bce);

		bca = eba ^ ega ^ eka ^ ema ^ esa;
		bce = ebe ^ ege ^ eke ^ eme ^ ese;
		bci = ebi ^ egi ^ eki ^ emi ^ esi;
		bco = ebo ^ ego ^ eko ^ emo ^ eso;
		bcu = ebu ^ egu ^ eku ^ emu ^ esu;

		da = bcu ^ rol(bce, 1);
		de = bca ^ rol(bci, 1);
		di = bce ^ rol(bco, 1);
		d_o = bci ^ rol(bcu, 1);
		du = bco ^ rol(bca, 1);

		eba ^= da;
		bca = eba;
		ege ^= de;
		bce = rol(ege, 44);
		eki ^= di;
		bci = rol(eki, 43);
		emo ^= d_o;
		bco = rol(emo, 21);
		esu ^= du;
		bcu = rol(esu, 14);
		aba = bca ^ ((!bce) & bci);
		aba ^= KECCAKF_ROUNDCONSTANTS[round + 1];
		abe = bce ^ ((!bci) & bco);
		abi = bci ^ ((!bco) & bcu);
		abo = bco ^ ((!bcu) & bca);
		abu = bcu ^ ((!bca) & bce);

		ebo ^= d_o;
		bca = rol(ebo, 28);
		egu ^= du;
		bce = rol(egu, 20);
		eka ^= da;
		bci = rol(eka, 3);
		eme ^= de;
		bco = rol(eme, 45);
		esi ^= di;
		bcu = rol(esi, 61);
		aga = bca ^ ((!bce) & bci);
		age = bce ^ ((!bci) & bco);
		agi = bci ^ ((!bco) & bcu);
		ago = bco ^ ((!bcu) & bca);
		agu = bcu ^ ((!bca) & bce);

		ebe ^= de;
		bca = rol(ebe, 1);
		egi ^= di;
		bce = rol(egi, 6);
		eko ^= d_o;
		bci = rol(eko, 25);
		emu ^= du;
		bco = rol(emu, 8);
		esa ^= da;
		bcu = rol(esa, 18);
		aka = bca ^ ((!bce) & bci);
		ake = bce ^ ((!bci) & bco);
		aki = bci ^ ((!bco) & bcu);
		ako = bco ^ ((!bcu) & bca);
		aku = bcu ^ ((!bca) & bce);

		ebu ^= du;
		bca = rol(ebu, 27);
		ega ^= da;
		bce = rol(ega, 36);
		eke ^= de;
		bci = rol(eke, 10);
		emi ^= di;
		bco = rol(emi, 15);
		eso ^= d_o;
		bcu = rol(eso, 56);
		ama = bca ^ ((!bce) & bci);
		ame = bce ^ ((!bci) & bco);
		ami = bci ^ ((!bco) & bcu);
		amo = bco ^ ((!bcu) & bca);
		amu = bcu ^ ((!bca) & bce);

		ebi ^= di;
		bca = rol(ebi, 62);
		ego ^= d_o;
		bce = rol(ego, 55);
		eku ^= du;
		bci = rol(eku, 39);
		ema ^= da;
		bco = rol(ema, 41);
		ese ^= de;
		bcu = rol(ese, 2);
		asa = bca ^ ((!bce) & bci);
		ase = bce ^ ((!bci) & bco);
		asi = bci ^ ((!bco) & bcu);
		aso = bco ^ ((!bcu) & bca);
		asu = bcu ^ ((!bca) & bce);
	}

	state[0] = aba;
	state[1] = abe;
	state[2] = abi;
	state[3] = abo;
	state[4] = abu;
	state[5] = aga;
	state[6] = age;
	state[7] = agi;
	state[8] = ago;
	state[9] = agu;
	state[10] = aka;
	state[11] = ake;
	state[12] = aki;
	state[13] = ako;
	state[14] = aku;
	state[15] = ama;
	state[16] = ame;
	state[17] = ami;
	state[18] = amo;
	state[19] = amu;
	state[20] = asa;
	state[21] = ase;
	state[22] = asi;
	state[23] = aso;
	state[24] = asu;
}

/// Absorb step of Keccak; incremental. The rate comes from the state's type,
/// so `pos` can never be interpreted against the wrong block size.
fn keccak_absorb<const R: usize>(state: &mut KeccakState<R>, input: &[u8]) {
	debug_assert!(!state.squeezing, "fips202: absorb called on a finalized (squeezing) state");
	let mut inlen = input.len();
	let mut idx = 0;
	let mut pos = state.pos;
	while pos + inlen >= R {
		for i in pos..R {
			state.s[i / 8] ^= (input[idx] as u64) << 8 * (i % 8);
			idx += 1;
		}
		inlen -= R - pos;
		keccakf1600_statepermute(&mut state.s);
		pos = 0;
	}
	let mut i = pos;
	while i < pos + inlen {
		state.s[i / 8] ^= (input[idx] as u64) << 8 * (i % 8);
		idx += 1;
		i += 1
	}
	state.pos = i;
}

/// Finalize absorb step: apply domain-separation/padding and transition the
/// state to the squeezing phase. `pos = R` marks the current block as
/// exhausted, so the first squeeze permutes.
fn keccak_finalize<const R: usize>(state: &mut KeccakState<R>, p: u8) {
	debug_assert!(!state.squeezing, "fips202: finalize called twice on the same state");
	state.s[state.pos / 8] ^= (p as u64) << 8 * (state.pos % 8);
	state.s[R / 8 - 1] ^= 1u64 << 63;
	state.pos = R;
	state.squeezing = true;
}

/// Squeeze step of Keccak. Squeezes arbitrarily many bytes from the canonical
/// output stream. Can be called multiple times to keep squeezing, i.e., is
/// incremental.
fn keccak_squeeze<const R: usize>(out: &mut [u8], state: &mut KeccakState<R>) {
	debug_assert!(state.squeezing, "fips202: squeeze called before finalize");
	let mut pos = state.pos;
	let mut outlen = out.len();
	let mut out_idx = 0;
	while outlen != 0 {
		// `>=` (rather than `==`) is a defensive guard: a well-formed state always
		// has `pos <= R`, but if an out-of-range `pos` ever reaches here we must
		// still permute and reset so the loop makes progress. Without this, a
		// `pos > R` would emit zero bytes per iteration and spin forever.
		if pos >= R {
			keccakf1600_statepermute(&mut state.s);
			pos = 0;
		}
		let mut i = pos;
		while i < R && i < pos + outlen {
			out[out_idx] = (state.s[i / 8] >> 8 * (i % 8)) as u8;
			out_idx += 1;
			i += 1;
		}
		outlen -= i - pos;
		pos = i;
	}

	state.pos = pos;
}

/// Absorb step of Keccak; non-incremental, starts by zeroeing the state.
fn keccak_absorb_once<const R: usize>(s: &mut [u64; 25], input: &[u8], p: u8) {
	s.fill(0);

	// Process full blocks using chunks_exact for safe iteration
	let mut chunks = input.chunks_exact(R);
	for block in chunks.by_ref() {
		for (i, chunk) in block.chunks_exact(8).enumerate() {
			// SAFETY: chunks_exact(8) guarantees exactly 8 bytes, so this indexing is safe
			let bytes =
				[chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]];
			s[i] ^= load64(&bytes);
		}
		keccakf1600_statepermute(s);
	}

	// Handle remaining bytes
	let remainder = chunks.remainder();
	for (i, &byte) in remainder.iter().enumerate() {
		s[i / 8] ^= (byte as u64) << (8 * (i % 8));
	}

	s[remainder.len() / 8] ^= (p as u64) << (8 * (remainder.len() % 8));
	s[(R - 1) / 8] ^= 1u64 << 63;
}

/// Squeeze step of Keccak. Squeezes one full rate-sized block per entry of `out`,
/// reading from the same canonical output stream as [`keccak_squeeze`]: if the
/// current block is partially consumed, the stream continues from that offset
/// rather than skipping the unconsumed bytes.
///
/// The output is typed as whole blocks (`[[u8; R]]`) rather than a flat slice
/// plus a separate block count, so a count/capacity mismatch — which would
/// silently underfill the buffer and desynchronize the state — is
/// unrepresentable at the type level.
fn keccak_squeezeblocks<const R: usize>(out: &mut [[u8; R]], state: &mut KeccakState<R>) {
	debug_assert!(state.squeezing, "fips202: squeezeblocks called before finalize");
	if state.pos < R {
		// Mid-block: stay on the canonical stream via the byte-wise squeeze.
		keccak_squeeze(out.as_flattened_mut(), state);
		return;
	}
	// Block-aligned fast path: whole-lane copies.
	for block in out.iter_mut() {
		keccakf1600_statepermute(&mut state.s);
		for (i, chunk) in block.chunks_exact_mut(8).enumerate() {
			// chunks_exact_mut(8) guarantees exactly 8 bytes
			let bytes = state.s[i].to_le_bytes();
			chunk.copy_from_slice(&bytes);
		}
	}
	state.pos = R;
}

/// Absorb step of the SHAKE128 XOF; incremental.
pub fn shake128_absorb(state: &mut Shake128State, input: &[u8]) {
	keccak_absorb(state, input);
}

/// Finalize absorb step of the SHAKE128 XOF, transitioning the state to the
/// squeezing phase. Absorbing after this point is a caller bug (debug panic).
pub fn shake128_finalize(state: &mut Shake128State) {
	keccak_finalize(state, 0x1F);
}

/// Squeeze step of SHAKE128 XOF. Squeezes one full block of SHAKE128_RATE bytes
/// per entry of `output`, continuing the canonical output stream.
/// Can be called multiple times to keep squeezing.
///
/// Taking whole blocks (`[[u8; SHAKE128_RATE]]`) instead of a flat slice plus a
/// block count makes an inconsistent count/capacity pair unrepresentable: the
/// old shape silently underfilled a short slice, leaving stale bytes that the
/// caller would treat as XOF output.
pub fn shake128_squeezeblocks(output: &mut [[u8; SHAKE128_RATE]], state: &mut Shake128State) {
	keccak_squeezeblocks(output, state);
}

/// Absorb step of the SHAKE256 XOF; incremental.
pub fn shake256_absorb(state: &mut Shake256State, input: &[u8]) {
	keccak_absorb(state, input);
}

/// Finalize absorb step of the SHAKE256 XOF, transitioning the state to the
/// squeezing phase. Absorbing after this point is a caller bug (debug panic).
pub fn shake256_finalize(state: &mut Shake256State) {
	keccak_finalize(state, 0x1F);
}

/// Squeeze step of SHAKE256 XOF. Squeezes arbitrarily many bytes.
/// Can be called multiple times to keep squeezing.
pub fn shake256_squeeze(out: &mut [u8], state: &mut Shake256State) {
	keccak_squeeze(out, state);
}

/// Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
pub fn shake256_absorb_once(state: &mut Shake256State, input: &[u8]) {
	keccak_absorb_once::<SHAKE256_RATE>(&mut state.s, input, 0x1F);
	state.pos = SHAKE256_RATE;
	state.squeezing = true;
}

/// Squeeze step of SHAKE256 XOF. Squeezes one full block of SHAKE256_RATE bytes
/// per entry of `out`, continuing the canonical output stream.
/// Can be called multiple times to keep squeezing.
///
/// Taking whole blocks (`[[u8; SHAKE256_RATE]]`) instead of a flat slice plus a
/// block count makes an inconsistent count/capacity pair unrepresentable: the
/// old shape silently underfilled a short slice, leaving stale bytes that the
/// caller would treat as XOF output.
pub fn shake256_squeezeblocks(out: &mut [[u8; SHAKE256_RATE]], state: &mut Shake256State) {
	keccak_squeezeblocks(out, state);
}

/// SHAKE256 XOF with non-incremental API
pub fn shake256(output: &mut [u8], input: &[u8]) {
	let mut state = Shake256State::default();
	shake256_absorb_once(&mut state, input);
	shake256_squeeze(output, &mut state);
}

/// Initialize SHAKE128 stream with a fixed-size seed and nonce, leaving the
/// state finalized (ready to squeeze).
pub fn shake128_stream_init(
	state: &mut Shake128State,
	seed: &[u8; crate::params::SEEDBYTES],
	nonce: u16,
) {
	let t = [nonce as u8, (nonce >> 8) as u8];
	state.init();
	shake128_absorb(state, seed);
	shake128_absorb(state, &t);
	shake128_finalize(state);
}

/// Initialize SHAKE256 stream with a fixed-size seed and nonce, leaving the
/// state finalized (ready to squeeze).
pub fn shake256_stream_init(
	state: &mut Shake256State,
	seed: &[u8; crate::params::CRHBYTES],
	nonce: u16,
) {
	let t = [nonce as u8, (nonce >> 8) as u8];
	state.init();
	shake256_absorb(state, seed);
	shake256_absorb(state, &t);
	shake256_finalize(state);
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec::Vec;

	fn decode_hex(s: &str) -> Vec<u8> {
		assert_eq!(s.len() % 2, 0, "hex length must be even");

		(0..s.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex encoding"))
			.collect()
	}

	struct KeccakTest<const OUTPUT_LENGTH: usize> {
		input: Vec<u8>,
		output: [u8; OUTPUT_LENGTH],
	}

	struct TestSuite<const OUTPUT_LENGTH: usize> {
		tests: Vec<KeccakTest<OUTPUT_LENGTH>>,
	}

	impl<const OUTPUT_LENGTH: usize> TestSuite<OUTPUT_LENGTH> {
		fn from_file(content: &str) -> Self {
			let mut current_msg = None;

			let mut vectors = Vec::new();

			for line in content.lines() {
				let line = line.trim();

				if line.is_empty() || line.starts_with('#') {
					continue;
				}

				if line.starts_with('[') {
					continue;
				}

				if line.starts_with("Len =") {
					continue;
				}

				if line.starts_with("Msg =") {
					let hex = line.split('=').nth(1).unwrap().trim();
					current_msg = Some(decode_hex(hex));
					continue;
				}

				if line.starts_with("Output =") {
					let hex = line.split('=').nth(1).unwrap().trim();
					let expected = decode_hex(hex);
					assert_eq!(expected.len(), OUTPUT_LENGTH);

					let mut output = [0; OUTPUT_LENGTH];
					output.copy_from_slice(&expected);

					let vec = KeccakTest {
						input: current_msg.take().expect("the message is missing"),
						output,
					};

					vectors.push(vec);
					continue;
				}
			}

			Self { tests: vectors }
		}
	}

	#[test]
	fn nist_test_shake256_short_messages() {
		const OUTPUT_LENGTH: usize = 32;
		let content = include_str!("../../test_vectors/SHAKE256ShortMsg.rsp");
		let test_suite: TestSuite<OUTPUT_LENGTH> = TestSuite::from_file(content);
		for test in test_suite.tests {
			let mut output = [0; OUTPUT_LENGTH];

			let mut state = KeccakState::default();
			shake256_absorb(&mut state, &test.input);
			shake256_finalize(&mut state);
			shake256_squeeze(&mut output, &mut state);
			assert_eq!(output, test.output, "Input failed with {:?}", test.input);
		}
	}

	#[test]
	fn keccak_squeeze_terminates_with_out_of_range_pos() {
		// Regression (availability): a `pos` greater than the rate must not make
		// keccak_squeeze loop forever. Before hardening, `pos > r` meant the inner
		// `while i < r` loop emitted zero bytes, so `outlen` was never decremented
		// and the outer `while outlen != 0` spun indefinitely. This test wedges an
		// out-of-range position (as a corrupted state could) and requires the call
		// to leave a valid in-range position.
		let mut state: Shake256State =
			KeccakState { s: [0u64; 25], pos: SHAKE256_RATE + 1, squeezing: true };
		let mut out = [0u8; 32];
		keccak_squeeze(&mut out, &mut state);
		assert!(state.pos <= SHAKE256_RATE, "squeeze must leave an in-range position");
	}

	#[test]
	fn shake256_squeeze_terminates_with_corrupted_state_pos() {
		// End-to-end version through the public squeeze entry point. We reach into
		// the (module-private) `pos` field to simulate a state whose invariant was
		// violated - e.g. restored from untrusted bytes - and require that squeezing
		// still terminates and yields a full block of output.
		let mut state = KeccakState::default();
		shake256_absorb(&mut state, b"availability");
		shake256_finalize(&mut state);
		state.pos = usize::MAX;

		let mut out = [0u8; 64];
		shake256_squeeze(&mut out, &mut state);
		assert!(state.pos <= SHAKE256_RATE, "state position must be back in range");
	}

	#[test]
	fn squeezeblocks_matches_incremental_squeeze() {
		// Audit regression companion: the old API took a flat `&mut [u8]` plus
		// a separate `nblocks`, and a short slice was silently underfilled
		// (stale tail bytes treated as XOF output, Keccak state permuted fewer
		// times than requested). The API now takes whole blocks
		// (`&mut [[u8; RATE]]`), so that mismatch cannot be expressed at all —
		// this test pins down that the block-squeeze still produces exactly
		// the same stream as the byte-wise squeeze.
		let mut block_state = KeccakState::default();
		shake256_absorb(&mut block_state, b"equivalence");
		shake256_finalize(&mut block_state);
		let mut blocks = [[0u8; SHAKE256_RATE]; 2];
		shake256_squeezeblocks(&mut blocks, &mut block_state);

		let mut byte_state = KeccakState::default();
		shake256_absorb(&mut byte_state, b"equivalence");
		shake256_finalize(&mut byte_state);
		let mut bytes = [0u8; 2 * SHAKE256_RATE];
		shake256_squeeze(&mut bytes, &mut byte_state);

		assert_eq!(blocks.as_flattened(), bytes);

		// Same equivalence for SHAKE128.
		let mut block_state = KeccakState::default();
		shake128_absorb(&mut block_state, b"equivalence");
		shake128_finalize(&mut block_state);
		let mut blocks128 = [[0u8; SHAKE128_RATE]; 2];
		shake128_squeezeblocks(&mut blocks128, &mut block_state);

		let mut byte_state = KeccakState::default();
		shake128_absorb(&mut byte_state, b"equivalence");
		shake128_finalize(&mut byte_state);
		let mut bytes128 = [0u8; 2 * SHAKE128_RATE];
		keccak_squeeze(&mut bytes128, &mut byte_state);

		assert_eq!(blocks128.as_flattened(), bytes128);
	}

	/// The SHAKE256 output stream must be one canonical byte sequence no matter
	/// how reads are chunked. Mixing `shake256_squeeze` with
	/// `shake256_squeezeblocks` (which used to ignore `pos` and always permute)
	/// must not skip unconsumed bytes or re-emit bytes from an earlier block.
	#[test]
	fn squeeze_chunking_does_not_change_stream() {
		const TAIL: usize = 32;
		const TOTAL: usize = 17 + SHAKE256_RATE + TAIL;

		fn absorb() -> Shake256State {
			let mut state = KeccakState::default();
			shake256_absorb(&mut state, b"canonical-stream");
			shake256_finalize(&mut state);
			state
		}

		// Reference stream: one straight squeeze.
		let mut reference = [0u8; TOTAL];
		shake256_squeeze(&mut reference, &mut absorb());

		// Same transcript, chunked reads: partial squeeze, then a whole block
		// via the block API, then the tail.
		let mut chunked = [0u8; TOTAL];
		let mut state = absorb();
		shake256_squeeze(&mut chunked[..17], &mut state);
		let mut block = [[0u8; SHAKE256_RATE]; 1];
		shake256_squeezeblocks(&mut block, &mut state);
		chunked[17..17 + SHAKE256_RATE].copy_from_slice(&block[0]);
		shake256_squeeze(&mut chunked[17 + SHAKE256_RATE..], &mut state);

		assert_eq!(reference, chunked, "SHAKE256 output stream depends on how reads are chunked");
	}

	/// The debug-mode phase check: absorbing into a finalized state is a caller
	/// bug and must be caught loudly in debug builds. (Cross-*rate* misuse is
	/// caught at compile time; see the module-level `compile_fail` doctest.)
	#[test]
	#[cfg(debug_assertions)]
	#[should_panic(expected = "absorb called on a finalized")]
	fn absorb_after_finalize_debug_asserts() {
		let mut state = KeccakState::default();
		shake256_absorb(&mut state, b"seed");
		shake256_finalize(&mut state);
		shake256_absorb(&mut state, b"more");
	}

	#[test]
	fn nist_test_shake256_long_messages() {
		const OUTPUT_LENGTH: usize = 32;
		let content = include_str!("../../test_vectors/SHAKE256LongMsg.rsp");
		let test_suite: TestSuite<OUTPUT_LENGTH> = TestSuite::from_file(content);
		for test in test_suite.tests {
			let mut output = [0; OUTPUT_LENGTH];

			let mut state = KeccakState::default();
			shake256_absorb(&mut state, &test.input);
			shake256_finalize(&mut state);
			shake256_squeeze(&mut output, &mut state);
			assert_eq!(output, test.output);
		}
	}
}
