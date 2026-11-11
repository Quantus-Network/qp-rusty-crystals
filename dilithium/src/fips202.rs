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
/// state is cleared from memory when no longer needed. Neither `Copy` nor
/// `Clone` is implemented: a copy of a state that has absorbed secret
/// material (the signing path absorbs the private key seed `K` to derive
/// the mask seed ρ') is a second live instance of that secret, invisible to
/// the original's zeroization. Reuse a state via [`KeccakState::init`] or
/// start from `default()` instead of duplicating it (HQ8).
///
/// ```compile_fail
/// use qp_rusty_crystals_dilithium::fips202::{self, Shake256State};
/// let mut st = Shake256State::default();
/// fips202::shake256_absorb(&mut st, b"secret key seed");
/// let second_copy = st.clone(); // must not compile: no Clone on sponge state
/// ```
///
/// The fields are private. This is deliberate: `pos` must satisfy the
/// invariant `pos <= R`, and the squeeze/absorb routines rely on it to make
/// forward progress; `squeezing` must only flip on finalize. Exposing the
/// fields would let a caller (for example one that restores a state from
/// untrusted bytes) construct a state with `pos > R`, which previously caused
/// `keccak_squeeze` to loop forever.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
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
	/// Resets the sponge to its initial state: all-zero lanes, position 0, absorbing phase.
	pub fn init(&mut self) {
		self.s.fill(0);
		self.pos = 0;
		self.squeezing = false;
	}
}

/// Rotates a lane left by `offset` bits.
fn rol(a: u64, offset: u64) -> u64 {
	a.rotate_left(offset as u32)
}

/// Reads eight bytes as a little-endian `u64`.
#[inline]
fn load64(x: &[u8; 8]) -> u64 {
	u64::from_le_bytes(*x)
}

const KECCAKF_ROUND_CONSTANTS: [u64; NROUNDS] = [
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
];

/// Chi step on one row of five lanes.
fn chi([a, e, i, o, u]: [u64; 5]) -> [u64; 5] {
	[a ^ (!e & i), e ^ (!i & o), i ^ (!o & u), o ^ (!u & a), u ^ (!a & e)]
}

/// Secret-scrubbing boundary: this permutation unrolls the sponge into ~25 lane
/// locals plus per-round temporaries. These are deliberately *not* individually
/// zeroized. Doing so would be security theater with a real cost: `zeroize`'s
/// guarantee stops at owned buffers, the compiler already spills this round
/// state across registers and stack slots we cannot name, and adding volatile
/// wipes to every local in the hottest primitive in the library (run on every
/// absorb/squeeze for hashing, signing, and verification) is a measurable
/// regression for no reachable benefit. The owning [`KeccakState`] sponge is
/// `ZeroizeOnDrop`, so the durable copy of any absorbed secret is wiped when the
/// state is dropped; callers that squeeze secrets into their own buffers are
/// responsible for wiping those (see `poly::uniform_eta` / `uniform_gamma1`).
fn keccakf1600_statepermute(state: &mut [u64; 25]) {
	let [mut aba, mut abe, mut abi, mut abo, mut abu, rest @ ..] = *state;
	let [mut aga, mut age, mut agi, mut ago, mut agu, rest @ ..] = rest;
	let [mut aka, mut ake, mut aki, mut ako, mut aku, rest @ ..] = rest;
	let [mut ama, mut ame, mut ami, mut amo, mut amu, rest @ ..] = rest;
	let [mut asa, mut ase, mut asi, mut aso, mut asu] = rest;

	for round_constant in KECCAKF_ROUND_CONSTANTS {
		let bca = aba ^ aga ^ aka ^ ama ^ asa;
		let bce = abe ^ age ^ ake ^ ame ^ ase;
		let bci = abi ^ agi ^ aki ^ ami ^ asi;
		let bco = abo ^ ago ^ ako ^ amo ^ aso;
		let bcu = abu ^ agu ^ aku ^ amu ^ asu;

		let da = bcu ^ rol(bce, 1);
		let de = bca ^ rol(bci, 1);
		let di = bce ^ rol(bco, 1);
		let d_o = bci ^ rol(bcu, 1);
		let du = bco ^ rol(bca, 1);

		let [eba, ebe, ebi, ebo, ebu] = chi([
			aba ^ da,
			rol(age ^ de, 44),
			rol(aki ^ di, 43),
			rol(amo ^ d_o, 21),
			rol(asu ^ du, 14),
		]);
		let [ega, ege, egi, ego, egu] = chi([
			rol(abo ^ d_o, 28),
			rol(agu ^ du, 20),
			rol(aka ^ da, 3),
			rol(ame ^ de, 45),
			rol(asi ^ di, 61),
		]);
		let [eka, eke, eki, eko, eku] = chi([
			rol(abe ^ de, 1),
			rol(agi ^ di, 6),
			rol(ako ^ d_o, 25),
			rol(amu ^ du, 8),
			rol(asa ^ da, 18),
		]);
		let [ema, eme, emi, emo, emu] = chi([
			rol(abu ^ du, 27),
			rol(aga ^ da, 36),
			rol(ake ^ de, 10),
			rol(ami ^ di, 15),
			rol(aso ^ d_o, 56),
		]);
		let [esa, ese, esi, eso, esu] = chi([
			rol(abi ^ di, 62),
			rol(ago ^ d_o, 55),
			rol(aku ^ du, 39),
			rol(ama ^ da, 41),
			rol(ase ^ de, 2),
		]);

		[aba, abe, abi, abo, abu] = [eba ^ round_constant, ebe, ebi, ebo, ebu];
		[aga, age, agi, ago, agu] = [ega, ege, egi, ego, egu];
		[aka, ake, aki, ako, aku] = [eka, eke, eki, eko, eku];
		[ama, ame, ami, amo, amu] = [ema, eme, emi, emo, emu];
		[asa, ase, asi, aso, asu] = [esa, ese, esi, eso, esu];
	}

	*state = [
		aba, abe, abi, abo, abu, aga, age, agi, ago, agu, aka, ake, aki, ako, aku, ama, ame, ami,
		amo, amu, asa, ase, asi, aso, asu,
	];
}

/// XORs `bytes` into the state, starting at byte offset `pos` of the lane array.
fn xor_bytes(s: &mut [u64; 25], pos: usize, bytes: &[u8]) {
	for (i, &byte) in (pos..).zip(bytes) {
		s[i / 8] ^= (byte as u64) << (8 * (i % 8));
	}
}

/// Absorb step of Keccak; incremental. The rate comes from the state's type,
/// so `pos` can never be interpreted against the wrong block size.
fn keccak_absorb<const R: usize>(state: &mut KeccakState<R>, input: &[u8]) {
	debug_assert!(!state.squeezing, "fips202: absorb called on a finalized (squeezing) state");
	let mut input = input;
	while state.pos + input.len() >= R {
		let (block, rest) = input.split_at(R - state.pos);
		xor_bytes(&mut state.s, state.pos, block);
		keccakf1600_statepermute(&mut state.s);
		state.pos = 0;
		input = rest;
	}
	xor_bytes(&mut state.s, state.pos, input);
	state.pos += input.len();
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
	for byte in out.iter_mut() {
		// `>=` (rather than `==`) is a defensive guard: a well-formed state always
		// has `pos <= R`, but if an out-of-range `pos` ever reaches here we must
		// still permute and reset so the loop makes progress. Without this, a
		// `pos > R` would emit zero bytes per iteration and spin forever.
		if state.pos >= R {
			keccakf1600_statepermute(&mut state.s);
			state.pos = 0;
		}
		*byte = (state.s[state.pos / 8] >> (8 * (state.pos % 8))) as u8;
		state.pos += 1;
	}
}

/// Zeroes `s`, absorbs `input` at rate `R` and pads with domain byte `p`; no final permutation.
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

/// Absorbs `input` into a SHAKE128 state; may be called repeatedly before finalizing.
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
///
/// Taking whole blocks (`[[u8; SHAKE128_RATE]]`) instead of a flat slice plus a
/// block count makes an inconsistent count/capacity pair unrepresentable: the
/// old shape silently underfilled a short slice, leaving stale bytes that the
/// caller would treat as XOF output.
pub fn shake128_squeezeblocks(output: &mut [[u8; SHAKE128_RATE]], state: &mut Shake128State) {
	keccak_squeezeblocks(output, state);
}

/// Absorbs `input` into a SHAKE256 state; may be called repeatedly before finalizing.
pub fn shake256_absorb(state: &mut Shake256State, input: &[u8]) {
	keccak_absorb(state, input);
}

/// Finalize absorb step of the SHAKE256 XOF, transitioning the state to the
/// squeezing phase. Absorbing after this point is a caller bug (debug panic).
pub fn shake256_finalize(state: &mut Shake256State) {
	keccak_finalize(state, 0x1F);
}

/// Squeeze step of SHAKE256 XOF. Squeezes arbitrarily many bytes.
pub fn shake256_squeeze(out: &mut [u8], state: &mut Shake256State) {
	keccak_squeeze(out, state);
}

/// One-shot SHAKE256 absorb: resets `state`, absorbs `input` and leaves it ready to squeeze.
pub fn shake256_absorb_once(state: &mut Shake256State, input: &[u8]) {
	keccak_absorb_once::<SHAKE256_RATE>(&mut state.s, input, 0x1F);
	state.pos = SHAKE256_RATE;
	state.squeezing = true;
}

/// Squeeze step of SHAKE256 XOF. Squeezes one full block of SHAKE256_RATE bytes
/// per entry of `out`, continuing the canonical output stream.
///
/// Taking whole blocks (`[[u8; SHAKE256_RATE]]`) instead of a flat slice plus a
/// block count makes an inconsistent count/capacity pair unrepresentable: the
/// old shape silently underfilled a short slice, leaving stale bytes that the
/// caller would treat as XOF output.
pub fn shake256_squeezeblocks(out: &mut [[u8; SHAKE256_RATE]], state: &mut Shake256State) {
	keccak_squeezeblocks(out, state);
}

/// One-shot SHAKE256: fills all of `output` with the XOF output for `input`.
pub fn shake256(output: &mut [u8], input: &[u8]) {
	let mut state = Shake256State::default();
	shake256_absorb_once(&mut state, input);
	shake256_squeeze(output, &mut state);
}

/// Resets `state`, absorbs `seed` followed by the little-endian `nonce`, and finalizes it.
fn stream_init<const R: usize>(state: &mut KeccakState<R>, seed: &[u8], nonce: u16) {
	state.init();
	keccak_absorb(state, seed);
	keccak_absorb(state, &nonce.to_le_bytes());
	keccak_finalize(state, 0x1F);
}

/// Initialize SHAKE128 stream with a fixed-size seed and nonce, leaving the
/// state finalized (ready to squeeze).
pub fn shake128_stream_init(
	state: &mut Shake128State,
	seed: &[u8; crate::params::SEEDBYTES],
	nonce: u16,
) {
	stream_init(state, seed, nonce);
}

/// Initialize SHAKE256 stream with a fixed-size seed and nonce, leaving the
/// state finalized (ready to squeeze).
pub fn shake256_stream_init(
	state: &mut Shake256State,
	seed: &[u8; crate::params::CRHBYTES],
	nonce: u16,
) {
	stream_init(state, seed, nonce);
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
