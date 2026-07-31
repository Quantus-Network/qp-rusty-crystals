use alloc::vec::Vec;
use core::{ops::Deref, str::FromStr};
use sha2::{
	digest::{generic_array::GenericArray, Digest},
	Sha512,
};
use zeroize::Zeroizing;

use crate::{SensitiveBytes32, MAX_DERIVATION_DEPTH, MAX_DERIVATION_PATH_BYTES};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
	InvalidChildNumber,
	InvalidDerivationPath,
	NotHardened,
	PathTooLong(usize),
	PathTooDeep(usize),
	InvalidSeedLength(usize),
}

const HARDENED_BIT: u32 = 1 << 31;

/// SHA-512 block and output sizes (bytes), fixed by the hash function.
const HMAC_BLOCK_BYTES: usize = 128;
const HMAC_OUTPUT_BYTES: usize = 64;

/// SHA-512 over `first` followed by the concatenation of `rest`, writing the
/// digest into `out` and volatile-wiping the hasher state in place afterwards.
///
/// This is the only function in the crate containing `unsafe`; every other
/// primitive that hashes secret material is built on it. It exists because
/// `sha2` 0.10 has no zeroizing drop semantics: a plainly dropped `Sha512`
/// leaves its block buffer — still holding input bytes verbatim — in a dead
/// stack frame (security review). The hasher here is only driven through
/// `&mut` methods (never moved), so wiping it in place erases every copy.
fn sha512_wiped(first: &[u8], rest: &[&[u8]], out: &mut [u8; HMAC_OUTPUT_BYTES]) {
	let mut hasher = Sha512::new();
	hasher.update(first);
	for part in rest {
		hasher.update(part);
	}
	hasher.finalize_into_reset(GenericArray::from_mut_slice(&mut out[..]));

	// SAFETY: `Sha512` is a flat struct (word state, length counter, block
	// buffer, position), containing no pointers or Drop glue, so writing
	// zeros over it is sound and it may be dropped afterwards.
	unsafe { zeroize::zeroize_flat_type(&mut hasher) };
}

/// HMAC-SHA512 over `key` and the concatenation of `message_parts`, writing
/// the tag into `out`.
///
/// This replaces the `hmac` crate, whose 0.12 state objects have no zeroizing
/// drop semantics (security review): its key-schedule local leaves
/// `key ^ opad` — and, depending on codegen, the raw key — in a dead stack
/// frame, its block buffer holds message bytes verbatim, and its consuming
/// `finalize(self)` moves all of that around the stack unwiped. Here every
/// secret-bearing buffer is under our control: the ipad/opad key blocks are
/// self-wiping and both hash passes go through [`sha512_wiped`].
///
/// Only keys up to one block are supported (the longer-key hashing step of
/// RFC 2104 is intentionally omitted); callers pass 14, 32, or 64 bytes.
fn hmac_sha512(key: &[u8], message_parts: &[&[u8]], out: &mut [u8; HMAC_OUTPUT_BYTES]) {
	debug_assert!(key.len() <= HMAC_BLOCK_BYTES, "keys longer than one block are unsupported");

	let mut ipad = Zeroizing::new([0x36u8; HMAC_BLOCK_BYTES]);
	let mut opad = Zeroizing::new([0x5cu8; HMAC_BLOCK_BYTES]);
	for (i, b) in key.iter().enumerate() {
		ipad[i] ^= *b;
		opad[i] ^= *b;
	}

	// The pads are always passed as slices: passing the (Copy) arrays by
	// value would leave unwiped copies of key material on the stack.
	let mut inner_hash = Zeroizing::new([0u8; HMAC_OUTPUT_BYTES]);
	sha512_wiped(ipad.as_slice(), message_parts, &mut inner_hash);
	sha512_wiped(opad.as_slice(), &[inner_hash.as_slice()], out);
}

/// PBKDF2-HMAC-SHA512 restricted to a single 64-byte output block (all this
/// crate needs: BIP39 seed stretching), built on the zeroizing [`hmac_sha512`].
///
/// This replaces `bip39::Mnemonic::to_seed_normalized`, which returns the
/// stretched seed as a plain `[u8; 64]` from a non-inlinable external
/// function: its internal seed local is dropped unwiped in a dead stack
/// frame, out of reach of any caller-side hygiene (security review). Here the
/// caller provides the output buffer and every intermediate is self-wiping.
pub(crate) fn pbkdf2_hmac_sha512(
	password: &[u8],
	salt_parts: &[&[u8]],
	rounds: u32,
	out: &mut [u8; HMAC_OUTPUT_BYTES],
) {
	// HMAC keys longer than one block are pre-hashed, exactly as RFC 2104
	// prescribes (and as any HMAC implementation would do internally), so
	// `hmac_sha512`'s one-block key limit holds. A 24-word mnemonic phrase —
	// the PBKDF2 password — is typically longer than 128 bytes.
	let mut hashed_key = Zeroizing::new([0u8; HMAC_OUTPUT_BYTES]);
	let key: &[u8] = if password.len() > HMAC_BLOCK_BYTES {
		sha512_wiped(password, &[], &mut hashed_key);
		&hashed_key[..]
	} else {
		password
	};

	// U1 = HMAC(P, salt || INT_32_BE(1)); the single output block is
	// U1 ^ U2 ^ ... ^ Uc with U_i = HMAC(P, U_{i-1}).
	let mut u = Zeroizing::new([0u8; HMAC_OUTPUT_BYTES]);
	let mut next = Zeroizing::new([0u8; HMAC_OUTPUT_BYTES]);
	let mut first_parts: Vec<&[u8]> = salt_parts.to_vec();
	let block_index = 1u32.to_be_bytes();
	first_parts.push(&block_index);
	hmac_sha512(key, &first_parts, &mut u);
	out.copy_from_slice(&*u);

	for _ in 1..rounds {
		hmac_sha512(key, &[&u[..]], &mut next);
		u.copy_from_slice(&*next);
		for (o, v) in out.iter_mut().zip(u.iter()) {
			*o ^= v;
		}
	}
}

/// Master-seed length bounds (bytes), per BIP32 (128..=512 bits). The
/// higher-level wrappers always pass a fixed 64-byte BIP39 seed; this bound
/// keeps the public low-level entrypoint from doing unbounded HMAC work over
/// an attacker-sized buffer.
pub const MIN_SEED_BYTES: usize = 16;
pub const MAX_SEED_BYTES: usize = 64;

/// Reject paths whose raw byte length or `/`-segment count exceed the workspace caps.
/// Runs before any allocation so attacker-controlled paths cannot drive memory or CPU.
pub(crate) fn check_path_bounds(path: &str) -> Result<(), Error> {
	if path.len() > MAX_DERIVATION_PATH_BYTES {
		return Err(Error::PathTooLong(path.len()));
	}
	let depth = path.bytes().filter(|b| *b == b'/').count();
	if depth > MAX_DERIVATION_DEPTH {
		return Err(Error::PathTooDeep(depth));
	}
	Ok(())
}

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChildNumber(u32);

impl ChildNumber {
	pub fn to_bytes(&self) -> [u8; 4] {
		self.0.to_be_bytes()
	}
}

impl FromStr for ChildNumber {
	type Err = Error;

	fn from_str(child: &str) -> Result<ChildNumber, Error> {
		let child = child.strip_suffix('\'').ok_or(Error::NotHardened)?;

		// Enforce a canonical decimal encoding before parsing. `u32::from_str`
		// tolerates a leading '+' and any number of leading zeros, so "44'",
		// "+44'", "0044'" and "000000044'" would all decode to the same child
		// index. Since the child index (not the string) feeds the HMAC step,
		// those distinct path strings would derive byte-identical keys and
		// addresses — collapsing textually distinct paths onto one identity.
		// Require: non-empty, ASCII digits only, and no redundant leading zero.
		if child.is_empty() || !child.bytes().all(|b| b.is_ascii_digit()) {
			return Err(Error::InvalidChildNumber);
		}
		if child.len() > 1 && child.starts_with('0') {
			return Err(Error::InvalidChildNumber);
		}

		let index: u32 = child.parse().map_err(|_| Error::InvalidChildNumber)?;
		if index & HARDENED_BIT != 0 {
			return Err(Error::InvalidChildNumber);
		}
		Ok(ChildNumber(index | HARDENED_BIT))
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DerivationPath {
	path: Vec<ChildNumber>,
}

impl FromStr for DerivationPath {
	type Err = Error;

	fn from_str(path: &str) -> Result<DerivationPath, Error> {
		check_path_bounds(path)?;

		let mut parts = path.split('/');

		if parts.next() != Some("m") {
			return Err(Error::InvalidDerivationPath);
		}

		Ok(DerivationPath {
			path: parts.map(str::parse).collect::<Result<Vec<ChildNumber>, Error>>()?,
		})
	}
}

impl Deref for DerivationPath {
	type Target = [ChildNumber];

	fn deref(&self) -> &Self::Target {
		&self.path
	}
}

impl<T> AsRef<T> for DerivationPath
where
	T: ?Sized,
	<DerivationPath as Deref>::Target: AsRef<T>,
{
	fn as_ref(&self) -> &T {
		self.deref().as_ref()
	}
}

impl DerivationPath {
	pub fn iter(&self) -> impl Iterator<Item = &ChildNumber> {
		self.path.iter()
	}
}

pub trait IntoDerivationPath {
	fn into(self) -> Result<DerivationPath, Error>;
}

impl IntoDerivationPath for DerivationPath {
	fn into(self) -> Result<DerivationPath, Error> {
		Ok(self)
	}
}

impl IntoDerivationPath for &str {
	fn into(self) -> Result<DerivationPath, Error> {
		self.parse()
	}
}
pub struct ExtendedPrivKey {
	// Debug intentionally omitted to avoid leaking key material.
	// Clone intentionally omitted: the embedded SensitiveBytes32 fields are move-only.
	secret_key: SensitiveBytes32,
	chain_code: SensitiveBytes32,
}

impl ExtendedPrivKey {
	/// Attempts to derive an extended private key from a path.
	///
	/// The path is parsed and validated first and the seed length is bounded
	/// to [`MIN_SEED_BYTES`]`..=`[`MAX_SEED_BYTES`], so malformed requests are
	/// rejected before any HMAC work is spent on the seed.
	pub fn derive<Path>(seed: &[u8], path: Path) -> Result<ExtendedPrivKey, Error>
	where
		Path: IntoDerivationPath,
	{
		let path = path.into()?;
		if seed.len() < MIN_SEED_BYTES || seed.len() > MAX_SEED_BYTES {
			return Err(Error::InvalidSeedLength(seed.len()));
		}

		// `result` holds secret_key || chain_code; the self-wiping buffer is
		// zeroized on drop, after the halves are copied into the
		// self-zeroizing `SensitiveBytes32` fields.
		let mut result = Zeroizing::new([0u8; HMAC_OUTPUT_BYTES]);
		hmac_sha512(b"Dilithium seed", &[seed], &mut result);
		let (secret_key, chain_code) = result.split_at(32);

		let mut sk = ExtendedPrivKey {
			secret_key: SensitiveBytes32::from(&mut secret_key.try_into().unwrap()),
			chain_code: SensitiveBytes32::from(&mut chain_code.try_into().unwrap()),
		};

		for child in path.as_ref() {
			sk = sk.child(*child)?;
		}

		Ok(sk)
	}

	pub fn secret(&self) -> [u8; 32] {
		*self.secret_key.as_bytes()
	}

	pub fn child(&self, child: ChildNumber) -> Result<ExtendedPrivKey, Error> {
		// Feed the HMAC directly from the stored secret rather than
		// `self.secret()`, which would materialize a throwaway `[u8; 32]` copy
		// on the stack that is never wiped. See `derive` for the lifecycle of
		// the self-wiping `result` buffer.
		let mut result = Zeroizing::new([0u8; HMAC_OUTPUT_BYTES]);
		hmac_sha512(
			self.chain_code.as_bytes(),
			&[&[0], self.secret_key.as_bytes(), &child.to_bytes()],
			&mut result,
		);
		let (secret_key, chain_code) = result.split_at(32);

		let child = ExtendedPrivKey {
			secret_key: SensitiveBytes32::from(&mut secret_key.try_into().unwrap()),
			chain_code: SensitiveBytes32::from(&mut chain_code.try_into().unwrap()),
		};
		Ok(child)
	}
}

impl core::fmt::Debug for ExtendedPrivKey {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		f.debug_struct("ExtendedPrivKey").finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;
	use bip39::{Language, Mnemonic};

	#[test]
	fn bip39_to_address() {
		let phrase = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";

		let expected_secret_key = b"\x2f\xbd\x41\x6a\x34\xc0\xac\x40\x98\xea\xad\xd0\x8c\x07\xc7\x09\xad\xf4\xd8\x7e\x7a\xa8\x12\x44\xa4\xbf\x2b\xf9\xfb\xfb\xbf\x76";

		let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase).unwrap();
		let seed = mnemonic.to_seed_normalized("");

		let account = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0'/0'").unwrap();

		assert_eq!(expected_secret_key, &account.secret(), "Secret key is invalid");
	}

	// The in-crate zeroizing HMAC must be a correct HMAC-SHA512. Pin it to the
	// official RFC 4231 test vectors (cases 1-4; the remaining cases use
	// truncated outputs or keys longer than one block, which this
	// implementation intentionally does not support).
	#[test]
	fn hmac_sha512_matches_rfc4231_vectors() {
		use hex_literal::hex;

		let cases: &[(&[u8], &[u8], [u8; 64])] = &[
			(
				&[0x0b; 20],
				b"Hi There",
				hex!(
					"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
					"daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
				),
			),
			(
				b"Jefe",
				b"what do ya want for nothing?",
				hex!(
					"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
					"9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
				),
			),
			(
				&[0xaa; 20],
				&[0xdd; 50],
				hex!(
					"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
					"bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
				),
			),
			(
				&hex!("0102030405060708090a0b0c0d0e0f10111213141516171819"),
				&[0xcd; 50],
				hex!(
					"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
					"a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
				),
			),
		];

		for (i, (key, data, expected)) in cases.iter().enumerate() {
			let mut out = [0u8; 64];
			hmac_sha512(key, &[data], &mut out);
			assert_eq!(&out, expected, "RFC 4231 test case {} failed", i + 1);
		}
	}

	// Cross-check against the `hmac` crate (the previous implementation, kept
	// as a dev-dependency) across key lengths up to a full block and across
	// message-part splits, including boundary-straddling ones. This covers the
	// exact shapes used by `derive` (14-byte key, one part) and `child`
	// (32-byte key, three parts) and everything in between.
	#[test]
	fn hmac_sha512_matches_reference_implementation() {
		use hmac::{Hmac, Mac};

		let msg: Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(31) ^ 0x5f) as u8).collect();
		for key_len in [0usize, 1, 14, 32, 63, 64, 65, 127, 128] {
			let key: Vec<u8> = (0..key_len as u32).map(|i| (i.wrapping_mul(7) + 3) as u8).collect();

			let mut reference: Hmac<sha2::Sha512> = Hmac::new_from_slice(&key).unwrap();
			reference.update(&msg);
			let expected = reference.finalize().into_bytes();

			let splits: &[&[&[u8]]] = &[
				&[&msg],
				&[&msg[..1], &msg[1..]],
				&[&msg[..37], &msg[37..37], &msg[37..]],
				// straddles the first SHA-512 block boundary of the inner
				// hash (128-byte ipad block + 64 message bytes)
				&[&msg[..64], &msg[64..]],
				&[&msg[..128], &msg[128..]],
			];
			for parts in splits {
				let mut out = [0u8; 64];
				hmac_sha512(&key, parts, &mut out);
				assert_eq!(
					out[..],
					expected[..],
					"mismatch vs reference for key_len={key_len}, {} part(s)",
					parts.len()
				);
			}
		}
	}

	#[test]
	fn derive_path() {
		let path: DerivationPath = "m/44'/60'/0'".parse().unwrap();
		assert_eq!(
			path,
			DerivationPath {
				path: vec![
					ChildNumber(44 | HARDENED_BIT),
					ChildNumber(60 | HARDENED_BIT),
					ChildNumber(HARDENED_BIT),
				],
			}
		);
	}

	#[test]
	fn non_hardened_path_rejected() {
		assert_eq!("m/44'/60'/0".parse::<DerivationPath>().unwrap_err(), Error::NotHardened);
		assert_eq!("0".parse::<ChildNumber>().unwrap_err(), Error::NotHardened);
	}

	// Non-canonical decimal spellings must be rejected. Otherwise "+44'",
	// "0044'", etc. would alias to the same child index as "44'" and derive
	// byte-identical keys/addresses, collapsing distinct path strings onto one
	// on-chain identity.
	#[test]
	fn non_canonical_child_numbers_rejected() {
		// The canonical form still works.
		assert_eq!("44'".parse::<ChildNumber>().unwrap(), ChildNumber(44 | HARDENED_BIT));
		assert_eq!("0'".parse::<ChildNumber>().unwrap(), ChildNumber(HARDENED_BIT));

		for bad in ["+44'", "0044'", "000000044'", "+0'", "00'", " 44'", "44 '", "4_4'"] {
			assert_eq!(
				bad.parse::<ChildNumber>().unwrap_err(),
				Error::InvalidChildNumber,
				"non-canonical child number {:?} must be rejected",
				bad
			);
		}

		// And the same via a full path so the aliasing can't slip in mid-path.
		assert_eq!(
			"m/44'/189189189'/+0'".parse::<DerivationPath>().unwrap_err(),
			Error::InvalidChildNumber
		);
	}

	// Every ChildNumber construction path must enforce `index < 2^31` before
	// setting the hardened bit. An index with the bit already set (e.g.
	// 2147483648) would encode to the same four bytes as its low alias (0'),
	// and since only those bytes feed the HMAC derivation, two distinct
	// advertised indexes would silently derive the same wallet key. The
	// string parser is the only remaining public constructor (the unchecked
	// numeric constructor `hardened_from_u32` was removed for exactly this
	// aliasing risk), so pin the parser's rejection here.
	#[test]
	fn child_indexes_with_hardened_bit_set_rejected() {
		// The largest valid index and its would-be aliases.
		assert_eq!("2147483647'".parse::<ChildNumber>().unwrap(), ChildNumber(u32::MAX));
		for (aliased, canonical) in [("2147483648'", "0'"), ("2147483692'", "44'")] {
			assert!(
				canonical.parse::<ChildNumber>().is_ok(),
				"canonical child number {canonical:?} must parse"
			);
			assert_eq!(
				aliased.parse::<ChildNumber>().unwrap_err(),
				Error::InvalidChildNumber,
				"{aliased:?} must be rejected, not alias {canonical:?}"
			);
		}
		// Beyond u32 entirely.
		assert_eq!("4294967296'".parse::<ChildNumber>().unwrap_err(), Error::InvalidChildNumber);
	}

	// `derive` is a public entrypoint that may see attacker-controlled input.
	// The seed must be bounded (BIP32-style 16..=64 bytes) so a caller cannot
	// force linear HMAC work over an arbitrarily large buffer.
	#[test]
	fn seed_length_bounds_enforced() {
		let path = "m/44'/60'/0'";
		for ok_len in [16usize, 32, 64] {
			assert!(
				ExtendedPrivKey::derive(&vec![7u8; ok_len], path).is_ok(),
				"seed of {ok_len} bytes must be accepted"
			);
		}
		for bad_len in [0usize, 15, 65, 1 << 20] {
			assert_eq!(
				ExtendedPrivKey::derive(&vec![7u8; bad_len], path).unwrap_err(),
				Error::InvalidSeedLength(bad_len),
				"seed of {bad_len} bytes must be rejected"
			);
		}
	}

	// The path must be validated before any seed processing, so a malformed
	// request fails on the cheap string parse rather than after doing HMAC
	// work over the seed. Pinned observably: with a bad path AND a bad seed,
	// the path error wins.
	#[test]
	fn invalid_path_rejected_before_seed_is_touched() {
		let huge_seed = vec![7u8; 1 << 20];
		assert_eq!(
			ExtendedPrivKey::derive(&huge_seed, "not-a-path").unwrap_err(),
			Error::InvalidDerivationPath,
			"path validation must run (and fail) before the seed is processed"
		);
	}
}
