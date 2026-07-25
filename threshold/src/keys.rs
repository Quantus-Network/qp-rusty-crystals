//! Key types for threshold ML-DSA-87.
//!
//! This module defines the public key and private key share types used in
//! threshold signing. The private key share is intentionally opaque to
//! prevent accidental exposure of secret material.

use alloc::{collections::BTreeMap, format};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use borsh::{BorshDeserialize, BorshSerialize};
use qp_rusty_crystals_dilithium::params::{K, L};

use crate::{
	error::MAX_SUBSETS,
	participants::{ParticipantId, ParticipantList},
};

/// Size of the packed ML-DSA-87 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 2592;

/// Size of the TR hash (public key hash) in bytes.
pub const TR_SIZE: usize = 64;

/// Compute TR = SHAKE256(pk_bytes).
fn compute_tr(bytes: &[u8; PUBLIC_KEY_SIZE]) -> [u8; TR_SIZE] {
	let mut tr = [0u8; TR_SIZE];
	let mut state = qp_rusty_crystals_dilithium::fips202::KeccakState::default();
	qp_rusty_crystals_dilithium::fips202::shake256_absorb(&mut state, bytes);
	qp_rusty_crystals_dilithium::fips202::shake256_finalize(&mut state);
	qp_rusty_crystals_dilithium::fips202::shake256_squeeze(&mut tr, &mut state);
	tr
}

/// Validate public key bytes through the canonical ML-DSA parser.
///
/// Every import boundary (`from_bytes`, Borsh deserialization) must apply
/// the same key-validity rules as `ml_dsa_87::PublicKey::from_bytes` and the
/// verifier — in particular the rejection of the degenerate all-zero t1 key,
/// which removes challenge binding and makes signatures forgeable. Accepting
/// such bytes here would hand downstream code a trusted-looking `PublicKey`
/// that the core implementation itself treats as invalid.
fn validate_pk_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Result<(), &'static str> {
	qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(bytes)
		.map(|_| ())
		.map_err(|_| "invalid ML-DSA public key")
}

/// Public key for threshold ML-DSA-87.
///
/// This key is shared among all parties and is used for signature verification.
/// It can be freely distributed - there is no secret material here.
///
/// The public key is compatible with standard ML-DSA-87 verification.
///
/// # Serialization
///
/// Only the public key bytes are serialized. The TR hash (used internally for
/// signing) is recomputed from bytes during deserialization. This eliminates
/// the possibility of "poisoned" public keys with mismatched TR values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
	/// Packed public key bytes (standard ML-DSA-87 format).
	bytes: [u8; PUBLIC_KEY_SIZE],
	/// Public key hash (TR), used in signing. Always equals SHAKE256(bytes).
	/// Cached for performance since it's used in hot paths during signing.
	tr: [u8; TR_SIZE],
}

impl BorshSerialize for PublicKey {
	fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
		// Only serialize bytes; tr is recomputed on deserialize
		self.bytes.serialize(writer)
	}
}

impl BorshDeserialize for PublicKey {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let bytes = <[u8; PUBLIC_KEY_SIZE]>::deserialize_reader(reader)?;
		validate_pk_bytes(&bytes)
			.map_err(|e| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, e))?;
		let tr = compute_tr(&bytes);
		Ok(Self { bytes, tr })
	}
}

impl PublicKey {
	/// Create a new public key from packed bytes.
	///
	/// TR is computed automatically as `SHAKE256(bytes)`.
	pub(crate) fn new(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
		let tr = compute_tr(&bytes);
		Self { bytes, tr }
	}

	/// Get the packed public key bytes.
	///
	/// These bytes are in standard ML-DSA-87 format and can be used
	/// with the `qp-rusty-crystals-dilithium` crate for verification.
	pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
		&self.bytes
	}

	/// Get the public key hash (TR).
	pub fn tr(&self) -> &[u8; TR_SIZE] {
		&self.tr
	}

	/// Create a public key from bytes.
	///
	/// The bytes are validated through the canonical ML-DSA parser (rejecting
	/// e.g. the forgeable all-zero t1 key), and the TR hash is computed from
	/// them.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != PUBLIC_KEY_SIZE {
			return Err("invalid public key length");
		}

		let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE];
		pk_bytes.copy_from_slice(bytes);
		validate_pk_bytes(&pk_bytes)?;

		let tr = compute_tr(&pk_bytes);
		Ok(Self { bytes: pk_bytes, tr })
	}
}

/// Private key share for one party in threshold ML-DSA-87.
///
/// **This contains secret material and MUST be kept confidential.**
///
/// Each party in the threshold scheme holds one private key share.
/// The share is intentionally opaque - the API exposes no way to read the
/// internal secret values. This prevents accidental leakage. (Note that
/// the share must remain serializable so it can be stored and restored;
/// the serialized bytes contain the secret material and must be protected
/// accordingly.)
///
/// # Security
///
/// - Never transmit this over an insecure channel
/// - Never log or print this value
/// - Store securely (encrypted at rest)
/// - The `Zeroize` trait ensures memory is cleared on drop
#[derive(Clone, PartialEq, Eq, BorshSerialize)]
pub struct PrivateKeyShare {
	/// Party identifier (can be arbitrary u32, e.g., NEAR participant ID).
	party_id: ParticipantId,
	/// Total number of parties.
	total_parties: u32,
	/// Threshold value.
	threshold: u32,
	/// DKG participants list - maps arbitrary party IDs to sequential indices.
	/// The sequential indices (0, 1, 2, ...) are used for share subset masks.
	dkg_participants: ParticipantList,
	/// Private key seed.
	key: [u8; 32],
	/// Random seed rho (same as public key).
	rho: [u8; 32],
	/// Hash of public key for signing.
	tr: [u8; TR_SIZE],
	/// Secret shares for this party, keyed by signer subset ID.
	/// Each share contains (s1_share, s2_share) polynomial vectors.
	/// Uses u16 as subset mask to support up to 16 parties.
	/// BTreeMap ensures deterministic serialization order.
	shares: BTreeMap<u16, SecretShareData>,
}

impl BorshDeserialize for PrivateKeyShare {
	/// Deserialize with cross-field consistency validation.
	///
	/// The signing state machine treats this metadata as authoritative
	/// without re-checking it: Round 3 share recovery looks `party_id` up in
	/// `dkg_participants`, and `translated_subset_masks` indexes arrays sized
	/// by `total_parties` with dkg indices. A tampered blob violating these
	/// invariants would otherwise initialize a signer, run rounds 1-2
	/// (wasting local and peer work on a session that can never complete),
	/// and only surface at Round 3 - as a late `InvalidConfiguration` error
	/// or, for `dkg_participants.len() > total_parties`, an out-of-bounds
	/// panic. Every producer (dealer, DKG, resharing) satisfies these
	/// invariants by construction, so rejecting violations here only rejects
	/// malformed or tampered blobs.
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let invalid = |msg: &str| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, msg);

		let party_id = ParticipantId::deserialize_reader(reader)?;
		let total_parties = u32::deserialize_reader(reader)?;
		let threshold = u32::deserialize_reader(reader)?;
		let dkg_participants = ParticipantList::deserialize_reader(reader)?;
		let key = <[u8; 32]>::deserialize_reader(reader)?;
		let rho = <[u8; 32]>::deserialize_reader(reader)?;
		let tr = <[u8; TR_SIZE]>::deserialize_reader(reader)?;

		// (threshold, total_parties) must be a combination the scheme
		// actually supports; this also bounds total_parties by MAX_PARTIES,
		// keeping the mask-domain shift below well-defined.
		crate::config::ThresholdConfig::new(threshold, total_parties).map_err(|_| {
			invalid("PrivateKeyShare threshold/total_parties is not a supported configuration")
		})?;
		if dkg_participants.len() != total_parties as usize {
			return Err(invalid(
				"PrivateKeyShare dkg_participants length does not match total_parties",
			));
		}
		if dkg_participants.index_of(party_id).is_none() {
			return Err(invalid("PrivateKeyShare party_id is not in dkg_participants"));
		}

		// Read shares map with bound check
		let len = u32::deserialize_reader(reader)? as usize;
		if len > MAX_SUBSETS {
			return Err(invalid("PrivateKeyShare.shares exceeds MAX_SUBSETS"));
		}

		// Subset masks are bitmasks over dkg indices 0..total_parties.
		let mask_domain: u32 = 1u32 << total_parties;

		let mut shares = BTreeMap::new();
		for _ in 0..len {
			let key = u16::deserialize_reader(reader)?;
			if key == 0 || u32::from(key) >= mask_domain {
				return Err(invalid(
					"PrivateKeyShare share subset mask outside participant index domain",
				));
			}
			let value = SecretShareData::deserialize_reader(reader)?;
			shares.insert(key, value);
		}

		Ok(Self { party_id, total_parties, threshold, dkg_participants, key, rho, tr, shares })
	}
}

/// Internal secret share data for a specific signer subset.
///
/// Uses fixed-size arrays to guarantee exact dimensions at compile time,
/// preventing malformed deserialized data from causing issues downstream.
#[derive(Clone, PartialEq, Eq, BorshSerialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretShareData {
	/// Share of s1 polynomial vector (exactly L polynomials of 256 coefficients).
	pub(crate) s1: [[i32; 256]; L],
	/// Share of s2 polynomial vector (exactly K polynomials of 256 coefficients).
	pub(crate) s2: [[i32; 256]; K],
}

impl BorshDeserialize for SecretShareData {
	/// Deserialize with coefficient-range validation.
	///
	/// Every producer of share data emits coefficients in (-Q, Q): the
	/// dealer's shares are η-bounded, and DKG/resharing shares are reduced
	/// mod Q before storage. Signing copies these raw arrays into `Poly`
	/// values and runs `poly::ntt` on them, whose coefficient bound is a
	/// caller-enforced contract — so a malformed blob with out-of-range
	/// coefficients must be rejected at import, not discovered as a panic
	/// (overflow checks on) or silent wraparound (release) mid-signing.
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		const Q: i32 = qp_rusty_crystals_dilithium::params::Q;
		let s1 = <[[i32; 256]; L]>::deserialize_reader(reader)?;
		let s2 = <[[i32; 256]; K]>::deserialize_reader(reader)?;
		let in_range =
			|polys: &[[i32; 256]]| polys.iter().all(|poly| poly.iter().all(|&c| c > -Q && c < Q));
		if !in_range(&s1) || !in_range(&s2) {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"SecretShareData coefficient outside (-Q, Q)",
			));
		}
		Ok(Self { s1, s2 })
	}
}

impl PrivateKeyShare {
	/// Create a new private key share.
	pub(crate) fn new(
		party_id: ParticipantId,
		total_parties: u32,
		threshold: u32,
		key: [u8; 32],
		rho: [u8; 32],
		tr: [u8; TR_SIZE],
		shares: BTreeMap<u16, SecretShareData>,
		dkg_participants: ParticipantList,
	) -> Self {
		Self { party_id, total_parties, threshold, key, rho, tr, shares, dkg_participants }
	}

	/// Get this party's ID (can be arbitrary, e.g., NEAR participant ID).
	pub fn party_id(&self) -> ParticipantId {
		self.party_id
	}

	/// Get this party's DKG index (0 to n-1).
	/// This is used internally for share lookup via subset masks.
	pub fn dkg_index(&self) -> Option<usize> {
		self.dkg_participants.index_of(self.party_id)
	}

	/// Get the DKG participants list.
	/// This maps arbitrary party IDs to sequential indices for share operations.
	pub fn dkg_participants(&self) -> &ParticipantList {
		&self.dkg_participants
	}

	/// Get the total number of parties.
	pub fn total_parties(&self) -> u32 {
		self.total_parties
	}

	/// Get the threshold value.
	pub fn threshold(&self) -> u32 {
		self.threshold
	}

	/// Get the random seed rho (for internal use).
	pub(crate) fn rho(&self) -> &[u8; 32] {
		&self.rho
	}

	/// Get the public key hash TR (for internal use).
	pub(crate) fn tr(&self) -> &[u8; TR_SIZE] {
		&self.tr
	}

	/// Get the secret shares (for internal use).
	pub(crate) fn shares(&self) -> &BTreeMap<u16, SecretShareData> {
		&self.shares
	}
}

impl Zeroize for PrivateKeyShare {
	fn zeroize(&mut self) {
		self.party_id.zeroize();
		self.total_parties.zeroize();
		self.threshold.zeroize();
		self.key.zeroize();
		self.rho.zeroize();
		self.tr.zeroize();
		for (_, share) in self.shares.iter_mut() {
			share.zeroize();
		}
		self.shares.clear();
	}
}

impl Drop for PrivateKeyShare {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl ZeroizeOnDrop for PrivateKeyShare {}

impl fmt::Debug for PrivateKeyShare {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("PrivateKeyShare")
			.field("party_id", &self.party_id)
			.field("total_parties", &self.total_parties)
			.field("threshold", &self.threshold)
			.field("key", &"[REDACTED]")
			.field("shares", &format!("{} subsets", self.shares.len()))
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_public_key_roundtrip() {
		let bytes = [0x42u8; PUBLIC_KEY_SIZE];
		let pk = PublicKey::from_bytes(&bytes).unwrap();
		assert_eq!(pk.as_bytes(), &bytes);
	}

	#[test]
	fn test_public_key_invalid_length() {
		let bytes = [0u8; 100];
		assert!(PublicKey::from_bytes(&bytes).is_err());
	}

	/// Security review: the threshold public key import paths must apply the
	/// same degenerate-key check as the canonical ML-DSA parser
	/// (`ml_dsa_87::PublicKey::from_bytes`) and the verifier, both of which
	/// reject an all-zero t1 because it removes challenge binding and makes
	/// signatures forgeable for that key. Accepting it here would let
	/// downstream code trust a forgeable PublicKey object (or its
	/// `as_bytes()` output) without ever re-parsing through the safe wrapper.
	#[test]
	fn test_public_key_from_bytes_rejects_zero_t1() {
		// rho nonzero, t1 region all zero — the forgeable class.
		let mut bytes = [0u8; PUBLIC_KEY_SIZE];
		bytes[..32].copy_from_slice(&[0x42u8; 32]);
		assert!(
			PublicKey::from_bytes(&bytes).is_err(),
			"all-zero t1 public key must be rejected by from_bytes"
		);
	}

	/// Borsh deserialization is an import boundary too (broadcast messages,
	/// stored state) and must enforce the same check as `from_bytes`.
	#[test]
	fn test_public_key_borsh_rejects_zero_t1() {
		let mut bytes = [0u8; PUBLIC_KEY_SIZE];
		bytes[..32].copy_from_slice(&[0x42u8; 32]);
		let result: Result<PublicKey, _> = borsh::from_slice(&bytes);
		assert!(result.is_err(), "all-zero t1 public key must be rejected by Borsh deserialize");
	}

	#[test]
	fn test_private_key_debug_redacts_secrets() {
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let pk_share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0x42u8; 32],
			[0u8; 32],
			[0u8; TR_SIZE],
			BTreeMap::new(),
			dkg_participants,
		);
		let debug_str = format!("{:?}", pk_share);
		assert!(debug_str.contains("REDACTED"));
		assert!(!debug_str.contains("42")); // Should not contain the key bytes
	}

	#[test]
	fn test_private_key_zeroize() {
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut pk_share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0x42u8; 32],
			[0x43u8; 32],
			[0x44u8; TR_SIZE],
			BTreeMap::new(),
			dkg_participants,
		);
		pk_share.zeroize();
		assert_eq!(pk_share.key, [0u8; 32]);
		assert_eq!(pk_share.rho, [0u8; 32]);
		assert_eq!(pk_share.tr, [0u8; TR_SIZE]);
	}

	/// Security review: PrivateKeyShare deserialization must validate share
	/// coefficient ranges, not just the share-map length. Signing copies the
	/// raw arrays into Poly values and runs poly::ntt on them, whose
	/// coefficient-bound contract is caller-enforced — a malformed blob would
	/// import cleanly and only blow up (panic with overflow checks, silent
	/// wrap in release) once the signer tries to use it.
	#[test]
	fn test_private_key_share_borsh_rejects_out_of_range_coefficients() {
		use qp_rusty_crystals_dilithium::params::Q;

		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut shares = BTreeMap::new();
		let mut bad = SecretShareData { s1: [[0i32; 256]; L], s2: [[0i32; 256]; K] };
		bad.s1[0][0] = i32::MAX;
		shares.insert(0b011u16, bad);

		let share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0x11u8; 32],
			[0x22u8; 32],
			[0x33u8; TR_SIZE],
			shares,
			dkg_participants.clone(),
		);
		let bytes = borsh::to_vec(&share).unwrap();
		let result: Result<PrivateKeyShare, _> = borsh::from_slice(&bytes);
		assert!(result.is_err(), "share coefficient outside (-Q, Q) must be rejected at import");

		// Boundary: exactly Q and -Q are invalid, Q-1 and -(Q-1) are valid.
		for (value, valid) in [(Q, false), (-Q, false), (Q - 1, true), (-(Q - 1), true)] {
			let mut shares = BTreeMap::new();
			let mut data = SecretShareData { s1: [[0i32; 256]; L], s2: [[0i32; 256]; K] };
			data.s2[K - 1][255] = value;
			shares.insert(0b011u16, data);
			let share = PrivateKeyShare::new(
				0,
				3,
				2,
				[0x11u8; 32],
				[0x22u8; 32],
				[0x33u8; TR_SIZE],
				shares,
				dkg_participants.clone(),
			);
			let bytes = borsh::to_vec(&share).unwrap();
			let result: Result<PrivateKeyShare, _> = borsh::from_slice(&bytes);
			assert_eq!(
				result.is_ok(),
				valid,
				"coefficient {} should be {}",
				value,
				if valid { "accepted" } else { "rejected" }
			);
		}
	}

	/// Security review: deserialization must reject metadata that is not
	/// mutually consistent. Round 3 share recovery and
	/// `translated_subset_masks` treat `party_id`, `threshold`,
	/// `total_parties`, and `dkg_participants` as already self-consistent; a
	/// tampered blob that violates that either fails only after the signing
	/// state machine has progressed (wasting peer work) or panics with an
	/// out-of-bounds index instead of returning an error.
	#[test]
	fn test_private_key_share_borsh_rejects_inconsistent_metadata() {
		let roundtrip = |party_id: u32,
		                 total_parties: u32,
		                 threshold: u32,
		                 participants: &[ParticipantId],
		                 masks: &[u16]|
		 -> Result<PrivateKeyShare, borsh::io::Error> {
			let dkg_participants = ParticipantList::new(participants).unwrap();
			let mut shares = BTreeMap::new();
			for &mask in masks {
				shares.insert(mask, SecretShareData { s1: [[0i32; 256]; L], s2: [[0i32; 256]; K] });
			}
			let share = PrivateKeyShare::new(
				party_id,
				total_parties,
				threshold,
				[0x11u8; 32],
				[0x22u8; 32],
				[0x33u8; TR_SIZE],
				shares,
				dkg_participants,
			);
			let bytes = borsh::to_vec(&share).unwrap();
			borsh::from_slice(&bytes)
		};

		// Baseline: consistent metadata imports fine.
		assert!(roundtrip(0, 3, 2, &[0, 1, 2], &[0b011]).is_ok());

		// party_id not in dkg_participants: Round 3 recovery would fail late
		// with InvalidConfiguration after rounds 1-2 already ran.
		assert!(
			roundtrip(99, 3, 2, &[0, 1, 2], &[0b011]).is_err(),
			"party_id missing from dkg_participants must be rejected at import"
		);

		// dkg_participants larger than total_parties: drives an out-of-bounds
		// panic in translated_subset_masks during signing.
		assert!(
			roundtrip(0, 2, 2, &[0, 1, 2], &[0b01]).is_err(),
			"dkg_participants.len() > total_parties must be rejected at import"
		);

		// dkg_participants smaller than total_parties: protocol waits on
		// share subsets that cannot exist.
		assert!(
			roundtrip(0, 3, 2, &[0, 1], &[0b011]).is_err(),
			"dkg_participants.len() < total_parties must be rejected at import"
		);

		// (threshold, total_parties) pairs the scheme does not support.
		assert!(
			roundtrip(0, 3, 1, &[0, 1, 2], &[0b011]).is_err(),
			"threshold below 2 must be rejected at import"
		);
		assert!(
			roundtrip(0, 3, 4, &[0, 1, 2], &[0b011]).is_err(),
			"threshold above total_parties must be rejected at import"
		);

		// Subset masks outside the participant index domain.
		assert!(
			roundtrip(0, 3, 2, &[0, 1, 2], &[0b1001]).is_err(),
			"share mask with a bit beyond total_parties must be rejected at import"
		);
		assert!(
			roundtrip(0, 3, 2, &[0, 1, 2], &[0]).is_err(),
			"empty share mask must be rejected at import"
		);
	}

	#[test]
	fn test_public_key_borsh_roundtrip() {
		// Valid public key should serialize and deserialize correctly
		let bytes = [0x42u8; PUBLIC_KEY_SIZE];
		let pk = PublicKey::from_bytes(&bytes).unwrap();

		let serialized = borsh::to_vec(&pk).unwrap();
		let deserialized: PublicKey = borsh::from_slice(&serialized).unwrap();

		assert_eq!(pk, deserialized);
		assert_eq!(pk.as_bytes(), deserialized.as_bytes());
		assert_eq!(pk.tr(), deserialized.tr());
	}

	#[test]
	fn test_public_key_serialization_only_includes_bytes() {
		// Verify that only the public key bytes are serialized (not TR)
		let bytes = [0x42u8; PUBLIC_KEY_SIZE];
		let pk = PublicKey::from_bytes(&bytes).unwrap();

		let serialized = borsh::to_vec(&pk).unwrap();

		// Serialized size should be exactly PUBLIC_KEY_SIZE (no TR)
		assert_eq!(serialized.len(), PUBLIC_KEY_SIZE);

		// TR is recomputed on deserialize, so any modification to the
		// serialized bytes will result in a different (but consistent) TR
		let mut modified = serialized.clone();
		modified[0] ^= 0xFF;
		let deserialized: PublicKey = borsh::from_slice(&modified).unwrap();

		// The deserialized key should have different bytes AND different TR
		assert_ne!(deserialized.as_bytes(), pk.as_bytes());
		assert_ne!(deserialized.tr(), pk.tr());
	}
}
