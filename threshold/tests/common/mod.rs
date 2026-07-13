//! Shared test helpers for integration tests.

use std::collections::BTreeMap;

use qp_rusty_crystals_threshold::resharing::{
	ResharingConfig, ResharingProtocol, ResharingSignerConfig, TranscriptSigner,
};

/// Minimal transcript signer for tests: "signature" = party_id || hash.
///
/// Mirrors the DKG unit-test signer. Verification checks that the embedded
/// party ID matches the public key (which is just the party ID) and that the
/// embedded hash matches, so signatures over a *different* transcript hash
/// fail verification exactly like a real scheme.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct TestSigner {
	pub id: u32,
}

impl TranscriptSigner for TestSigner {
	type Signature = Vec<u8>;
	type PublicKey = u32;

	fn sign(&self, hash: &[u8; 32]) -> Self::Signature {
		let mut sig = vec![0u8; 36];
		sig[..4].copy_from_slice(&self.id.to_le_bytes());
		sig[4..36].copy_from_slice(hash);
		sig
	}

	fn verify(pk: &Self::PublicKey, hash: &[u8; 32], sig: &Self::Signature) -> bool {
		Self::verify_bytes(pk, hash, sig)
	}

	fn verify_bytes(pk: &Self::PublicKey, hash: &[u8; 32], sig: &[u8]) -> bool {
		if sig.len() < 36 {
			return false;
		}
		let sig_id = u32::from_le_bytes(sig[..4].try_into().unwrap());
		sig_id == *pk && &sig[4..36] == hash
	}

	fn public_key(&self) -> Self::PublicKey {
		self.id
	}
}

/// Build a `ResharingSignerConfig<TestSigner>` for the given config: this
/// party's signer plus verifying keys for every participant.
pub fn test_signer_config(config: &ResharingConfig) -> ResharingSignerConfig<TestSigner> {
	let new_participants: Vec<u32> = config.new_participants().iter().collect();
	let keys: BTreeMap<u32, u32> = config
		.old_participants()
		.iter()
		.chain(config.new_participants().iter())
		.map(|p| (p, p))
		.collect();
	ResharingSignerConfig::new(TestSigner { id: config.my_party_id() }, keys, &new_participants)
		.expect("keys cover the new committee")
}

/// Construct a `ResharingProtocol<TestSigner>` with a signer config derived
/// from the resharing config (drop-in for the pre-Round-6 constructor).
pub fn new_test_protocol(
	config: ResharingConfig,
	seed: [u8; 32],
	session_nonce: &[u8; 32],
) -> ResharingProtocol<TestSigner> {
	new_test_protocol_with_epoch(config, seed, session_nonce, 0)
}

/// Like [`new_test_protocol`], but with an explicit handoff epoch.
pub fn new_test_protocol_with_epoch(
	config: ResharingConfig,
	seed: [u8; 32],
	session_nonce: &[u8; 32],
	epoch: u64,
) -> ResharingProtocol<TestSigner> {
	let signer_config = test_signer_config(&config);
	ResharingProtocol::new(config, signer_config, seed, session_nonce, epoch)
}
